// Package engine is the BitGate authorization core. It ties together the
// permission registry, role store, and per-user assignments, and answers
// permission checks.
//
// Design:
//   - A single sync.RWMutex guards all mutable state (registry, roles, users,
//     caches). Internal building blocks are lock-free for speed.
//   - Each user's effective permission set is cached as an immutable
//     *bitset.Bitset snapshot. Mutations bump a version counter; the snapshot is
//     rebuilt lazily on the next check. Once built, a snapshot is never modified,
//     so the hot path can read it after releasing the lock.
//   - Can is O(1): resolve the permission handle, then test one bit.
package engine

import (
	"errors"
	"sync"

	"github.com/Revelts/bitgate/bitset"
	"github.com/Revelts/bitgate/permission"
	"github.com/Revelts/bitgate/role"
)

// Permission is an opaque handle to a registered permission. Use it with CanID
// for a string-free check on hot paths.
type Permission = permission.ID

// Errors returned by the engine.
var (
	ErrEmptyName        = errors.New("bitgate: empty name")
	ErrUnknownRole      = role.ErrUnknownRole
	ErrInheritanceCycle = role.ErrCycle
)

type userRec struct {
	roles  []string
	direct *bitset.Bitset

	eff    *bitset.Bitset // cached effective snapshot (immutable once built)
	effVer uint64
}

// Engine is a thread-safe RBAC/permission engine.
type Engine struct {
	mu      sync.RWMutex
	reg     *permission.Registry
	roles   *role.Store
	users   map[string]*userRec
	version uint64 // bumped whenever effective permissions may change
}

// New returns an empty Engine.
func New() *Engine {
	return &Engine{
		reg:   permission.NewRegistry(),
		roles: role.NewStore(),
		users: make(map[string]*userRec),
	}
}

// --- registration -------------------------------------------------------

// RegisterPermission registers name and returns its stable handle. It is
// idempotent. An empty name returns ErrEmptyName.
func (e *Engine) RegisterPermission(name string) (Permission, error) {
	if name == "" {
		return 0, ErrEmptyName
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reg.Register(name), nil
}

// --- roles --------------------------------------------------------------

// CreateRole creates an empty role. It is idempotent. An empty name returns
// ErrEmptyName.
func (e *Engine) CreateRole(name string) error {
	if name == "" {
		return ErrEmptyName
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roles.Create(name)
	// A new empty role affects no existing user, so no version bump is needed.
	return nil
}

// GrantToRole grants permissions to a role, registering any unseen permission
// names. Returns ErrUnknownRole if the role does not exist.
func (e *Engine) GrantToRole(roleName string, perms ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.roles.Has(roleName) {
		return ErrUnknownRole
	}
	e.roles.Grant(roleName, e.registerAll(perms)...)
	e.version++
	return nil
}

// RevokeFromRole removes permissions from a role. Unknown permission names are
// ignored. Returns ErrUnknownRole if the role does not exist.
func (e *Engine) RevokeFromRole(roleName string, perms ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.roles.Has(roleName) {
		return ErrUnknownRole
	}
	for _, p := range perms {
		if id, ok := e.reg.Lookup(p); ok {
			e.roles.Revoke(roleName, uint(id))
		}
	}
	e.version++
	return nil
}

// InheritRole makes child inherit parent's permissions. Returns ErrUnknownRole
// if either role is missing, or ErrInheritanceCycle if a cycle would form.
func (e *Engine) InheritRole(child, parent string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.roles.Inherit(child, parent); err != nil {
		return err
	}
	e.version++
	return nil
}

// UninheritRole removes an inheritance edge. No-op if absent.
func (e *Engine) UninheritRole(child, parent string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roles.Uninherit(child, parent)
	e.version++
	return nil
}

// --- users --------------------------------------------------------------

// AssignRole assigns a role to a user, creating the user if needed. Returns
// ErrUnknownRole if the role does not exist.
func (e *Engine) AssignRole(user, roleName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.roles.Has(roleName) {
		return ErrUnknownRole
	}
	rec := e.userLocked(user)
	for _, r := range rec.roles {
		if r == roleName {
			return nil
		}
	}
	rec.roles = append(rec.roles, roleName)
	e.version++
	return nil
}

// UnassignRole removes a role from a user. No-op if not assigned.
func (e *Engine) UnassignRole(user, roleName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec := e.users[user]
	if rec == nil {
		return nil
	}
	out := make([]string, 0, len(rec.roles))
	for _, r := range rec.roles {
		if r != roleName {
			out = append(out, r)
		}
	}
	rec.roles = out
	e.version++
	return nil
}

// GrantToUser grants direct permissions to a user, creating the user and
// registering any unseen permission names.
func (e *Engine) GrantToUser(user string, perms ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec := e.userLocked(user)
	for _, p := range perms {
		if p == "" {
			continue
		}
		rec.direct.Set(uint(e.reg.Register(p)))
	}
	e.version++
	return nil
}

// RevokeFromUser removes direct permissions from a user. Unknown names and
// unknown users are ignored. Note: this only affects direct grants, not
// permissions inherited via roles.
func (e *Engine) RevokeFromUser(user string, perms ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec := e.users[user]
	if rec == nil {
		return nil
	}
	for _, p := range perms {
		if id, ok := e.reg.Lookup(p); ok {
			rec.direct.Clear(uint(id))
		}
	}
	e.version++
	return nil
}

// --- checks -------------------------------------------------------------

// Can reports whether the user has the named permission.
func (e *Engine) Can(user, perm string) bool {
	id, ok := e.lookup(perm)
	if !ok {
		return false
	}
	return e.CanID(user, id)
}

// CanID reports whether the user has the permission identified by handle. This
// is the fastest check path: no string lookup, a single bit test on a cached
// snapshot.
func (e *Engine) CanID(user string, perm Permission) bool {
	es := e.effective(user)
	if es == nil {
		return false
	}
	return es.Test(uint(perm))
}

// CanAll reports whether the user has every named permission. With no
// permissions it returns true for a known user. An unknown user always fails.
func (e *Engine) CanAll(user string, perms ...string) bool {
	es := e.effective(user)
	if es == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, p := range perms {
		id, ok := e.reg.Lookup(p)
		if !ok || !es.Test(uint(id)) {
			return false
		}
	}
	return true
}

// CanAny reports whether the user has at least one of the named permissions.
func (e *Engine) CanAny(user string, perms ...string) bool {
	es := e.effective(user)
	if es == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, p := range perms {
		if id, ok := e.reg.Lookup(p); ok && es.Test(uint(id)) {
			return true
		}
	}
	return false
}

// --- internals ----------------------------------------------------------

func (e *Engine) lookup(perm string) (Permission, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.reg.Lookup(perm)
}

// effective returns the user's effective permission snapshot, rebuilding it if
// stale. The returned bitset is immutable and safe to read after the lock is
// released. Returns nil for an unknown user.
func (e *Engine) effective(user string) *bitset.Bitset {
	e.mu.RLock()
	rec := e.users[user]
	if rec != nil && rec.eff != nil && rec.effVer == e.version {
		es := rec.eff
		e.mu.RUnlock()
		return es
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.buildEffectiveLocked(user)
}

func (e *Engine) buildEffectiveLocked(user string) *bitset.Bitset {
	rec := e.users[user]
	if rec == nil {
		return nil
	}
	if rec.eff != nil && rec.effVer == e.version {
		return rec.eff // another goroutine already rebuilt it
	}
	acc := bitset.New()
	acc.Or(rec.direct)
	for _, rn := range rec.roles {
		if rs := e.roles.Resolve(rn); rs != nil {
			acc.Or(rs)
		}
	}
	rec.eff = acc
	rec.effVer = e.version
	return acc
}

func (e *Engine) userLocked(user string) *userRec {
	rec := e.users[user]
	if rec == nil {
		rec = &userRec{direct: bitset.New()}
		e.users[user] = rec
	}
	return rec
}

func (e *Engine) registerAll(perms []string) []uint {
	ids := make([]uint, 0, len(perms))
	for _, p := range perms {
		if p == "" {
			continue
		}
		ids = append(ids, uint(e.reg.Register(p)))
	}
	return ids
}
