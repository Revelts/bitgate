// Package role stores roles, their directly granted permissions, and role
// inheritance edges. It resolves a role's effective permission set (own grants
// unioned with all ancestors) and caches the result by store version.
//
// A Store is not safe for concurrent use; the engine guards it. Resolve mutates
// the per-role cache, so it must be called under the engine's write lock.
package role

import (
	"errors"

	"github.com/Revelts/bitgate/bitset"
)

// Errors returned by Store mutations.
var (
	ErrUnknownRole = errors.New("bitgate: unknown role")
	ErrCycle       = errors.New("bitgate: role inheritance cycle")
)

type role struct {
	perms   *bitset.Bitset
	parents []string

	eff    *bitset.Bitset // cached effective set
	effVer uint64
}

// Store is a collection of roles.
type Store struct {
	roles map[string]*role
	ver   uint64 // bumped on every mutation; invalidates per-role caches
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{roles: make(map[string]*role)}
}

// Has reports whether a role exists.
func (s *Store) Has(name string) bool {
	_, ok := s.roles[name]
	return ok
}

// Version returns the current mutation counter.
func (s *Store) Version() uint64 { return s.ver }

// Create adds an empty role. It is idempotent.
func (s *Store) Create(name string) {
	if _, ok := s.roles[name]; ok {
		return
	}
	s.roles[name] = &role{perms: bitset.New()}
	s.ver++
}

// Grant adds permission IDs to a role. Reports false if the role is unknown.
func (s *Store) Grant(name string, ids ...uint) bool {
	r, ok := s.roles[name]
	if !ok {
		return false
	}
	for _, id := range ids {
		r.perms.Set(id)
	}
	s.ver++
	return true
}

// Revoke removes permission IDs from a role. Reports false if the role is unknown.
func (s *Store) Revoke(name string, ids ...uint) bool {
	r, ok := s.roles[name]
	if !ok {
		return false
	}
	for _, id := range ids {
		r.perms.Clear(id)
	}
	s.ver++
	return true
}

// Inherit makes child inherit from parent. It returns ErrUnknownRole if either
// role is missing and ErrCycle if the edge would create a cycle.
func (s *Store) Inherit(child, parent string) error {
	c, ok := s.roles[child]
	if !ok {
		return ErrUnknownRole
	}
	if _, ok := s.roles[parent]; !ok {
		return ErrUnknownRole
	}
	if child == parent || s.reaches(parent, child) {
		return ErrCycle
	}
	for _, p := range c.parents {
		if p == parent {
			return nil // already inherited
		}
	}
	c.parents = append(c.parents, parent)
	s.ver++
	return nil
}

// Uninherit removes an inheritance edge. It is a no-op if the edge is absent.
func (s *Store) Uninherit(child, parent string) {
	c, ok := s.roles[child]
	if !ok {
		return
	}
	out := make([]string, 0, len(c.parents))
	changed := false
	for _, p := range c.parents {
		if p == parent {
			changed = true
			continue
		}
		out = append(out, p)
	}
	if changed {
		c.parents = out
		s.ver++
	}
}

// Resolve returns the effective permission set for a role (own grants plus all
// ancestors). It returns nil for an unknown role. The result is cached by store
// version and must be treated as read-only by callers.
func (s *Store) Resolve(name string) *bitset.Bitset {
	r, ok := s.roles[name]
	if !ok {
		return nil
	}
	if r.eff != nil && r.effVer == s.ver {
		return r.eff
	}
	acc := bitset.New()
	seen := make(map[string]bool)
	var dfs func(string)
	dfs = func(n string) {
		if seen[n] {
			return
		}
		seen[n] = true
		cur, ok := s.roles[n]
		if !ok {
			return
		}
		acc.Or(cur.perms)
		for _, p := range cur.parents {
			dfs(p)
		}
	}
	dfs(name)
	r.eff = acc
	r.effVer = s.ver
	return acc
}

// reaches reports whether `from` can reach `target` by following parent edges.
func (s *Store) reaches(from, target string) bool {
	seen := make(map[string]bool)
	var dfs func(string) bool
	dfs = func(n string) bool {
		if n == target {
			return true
		}
		if seen[n] {
			return false
		}
		seen[n] = true
		r, ok := s.roles[n]
		if !ok {
			return false
		}
		for _, p := range r.parents {
			if dfs(p) {
				return true
			}
		}
		return false
	}
	return dfs(from)
}
