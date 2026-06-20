package bitgate

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Revelts/bitgate/bitset"
	"github.com/Revelts/bitgate/permission"
)

// This file is BitGate's stateless mode. Unlike the engine (which holds all
// users and roles in memory), here your application owns storage: you keep a
// shared Registry, and you persist each user's and role's permission Set as
// bytes in your own database, Redis, etc.
//
// Lifecycle:
//
//  1. Boot: build the Registry once and reload its saved mapping so bit
//     positions are identical to last run (LoadRegistry / Export).
//  2. Write: Grant/Revoke return a new Set value; store Set.Bytes().
//  3. Read: load the bytes with SetFromBytes and call Can / CanAll / CanAny.
//
// Roles are just stored Sets. Combine a user's own Set with their roles' Sets
// using Union at check time, so editing a role instantly affects its members.

// Registry is a stateless, serializable permission name<->bit map. It is safe
// for concurrent use.
type Registry struct {
	mu  sync.RWMutex
	reg *permission.Registry
}

// NewRegistry returns an empty Registry. Register your permissions at startup,
// then Export the mapping so it can be reloaded on the next boot.
func NewRegistry() *Registry {
	return &Registry{reg: permission.NewRegistry()}
}

// LoadRegistry rebuilds a Registry from Export output. Bit positions are
// preserved exactly, so previously stored Sets remain valid.
func LoadRegistry(data []byte) (*Registry, error) {
	var names []string
	if len(data) > 0 {
		if err := json.Unmarshal(data, &names); err != nil {
			return nil, fmt.Errorf("bitgate: load registry: %w", err)
		}
	}
	r := NewRegistry()
	for _, n := range names {
		r.reg.Register(n)
	}
	return r, nil
}

// Export serializes the name->bit mapping (a JSON array of names; the array
// index is the bit position). Persist this whenever you register new
// permissions, and reload it on boot with LoadRegistry.
func (r *Registry) Export() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return json.Marshal(r.reg.Names())
}

// Register assigns a stable bit to name and returns its handle. It is
// idempotent and append-only: an existing name keeps its current bit and
// nothing changes; a new name is appended without disturbing existing bits.
// After registering new names, call Export again to persist the extended map.
func (r *Registry) Register(name string) Permission {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reg.Register(name)
}

// Has reports whether name is registered.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.reg.Lookup(name)
	return ok
}

// Len returns the number of registered permissions.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reg.Len()
}

// Grant returns a new Set with the named permissions added. The input Set is
// not modified. Unseen names are registered (append-only); persist the registry
// afterwards if that happens.
func (r *Registry) Grant(s Set, perms ...string) Set {
	nb := s.clone()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range perms {
		if p == "" {
			continue
		}
		nb.Set(uint(r.reg.Register(p)))
	}
	return Set{b: nb}
}

// Revoke returns a new Set with the named permissions removed. The input Set is
// not modified. Unknown names are ignored.
func (r *Registry) Revoke(s Set, perms ...string) Set {
	nb := s.clone()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range perms {
		if id, ok := r.reg.Lookup(p); ok {
			nb.Clear(uint(id))
		}
	}
	return Set{b: nb}
}

// Can reports whether the Set holds the named permission. O(1).
func (r *Registry) Can(s Set, perm string) bool {
	if s.b == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.reg.Lookup(perm)
	return ok && s.b.Test(uint(id))
}

// CanAll reports whether the Set holds every named permission. With no
// permissions it is vacuously true.
func (r *Registry) CanAll(s Set, perms ...string) bool {
	if len(perms) == 0 {
		return true
	}
	if s.b == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range perms {
		id, ok := r.reg.Lookup(p)
		if !ok || !s.b.Test(uint(id)) {
			return false
		}
	}
	return true
}

// CanAny reports whether the Set holds at least one named permission.
func (r *Registry) CanAny(s Set, perms ...string) bool {
	if s.b == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range perms {
		if id, ok := r.reg.Lookup(p); ok && s.b.Test(uint(id)) {
			return true
		}
	}
	return false
}

// Set is a serializable permission value: the bitset you store per user or per
// role. Set is immutable; Grant and Revoke return new values. The zero Set is
// an empty, usable set.
type Set struct {
	b *bitset.Bitset
}

// NewSet returns an empty Set.
func NewSet() Set { return Set{b: bitset.New()} }

// SetFromBytes restores a Set from Bytes output (e.g. a column or Redis value).
func SetFromBytes(data []byte) (Set, error) {
	bs := bitset.New()
	if err := bs.UnmarshalBinary(data); err != nil {
		return Set{}, fmt.Errorf("bitgate: decode set: %w", err)
	}
	return Set{b: bs}, nil
}

// Bytes serializes the Set for storage. The encoding is canonical and compact
// (trailing empty words are trimmed).
func (s Set) Bytes() []byte {
	if s.b == nil {
		return nil
	}
	out, _ := s.b.MarshalBinary() // MarshalBinary never returns an error
	return out
}

// Count returns the number of permissions held.
func (s Set) Count() int {
	if s.b == nil {
		return 0
	}
	return s.b.Count()
}

func (s Set) clone() *bitset.Bitset {
	if s.b == nil {
		return bitset.New()
	}
	return s.b.Clone()
}

// Union returns a new Set containing every permission present in any input Set.
// Use it to combine a user's own Set with the Sets of the roles they hold
// (including inherited roles) before a check.
func Union(sets ...Set) Set {
	acc := bitset.New()
	for _, s := range sets {
		if s.b != nil {
			acc.Or(s.b)
		}
	}
	return Set{b: acc}
}
