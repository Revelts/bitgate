// Package permission maps permission names to stable, monotonic bit indices.
//
// A Registry is not safe for concurrent use on its own; the engine serializes
// access. Keeping it lock-free here avoids a redundant second mutex on the hot
// path (see CLAUDE.md: minimize allocations, avoid string compares in hot code).
package permission

// ID is the bit index assigned to a permission. It doubles as the public
// permission handle used for the fast, string-free check path.
type ID uint

// Registry assigns and resolves permission IDs.
type Registry struct {
	ids   map[string]ID
	names []string // index == ID, for reverse lookup / debugging
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{ids: make(map[string]ID)}
}

// Register returns the stable ID for name, allocating a new one if the name is
// unseen. It is idempotent: the same name always returns the same ID.
func (r *Registry) Register(name string) ID {
	if id, ok := r.ids[name]; ok {
		return id
	}
	id := ID(len(r.names))
	r.names = append(r.names, name)
	r.ids[name] = id
	return id
}

// Lookup returns the ID for name and whether it has been registered.
func (r *Registry) Lookup(name string) (ID, bool) {
	id, ok := r.ids[name]
	return id, ok
}

// Name returns the name registered for id, if any.
func (r *Registry) Name(id ID) (string, bool) {
	if int(id) >= len(r.names) {
		return "", false
	}
	return r.names[id], true
}

// Len returns the number of registered permissions.
func (r *Registry) Len() int { return len(r.names) }

// Names returns a copy of registered names in ID order (index == ID). This is
// the canonical form for persisting the registry: bit positions are the slice
// indices, so reloading in the same order preserves every assignment.
func (r *Registry) Names() []string {
	out := make([]string, len(r.names))
	copy(out, r.names)
	return out
}
