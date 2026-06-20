package permission

import "testing"

func TestRegisterIsIdempotentAndMonotonic(t *testing.T) {
	r := NewRegistry()

	a := r.Register("read")
	b := r.Register("write")
	again := r.Register("read")

	if a != again {
		t.Errorf("re-registering a name must return the same ID: %d != %d", a, again)
	}
	if a == b {
		t.Error("distinct names must get distinct IDs")
	}
	if a != 0 || b != 1 {
		t.Errorf("IDs must be monotonic from 0: got read=%d write=%d", a, b)
	}
}

func TestLookup(t *testing.T) {
	r := NewRegistry()
	id := r.Register("read")

	got, ok := r.Lookup("read")
	if !ok || got != id {
		t.Errorf("Lookup(read) = %d,%v want %d,true", got, ok, id)
	}

	if _, ok := r.Lookup("missing"); ok {
		t.Error("Lookup of unregistered name must report false")
	}
}

func TestName(t *testing.T) {
	r := NewRegistry()
	id := r.Register("read")

	name, ok := r.Name(id)
	if !ok || name != "read" {
		t.Errorf("Name(%d) = %q,%v want read,true", id, name, ok)
	}
	if _, ok := r.Name(99); ok {
		t.Error("Name of unknown ID must report false")
	}
}

func TestLen(t *testing.T) {
	r := NewRegistry()
	r.Register("a")
	r.Register("b")
	r.Register("a") // idempotent, no growth
	if r.Len() != 2 {
		t.Errorf("Len = %d, want 2", r.Len())
	}
}
