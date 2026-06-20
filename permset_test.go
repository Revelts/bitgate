package bitgate

import "testing"

func TestStatelessGrantCheckRevoke(t *testing.T) {
	reg := NewRegistry()

	// Grant returns a new value; the input is untouched (immutability).
	empty := NewSet()
	set := reg.Grant(empty, "post.read", "post.write")

	if empty.Count() != 0 {
		t.Error("Grant must not mutate its input Set")
	}
	if !reg.Can(set, "post.write") {
		t.Error("granted permission should be present")
	}
	if reg.Can(set, "post.delete") {
		t.Error("ungranted permission should be absent")
	}

	revoked := reg.Revoke(set, "post.write")
	if reg.Can(revoked, "post.write") {
		t.Error("revoked permission should be gone from the new Set")
	}
	if !reg.Can(set, "post.write") {
		t.Error("Revoke must not mutate the original Set")
	}
}

func TestSetRoundTripThroughBytes(t *testing.T) {
	reg := NewRegistry()
	set := reg.Grant(NewSet(), "a", "b", "c.long.name", "d")

	// Persist + reload, as an app would with a DB/Redis value.
	blob := set.Bytes()
	restored, err := SetFromBytes(blob)
	if err != nil {
		t.Fatalf("SetFromBytes: %v", err)
	}

	for _, p := range []string{"a", "b", "c.long.name", "d"} {
		if !reg.Can(restored, p) {
			t.Errorf("restored Set lost permission %q", p)
		}
	}
	if restored.Count() != 4 {
		t.Errorf("restored Count = %d, want 4", restored.Count())
	}
}

func TestRegistryExportLoadPreservesBits(t *testing.T) {
	reg := NewRegistry()
	reg.Register("alpha")
	reg.Register("beta")
	reg.Register("gamma")

	// A user's stored value, captured under the first registry.
	stored := reg.Grant(NewSet(), "beta").Bytes()

	// Simulate a restart: persist the mapping, then reload it.
	mapping, err := reg.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	reloaded, err := LoadRegistry(mapping)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}

	set, _ := SetFromBytes(stored)
	if !reloaded.Can(set, "beta") {
		t.Error("bit positions must survive Export/LoadRegistry")
	}
	if reloaded.Can(set, "alpha") || reloaded.Can(set, "gamma") {
		t.Error("only the originally granted permission should match")
	}
}

func TestRegisterIsAppendOnlyAndIdempotent(t *testing.T) {
	reg := NewRegistry()
	a := reg.Register("first")
	b := reg.Register("second")
	again := reg.Register("first") // must not duplicate or move anything

	if a != again {
		t.Errorf("re-registering an existing name must return the same bit: %d != %d", a, again)
	}
	if a == b {
		t.Error("distinct names must occupy distinct bits")
	}
	if reg.Len() != 2 {
		t.Errorf("Len = %d, want 2 (no duplicate added)", reg.Len())
	}

	// A permission added later must not disturb earlier bits.
	stored := reg.Grant(NewSet(), "first").Bytes()
	reg.Register("third")
	set, _ := SetFromBytes(stored)
	if !reg.Can(set, "first") {
		t.Error("appending a new permission must not shift existing bits")
	}
}

func TestUnionForRoleComposition(t *testing.T) {
	reg := NewRegistry()

	// Roles are just stored Sets.
	viewer := reg.Grant(NewSet(), "doc.read")
	editor := reg.Grant(NewSet(), "doc.write")
	// "admin" inherits both, expressed as a Union of role Sets.
	admin := Union(viewer, editor)

	// A user's own direct Set plus their role.
	userDirect := reg.Grant(NewSet(), "billing.view")
	effective := Union(userDirect, admin)

	for _, p := range []string{"doc.read", "doc.write", "billing.view"} {
		if !reg.Can(effective, p) {
			t.Errorf("composed Set should grant %q", p)
		}
	}
	if !reg.CanAll(effective, "doc.read", "doc.write") {
		t.Error("CanAll should pass for the composed set")
	}

	// Editing the role (here, the editor Set) and re-Unioning reflects live.
	editor2 := reg.Grant(editor, "doc.delete")
	effective2 := Union(userDirect, viewer, editor2)
	if !reg.Can(effective2, "doc.delete") {
		t.Error("re-composing with an updated role Set should include the new permission")
	}
}

func TestZeroAndNilSetSafety(t *testing.T) {
	reg := NewRegistry()
	reg.Register("x")

	var zero Set // nil internal bitset
	if reg.Can(zero, "x") {
		t.Error("zero Set should hold nothing")
	}
	if reg.CanAny(zero, "x") {
		t.Error("CanAny on zero Set should be false")
	}
	if !reg.CanAll(zero) {
		t.Error("CanAll with no perms should be vacuously true")
	}
	if zero.Bytes() != nil {
		t.Error("zero Set Bytes should be nil")
	}
	// Grant on a zero Set should work and not panic.
	got := reg.Grant(zero, "x")
	if !reg.Can(got, "x") {
		t.Error("Grant on a zero Set should produce a usable Set")
	}
}
