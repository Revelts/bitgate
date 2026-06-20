package role

import (
	"errors"
	"testing"
)

func TestResolveOwnGrants(t *testing.T) {
	s := NewStore()
	s.Create("editor")
	s.Grant("editor", 1, 3)

	eff := s.Resolve("editor")
	if eff == nil {
		t.Fatal("Resolve of existing role must not be nil")
	}
	if !eff.Test(1) || !eff.Test(3) {
		t.Error("resolved set must contain own grants")
	}
	if eff.Test(2) {
		t.Error("resolved set must not contain ungranted permission")
	}
}

func TestResolveUnknownRoleIsNil(t *testing.T) {
	s := NewStore()
	if s.Resolve("ghost") != nil {
		t.Error("Resolve of unknown role must be nil")
	}
}

func TestInheritanceUnionsAncestors(t *testing.T) {
	s := NewStore()
	s.Create("viewer")
	s.Create("editor")
	s.Grant("viewer", 1)
	s.Grant("editor", 2)
	if err := s.Inherit("editor", "viewer"); err != nil {
		t.Fatalf("Inherit: %v", err)
	}

	eff := s.Resolve("editor")
	if !eff.Test(1) || !eff.Test(2) {
		t.Error("editor must have both its own and inherited permissions")
	}
	// Inheritance is directional: viewer must not gain editor's perms.
	if s.Resolve("viewer").Test(2) {
		t.Error("parent must not inherit from child")
	}
}

func TestMultiLevelInheritance(t *testing.T) {
	s := NewStore()
	for _, r := range []string{"a", "b", "c"} {
		s.Create(r)
	}
	s.Grant("a", 1)
	s.Grant("b", 2)
	s.Grant("c", 3)
	_ = s.Inherit("c", "b")
	_ = s.Inherit("b", "a")

	eff := s.Resolve("c")
	for _, want := range []uint{1, 2, 3} {
		if !eff.Test(want) {
			t.Errorf("c must transitively inherit perm %d", want)
		}
	}
}

func TestInheritCycleRejected(t *testing.T) {
	s := NewStore()
	s.Create("a")
	s.Create("b")
	_ = s.Inherit("a", "b")

	if err := s.Inherit("b", "a"); !errors.Is(err, ErrCycle) {
		t.Errorf("expected ErrCycle, got %v", err)
	}
	if err := s.Inherit("a", "a"); !errors.Is(err, ErrCycle) {
		t.Errorf("self-inheritance must be ErrCycle, got %v", err)
	}
}

func TestInheritUnknownRole(t *testing.T) {
	s := NewStore()
	s.Create("a")
	if err := s.Inherit("a", "ghost"); !errors.Is(err, ErrUnknownRole) {
		t.Errorf("expected ErrUnknownRole, got %v", err)
	}
	if err := s.Inherit("ghost", "a"); !errors.Is(err, ErrUnknownRole) {
		t.Errorf("expected ErrUnknownRole, got %v", err)
	}
}

func TestRevokeAndUninherit(t *testing.T) {
	s := NewStore()
	s.Create("viewer")
	s.Create("editor")
	s.Grant("viewer", 1)
	s.Grant("editor", 2)
	_ = s.Inherit("editor", "viewer")

	s.Revoke("editor", 2)
	if s.Resolve("editor").Test(2) {
		t.Error("revoked permission must be gone")
	}
	if !s.Resolve("editor").Test(1) {
		t.Error("inherited permission should remain after revoking own")
	}

	s.Uninherit("editor", "viewer")
	if s.Resolve("editor").Test(1) {
		t.Error("uninheriting must drop inherited permissions")
	}
}

func TestResolveCacheInvalidatedByMutation(t *testing.T) {
	s := NewStore()
	s.Create("r")
	s.Grant("r", 1)

	first := s.Resolve("r")
	second := s.Resolve("r")
	if first != second {
		t.Error("Resolve should return the cached set when version is unchanged")
	}

	s.Grant("r", 2) // bumps version
	third := s.Resolve("r")
	if !third.Test(2) {
		t.Error("Resolve must reflect grants made after the cached build")
	}
}
