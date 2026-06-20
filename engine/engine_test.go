package engine

import (
	"errors"
	"sync"
	"testing"
)

func TestRoleGrantAndCheck(t *testing.T) {
	e := New()
	if err := e.CreateRole("editor"); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := e.GrantToRole("editor", "post.read", "post.write"); err != nil {
		t.Fatalf("GrantToRole: %v", err)
	}
	if err := e.AssignRole("alice", "editor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	if !e.Can("alice", "post.read") {
		t.Error("alice should be able to post.read via editor role")
	}
	if !e.Can("alice", "post.write") {
		t.Error("alice should be able to post.write via editor role")
	}
	if e.Can("alice", "post.delete") {
		t.Error("alice should not have an unregistered/unowned permission")
	}
}

func TestDirectUserGrant(t *testing.T) {
	e := New()
	if err := e.GrantToUser("bob", "billing.view"); err != nil {
		t.Fatalf("GrantToUser: %v", err)
	}
	if !e.Can("bob", "billing.view") {
		t.Error("bob should have the directly granted permission")
	}
}

func TestUnknownUserAndPermission(t *testing.T) {
	e := New()
	if e.Can("nobody", "anything") {
		t.Error("unknown user must not pass any check")
	}
	_, _ = e.RegisterPermission("known")
	if e.Can("nobody", "known") {
		t.Error("known permission, unknown user must still fail")
	}
}

func TestInheritanceThroughRoles(t *testing.T) {
	e := New()
	_ = e.CreateRole("viewer")
	_ = e.CreateRole("editor")
	_ = e.GrantToRole("viewer", "doc.read")
	_ = e.GrantToRole("editor", "doc.write")
	if err := e.InheritRole("editor", "viewer"); err != nil {
		t.Fatalf("InheritRole: %v", err)
	}
	_ = e.AssignRole("carol", "editor")

	if !e.Can("carol", "doc.read") {
		t.Error("editor must inherit viewer's doc.read")
	}
	if !e.Can("carol", "doc.write") {
		t.Error("editor must keep its own doc.write")
	}
}

func TestCanAnyAndCanAll(t *testing.T) {
	e := New()
	_ = e.GrantToUser("dan", "a", "b")

	if !e.CanAll("dan", "a", "b") {
		t.Error("CanAll should be true when user has all perms")
	}
	if e.CanAll("dan", "a", "c") {
		t.Error("CanAll should be false when a perm is missing")
	}
	if !e.CanAny("dan", "c", "b") {
		t.Error("CanAny should be true when at least one perm is held")
	}
	if e.CanAny("dan", "c", "d") {
		t.Error("CanAny should be false when no perm is held")
	}
	if !e.CanAll("dan") {
		t.Error("CanAll with no perms must be vacuously true for a known user")
	}
	if e.CanAll("ghost") {
		t.Error("CanAll for an unknown user must be false")
	}
}

func TestRevokeFromRoleAndUser(t *testing.T) {
	e := New()
	_ = e.CreateRole("ops")
	_ = e.GrantToRole("ops", "deploy")
	_ = e.AssignRole("erin", "ops")
	_ = e.GrantToUser("erin", "ssh")

	if !e.Can("erin", "deploy") || !e.Can("erin", "ssh") {
		t.Fatal("precondition: erin should have deploy and ssh")
	}

	if err := e.RevokeFromRole("ops", "deploy"); err != nil {
		t.Fatalf("RevokeFromRole: %v", err)
	}
	if e.Can("erin", "deploy") {
		t.Error("deploy should be revoked from the role")
	}

	if err := e.RevokeFromUser("erin", "ssh"); err != nil {
		t.Fatalf("RevokeFromUser: %v", err)
	}
	if e.Can("erin", "ssh") {
		t.Error("ssh should be revoked from the user")
	}
}

func TestUnassignAndUninherit(t *testing.T) {
	e := New()
	_ = e.CreateRole("base")
	_ = e.CreateRole("super")
	_ = e.GrantToRole("base", "p.base")
	_ = e.GrantToRole("super", "p.super")
	_ = e.InheritRole("super", "base")
	_ = e.AssignRole("frank", "super")

	if !e.Can("frank", "p.base") {
		t.Fatal("precondition: frank inherits p.base")
	}
	_ = e.UninheritRole("super", "base")
	if e.Can("frank", "p.base") {
		t.Error("after uninherit, frank must lose p.base")
	}
	if !e.Can("frank", "p.super") {
		t.Error("frank should keep super's own permission")
	}

	_ = e.UnassignRole("frank", "super")
	if e.Can("frank", "p.super") {
		t.Error("after unassign, frank must lose role permissions")
	}
}

func TestErrors(t *testing.T) {
	e := New()
	if _, err := e.RegisterPermission(""); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty permission name: got %v want ErrEmptyName", err)
	}
	if err := e.CreateRole(""); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty role name: got %v want ErrEmptyName", err)
	}
	if err := e.GrantToRole("ghost", "x"); !errors.Is(err, ErrUnknownRole) {
		t.Errorf("grant to unknown role: got %v want ErrUnknownRole", err)
	}
	if err := e.AssignRole("u", "ghost"); !errors.Is(err, ErrUnknownRole) {
		t.Errorf("assign unknown role: got %v want ErrUnknownRole", err)
	}

	_ = e.CreateRole("a")
	_ = e.CreateRole("b")
	_ = e.InheritRole("a", "b")
	if err := e.InheritRole("b", "a"); !errors.Is(err, ErrInheritanceCycle) {
		t.Errorf("cycle: got %v want ErrInheritanceCycle", err)
	}
}

func TestCanID(t *testing.T) {
	e := New()
	p, err := e.RegisterPermission("fast.path")
	if err != nil {
		t.Fatalf("RegisterPermission: %v", err)
	}
	_ = e.GrantToUser("gwen", "fast.path")

	if !e.CanID("gwen", p) {
		t.Error("CanID should pass for a held permission handle")
	}
}

func TestEffectiveCacheReflectsLaterGrants(t *testing.T) {
	e := New()
	_ = e.GrantToUser("hank", "first")
	if !e.Can("hank", "first") { // builds and caches the snapshot
		t.Fatal("precondition failed")
	}
	_ = e.GrantToUser("hank", "second") // must invalidate the cache
	if !e.Can("hank", "second") {
		t.Error("a grant after the first check must be visible (cache invalidation)")
	}
}

// TestConcurrentAccess is meant to be run with -race.
func TestConcurrentAccess(t *testing.T) {
	e := New()
	_ = e.CreateRole("worker")
	_ = e.GrantToRole("worker", "task.run")
	_ = e.AssignRole("ivy", "worker")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				e.Can("ivy", "task.run")
				e.CanAny("ivy", "task.run", "task.stop")
			}
		}()
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = e.GrantToUser("ivy", "extra")
				_ = e.GrantToRole("worker", "task.stop")
			}
		}(i)
	}
	wg.Wait()

	if !e.Can("ivy", "task.run") {
		t.Error("ivy should still have task.run after concurrent churn")
	}
}
