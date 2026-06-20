package engine

import (
	"strconv"
	"testing"
)

// setupEngine builds an engine with n registered permissions, a role holding
// them all, and one user assigned that role.
func setupEngine(n int) (*Engine, []string, []Permission) {
	e := New()
	_ = e.CreateRole("everything")
	names := make([]string, n)
	handles := make([]Permission, n)
	for i := 0; i < n; i++ {
		names[i] = "perm." + strconv.Itoa(i)
		p, _ := e.RegisterPermission(names[i])
		handles[i] = p
	}
	_ = e.GrantToRole("everything", names...)
	_ = e.AssignRole("user", "everything")
	// Warm the effective-set cache.
	e.Can("user", names[0])
	return e, names, handles
}

func BenchmarkCan(b *testing.B) {
	e, names, _ := setupEngine(1000)
	perm := names[500]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.Can("user", perm) {
			b.Fatal("expected true")
		}
	}
}

func BenchmarkCanID(b *testing.B) {
	e, _, handles := setupEngine(1000)
	h := handles[500]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.CanID("user", h) {
			b.Fatal("expected true")
		}
	}
}

func BenchmarkCanAll10(b *testing.B) {
	e, names, _ := setupEngine(1000)
	query := names[:10]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.CanAll("user", query...) {
			b.Fatal("expected true")
		}
	}
}

func BenchmarkConcurrentCan(b *testing.B) {
	e, names, _ := setupEngine(1000)
	perm := names[500]
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e.Can("user", perm)
		}
	})
}

// BenchmarkRebuildEffective measures the cost of rebuilding a user's effective
// set after an invalidating mutation (the cold path).
func BenchmarkRebuildEffective(b *testing.B) {
	e, names, _ := setupEngine(1000)
	perm := names[500]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.GrantToUser("user", "churn") // invalidates cache
		e.Can("user", perm)                // forces rebuild
	}
}
