# BitGate

A framework-agnostic RBAC / permission engine for Go, powered by dynamic
bitsets. It registers permissions, defines roles with inheritance, assigns roles
and direct permissions to users, and answers permission checks in **O(1)** per
permission with a **zero-allocation** hot path.

BitGate is a pure decision engine. It holds **no** database, authentication,
persistence, or business logic — you embed it in your application and feed it
identities you have already authenticated.

## Why bitsets

Every permission is assigned a stable bit index on registration. A role's or
user's permission set is a dynamic `[]uint64`. A single check is one word index
plus one mask test, so `Can` is genuinely O(1) regardless of how many
permissions exist. Permissions are effectively unlimited — the backing slice
grows as needed.

## Install

```bash
go get github.com/Revelts/bitgate
```

## Quick start

```go
package main

import (
	"fmt"

	"github.com/Revelts/bitgate"
)

func main() {
	e := bitgate.New()

	// Define a role and grant it permissions (unseen names auto-register).
	_ = e.CreateRole("editor")
	_ = e.GrantToRole("editor", "post.read", "post.write")

	// Roles can inherit other roles.
	_ = e.CreateRole("admin")
	_ = e.InheritRole("admin", "editor")
	_ = e.GrantToRole("admin", "post.delete")

	// Assign roles and/or direct permissions to users.
	_ = e.AssignRole("alice", "editor")
	_ = e.AssignRole("bob", "admin")
	_ = e.GrantToUser("alice", "billing.view")

	fmt.Println(e.Can("alice", "post.write"))   // true  (via editor)
	fmt.Println(e.Can("alice", "post.delete"))  // false
	fmt.Println(e.Can("bob", "post.write"))     // true  (admin inherits editor)
	fmt.Println(e.Can("bob", "post.delete"))    // true
	fmt.Println(e.CanAny("alice", "x", "billing.view")) // true
	fmt.Println(e.CanAll("bob", "post.read", "post.delete")) // true
}
```

## API

| Method | Purpose |
|---|---|
| `RegisterPermission(name) (Permission, error)` | Pre-register a permission; returns a handle |
| `CreateRole(name) error` | Create an empty role |
| `GrantToRole(role, perms...) error` | Grant permissions to a role |
| `RevokeFromRole(role, perms...) error` | Revoke permissions from a role |
| `InheritRole(child, parent) error` | Make `child` inherit `parent` (cycle-checked) |
| `UninheritRole(child, parent) error` | Remove an inheritance edge |
| `AssignRole(user, role) error` | Assign a role to a user |
| `UnassignRole(user, role) error` | Remove a role from a user |
| `GrantToUser(user, perms...) error` | Grant direct permissions to a user |
| `RevokeFromUser(user, perms...) error` | Revoke direct permissions from a user |
| `Can(user, perm) bool` | Check one permission |
| `CanID(user, Permission) bool` | Check via handle (fastest, no string lookup) |
| `CanAny(user, perms...) bool` | True if the user has any of them |
| `CanAll(user, perms...) bool` | True if the user has all of them |

Semantics:

- Grants auto-register unseen permission names; roles must exist before use
  (`ErrUnknownRole`).
- Unknown user or unknown permission → checks return `false`.
- `CanAll` with no permissions is vacuously `true` for a known user.
- Errors: `ErrEmptyName`, `ErrUnknownRole`, `ErrInheritanceCycle`.

## Concurrency

The engine is safe for concurrent use. A single `sync.RWMutex` guards all state.
Each user's effective permission set is cached as an immutable snapshot and
rebuilt lazily after a mutation, so the read path tests a bit without copying.
Run the suite with `-race` to verify.

## Middleware

The engine is framework-agnostic. Adapters live in separate modules so the core
stays dependency-free — you only pull in a framework if you import its adapter.
Each adapter takes a `Subject` function that returns the **already
authenticated** user identity; BitGate does not authenticate.

| Framework | Import |
|---|---|
| net/http (and chi) | `github.com/Revelts/bitgate/middleware/nethttp` |
| Gin | `github.com/Revelts/bitgate/middleware/gin` |
| Fiber v3 | `github.com/Revelts/bitgate/middleware/fiber` |
| Echo v4 | `github.com/Revelts/bitgate/middleware/echo` |

chi uses the same `func(http.Handler) http.Handler` middleware shape as
net/http, so the `nethttp` adapter works with chi directly.

```go
// net/http
guard := nethttp.New(engine, func(r *http.Request) string {
	return r.Header.Get("X-User-ID") // your authenticated identity
})
mux.Handle("/posts", guard.Require("post.read")(postsHandler))

// chi
r.With(guard.Require("post.write")).Post("/posts", createPost)
```

## Performance

Apple M2, 1000 permissions:

```
BenchmarkCan-8                 32 ns/op     0 B/op   0 allocs/op
BenchmarkCanID-8               15 ns/op     0 B/op   0 allocs/op
BenchmarkCanAll10-8            93 ns/op     0 B/op   0 allocs/op
BenchmarkConcurrentCan-8      157 ns/op     0 B/op   0 allocs/op
```

## Layout

```
bitset/            dynamic []uint64 bit array
permission/        name -> stable bit ID registry
role/              role store, inheritance, effective-set resolution
engine/            the engine: users, checks, caching, locking
bitgate.go         thin facade (bitgate.New)
middleware/
  nethttp/         net/http + chi adapter (stdlib only)
  gin/  fiber/  echo/   per-framework adapters (own go.mod)
```

Core packages never depend on middleware packages.

## Roadmap

- WASM export (`syscall/js`) for browser/JS consumers
- C-ABI FFI export (`-buildmode=c-shared`) for C#, JS-FFI, and other languages
- Snapshot serialization to support those exports

## License

MIT
# bitgate
