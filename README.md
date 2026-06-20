<h1 align="center">BitGate</h1>

<img width="1231" height="585" alt="Screenshot 2026-06-20 at 20 56 02" src="https://github.com/user-attachments/assets/b7da5b11-0bf4-4162-ab22-acade1967c30" />


A framework-agnostic **RBAC / permission engine for Go**, powered by dynamic
bitsets. Register permissions, define roles with inheritance, assign roles and
direct permissions to users, and answer `Can` / `CanAny` / `CanAll` checks in
**O(1)** per permission with a **zero-allocation** hot path.

BitGate is a pure decision engine. It holds **no** database, authentication,
persistence, or business logic. You embed it in your application and feed it
identities you have already authenticated.

```go
e := bitgate.New()
_ = e.CreateRole("editor")
_ = e.GrantToRole("editor", "post.read", "post.write")
_ = e.AssignRole("alice", "editor")

e.Can("alice", "post.write") // true
```

---

## Table of contents

- [BitGate](#bitgate)
	- [Table of contents](#table-of-contents)
	- [Why bitsets](#why-bitsets)
	- [Features](#features)
	- [Install](#install)
	- [The two modes](#the-two-modes)
	- [Quick start — Engine mode](#quick-start--engine-mode)
	- [Quick start — Stateless mode (save to a database)](#quick-start--stateless-mode-save-to-a-database)
	- [Core concepts](#core-concepts)
	- [Middleware](#middleware)
	- [Performance](#performance)
	- [Project layout](#project-layout)
	- [Stability guarantee](#stability-guarantee)
	- [Roadmap](#roadmap)
	- [License](#license)

---

## Documentation

Full documentation lives in the **[project wiki](https://github.com/Revelts/bitgate/wiki)**:

- [API Reference](https://github.com/Revelts/bitgate/wiki/API) — every type, function, signature, error, and complexity note
- [Persistence](https://github.com/Revelts/bitgate/wiki/Persistence) — saving sets to Postgres/Redis, registry lifecycle, migrations
- [Middleware](https://github.com/Revelts/bitgate/wiki/Middleware) — net/http, chi, Gin, Fiber, Echo adapters


---

## Why bitsets

Every permission is assigned a stable bit index when it is registered. A role's
or user's permission set is a dynamic `[]uint64`. A single check is one word
index plus one mask test, so `Can` is genuinely O(1) regardless of how many
permissions exist. Permissions are effectively unlimited — the backing slice
grows as needed. Set operations (a user's roles unioned together) are bitwise OR
over a handful of 64-bit words.

## Features

- Register permissions (unlimited, dynamic bitset)
- Create roles and grant permissions to them
- Role inheritance (multi-level, cycle-checked)
- Assign roles to users
- Assign direct permissions to users
- `Can`, `CanAny`, `CanAll`, plus a handle-based `CanID` fast path
- Revoke / unassign / uninherit
- Thread-safe (`sync.RWMutex`, immutable cached snapshots)
- Two modes: in-memory **Engine** and persistable **Stateless** sets
- Framework adapters: net/http, chi, Gin, Fiber v3, Echo v4
- Zero third-party dependencies in the core

## Install

Core library:

```bash
go get github.com/Revelts/bitgate
```

```go
import "github.com/Revelts/bitgate"
```

Middleware adapters are separate modules, so importing the core never pulls in a
web framework. Install only the adapter you need:

```bash
go get github.com/Revelts/bitgate/middleware/gin
go get github.com/Revelts/bitgate/middleware/fiber
go get github.com/Revelts/bitgate/middleware/echo
# net/http and chi use the dependency-free middleware/nethttp adapter
```

Requires Go 1.25+.

## The two modes

BitGate ships two ways to use the same engine. Pick per service.

| | **Engine** (`bitgate.New`) | **Stateless** (`bitgate.NewRegistry`) |
|---|---|---|
| State location | In memory, inside the engine | In your DB / Redis; library is just a codec |
| What you store | Nothing (rebuild on boot) | A `[]byte` permission `Set` per user/role |
| Roles | Managed by the engine | A role is just a stored `Set` you `Union` at check time |
| Best for | A single service that rebuilds its rules on startup | Horizontally scaled services; permissions that must survive restarts |
| Check cost | O(1), zero-alloc | O(1), one decode |

You can use both: the in-memory engine for a service that owns its rules, the
stateless layer wherever you persist per-user bits.

## Quick start — Engine mode

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

	fmt.Println(e.Can("alice", "post.write"))                 // true  (via editor)
	fmt.Println(e.Can("alice", "post.delete"))                // false
	fmt.Println(e.Can("bob", "post.write"))                   // true  (admin inherits editor)
	fmt.Println(e.Can("bob", "post.delete"))                  // true
	fmt.Println(e.CanAny("alice", "x", "billing.view"))       // true
	fmt.Println(e.CanAll("bob", "post.read", "post.delete"))  // true
}
```

## Quick start — Stateless mode (save to a database)

Here your app owns storage. The library gives you a shared `Registry` plus a
serializable `Set` value you persist per user and per role.

```go
package main

import (
	"fmt"

	"github.com/Revelts/bitgate"
)

func main() {
	// 1. Boot: build the registry once, persist the mapping, reload it next time.
	reg := bitgate.NewRegistry()
	reg.Register("post.read")
	reg.Register("post.write")
	reg.Register("post.delete")
	mapping, _ := reg.Export()      // store these bytes once (DB / Redis / file)
	_ = mapping

	// On every later boot instead:
	//   reg, _ = bitgate.LoadRegistry(savedMapping)

	// 2. Write: Grant returns a NEW Set value to persist. Input is never mutated.
	set := reg.Grant(bitgate.NewSet(), "post.read", "post.write")
	stored := set.Bytes()           // []byte -> Postgres BYTEA, Redis value, etc.

	// 3. Read: decode the stored bytes and check.
	loaded, _ := bitgate.SetFromBytes(stored)
	fmt.Println(reg.Can(loaded, "post.write"))                 // true
	fmt.Println(reg.CanAll(loaded, "post.read", "post.write")) // true

	// Roles are just stored Sets. Combine user + roles live with Union.
	adminRole := reg.Grant(bitgate.NewSet(), "post.delete")
	effective := bitgate.Union(loaded, adminRole)
	fmt.Println(reg.Can(effective, "post.delete"))             // true
}
```

Full persistence walkthrough (Postgres + Redis schemas, registry migrations,
role composition): **[Persistence guide (wiki)](https://github.com/Revelts/bitgate/wiki/Persistence)**.

## Core concepts

- **Permission** — a named capability (`"post.write"`). On registration it gets
  a stable bit index. `bitgate.Permission` is the opaque handle for that bit.
- **Registry** — the name → bit map. In Engine mode it is internal. In Stateless
  mode it is the `bitgate.Registry` you own and persist.
- **Role** — a named set of permissions. Roles can inherit other roles; a role's
  effective set is its own grants unioned with all ancestors.
- **User** — an identity (any string key) with assigned roles and/or direct
  permissions. A user's effective set is direct grants unioned with every role's
  effective set.
- **Set** (stateless mode) — a serializable bitset value you store per user/role.
- **Effective set** — the fully resolved bitset a check tests against. In Engine
  mode it is cached and rebuilt lazily after any change.

Semantics that apply across the API:

- Grants auto-register unseen permission names.
- Roles must exist (`CreateRole`) before use, else `ErrUnknownRole`.
- Unknown user or unknown permission → checks return `false`.
- `CanAll` with no permissions is vacuously `true`.
- Errors: `ErrEmptyName`, `ErrUnknownRole`, `ErrInheritanceCycle`.

## Middleware

Each adapter takes a `Subject` function returning the **already authenticated**
user identity. BitGate does not authenticate — wire it after your auth layer.

```go
import bgnet "github.com/Revelts/bitgate/middleware/nethttp"

guard := bgnet.New(engine, func(r *http.Request) string {
	return r.Header.Get("X-User-ID") // your authenticated identity
})

mux.Handle("/posts", guard.Require("post.read")(postsHandler))      // needs all
mux.Handle("/admin", guard.RequireAny("admin", "superuser")(admin)) // needs any
```

| Framework | Import | Returns |
|---|---|---|
| net/http (and chi) | `github.com/Revelts/bitgate/middleware/nethttp` | `func(http.Handler) http.Handler` |
| Gin | `github.com/Revelts/bitgate/middleware/gin` | `gin.HandlerFunc` |
| Fiber v3 | `github.com/Revelts/bitgate/middleware/fiber` | `fiber.Handler` |
| Echo v4 | `github.com/Revelts/bitgate/middleware/echo` | `echo.MiddlewareFunc` |

chi reuses the `nethttp` adapter (same `func(http.Handler) http.Handler` shape).
Per-framework examples: **[Middleware guide (wiki)](https://github.com/Revelts/bitgate/wiki/Middleware)**.

## Performance

Apple M2, 1000 registered permissions:

```
BenchmarkCan-8                 32 ns/op     0 B/op   0 allocs/op
BenchmarkCanID-8               15 ns/op     0 B/op   0 allocs/op
BenchmarkCanAll10-8            93 ns/op     0 B/op   0 allocs/op
BenchmarkConcurrentCan-8      157 ns/op     0 B/op   0 allocs/op
BenchmarkRebuildEffective-8   128 ns/op   152 B/op   2 allocs/op   (cold path)
```

Reproduce:

```bash
go test -bench=. -benchmem ./engine/
```

## Project layout

```
bitset/            dynamic []uint64 bit array (+ binary marshal)
permission/        name -> stable bit ID registry
role/              role store, inheritance, effective-set resolution
engine/            the engine: users, checks, caching, locking
bitgate.go         engine facade (bitgate.New, Engine, Permission)
permset.go         stateless mode (Registry, Set, Union)
middleware/
  nethttp/         net/http + chi adapter (stdlib only)
  gin/  fiber/  echo/   per-framework adapters (own go.mod)
```

Core packages never depend on middleware packages.

## Stability guarantee

In stateless mode, a permission's **bit position must never change** once any set
has been stored, or every stored value is silently corrupted.

`Register` is **append-only and idempotent**: an existing name returns its
current bit unchanged; a new name takes the next free bit and never disturbs the
existing ones. Persist the mapping (`Export`) after registering new permissions,
and reload it on boot (`LoadRegistry`). Never reorder or delete registrations for
a live dataset — see the [Persistence guide](https://github.com/Revelts/bitgate/wiki/Persistence#migrations)
for the migration playbook.

## Roadmap

- WASM export (`syscall/js`) for browser / JS consumers
- C-ABI FFI export (`-buildmode=c-shared`) for C#, JS-FFI, and other languages
- Snapshot serialization for the engine mode

## License

MIT
