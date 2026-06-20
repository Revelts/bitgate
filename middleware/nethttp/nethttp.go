// Package nethttp provides net/http middleware for BitGate.
//
// Because its middleware has the standard func(http.Handler) http.Handler shape,
// it also works directly with chi (chi.Router.Use accepts the same type), so no
// separate chi adapter is needed.
//
// The middleware carries no authentication: you supply a Subject function that
// extracts the already-authenticated user identity from the request.
package nethttp

import (
	"net/http"

	"github.com/Revelts/bitgate"
)

// Subject extracts the user identity from a request. It must return the same
// key your application used with the engine (e.g. a user ID). An empty string
// means "no identity" and will fail every check.
type Subject func(*http.Request) string

// Guard builds permission-checking middleware bound to an engine and subject
// extractor.
type Guard struct {
	engine  *bitgate.Engine
	subject Subject
	denied  http.Handler
}

// New returns a Guard. The default denial response is 403 Forbidden; override
// it with OnDenied.
func New(e *bitgate.Engine, subject Subject) *Guard {
	return &Guard{
		engine:  e,
		subject: subject,
		denied:  http.HandlerFunc(defaultDenied),
	}
}

// OnDenied sets the handler invoked when a check fails. It returns the Guard for
// chaining.
func (g *Guard) OnDenied(h http.Handler) *Guard {
	g.denied = h
	return g
}

// Require returns middleware that allows the request only if the subject has
// all of the given permissions.
func (g *Guard) Require(perms ...string) func(http.Handler) http.Handler {
	return g.guard(func(user string) bool { return g.engine.CanAll(user, perms...) })
}

// RequireAny returns middleware that allows the request if the subject has any
// of the given permissions.
func (g *Guard) RequireAny(perms ...string) func(http.Handler) http.Handler {
	return g.guard(func(user string) bool { return g.engine.CanAny(user, perms...) })
}

func (g *Guard) guard(allow func(string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allow(g.subject(r)) {
				next.ServeHTTP(w, r)
				return
			}
			g.denied.ServeHTTP(w, r)
		})
	}
}

func defaultDenied(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "forbidden", http.StatusForbidden)
}
