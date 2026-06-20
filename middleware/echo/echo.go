// Package echo provides Echo v4 middleware for BitGate.
//
// It carries no authentication: supply a Subject function that returns the
// already-authenticated user identity from the Echo context.
package echo

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/Revelts/bitgate"
)

// Subject extracts the user identity from an Echo context.
type Subject func(echo.Context) string

// Guard builds Echo permission middleware.
type Guard struct {
	engine  *bitgate.Engine
	subject Subject
	status  int
}

// New returns a Guard that responds with 403 Forbidden on denial.
func New(e *bitgate.Engine, subject Subject) *Guard {
	return &Guard{engine: e, subject: subject, status: http.StatusForbidden}
}

// WithStatus overrides the HTTP status used on denial. Returns the Guard for
// chaining.
func (g *Guard) WithStatus(code int) *Guard {
	g.status = code
	return g
}

// Require allows the request only if the subject has all of the permissions.
func (g *Guard) Require(perms ...string) echo.MiddlewareFunc {
	return g.guard(func(user string) bool { return g.engine.CanAll(user, perms...) })
}

// RequireAny allows the request if the subject has any of the permissions.
func (g *Guard) RequireAny(perms ...string) echo.MiddlewareFunc {
	return g.guard(func(user string) bool { return g.engine.CanAny(user, perms...) })
}

func (g *Guard) guard(allow func(string) bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if allow(g.subject(c)) {
				return next(c)
			}
			return echo.NewHTTPError(g.status)
		}
	}
}
