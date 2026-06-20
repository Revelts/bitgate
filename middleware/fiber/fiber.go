// Package fiber provides Fiber v3 middleware for BitGate.
//
// It carries no authentication: supply a Subject function that returns the
// already-authenticated user identity from the Fiber context.
package fiber

import (
	fiber "github.com/gofiber/fiber/v3"
	"github.com/Revelts/bitgate"
)

// Subject extracts the user identity from a Fiber context.
type Subject func(fiber.Ctx) string

// Guard builds Fiber permission middleware.
type Guard struct {
	engine  *bitgate.Engine
	subject Subject
	status  int
}

// New returns a Guard that responds with 403 Forbidden on denial.
func New(e *bitgate.Engine, subject Subject) *Guard {
	return &Guard{engine: e, subject: subject, status: fiber.StatusForbidden}
}

// WithStatus overrides the HTTP status used on denial. Returns the Guard for
// chaining.
func (g *Guard) WithStatus(code int) *Guard {
	g.status = code
	return g
}

// Require allows the request only if the subject has all of the permissions.
func (g *Guard) Require(perms ...string) fiber.Handler {
	return g.guard(func(user string) bool { return g.engine.CanAll(user, perms...) })
}

// RequireAny allows the request if the subject has any of the permissions.
func (g *Guard) RequireAny(perms ...string) fiber.Handler {
	return g.guard(func(user string) bool { return g.engine.CanAny(user, perms...) })
}

func (g *Guard) guard(allow func(string) bool) fiber.Handler {
	return func(c fiber.Ctx) error {
		if allow(g.subject(c)) {
			return c.Next()
		}
		return c.SendStatus(g.status)
	}
}
