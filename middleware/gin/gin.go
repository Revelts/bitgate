// Package gin provides Gin middleware for BitGate.
//
// It carries no authentication: supply a Subject function that returns the
// already-authenticated user identity from the Gin context.
package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/Revelts/bitgate"
)

// Subject extracts the user identity from a Gin context.
type Subject func(*gin.Context) string

// Guard builds Gin permission middleware.
type Guard struct {
	engine  *bitgate.Engine
	subject Subject
	status  int
}

// New returns a Guard that aborts with 403 Forbidden on denial.
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
func (g *Guard) Require(perms ...string) gin.HandlerFunc {
	return g.guard(func(user string) bool { return g.engine.CanAll(user, perms...) })
}

// RequireAny allows the request if the subject has any of the permissions.
func (g *Guard) RequireAny(perms ...string) gin.HandlerFunc {
	return g.guard(func(user string) bool { return g.engine.CanAny(user, perms...) })
}

func (g *Guard) guard(allow func(string) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if allow(g.subject(c)) {
			c.Next()
			return
		}
		c.AbortWithStatus(g.status)
	}
}
