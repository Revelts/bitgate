// Package bitgate is a framework-agnostic RBAC/permission engine powered by
// dynamic bitsets.
//
// It registers permissions, defines roles with inheritance, assigns roles and
// direct permissions to users, and answers Can / CanAny / CanAll checks in O(1)
// per permission. It holds no database, authentication, persistence, or business
// logic — it is a pure in-memory decision engine you embed in your application.
//
// This package is a thin facade over the engine package so callers can simply
// import bitgate and call bitgate.New.
//
// Basic usage:
//
//	e := bitgate.New()
//	_ = e.CreateRole("editor")
//	_ = e.GrantToRole("editor", "post.read", "post.write")
//	_ = e.AssignRole("alice", "editor")
//	e.Can("alice", "post.write") // true
package bitgate

import "github.com/Revelts/bitgate/engine"

// Engine is the BitGate authorization engine.
type Engine = engine.Engine

// Permission is an opaque handle to a registered permission, for use with CanID.
type Permission = engine.Permission

// Errors re-exported from the engine.
var (
	ErrEmptyName        = engine.ErrEmptyName
	ErrUnknownRole      = engine.ErrUnknownRole
	ErrInheritanceCycle = engine.ErrInheritanceCycle
)

// New returns a ready-to-use Engine.
func New() *Engine { return engine.New() }
