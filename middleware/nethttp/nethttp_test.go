package nethttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Revelts/bitgate"
)

// subjectFromHeader treats the X-User header as the authenticated identity.
func subjectFromHeader(r *http.Request) string { return r.Header.Get("X-User") }

func newGuard() *Guard {
	e := bitgate.New()
	_ = e.CreateRole("editor")
	_ = e.GrantToRole("editor", "post.write")
	_ = e.AssignRole("alice", "editor")
	return New(e, subjectFromHeader)
}

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func TestRequireAllows(t *testing.T) {
	h := newGuard().Require("post.write")(http.HandlerFunc(ok))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User", "alice")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("authorized request: got %d want 200", rec.Code)
	}
}

func TestRequireDenies(t *testing.T) {
	h := newGuard().Require("post.write")(http.HandlerFunc(ok))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User", "mallory")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("unauthorized request: got %d want 403", rec.Code)
	}
}

func TestRequireAny(t *testing.T) {
	h := newGuard().RequireAny("post.read", "post.write")(http.HandlerFunc(ok))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User", "alice")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("RequireAny with one held perm: got %d want 200", rec.Code)
	}
}

func TestOnDeniedOverride(t *testing.T) {
	teapot := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := newGuard().OnDenied(teapot).Require("post.write")(http.HandlerFunc(ok))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User", "mallory")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("custom denial handler: got %d want 418", rec.Code)
	}
}
