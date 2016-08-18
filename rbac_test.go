package rbac

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/lunny/tango"
	"github.com/mikespook/gorbac"
	"github.com/tango-contrib/session"
)

type RBACPermAction struct {
	Perm `write`
}

func (r *RBACPermAction) Get() string {
	return "You have write permission"
}

func TestNoPerm(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACPermAction))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), DefaultNoPermString)
}

func TestHasPerm(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rA := gorbac.NewStdRole("writer")
	pA := gorbac.NewStdPermission("write")
	rA.Assign(pA)
	rbac.Add(rA)

	if !rbac.IsGranted("writer", pA, nil) {
		t.Error(errors.New("rbac setting error"))
	}

	tg.Use(tango.HandlerFunc(func(ctx *tango.Context) {
		sess := sessions.Session(ctx.Req(), ctx.ResponseWriter)
		sess.Set(DefaultRoleSessionKey, []string{"writer"})
		ctx.Next()
	}))

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACPermAction))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "You have write permission")
}

type RBACRoleAction struct {
	Role `writer`
}

func (r *RBACRoleAction) Get() string {
	return "You are a writer"
}

func TestNoRole(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rA := gorbac.NewStdRole("writer")
	rbac.Add(rA)

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACRoleAction))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), DefaultNoPermString)
}

func TestHasRole(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rA := gorbac.NewStdRole("writer")
	rbac.Add(rA)

	tg.Use(tango.HandlerFunc(func(ctx *tango.Context) {
		sess := sessions.Session(ctx.Req(), ctx.ResponseWriter)
		sess.Set(DefaultRoleSessionKey, []string{"writer"})
		ctx.Next()
	}))

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACRoleAction))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "You are a writer")
}

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
