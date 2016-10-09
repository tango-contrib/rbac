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

type RBACPermAction2 struct {
	Perm `GET:"read" POST:"write"`
}

func (r *RBACPermAction2) Get() string {
	return "You have read permission"
}

func (r *RBACPermAction2) Post() string {
	return "You have write permission"
}

func TestNoPerm2(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_read_write", new(RBACPermAction2))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_read_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), DefaultNoPermString)

	buff.Reset()

	req, err = http.NewRequest("POST", "http://localhost:8000/perm_read_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), DefaultNoPermString)
}

func TestHasPerm2(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rA := gorbac.NewStdRole("writer")
	pRead := gorbac.NewStdPermission("read")
	pWrite := gorbac.NewStdPermission("write")
	rA.Assign(pRead)
	rA.Assign(pWrite)
	rbac.Add(rA)

	if !rbac.IsGranted("writer", pWrite, nil) {
		t.Error(errors.New("rbac setting error"))
	}

	tg.Use(tango.HandlerFunc(func(ctx *tango.Context) {
		sess := sessions.Session(ctx.Req(), ctx.ResponseWriter)
		sess.Set(DefaultRoleSessionKey, []string{"writer"})
		ctx.Next()
	}))

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACPermAction2))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "You have read permission")

	buff.Reset()

	req, err = http.NewRequest("POST", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "You have write permission")
}

type RBACPermAction3 struct {
}

func (r *RBACPermAction3) PermTag() string {
	return `GET:"read" POST:"write"`
}

func (r *RBACPermAction3) Get() string {
	return "You have read permission"
}

func (r *RBACPermAction3) Post() string {
	return "You have write permission"
}

func TestNoPerm3(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_read_write", new(RBACPermAction3))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_read_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), DefaultNoPermString)

	buff.Reset()

	req, err = http.NewRequest("POST", "http://localhost:8000/perm_read_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), DefaultNoPermString)
}

func TestHasPerm3(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rA := gorbac.NewStdRole("writer")
	pRead := gorbac.NewStdPermission("read")
	pWrite := gorbac.NewStdPermission("write")
	rA.Assign(pRead)
	rA.Assign(pWrite)
	rbac.Add(rA)

	if !rbac.IsGranted("writer", pWrite, nil) {
		t.Error(errors.New("rbac setting error"))
	}

	tg.Use(tango.HandlerFunc(func(ctx *tango.Context) {
		sess := sessions.Session(ctx.Req(), ctx.ResponseWriter)
		sess.Set(DefaultRoleSessionKey, []string{"writer"})
		ctx.Next()
	}))

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACPermAction3))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "You have read permission")

	buff.Reset()

	req, err = http.NewRequest("POST", "http://localhost:8000/perm_write", nil)
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

type RBACRoleAction2 struct {
	Role `GET:"reader" POST:"writer"`
}

func (r *RBACRoleAction2) Get() string {
	return "You are a reader"
}

func (r *RBACRoleAction2) Post() string {
	return "You are a writer"
}

func TestNoRole2(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rReader := gorbac.NewStdRole("reader")
	rWriter := gorbac.NewStdRole("writer")
	rbac.Add(rReader)
	rbac.Add(rWriter)

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACRoleAction2))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), DefaultNoPermString)
}

func TestHasRole2(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rReader := gorbac.NewStdRole("reader")
	rWriter := gorbac.NewStdRole("writer")
	rbac.Add(rReader)
	rbac.Add(rWriter)

	tg.Use(tango.HandlerFunc(func(ctx *tango.Context) {
		sess := sessions.Session(ctx.Req(), ctx.ResponseWriter)
		sess.Set(DefaultRoleSessionKey, []string{"writer", "reader"})
		ctx.Next()
	}))

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACRoleAction2))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "You are a reader")

	buff.Reset()

	req, err = http.NewRequest("POST", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "You are a writer")
}

type RBACRoleAction3 struct {
}

func (r *RBACRoleAction3) RolesTag() string {
	return `GET:"reader" POST:"writer"`
}

func (r *RBACRoleAction3) Get() string {
	return "You are a reader"
}

func (r *RBACRoleAction3) Post() string {
	return "You are a writer"
}

func TestNoRole3(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rReader := gorbac.NewStdRole("reader")
	rWriter := gorbac.NewStdRole("writer")
	rbac.Add(rReader)
	rbac.Add(rWriter)

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACRoleAction3))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), DefaultNoPermString)
}

func TestHasRole3(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recorder.Body = buff

	tg := tango.Classic()
	sessions := session.New()
	rbac := gorbac.New()
	rReader := gorbac.NewStdRole("reader")
	rWriter := gorbac.NewStdRole("writer")
	rbac.Add(rReader)
	rbac.Add(rWriter)

	tg.Use(tango.HandlerFunc(func(ctx *tango.Context) {
		sess := sessions.Session(ctx.Req(), ctx.ResponseWriter)
		sess.Set(DefaultRoleSessionKey, []string{"writer", "reader"})
		ctx.Next()
	}))

	tg.Use(RBAC(rbac, sessions))
	tg.Any("/perm_write", new(RBACRoleAction3))

	req, err := http.NewRequest("GET", "http://localhost:8000/perm_write", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	refute(t, len(buff.String()), 0)
	expect(t, buff.String(), "You are a reader")

	buff.Reset()

	req, err = http.NewRequest("POST", "http://localhost:8000/perm_write", nil)
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
