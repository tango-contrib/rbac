package rbac

import (
	"reflect"
	"strconv"
	"sync"

	"github.com/lunny/tango"
	"github.com/mikespook/gorbac"
	"github.com/tango-contrib/session"
)

type Options struct {
	RoleSessionKey string
	OnNoPerm       tango.HandlerFunc
}

func prepareOptions(opts []Options) Options {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	if len(opt.RoleSessionKey) == 0 {
		opt.RoleSessionKey = DefaultRoleSessionKey
	}
	if opt.OnNoPerm == nil {
		opt.OnNoPerm = func(ctx *tango.Context) {
			ctx.Write([]byte(DefaultNoPermString))
		}
	}

	return opt
}

type Perm struct{}

type Role struct{}

var (
	DefaultRoleSessionKey = "rbac_roles"
	DefaultNoPermString   = "You have no permission to visit this page"
)

type manager interface {
	SetRBACSession(Options, *session.Sessions, *tango.Context)
}

type Manager struct {
	opt      Options
	sessions *session.Sessions
	ctx      *tango.Context
}

func (m *Manager) SetRBACSession(opt Options, sessions *session.Sessions, ctx *tango.Context) {
	m.opt = opt
	m.sessions = sessions
	m.ctx = ctx
}

func (m *Manager) SetRBACRole(roles ...string) {
	sess := m.sessions.Session(m.ctx.Req(), m.ctx.ResponseWriter)
	sess.Set(m.opt.RoleSessionKey, roles)
}

// lookup search the tag
func lookup(tag, key string) (string, bool, bool) {
	// When modifying this code, also update the validateStructTag code
	// in golang.org/x/tools/cmd/vet/structtag.go.
	var hasColon bool
	for tag != "" {
		// Skip leading space.
		i := 0
		for i < len(tag) && tag[i] == ' ' {
			i++
		}

		tag = tag[i:]
		if tag == "" {
			break
		}

		// Scan to colon. A space, a quote or a control character is a syntax error.
		// Strictly speaking, control chars include the range [0x7f, 0x9f], not just
		// [0x00, 0x1f], but in practice, we ignore the multi-byte control characters
		// as it is simpler to inspect the tag's bytes than the tag's runes.
		i = 0
		for i < len(tag) && tag[i] > ' ' && tag[i] != ':' && tag[i] != '"' && tag[i] != 0x7f {
			i++
		}

		if i == 0 || i+1 >= len(tag) || tag[i] != ':' || tag[i+1] != '"' {
			break
		}

		if tag[i] == ':' && tag[i+1] == '"' {
			hasColon = true
		}

		name := string(tag[:i])
		tag = tag[i+1:]

		// Scan quoted string to find value.
		i = 1
		for i < len(tag) && tag[i] != '"' {
			if tag[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(tag) {
			break
		}
		qvalue := string(tag[:i+1])
		tag = tag[i+1:]

		if key == name {
			value, err := strconv.Unquote(qvalue)
			if err != nil {
				break
			}
			return value, true, hasColon
		}
	}
	return "", false, hasColon
}

var _ manager = &Manager{}

type PermTager interface {
	PermTag() string
}

type RolesTager interface {
	RolesTag() string
}

// RBAC return a rbac handler.
func RBAC(rbac *gorbac.RBAC, sessions *session.Sessions, opts ...Options) tango.HandlerFunc {
	opt := prepareOptions(opts)
	var cachePerms = make(map[reflect.Value]string)
	var cachePermsLock sync.Mutex
	var cacheRoles = make(map[reflect.Value]string)
	var cacheRolesLock sync.Mutex

	return func(ctx *tango.Context) {
		if action := ctx.Action(); action != nil {
			if mgr, ok := action.(manager); ok {
				mgr.SetRBACSession(opt, sessions, ctx)
			}

			var permTag string
			actionValue := ctx.ActionValue()

			if pt, ok := action.(PermTager); ok {
				permTag = pt.PermTag()
			} else {
				cachePermsLock.Lock()
				if permTag, ok = cachePerms[actionValue]; !ok {
					permTag = ctx.ActionTag("Perm")
					if len(permTag) > 0 {
						cachePerms[actionValue] = permTag
					}
				}
				cachePermsLock.Unlock()
			}

			if len(permTag) > 0 {
				tag, ok, hasColon := lookup(permTag, ctx.Req().Method)
				if hasColon {
					if !ok || tag == "" {
						ctx.Next()
						return
					}
				} else {
					tag = permTag
				}

				roles, ok := sessions.Session(ctx.Req(), ctx.ResponseWriter).Get(opt.RoleSessionKey).([]string)
				if !ok {
					opt.OnNoPerm(ctx)
					return
				}

				var pA gorbac.Permission
				pA = gorbac.NewStdPermission(tag)
				for _, role := range roles {
					if rbac.IsGranted(role, pA, nil) {
						ctx.Next()
						return
					}
				}

				opt.OnNoPerm(ctx)
				return
			}

			var rolesTag string
			if pt, ok := action.(RolesTager); ok {
				rolesTag = pt.RolesTag()
			} else {
				cacheRolesLock.Lock()
				if rolesTag, ok = cacheRoles[actionValue]; !ok {
					rolesTag = ctx.ActionTag("Role")
					if len(rolesTag) > 0 {
						cacheRoles[actionValue] = rolesTag
					}
				}
				cacheRolesLock.Unlock()
			}

			if len(rolesTag) > 0 {
				tag, ok, hasColon := lookup(rolesTag, ctx.Req().Method)
				if hasColon {
					if !ok || tag == "" {
						ctx.Next()
						return
					}
				} else {
					tag = rolesTag
				}

				roles, ok := sessions.Session(ctx.Req(), ctx.ResponseWriter).Get(opt.RoleSessionKey).([]string)
				if !ok {
					opt.OnNoPerm(ctx)
					return
				}

				for _, role := range roles {
					if tag == role {
						ctx.Next()
						return
					}
				}
				opt.OnNoPerm(ctx)
				return
			}
		}
		ctx.Next()
	}
}
