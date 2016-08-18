package rbac

import (
	"reflect"
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

var _ manager = &Manager{}

// RBAC return a rbac handler.
func RBAC(rbac *gorbac.RBAC, sessions *session.Sessions, opts ...Options) tango.HandlerFunc {
	opt := prepareOptions(opts)
	var cachePerms = make(map[reflect.Value]string)
	var cachePermsLock sync.Mutex

	return func(ctx *tango.Context) {
		if action := ctx.Action(); action != nil {
			if mgr, ok := action.(manager); ok {
				mgr.SetRBACSession(opt, sessions, ctx)
			}

			var permTag string
			var ok bool
			actionValue := ctx.ActionValue()

			cachePermsLock.Lock()
			if permTag, ok = cachePerms[actionValue]; !ok {
				permTag = ctx.ActionTag("Perm")
				if len(permTag) > 0 {
					cachePerms[actionValue] = permTag
				}
			}
			cachePermsLock.Unlock()

			if permTag != "" {
				pA := gorbac.NewStdPermission(permTag)
				roles, ok := sessions.Session(ctx.Req(), ctx.ResponseWriter).Get(opt.RoleSessionKey).([]string)
				if !ok {
					opt.OnNoPerm(ctx)
					return
				}
				for _, role := range roles {
					if rbac.IsGranted(role, pA, nil) {
						ctx.Next()
						return
					}
				}
				opt.OnNoPerm(ctx)
				return
			}

			if roleTag := ctx.ActionTag("Role"); roleTag != "" {
				roles, ok := sessions.Session(ctx.Req(), ctx.ResponseWriter).Get(opt.RoleSessionKey).([]string)
				if !ok {
					opt.OnNoPerm(ctx)
					return
				}
				for _, role := range roles {
					if roleTag == role {
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
