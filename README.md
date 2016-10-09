rbac [![Build Status](https://drone.io/github.com/tango-contrib/rbac/status.png)](https://drone.io/github.com/tango-contrib/rbac/latest) [![](http://gocover.io/_badge/github.com/tango-contrib/rbac)](http://gocover.io/github.com/tango-contrib/rbac)
======

Rbac is a rbac middleware for [Tango](https://github.com/lunny/tango), it's based on [https://github.com/mikespook/gorbac](https://github.com/mikespook/gorbac).

## Installation

    go get github.com/tango-contrib/rbac

## Simple Example

```Go
package main

import (
	"github.com/lunny/tango"
	"github.com/mikespook/gorbac"
	"github.com/tango-contrib/rbac"
	"github.com/tango-contrib/session"
)

type LoginAction struct {
	session.Session
	rbac.Manager
}

func (l *LoginAction) Post() {
	l.SetRBACRole("writer")
}

type RBACPermAction struct {
	rbac.Perm `write`
}

func (a *RBACPermAction) Get() string {
	return "You have write permission"
}

func main() {
	t := tango.Classic()

	// init session middleware to store roles
	sessions := session.New()
	t.Use(sessions)

	// init rbac middleware
	goRBAC := gorbac.New()
	rA := gorbac.NewStdRole("writer")
	pA := gorbac.NewStdPermission("write")
	rA.Assign(pA)
	goRBAC.Add(rA)

	t.Use(rbac.RBAC(goRBAC, sessions))

	// define the routers
	t.Post("/login", new(LoginAction))
	t.Any("/perm_write", new(RBACPermAction))
	t.Run()
}
```

* If you want to give difference perm for GET and POST, then you can give a tag

```Go
type Action struct {
	Perm `GET:"read" POST:"write"`
}
```

```Go
type Action struct {
	Role `GET:"reader" POST:"writer"`
}
```

* If you want to dynamic perm, you can use `rbac.PermTager` and `rbac.RolesTager` interfaces.

```Go
type Action struct {
}

func (a *Action) PermTag() string {
	return `GET:"read" POST:"write"`
}
```

```Go
type Action struct {
}

func (a *Action) RolesTag() string {
	return `GET:"reader" POST:"writer"`
}
```

## Getting Help

- [API Reference](https://gowalker.org/github.com/tango-contrib/rbac)

## License

This project is under BSD License. See the [LICENSE](LICENSE) file for the full license text.
