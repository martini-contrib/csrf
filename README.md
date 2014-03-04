csrf
====

Martini cross-site request forgery protection middlware.

[API Reference](http://godoc.org/github.com/martini-contrib/csrf)

## Usage

~~~ go

package main

import (
	"github.com/codegangsta/martini"
	"github.com/martini-contib/csrf"
	"github.com/martini-contib/sessions"
	"github.com/martini-contrib/render"
	"net/http"
)

func main() {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	// Setup generation middleware.
	m.Use(csrf.Generate(&csrf.Options{
		Secret:     "token123",
		SessionKey: "userId",
	}))
	m.Use(render.Renderer())

	// Simulate the authentication of a session. If userId exists redirect
	// to a form that requires csrf protection.
	m.Get("/", func(s sessions.Session, r render.Render, x csrf.Csrf) {
		if s.Get("userId") == nil {
			r.Redirect("/login", 302)
			return
		}
		r.Redirect("/protected", 302)
	})

	// Set userId for the session.
	m.Get("/login", func(s sessions.Session, r render.Render) {
		s.Set("userId", "123456")
		r.Redirect("/", 302)
	})

	// Render a protected form. Passing a csrf token by calling x.GetToken()
	m.Get("/protected", func(s sessions.Session, r render.Render, x csrf.Csrf) {
		r.HTML(200, "protected", x.GetToken())
	})

	// Apply csrf validation to route.
	m.Post("/protected", csrf.Validate, func(s sessions.Session, r render.Render) {
		if u := s.Get("userId"); u != nil {
			r.HTML(200, "result", "You submitted a valid token")
			return
		}
		r.Redirect("/login", 401)
	})

	m.Run()
}

~~~

## Authors
* [Tom Steele](http://github.com/tomsteele)
