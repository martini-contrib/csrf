csrf [![wercker status](https://app.wercker.com/status/ba1aa8d0a0e9c990bff5ceb06af4bc33/s/ "wercker status")](https://app.wercker.com/project/bykey/ba1aa8d0a0e9c990bff5ceb06af4bc33)
====

Martini cross-site request forgery protection middlware.

[API Reference](http://godoc.org/github.com/martini-contrib/csrf)

## Usage

~~~ go

package main

import (
	"github.com/go-martini/martini"
	"github.com/martini-contrib/csrf"
	"github.com/martini-contrib/sessions"
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
		SessionKey: "userID",
		// Custom error response.
		ErrorFunc: func(w http.ResponseWriter) {
			http.Error(w, "CSRF token validation failed", http.StatusBadRequest)
		}
	}))
	m.Use(render.Renderer())

	// Simulate the authentication of a session. If userID exists redirect
	// to a form that requires csrf protection.
	m.Get("/", func(s sessions.Session, r render.Render) {
		if s.Get("userID") == nil {
			r.Redirect("/login", 302)
			return
		}
		r.Redirect("/protected", 302)
	})

	// Set userID for the session.
	m.Get("/login", func(s sessions.Session, r render.Render) {
		s.Set("userID", "123456")
		r.Redirect("/", 302)
	})

	// Render a protected form. Passing a csrf token by calling x.GetToken()
	m.Get("/protected", func(s sessions.Session, r render.Render, x csrf.CSRF) {
		if s.Get("userID") == nil {
			r.Redirect("/login", 401)
			return
		}
		// Pass token to the protected template.
		r.HTML(200, "protected", x.GetToken())
	})

	// Apply csrf validation to route.
	m.Post("/protected", csrf.Validate, func(s sessions.Session, r render.Render) {
		if s.Get("userID") != nil {
			r.HTML(200, "result", "You submitted a valid token")
			return
		}
		r.Redirect("/login", 401)
	})

	m.Run()
}

~~~

## Security
Applications using the [method](https://github.com/martini-contrib/method) package should also validate PATCH, PUT, and DELETE requests.

## Authors
* [Tom Steele](http://github.com/tomsteele)
