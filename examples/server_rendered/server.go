// Simple example using Martini Render HTML templates.
// Passes the csrf.Token to the template that then
// places it in a hidden _csrf input.

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-martini/martini"
	"github.com/martini-contrib/csrf"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessions"
)

func main() {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(render.Renderer())
	m.Use(sessions.Sessions("my_session", store))
	m.Use(csrf.Generate(&csrf.Options{
		Secret:     "token123",
		SessionKey: "userID",
		ErrorFunc: func(w http.ResponseWriter) {
			buf, _ := ioutil.ReadFile("templates/error.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(422)
			fmt.Fprintln(w, string(buf))
		},
	}))

	m.Get("/", func(s sessions.Session, r render.Render, x csrf.CSRF) {
		if s.Get("userID") == nil {
			r.Redirect("/login", 302)
			return
		}
		r.HTML(200, "index", x.GetToken())
	})

	m.Get("/login", func(r render.Render) {
		r.HTML(200, "login", nil)
	})

	m.Post("/login", func(s sessions.Session, r render.Render) {
		s.Set("userID", "123456")
		r.Redirect("/")
	})

	m.Post("/protected", csrf.Validate, func(s sessions.Session, r render.Render) {
		if s.Get("userID") != nil {
			r.HTML(200, "result", "You submitted a valid token")
			return
		}
		r.Redirect("/login", 401)
	})

	m.Get("/error", func(r render.Render) {
		r.HTML(200, "custom_error", nil)
	})

	m.Run()

}
