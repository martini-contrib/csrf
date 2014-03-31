// Simple angular.js example. Simulates authentication and sends csrf
// token in cookie. Angular.js is then configured to pull the token
// from the cookie and send as X-CSRFToken header.

package main

import (
	"github.com/go-martini/martini"
	"github.com/martini-contrib/csrf"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessions"
	"net/http"
)

func main() {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(render.Renderer())
	m.Use(sessions.Sessions("my_session", store))
	// Send token as a cookie.
	m.Use(csrf.Generate(&csrf.Options{
		Secret:     "token123",
		SessionKey: "userID",
		SetCookie:  true,
	}))

	// Simulate a typical authentication example. If the user has a valid userID render index.html
	// else redirect to "/login".
	m.Get("/", func(s sessions.Session, r render.Render, req *http.Request, resp http.ResponseWriter) {
		if u := s.Get("userID"); u == nil {
			r.Redirect("/login", 302)
			return
		}
		// Token will be generated here. Using ServeFile for lazy angular loading.
		http.ServeFile(resp, req, "templates/index.html")
	})

	m.Get("/login", func(r render.Render) {
		r.HTML(200, "login", nil)
	})

	// Simulate a valid login by setting a bogus session id.
	m.Post("/login", func(s sessions.Session, r render.Render) {
		s.Set("userID", "123456789")
		r.Redirect("/", 302)
	})

	// csrf.Validate requires a proper token.
	m.Post("/protected", csrf.Validate, func(r render.Render, s sessions.Session) {
		if u := s.Get("userID"); u != nil {
			r.JSON(200, map[string]interface{}{"message": "You did something that required a valid token!"})
			return
		}
		r.JSON(401, nil)
	})

	m.Run()
}
