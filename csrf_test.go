package csrf

import (
	"bytes"
	"github.com/codegangsta/martini"
	"github.com/martini-contrib/sessions"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func Test_GenerateToken(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userId",
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userId", "123456")
		return "OK"
	})

	// Generate token.
	m.Get("/private", func(s sessions.Session, x Csrf) string {
		return x.GetToken()
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	m.ServeHTTP(res2, req2)

	if res2.Body.String() == "" {
		t.Error("Failed to generate token")
	}
}

func Test_GenerateCookie(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userId",
		SetCookie:  true,
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userId", "123456")
		return "OK"
	})

	// Generate cookie.
	m.Get("/private", func(s sessions.Session, x Csrf) string {
		return "OK"
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	m.ServeHTTP(res2, req2)

	if !strings.Contains(res2.Header().Get("Set-Cookie"), "_csrf") {
		t.Error("Failed to set csrf cookie")
	}
}

func Test_GenerateCustomCookie(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userId",
		SetCookie:  true,
		Cookie:     "seesurf",
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userId", "123456")
		return "OK"
	})

	// Generate cookie.
	m.Get("/private", func(s sessions.Session, x Csrf) string {
		return "OK"
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	m.ServeHTTP(res2, req2)

	if !strings.Contains(res2.Header().Get("Set-Cookie"), "seesurf") {
		t.Error("Failed to set custom csrf cookie")
	}
}

func Test_GenerateHeader(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userId",
		SetHeader:  true,
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userId", "123456")
		return "OK"
	})

	// Generate HTTP header.
	m.Get("/private", func(s sessions.Session, x Csrf) string {
		return "OK"
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	m.ServeHTTP(res2, req2)

	if res2.Header().Get("X-CSRFToken") == "" {
		t.Error("Failed to set X-CSRFToken header")
	}
}

func Test_Validate(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userId",
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userId", "123456")
		return "OK"
	})

	// Generate token.
	m.Get("/private", func(s sessions.Session, x Csrf) string {
		return x.GetToken()
	})

	m.Post("/private", Validate, func(s sessions.Session) string {
		return "OK"
	})

	// Login to set session.
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	cookie := res.Header().Get("Set-Cookie")

	// Get a new token.
	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", cookie)
	m.ServeHTTP(res2, req2)

	// Post using _csrf form value.
	data := url.Values{}
	data.Set("_csrf", res2.Body.String())
	res3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("POST", "/private", bytes.NewBufferString(data.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
	req3.Header.Set("Cookie", cookie)
	m.ServeHTTP(res3, req3)
	if res3.Code == 400 {
		t.Error("Valiation of _csrf form value failed")
	}

	// Post using X-CSRFToken HTTP header.
	res4 := httptest.NewRecorder()
	req4, _ := http.NewRequest("POST", "/private", nil)
	req4.Header.Set("X-CSRFToken", res2.Body.String())
	req4.Header.Set("Cookie", cookie)
	m.ServeHTTP(res4, req4)
	if res4.Code == 400 {
		t.Error("Validation of X-CSRFToken failed")
	}
}
