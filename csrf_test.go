package csrf

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/go-martini/martini"
	"github.com/martini-contrib/sessions"
)

func Test_GenerateToken(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userID",
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate token.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
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
		SessionKey: "userID",
		SetCookie:  true,
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate cookie.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
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
		SessionKey: "userID",
		SetCookie:  true,
		Cookie:     "seesurf",
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate cookie.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
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
		SessionKey: "userID",
		SetHeader:  true,
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate HTTP header.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
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
func Test_SameOriginHeader(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userID",
		SetHeader:  true,
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate HTTP header.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
		return "OK"
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Host = "localhost:3000"
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	req2.Header.Set("Origin", "https://localhost:3000")
	m.ServeHTTP(res2, req2)

	if res2.Header().Get("X-CSRFToken") == "" {
		t.Error("X-CSRFToken not present in same origin request")
	}
}

func Test_NotOriginHeader(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userID",
		SetHeader:  true,
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate HTTP header.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
		return "OK"
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	req2.Header.Set("Origin", "https://www.example.com")
	m.ServeHTTP(res2, req2)

	if res2.Header().Get("X-CSRFToken") != "" {
		t.Error("X-CSRFToken present in cross origin request")
	}
}

func Test_AllowedOriginHeader(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:         "token123",
		SessionKey:     "userID",
		SetHeader:      true,
		AllowedOrigins: []string{"https://www.example.com"},
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate HTTP header.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
		return "OK"
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	req2.Header.Set("Origin", "https://www.example.com")
	m.ServeHTTP(res2, req2)

	if res2.Header().Get("X-CSRFToken") == "" {
		t.Error("X-CSRFToken not present in allowed origin request")
	}
}

func Test_NotAllowedOriginHeader(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:         "token123",
		SessionKey:     "userID",
		SetHeader:      true,
		AllowedOrigins: []string{"http://www.example.com"},
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate HTTP header.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
		return "OK"
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	req2.Header.Set("Origin", "https://www.example.com")
	m.ServeHTTP(res2, req2)

	if res2.Header().Get("X-CSRFToken") != "" {
		t.Error("X-CSRFToken present in allowed origin request")
	}
}
func Test_GenerateCustomHeader(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userID",
		SetHeader:  true,
		Header:     "X-SEESurfToken",
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate HTTP header.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
		return "OK"
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	m.ServeHTTP(res, req)

	res2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/private", nil)
	req2.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	m.ServeHTTP(res2, req2)

	if res2.Header().Get("X-SEESurfToken") == "" {
		t.Error("Failed to set X-SEESurfToken custom header")
	}
}

func Test_Validate(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userID",
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate token.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
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
		t.Error("Validation of _csrf form value failed")
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

func Test_ValidateCustom(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userID",
		Header:     "X-SEESurfToken",
		Form:       "_seesurf",
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate token.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
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

	// Post using custom form value.
	data := url.Values{}
	data.Set("_seesurf", res2.Body.String())
	res3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("POST", "/private", bytes.NewBufferString(data.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
	req3.Header.Set("Cookie", cookie)
	m.ServeHTTP(res3, req3)
	if res3.Code == 400 {
		t.Error("Valiation of _seesurf custom form value failed")
	}

	// Post using custom HTTP header.
	res4 := httptest.NewRecorder()
	req4, _ := http.NewRequest("POST", "/private", nil)
	req4.Header.Set("X-SEESurfToken", res2.Body.String())
	req4.Header.Set("Cookie", cookie)
	m.ServeHTTP(res4, req4)
	if res4.Code == 400 {
		t.Error("Validation of X-SEESurfToken custom header value failed")
	}
}

func Test_ValidateCustomError(t *testing.T) {
	m := martini.Classic()
	store := sessions.NewCookieStore([]byte("secret123"))
	m.Use(sessions.Sessions("my_session", store))
	m.Use(Generate(&Options{
		Secret:     "token123",
		SessionKey: "userID",
		ErrorFunc: func(w http.ResponseWriter) {
			http.Error(w, "custom error", 422)
		},
	}))

	// Simulate login.
	m.Get("/login", func(s sessions.Session) string {
		s.Set("userID", "123456")
		return "OK"
	})

	// Generate token.
	m.Get("/private", func(s sessions.Session, x CSRF) string {
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
	data.Set("_csrf", "invalid")
	res3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("POST", "/private", bytes.NewBufferString(data.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
	m.ServeHTTP(res3, req3)
	if res3.Code != 422 {
		t.Errorf("Custom error response code failed: %d", res3.Code)
	}
	if res3.Body.String() != "custom error\n" {
		t.Errorf("Custom error response body failed: %s", res3.Body)
	}

	// Post using X-CSRFToken HTTP header.
	res4 := httptest.NewRecorder()
	req4, _ := http.NewRequest("POST", "/private", nil)
	req4.Header.Set("X-CSRFToken", "invalid")
	m.ServeHTTP(res4, req4)
	if res4.Code != 422 {
		t.Errorf("Custom error response code failed: %d", res4.Code)
	}
	if res4.Body.String() != "custom error\n" {
		t.Errorf("Custom error response body failed: %s", res4.Body)
	}
}
