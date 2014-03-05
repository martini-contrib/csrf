// Package csrf generates and validates csrf tokens for martini.
// There are multiple methods of delivery including via a cookie or HTTP
// header.
// Validation occurs via a traditional hidden form key of "_csrf", or via
// a custom HTTP haeder "X-CSRFToken".
//
// package main
//
// import (
//     "github.com/codegangsta/martini"
//     "github.com/martini-contib/csrf"
//     "github.com/martini-contrib/render"
//     "github.com/martini-contib/sessions"
//     "net/http"
// )
//
// func main() {
//     m := martini.Classic()
//     store := sessions.NewCookieStore([]byte("secret123"))
//     m.Use(sessions.Sessions("my_session", store))
//     // Setup generation middleware.
//     m.Use(csrf.Generate(&csrf.Options{
//         Secret:     "token123",
//         SessionKey: "userID",
//     }))
//     m.Use(render.Renderer())
//
//     // Simulate the authentication of a session. If userID exists redirect
//     // to a form that requires csrf protection.
//     m.Get("/", func(s sessions.Session, r render.Render, x csrf.Csrf) {
//         if s.Get("userID") == nil {
//             r.Redirect("/login", 302)
//             return
//         }
//         r.Redirect("/protected", 302)
//     })
//
//     // Set userID for the session.
//     m.Get("/login", func(s sessions.Session, r render.Render) {
//         s.Set("userID", "123456")
//         r.Redirect("/", 302)
//     })
//
//     // Render a protected form. Passing a csrf token by calling x.GetToken()
//     m.Get("/protected", func(s sessions.Session, r render.Render, x csrf.Csrf) {
//         r.HTML(200, "protected", x.GetToken())
//     })
//
//     // Apply csrf validation to route.
//     m.Post("/protected", csrf.Validate, func(s sessions.Session, r render.Render) {
//         if u := s.Get("userID"); u != nil {
//             r.HTML(200, "result", "You submitted a valid token")
//             return
//         }
//         r.Redirect("/login", 401)
//     })
//
//     m.Run()
// }
package csrf

import (
	"code.google.com/p/xsrftoken"
	"fmt"
	"github.com/codegangsta/martini"
	"github.com/martini-contrib/sessions"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Csrf is used to get the current token and validate a suspect token.
type Csrf interface {
	// Return Http header to search for token.
	GetHeaderName() string
	// Return form value to search for token.
	GetFormName() string
	// Return cookie name to search for token.
	GetCookieName() string
	// Return the token.
	GetToken() string
	// Validate by token.
	ValidToken(t string) bool
}

type csrf struct {
	// Header name value for setting and getting csrf token.
	Header string
	// Form name value for setting and getting csrf token.
	Form string
	// Cookie name value for setting and getting csrf token.
	Cookie string
	// Token generated to pass via header, cookie, or hidden form value.
	Token string
	// This value must be unique per user.
	ID string
	// Secret used along with the unique id above to generate the Token.
	Secret string
}

// Returns the name of the Http header for csrf token.
func (c *csrf) GetHeaderName() string {
	return c.Header
}

// Returns the name of the form value for csrf token.
func (c *csrf) GetFormName() string {
	return c.Form
}

// Returns the name of the cookie for csrf token.
func (c *csrf) GetCookieName() string {
	return c.Cookie
}

// Returns the current token. This is typically used
// to populate a hidden form in an HTML template.
func (c *csrf) GetToken() string {
	return c.Token
}

// Validates the passed token against the existing Secret and ID.
func (c *csrf) ValidToken(t string) bool {
	return xsrftoken.Valid(t, c.Secret, c.ID, "POST")
}

// Options maintains options to manage behavior of Generate.
type Options struct {
	// The global secret value used to generate Tokens.
	Secret string
	// Http header used to set and get token.
	Header string
	// Form value used to set and get token.
	Form string
	// Cookie value used to set and get token.
	Cookie string
	// Key used for getting the unique ID per user.
	SessionKey string
	// If true, send token via X-CSRFToken header.
	SetHeader bool
	// If true, send token via _csrf cookie.
	SetCookie bool
	// Set the Secure flag to true on the cookie.
	Secure bool
}

const domainReg = `/^\.?[a-z\d]+(?:(?:[a-z\d]*)|(?:[a-z\d\-]*[a-z\d]))(?:\.[a-z\d]+(?:(?:[a-z\d]*)|(?:[a-z\d\-]*[a-z\d])))*$/`

// Generate maps Csrf to each request. If this request is a Get request, it will generate a new token.
// Additionally, depending on options set, generated tokens will be sent via Header and/or Cookie.
func Generate(opts *Options) martini.Handler {
	return func(s sessions.Session, c martini.Context, r *http.Request, w http.ResponseWriter) {
		if opts.Header == "" {
			opts.Header = "X-CSRFToken"
		}
		if opts.Form == "" {
			opts.Form = "_csrf"
		}
		if opts.Cookie == "" {
			opts.Cookie = "_csrf"
		}
		x := &csrf{
			Secret: opts.Secret,
			Header: opts.Header,
			Form:   opts.Form,
			Cookie: opts.Cookie,
		}
		c.MapTo(x, (*Csrf)(nil))
		uid := s.Get(opts.SessionKey)
		if uid == nil {
			return
		}
		switch uid.(type) {
		case string:
			x.ID = uid.(string)
		default:
			return
		}
		// Don't set cookie or send header if this is not a get request
		// or was sen't via an api request.
		if r.Method == "GET" && r.Header.Get("X-API-Key") == "" {
			// If cookie present, map existing token, else generate a new one.
			if ex, err := r.Cookie(opts.Cookie); err == nil && ex.Value != "" {
				x.Token = ex.Value
			} else {
				x.Token = xsrftoken.Generate(x.Secret, x.ID, "POST")
				if opts.SetCookie {
					expire := time.Now().AddDate(0, 0, 1)
					// Verify the domain is valid. If it is not, set as empty.
					domain := strings.Split(r.Host, ":")[0]
					if ok, err := regexp.Match(domainReg, []byte(domain)); !ok || err != nil {
						domain = ""
					}
					cookie := &http.Cookie{
						Name:       opts.Cookie,
						Value:      x.Token,
						Path:       "/",
						Domain:     domain,
						Expires:    expire,
						RawExpires: expire.Format(time.UnixDate),
						MaxAge:     0,
						Secure:     opts.Secure,
						HttpOnly:   false,
						Raw:        fmt.Sprintf("%s=%s", opts.Cookie, x.Token),
						Unparsed:   []string{fmt.Sprintf("token=%s", x.Token)},
					}
					http.SetCookie(w, cookie)
				}
			}
			if opts.SetHeader {
				w.Header().Add(opts.Header, x.Token)
			}
		}
	}
}

// Validate should be used as a per route middleware. It attempts to get a token from a "X-CSRFToken"
// HTTP header and then a "_csrf" form value. If one of these is found, the token will be validated
// using ValidToken. If this validation fails, http.StatusBadRequest is sent in the reply.
// If neither a header or form value is faound, http.StatusBadRequest is sent.
func Validate(r *http.Request, w http.ResponseWriter, x Csrf) {
	if token := r.Header.Get(x.GetHeaderName()); token != "" {
		if !x.ValidToken(token) {
			msg := fmt.Sprintf("Invalid %s", x.GetHeaderName())
			http.Error(w, msg, http.StatusBadRequest)
		}
		return
	}
	if token := r.FormValue(x.GetFormName()); token != "" {
		if !x.ValidToken(token) {
			msg := fmt.Sprintf("Invalid %s", x.GetFormName())
			http.Error(w, msg, http.StatusBadRequest)
		}
		return
	}
	http.Error(w, "Bad Request", http.StatusBadRequest)
	return
}
