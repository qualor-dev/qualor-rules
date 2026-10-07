package session

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
	echov5 "github.com/labstack/echo/v5"

	"example.com/session/store"
)

type Config struct {
	SecureCookies bool
}

var cfg Config

func newToken() string { return "token" }

// net/http: a cookie literal handed to http.SetCookie. Secure keeps the cookie off plain HTTP,
// HttpOnly keeps it away from scripts (OWASP Session Management Cheat Sheet).
func Login(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: newToken(), Path: "/"})
}

func LoginHTTPOnly(w http.ResponseWriter, r *http.Request) {
	// HttpOnly without Secure: the cookie still travels over plain HTTP.
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: newToken(), HttpOnly: true})
}

func LoginSecure(w http.ResponseWriter, r *http.Request) {
	// Secure without HttpOnly: scripts on the page can read the cookie.
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: newToken(), Secure: true, SameSite: http.SameSiteLaxMode})
}

func LoginExplicitFalse(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    newToken(),
		Secure:   false,
		HttpOnly: true,
	})
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "remember", Value: newToken(), Secure: true, HttpOnly: false})
}

// The cookie built first, in a variable.
func Preferences(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{Name: "theme", Value: "dark", MaxAge: 3600}
	// ruleid: go.insecure-cookie
	http.SetCookie(w, c)
}

func PreferencesValue(w http.ResponseWriter, r *http.Request) {
	c := http.Cookie{Name: "theme", Value: "dark", HttpOnly: true}
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &c)
}

func PreferencesAssigned(w http.ResponseWriter, r *http.Request) {
	var c *http.Cookie
	c = &http.Cookie{Name: "theme", Value: "dark", Secure: true}
	// ruleid: go.insecure-cookie
	http.SetCookie(w, c)
}

func Fields(w http.ResponseWriter, r *http.Request) {
	c := new(http.Cookie)
	c.Name = "id"
	c.Value = newToken()
	c.HttpOnly = true
	// ruleid: go.insecure-cookie
	http.SetCookie(w, c)
}

func FieldsVar(w http.ResponseWriter, r *http.Request) {
	var c http.Cookie
	c.Name = "id"
	c.Value = newToken()
	c.Secure = true
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &c)
}

// One flag set on the variable is not enough: the other one is still missing.
func OneFlagLater(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{Name: "id", Value: newToken()}
	c.Secure = true
	// ruleid: go.insecure-cookie
	http.SetCookie(w, c)
}

// Both flags set: safe.
func Safe(w http.ResponseWriter, r *http.Request) {
	// ok: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: newToken(), Path: "/", Secure: true, HttpOnly: true})
	// ok: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    newToken(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	c := &http.Cookie{Name: "id", Value: newToken(), Secure: true, HttpOnly: true}
	// ok: go.insecure-cookie
	http.SetCookie(w, c)
	v := http.Cookie{Name: "id", Value: newToken(), Secure: true, HttpOnly: true}
	// ok: go.insecure-cookie
	http.SetCookie(w, &v)
}

// The flags set on the variable after the literal, before http.SetCookie.
func SafeLater(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{Name: "id", Value: newToken()}
	c.Secure = true
	c.HttpOnly = true
	// ok: go.insecure-cookie
	http.SetCookie(w, c)
	n := new(http.Cookie)
	n.Name = "id"
	n.Value = newToken()
	n.HttpOnly = true
	n.Secure = true
	// ok: go.insecure-cookie
	http.SetCookie(w, n)
	var d http.Cookie
	d.Name = "id"
	d.Secure, d.HttpOnly = true, true
	// ok: go.insecure-cookie
	http.SetCookie(w, &d)
}

// A flag decided by configuration or by the request (HTTPS in production, HTTP on a developer's
// machine): set, so the setting is reviewed where it is decided, not here.
func Configured(w http.ResponseWriter, r *http.Request) {
	// ok: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: newToken(), Secure: cfg.SecureCookies, HttpOnly: true})
	// ok: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: newToken(), Secure: r.TLS != nil, HttpOnly: true})
	c := &http.Cookie{Name: "session", Value: newToken(), HttpOnly: true}
	if r.TLS != nil {
		c.Secure = true
	}
	// ok: go.insecure-cookie
	http.SetCookie(w, c)
}

// The flag decided in an else branch, an else-if, a switch case or default, or a loop.
func Decided(w http.ResponseWriter, r *http.Request, env string) {
	a := &http.Cookie{Name: "session", Value: newToken(), HttpOnly: true}
	if env == "dev" {
		a.Path = "/"
	} else {
		a.Secure = true
	}
	// ok: go.insecure-cookie
	http.SetCookie(w, a)
	b := &http.Cookie{Name: "session", Value: newToken(), Secure: true}
	if env == "dev" {
		b.Path = "/"
	} else if env == "prod" {
		b.HttpOnly = true
	}
	// ok: go.insecure-cookie
	http.SetCookie(w, b)
	c := &http.Cookie{Name: "session", Value: newToken(), HttpOnly: true}
	switch env {
	case "dev":
		c.Path = "/"
	case "prod":
		c.Secure = true
	}
	// ok: go.insecure-cookie
	http.SetCookie(w, c)
	var d http.Cookie
	d.Name = "session"
	switch {
	case env == "dev":
		d.Path = "/"
	default:
		d.Secure, d.HttpOnly = true, true
	}
	// ok: go.insecure-cookie
	http.SetCookie(w, &d)
	e := new(http.Cookie)
	for _, opt := range []string{"secure", "httponly"} {
		if opt == "secure" {
			e.Secure = true
		} else {
			e.HttpOnly = true
		}
	}
	// ok: go.insecure-cookie
	http.SetCookie(w, e)
	// A switch that never sets the flag.
	f := &http.Cookie{Name: "session", Value: newToken(), HttpOnly: true}
	switch env {
	case "dev":
		f.Path = "/"
	}
	// ruleid: go.insecure-cookie
	http.SetCookie(w, f)
	// A flag set only after the cookie was sent.
	g := &http.Cookie{Name: "session", Value: newToken(), HttpOnly: true}
	// ruleid: go.insecure-cookie
	http.SetCookie(w, g)
	g.Secure = true
}

// A cookie that deletes itself (MaxAge < 0 is "delete cookie now", net/http) holds nothing to
// protect, and neither does one that expired at the epoch.
func Logout(w http.ResponseWriter, r *http.Request) {
	// ok: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	// ok: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Path: "/", Expires: time.Unix(0, 0)})
	c := &http.Cookie{Name: "remember", Path: "/"}
	c.MaxAge = -1
	// ok: go.insecure-cookie
	http.SetCookie(w, c)
	// A later expiry is not a deletion.
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: newToken(), Expires: time.Now().Add(24 * time.Hour)})
}

// A deletion on one path only: the other path sets a live cookie without the flags.
func MaybeLogout(w http.ResponseWriter, r *http.Request, keep bool, action string) {
	c := &http.Cookie{Name: "session", Value: newToken()}
	if !keep {
		c.MaxAge = -1
	}
	// ruleid: go.insecure-cookie
	http.SetCookie(w, c)
	var d http.Cookie
	d.Name = "session"
	d.Value = newToken()
	switch action {
	case "logout":
		d.MaxAge = -1
	}
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &d)
}

// Look-alikes: cookies a client sends, a cookie jar, and SetCookie of other types.
type recorder struct{}

func (recorder) SetCookie(c *http.Cookie) {}

type legacySession struct{}

func (*legacySession) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
}

func LookAlikes(w http.ResponseWriter, r *http.Request) error {
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/items", nil)
	if err != nil {
		return err
	}
	// A cookie a client sends: Secure and HttpOnly are response attributes.
	// ok: go.insecure-cookie
	req.AddCookie(&http.Cookie{Name: "session", Value: newToken()})
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://api.example.com/")
	// ok: go.insecure-cookie
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: newToken()}})
	// ok: go.insecure-cookie
	store.SetCookie(w, &store.Cookie{Name: "session", Value: newToken()})
	var rec recorder
	// ok: go.insecure-cookie
	rec.SetCookie(&http.Cookie{Name: "session", Value: newToken()})
	s := &legacySession{}
	// ok: go.insecure-cookie
	s.SetCookie("session", newToken(), 3600, "/", "", false, false)
	return nil
}

// Gin: Context.SetCookie(name, value, maxAge, path, domain, secure, httpOnly) and
// Context.SetCookieData(*http.Cookie).
func GinLogin(c *gin.Context) {
	token := newToken()
	// ruleid: go.insecure-cookie
	c.SetCookie("session", token, 3600, "/", "localhost", false, true)
	// ruleid: go.insecure-cookie
	c.SetCookie("session", token, 3600, "/", "", true, false)
	// ruleid: go.insecure-cookie
	c.SetCookieData(&http.Cookie{Name: "gin_cookie", Value: "test", Path: "/", MaxAge: 3600, Secure: false, HttpOnly: true})
	ck := &http.Cookie{Name: "gin_cookie", Value: "test"}
	// ruleid: go.insecure-cookie
	c.SetCookieData(ck)
	// ruleid: go.insecure-cookie
	http.SetCookie(c.Writer, &http.Cookie{Name: "gin_cookie", Value: "test"})
	// ok: go.insecure-cookie
	c.SetCookie("session", token, 3600, "/", "", true, true)
	// ok: go.insecure-cookie
	c.SetCookie("session", token, 3600, "/", "", cfg.SecureCookies, true)
	// ok: go.insecure-cookie
	c.SetCookieData(&http.Cookie{Name: "gin_cookie", Value: "test", Secure: true, HttpOnly: true})
}

func GinRoutes(r *gin.Engine) {
	r.POST("/logout", func(ctx *gin.Context) {
		// A negative maxAge deletes the cookie.
		// ok: go.insecure-cookie
		ctx.SetCookie("session", "", -1, "/", "", false, false)
		// ruleid: go.insecure-cookie
		ctx.SetCookie("seen", "1", 0, "/", "", false, false)
	})
}

// A safe cookie call nested in the argument of a reported one is not reported itself.
func GinNested(c *gin.Context) {
	// ruleid: go.insecure-cookie
	c.SetCookie("session", func() string {
		// ok: go.insecure-cookie
		http.SetCookie(c.Writer, &http.Cookie{Name: "inner", Secure: true, HttpOnly: true})
		return newToken()
	}(), 3600, "/", "", false, true)
}

// Echo: Context.SetCookie(*http.Cookie), as in the Echo cookie guide.
func EchoWriteCookie(c echo.Context) error {
	cookie := new(http.Cookie)
	cookie.Name = "username"
	cookie.Value = "jon"
	cookie.Expires = time.Now().Add(24 * time.Hour)
	// ruleid: go.insecure-cookie
	c.SetCookie(cookie)
	// ruleid: go.insecure-cookie
	c.SetCookie(&http.Cookie{Name: "lang", Value: "en", HttpOnly: true})
	// ruleid: go.insecure-cookie
	http.SetCookie(c.Response(), &http.Cookie{Name: "lang", Value: "en"})
	return c.String(http.StatusOK, "write a cookie")
}

func EchoSafe(c echo.Context) error {
	cookie := new(http.Cookie)
	cookie.Name = "username"
	cookie.Value = "jon"
	cookie.Secure = true
	cookie.HttpOnly = true
	// ok: go.insecure-cookie
	c.SetCookie(cookie)
	// ok: go.insecure-cookie
	c.SetCookie(&http.Cookie{Name: "lang", Value: "en", Secure: true, HttpOnly: true})
	// ok: go.insecure-cookie
	c.SetCookie(&http.Cookie{Name: "username", MaxAge: -1})
	return c.NoContent(http.StatusOK)
}

// Echo v5: Context is a struct and handlers take *echo.Context (imported here under an alias,
// next to v4).
func EchoV5Login(c *echov5.Context) error {
	// ruleid: go.insecure-cookie
	c.SetCookie(&http.Cookie{Name: "session", Value: newToken()})
	cookie := &http.Cookie{Name: "session", Value: newToken(), HttpOnly: true}
	// ruleid: go.insecure-cookie
	c.SetCookie(cookie)
	// ok: go.insecure-cookie
	c.SetCookie(&http.Cookie{Name: "session", Value: newToken(), Secure: true, HttpOnly: true})
	return nil
}

// A helper of the same file that returns the cookie literal (*http.Cookie or http.Cookie): its
// flags are read from the literal it returns.
func newSessionCookie(token string) *http.Cookie {
	return &http.Cookie{Name: "session", Value: token, Path: "/"}
}

func themeCookie(theme string) http.Cookie {
	return http.Cookie{Name: "theme", Value: theme, HttpOnly: true}
}

func hardenedCookie(token string) *http.Cookie {
	return &http.Cookie{Name: "session", Value: token, Secure: true, HttpOnly: true}
}

func configuredCookie(token string) *http.Cookie {
	return &http.Cookie{Name: "session", Value: token, Secure: cfg.SecureCookies, HttpOnly: cfg.SecureCookies}
}

func expiredCookie(name string) *http.Cookie {
	return &http.Cookie{Name: name, Path: "/", MaxAge: -1}
}

func builtCookie(token string) *http.Cookie {
	c := &http.Cookie{Name: "session", Value: token}
	c.Secure = true
	c.HttpOnly = true
	return c
}

type cookieFactory struct{ path string }

func (f cookieFactory) session(token string) *http.Cookie {
	return &http.Cookie{Name: "session", Value: token, Path: f.path}
}

func (f cookieFactory) hardened(token string) *http.Cookie {
	return &http.Cookie{Name: "session", Value: token, Path: f.path, Secure: true, HttpOnly: true}
}

func Helpers(w http.ResponseWriter, r *http.Request, f cookieFactory) {
	// ruleid: go.insecure-cookie
	http.SetCookie(w, newSessionCookie(newToken()))
	ck := newSessionCookie(newToken())
	// ruleid: go.insecure-cookie
	http.SetCookie(w, ck)
	theme := themeCookie("dark")
	// ruleid: go.insecure-cookie
	http.SetCookie(w, &theme)
	// ruleid: go.insecure-cookie
	http.SetCookie(w, f.session(newToken()))
	viaMethod := f.session(newToken())
	// ruleid: go.insecure-cookie
	http.SetCookie(w, viaMethod)
	partly := newSessionCookie(newToken())
	partly.HttpOnly = true
	// ruleid: go.insecure-cookie
	http.SetCookie(w, partly)
	// ok: go.insecure-cookie
	http.SetCookie(w, hardenedCookie(newToken()))
	// ok: go.insecure-cookie
	http.SetCookie(w, configuredCookie(newToken()))
	// ok: go.insecure-cookie
	http.SetCookie(w, expiredCookie("session"))
	// ok: go.insecure-cookie
	http.SetCookie(w, builtCookie(newToken()))
	// ok: go.insecure-cookie
	http.SetCookie(w, f.hardened(newToken()))
	// Flags set on the helper's cookie before the call, and a deletion.
	later := newSessionCookie(newToken())
	later.Secure = true
	later.HttpOnly = true
	// ok: go.insecure-cookie
	http.SetCookie(w, later)
	themed := themeCookie("light")
	themed.Secure = cfg.SecureCookies
	// ok: go.insecure-cookie
	http.SetCookie(w, &themed)
	gone := newSessionCookie("")
	gone.MaxAge = -1
	// ok: go.insecure-cookie
	http.SetCookie(w, gone)
	// A client-side cookie built by a helper is not set on the response.
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	// ok: go.insecure-cookie
	req.AddCookie(newSessionCookie(newToken()))
}

// A helper declared after the function that uses it.
func RememberMe(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.insecure-cookie
	http.SetCookie(w, rememberCookie(newToken()))
}

func rememberCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     "remember",
		Value:    token,
		MaxAge:   30 * 24 * 3600,
		HttpOnly: true,
	}
}

func GinHelpers(c *gin.Context) {
	// ruleid: go.insecure-cookie
	c.SetCookieData(newSessionCookie(newToken()))
	ck := newSessionCookie(newToken())
	// ruleid: go.insecure-cookie
	c.SetCookieData(ck)
	// ok: go.insecure-cookie
	c.SetCookieData(hardenedCookie(newToken()))
}

func EchoHelpers(c echo.Context) error {
	ck := newSessionCookie(newToken())
	// ruleid: go.insecure-cookie
	c.SetCookie(ck)
	// ok: go.insecure-cookie
	c.SetCookie(hardenedCookie(newToken()))
	return nil
}

func EchoV5Helpers(c *echov5.Context) error {
	// ruleid: go.insecure-cookie
	c.SetCookie(newSessionCookie(newToken()))
	return nil
}

// Known limits.

func sessionCookie(token string) *http.Cookie {
	c := &http.Cookie{Name: "session", Value: token}
	return c
}

func cookieOrError(token string) (*http.Cookie, error) {
	return &http.Cookie{Name: "session", Value: token}, nil
}

func Limits(w http.ResponseWriter, r *http.Request) {
	// A cookie built by a function of another file or package is not followed, nor one a helper
	// of this file builds in a variable before returning it.
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, store.NewSessionCookie(newToken()))
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, sessionCookie(newToken()))
	// A helper that returns the cookie with an error is not followed.
	withErr, _ := cookieOrError(newToken())
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, withErr)
	// A Set-Cookie header written by hand is not parsed.
	// todoruleid: go.insecure-cookie
	w.Header().Add("Set-Cookie", "session="+newToken()+"; Path=/")
	// A flag turned off again on the variable is taken as set.
	c := &http.Cookie{Name: "session", Value: newToken(), Secure: true, HttpOnly: true}
	c.Secure = false
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, c)
	// A variable reused for a second cookie keeps what its first literal set (the flags, or a
	// deletion).
	reused := &http.Cookie{Name: "session", Value: newToken(), Secure: true, HttpOnly: true}
	http.SetCookie(w, reused)
	reused = &http.Cookie{Name: "theme", Value: "dark"}
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, reused)
	gone := &http.Cookie{Name: "session", MaxAge: -1}
	http.SetCookie(w, gone)
	gone = &http.Cookie{Name: "session", Value: newToken()}
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, gone)
	// A flag set between two calls with the same variable also covers the first call.
	twice := &http.Cookie{Name: "session", Value: newToken(), HttpOnly: true}
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, twice)
	twice.Secure = true
	http.SetCookie(w, twice)
	// Flags set in a closure defined before the call count as set, even when it runs after it.
	late := &http.Cookie{Name: "session", Value: newToken()}
	apply := func() {
		late.Secure = true
		late.HttpOnly = true
	}
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, late)
	apply()
	// A local variable holding false is taken as a decided value, like a configuration flag.
	secure := false
	// todoruleid: go.insecure-cookie
	http.SetCookie(w, &http.Cookie{Name: "session", Value: newToken(), Secure: secure, HttpOnly: true})
}

func harden(c *http.Cookie) {
	c.Secure = true
	c.HttpOnly = true
}

// Helpers are matched by name: a flagless method of one type makes a same-named method of another
// type, which sets both flags, count as flagless.
type debugJar struct{}

func (debugJar) visitor(id string) *http.Cookie {
	return &http.Cookie{Name: "visitor", Value: id}
}

type liveJar struct{}

func (liveJar) visitor(id string) *http.Cookie {
	return &http.Cookie{Name: "visitor", Value: id, Secure: true, HttpOnly: true}
}

func SameNamedHelpers(w http.ResponseWriter, r *http.Request, jar liveJar) {
	// todook: go.insecure-cookie
	http.SetCookie(w, jar.visitor(newToken()))
}

func GinLimits(c *gin.Context) {
	// Flags set by a helper are not followed.
	ck := &http.Cookie{Name: "session", Value: newToken()}
	harden(ck)
	// todook: go.insecure-cookie
	c.SetCookieData(ck)
	// A cookie deleted with a past expiry other than the epoch, or with a negative MaxAge other
	// than -1, is reported.
	// todook: go.insecure-cookie
	c.SetCookieData(&http.Cookie{Name: "session", Expires: time.Now().Add(-time.Hour)})
	// todook: go.insecure-cookie
	c.SetCookie("session", "", -10, "/", "", false, false)
}
