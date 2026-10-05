package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"example.com/shop/models"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
)

const siteHost = "https://shop.example.com"
const siteRoot = "https://shop.example.com/"

type Server struct {
	publicURL string
}

// net/http: request data as the whole redirect target, or as its scheme and host.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	// ruleid: go.open-redirect
	http.Redirect(w, r, next, http.StatusFound)
	// ruleid: go.open-redirect
	http.Redirect(w, r, r.FormValue("return_to"), http.StatusSeeOther)
	// ruleid: go.open-redirect
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusFound)
	// ruleid: go.open-redirect
	http.Redirect(w, r, r.Referer(), http.StatusFound)
	cookie, _ := r.Cookie("after_login")
	// ruleid: go.open-redirect
	http.Redirect(w, r, cookie.Value, http.StatusFound)
	// ruleid: go.open-redirect
	http.Redirect(w, r, "https://"+r.PathValue("tenant")+".example.com/home", http.StatusFound)
	// ruleid: go.open-redirect
	http.Redirect(w, r, fmt.Sprintf("https://%s/home", r.FormValue("host")), http.StatusFound)
	// A lone "/" lets "/evil.example" or "\evil.example" make a scheme-relative URL.
	// ruleid: go.open-redirect
	http.Redirect(w, r, "/"+next, http.StatusFound)
	// No "/" after the host: "@evil.example" sets the host.
	// ruleid: go.open-redirect
	http.Redirect(w, r, siteHost+next, http.StatusFound)
	// ruleid: go.open-redirect
	http.Redirect(w, r, next+"/welcome", http.StatusFound)
	// The Location header set directly.
	// ruleid: go.open-redirect
	w.Header().Set("Location", next)
	// ruleid: go.open-redirect
	w.Header().Add("location", r.FormValue("to"))
	// ruleid: go.open-redirect
	w.Header()["Location"] = []string{r.FormValue("to")}
	w.WriteHeader(http.StatusFound)
	// The request's own path can start with "//".
	// ruleid: go.open-redirect
	http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
	parsed, _ := url.Parse(next)
	// ruleid: go.open-redirect
	http.Redirect(w, r, parsed.String(), http.StatusFound)
}

// The safe forms: constants, paths and URLs built from constants with a separator, numbers.
func (s *Server) SafeLogin(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ok: go.open-redirect
	http.Redirect(w, r, "/dashboard", http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, "/items/"+id, http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, "/search?q="+url.QueryEscape(r.FormValue("q")), http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, "?page="+r.FormValue("page"), http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, "profile/"+id, http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, fmt.Sprintf("/orders/%s/receipt", id), http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, siteRoot+"items/"+id, http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, siteHost+"/items/"+id, http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, fmt.Sprintf("%s/items/%s", siteHost, id), http.StatusFound)
	// A fixed path given to the format as its first argument.
	// ok: go.open-redirect
	http.Redirect(w, r, fmt.Sprintf("%s?next=%s", "/login", url.QueryEscape(r.FormValue("next"))), http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, fmt.Sprintf("%s?next=%s", "/login", r.FormValue("next")), http.StatusFound)
	// A request-chosen first argument still decides the target.
	// ruleid: go.open-redirect
	http.Redirect(w, r, fmt.Sprintf("%s?from=%s", r.FormValue("back"), "/login"), http.StatusFound)
	// A base from the server's configuration, then a separator and the request data.
	// ok: go.open-redirect
	http.Redirect(w, r, s.publicURL+"/items/"+id, http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, os.Getenv("PUBLIC_URL")+"/items/"+id, http.StatusFound)
	n, err := strconv.Atoi(r.FormValue("n"))
	if err != nil {
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, "/page/"+strconv.Itoa(n), http.StatusFound)
	// ok: go.open-redirect
	w.Header().Set("Location", "/items/"+id)
	// The request's own path and query after a fixed base (an HTTPS upgrade, say).
	target := s.publicURL + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	// ok: go.open-redirect
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
	// ok: go.open-redirect
	http.Redirect(w, r, strings.TrimSuffix(s.publicURL, "/")+r.URL.RequestURI(), http.StatusPermanentRedirect)
	// Request data in another header.
	// ok: go.open-redirect
	w.Header().Set("X-Request-Next", r.FormValue("next"))
}

// Allow-lists: a map literal of constants, a switch that yields constants.
var destinations = map[string]string{
	"home":    "/",
	"billing": "https://billing.example.com/", // another site of ours
}

func Continue(w http.ResponseWriter, r *http.Request) {
	// ok: go.open-redirect
	http.Redirect(w, r, destinations[r.FormValue("to")], http.StatusFound)
	target, found := destinations[r.FormValue("to")]
	if !found {
		target = "/"
	}
	// ok: go.open-redirect
	http.Redirect(w, r, target, http.StatusFound)
	var dest string
	switch r.FormValue("to") {
	case "docs":
		dest = "https://docs.example.com/"
	default:
		dest = "/"
	}
	// ok: go.open-redirect
	http.Redirect(w, r, dest, http.StatusFound)
	// A table filled with request data, or a request-data fallback, is not an allow-list.
	filled := map[string]string{"back": r.FormValue("back")}
	// ruleid: go.open-redirect
	http.Redirect(w, r, filled["back"], http.StatusFound)
	fallback, ok := destinations[r.FormValue("to")]
	if !ok {
		fallback = r.FormValue("to")
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, fallback, http.StatusFound)
}

// Checks before the call are not followed: the value checked is still reported.
func Checked(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	// todook: go.open-redirect
	http.Redirect(w, r, next, http.StatusFound)
	u, err := url.Parse(r.FormValue("back"))
	if err != nil || u.IsAbs() || u.Host != "" {
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, u.String(), http.StatusFound)
	back := r.FormValue("back")
	if !isOwnSite(back) {
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, back, http.StatusFound)
}

func isOwnSite(target string) bool { return strings.HasPrefix(target, siteRoot) }

// The result of a function given request data counts as request data, whatever the function
// does: here a signed URL of a storage service, whose host comes from its configuration.
type Storage struct{}

func (Storage) SignedURL(name string) (string, error) { return "", nil }

func Download(w http.ResponseWriter, r *http.Request) {
	var store Storage
	link, err := store.SignedURL(r.FormValue("file"))
	if err != nil {
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, link, http.StatusTemporaryRedirect)
}

// Routers on net/http: chi and gorilla/mux route variables.
func Short(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.open-redirect
	http.Redirect(w, r, chi.URLParam(r, "target"), http.StatusFound)
	vars := mux.Vars(r)
	// ruleid: go.open-redirect
	http.Redirect(w, r, vars["url"], http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, "/s/"+vars["code"], http.StatusFound)
}

// JSON bodies decoded with encoding/json.
type LoginForm struct {
	User     string `json:"user" form:"user" query:"user"`
	ReturnTo string `json:"return_to" form:"return_to" query:"return_to"`
	Step     int    `json:"step" form:"step" query:"step"`
}

func APILogin(w http.ResponseWriter, r *http.Request) {
	var in LoginForm
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, in.ReturnTo, http.StatusSeeOther)
	// ok: go.open-redirect
	http.Redirect(w, r, fmt.Sprintf("/login/step/%d", in.Step), http.StatusSeeOther)
}

// Gin: c.Redirect and c.Header("Location", ...).
func GinLogin(c *gin.Context) {
	// ruleid: go.open-redirect
	c.Redirect(http.StatusFound, c.Query("next"))
	// ruleid: go.open-redirect
	c.Redirect(http.StatusFound, c.DefaultPostForm("return_to", "/"))
	var in LoginForm
	if err := c.ShouldBind(&in); err != nil {
		return
	}
	// ruleid: go.open-redirect
	c.Redirect(http.StatusSeeOther, in.ReturnTo)
	// ruleid: go.open-redirect
	c.Header("Location", c.GetHeader("Referer"))
	// ok: go.open-redirect
	c.Redirect(http.StatusFound, "/users/"+c.Param("id"))
	// ok: go.open-redirect
	c.Redirect(http.StatusMovedPermanently, "https://www.example.com/")
}

// Echo: c.Redirect and the Location header of c.Response().
func EchoLogin(c echo.Context) error {
	form := new(LoginForm)
	if err := c.Bind(form); err != nil {
		return err
	}
	// ruleid: go.open-redirect
	c.Response().Header().Set(echo.HeaderLocation, form.ReturnTo)
	// ruleid: go.open-redirect
	c.Redirect(http.StatusFound, c.QueryParam("next"))
	// ok: go.open-redirect
	c.Redirect(http.StatusFound, "/users/"+c.Param("id"))
	// ruleid: go.open-redirect
	return c.Redirect(http.StatusFound, form.ReturnTo)
}

// Limits of the shared request source block (go.sql-injection).
type Status int

type Wizard struct {
	Step  int    `query:"step"`
	Phase Status `query:"phase"`
	Next  string `query:"next"`
}

func SourceLimits(c echo.Context) error {
	// The binder of the Echo instance (an echo.Binder interface) is not followed.
	var viaEcho LoginForm
	c.Echo().Binder.Bind(&viaEcho, c)
	// todoruleid: go.open-redirect
	c.Redirect(http.StatusFound, viaEcho.ReturnTo)
	var wz Wizard
	echo.BindQueryParams(c, &wz)
	// ok: go.open-redirect
	c.Redirect(http.StatusFound, fmt.Sprintf("//step%d.example.com/", wz.Step))
	// A named numeric type is not in the list of clean types, so it stays tainted.
	// todook: go.open-redirect
	c.Redirect(http.StatusFound, fmt.Sprintf("//phase%d.example.com/", wz.Phase))
	// A struct declared in another package: its field types are not known here, so the whole
	// struct stays tainted.
	var ext models.Checkout
	echo.BindQueryParams(c, &ext)
	// todook: go.open-redirect
	c.Redirect(http.StatusFound, fmt.Sprintf("//shard%d.example.com/", ext.Shard))
	// OpenGrep 1.30.0 gives a field of such a struct the type of a same-named field of a struct
	// declared here (Wizard.Step is an int), so a string field called Step counts as a number.
	// todoruleid: go.open-redirect
	return c.Redirect(http.StatusFound, ext.Step)
}

// Look-alikes: a Redirect method of another type, a Location header on an outgoing request, and a
// function that is not a handler.
type Router struct{}

func (Router) Redirect(from, to string) {}

func LookAlikes(w http.ResponseWriter, r *http.Request) {
	var rt Router
	// ok: go.open-redirect
	rt.Redirect("/old", r.FormValue("to"))
	out, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	// ok: go.open-redirect
	out.Header.Set("Location", r.FormValue("to"))
	fmt.Fprintln(w, "ok")
}

func redirectTo(w http.ResponseWriter, r *http.Request, target string) {
	// ok: go.open-redirect
	http.Redirect(w, r, target, http.StatusFound)
}
