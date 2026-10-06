package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"example.com/shop/models"
	ssoclient "example.com/shop/oauth2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
	"github.com/minio/minio-go/v7"
	objstore "github.com/minio/minio-go/v7"
	"golang.org/x/oauth2"
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

// Checks before the call: a local-path check that replaces the value is followed; a check by a
// helper function is not, and the value checked is still reported.
func Checked(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	// ok: go.open-redirect
	http.Redirect(w, r, next, http.StatusFound)
	// No scheme and no host still lets "/\evil.example" through: browsers read "\" as "/".
	u, err := url.Parse(r.FormValue("back"))
	if err != nil || u.IsAbs() || u.Host != "" {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, u.String(), http.StatusFound)
	back := r.FormValue("back")
	if !isOwnSite(back) {
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, back, http.StatusFound)
}

func isOwnSite(target string) bool { return strings.HasPrefix(target, siteRoot) }

// Validators before the redirect: a local path ("/" first, then neither "/" nor "\", which
// browsers read as "/"), or a parsed URL whose host is compared with our own host. The check
// exits or replaces the value with a literal, or it is the condition of the redirecting branch.
const siteDomain = "shop.example.com"
const noHost = ""
const signInPath = "/sign-in"

func (s *Server) Validated(w http.ResponseWriter, r *http.Request) {
	back := r.FormValue("back")
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") || strings.Contains(back, "\\") {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, back, http.StatusFound)
	next := r.URL.Query().Get("next")
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") && !strings.HasPrefix(next, "/\\") {
		// ok: go.open-redirect
		http.Redirect(w, r, next, http.StatusSeeOther)
	}
	step := r.FormValue("step")
	if !strings.HasPrefix(step, "/") {
		return
	}
	if strings.HasPrefix(step, "//") || strings.HasPrefix(step, "/\\") {
		return
	}
	// ok: go.open-redirect
	w.Header().Set("Location", step)
	target, err := url.Parse(r.FormValue("target"))
	if err != nil || target.Host != siteDomain {
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, target.String(), http.StatusFound)
	raw := r.FormValue("raw")
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() == siteDomain {
		// ok: go.open-redirect
		http.Redirect(w, r, raw, http.StatusFound)
	}
	// Backslash checks written with raw strings.
	path := r.FormValue("path")
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, `\`) {
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, path, http.StatusFound)
	page := r.FormValue("page")
	if strings.HasPrefix(page, "/") && !strings.HasPrefix(page, "//") && !strings.HasPrefix(page, `/\`) {
		// ok: go.open-redirect
		http.Redirect(w, r, page, http.StatusFound)
	}
	// The host the request was sent to.
	same, err := url.Parse(r.FormValue("same"))
	if err != nil || same.Host != r.Host {
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, same.String(), http.StatusFound)
}

// Checks that leave a way out are still reported.
func (s *Server) WeakChecks(w http.ResponseWriter, r *http.Request) {
	// "/\evil.example" passes a check for "//" alone.
	next := r.FormValue("next")
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		// ruleid: go.open-redirect
		http.Redirect(w, r, next, http.StatusFound)
	}
	// "//evil.example" has no scheme, so it is not absolute.
	u, err := url.Parse(r.FormValue("u"))
	if err != nil || u.IsAbs() {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, u.String(), http.StatusFound)
	// A relative target passes when only other hosts are refused.
	v, err := url.Parse(r.FormValue("v"))
	if err != nil || (v.Host != "" && v.Host != siteDomain) {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, v.String(), http.StatusFound)
	rel, err := url.Parse(r.FormValue("rel"))
	if err != nil || rel.Hostname() != "" {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, rel.String(), http.StatusFound)
	// The check does not stop the request.
	to := r.FormValue("to")
	if !strings.HasPrefix(to, "/") || strings.HasPrefix(to, "//") || strings.HasPrefix(to, "/\\") {
		fmt.Println("unexpected target", to)
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, to, http.StatusFound)
	// The fallback is request data again.
	ret := r.FormValue("ret")
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") || strings.HasPrefix(ret, "/\\") {
		ret = r.Referer()
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, ret, http.StatusFound)
	// The redirect sits in the branch the check rejects.
	other := r.FormValue("other")
	if strings.HasPrefix(other, "/") && !strings.HasPrefix(other, "//") && !strings.HasPrefix(other, "/\\") {
		fmt.Fprintln(w, "local")
	} else {
		// ruleid: go.open-redirect
		http.Redirect(w, r, other, http.StatusFound)
	}
	// Our own host leads to an early exit, so every other host goes on.
	z, _ := url.Parse(r.FormValue("z"))
	if z.Host == siteDomain {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, z.String(), http.StatusFound)
	// A check whose if statement also has an else branch is not followed, even on its own branch.
	alt := r.FormValue("alt")
	if strings.HasPrefix(alt, "/") && !strings.HasPrefix(alt, "//") && !strings.HasPrefix(alt, "/\\") {
		// todook: go.open-redirect
		http.Redirect(w, r, alt, http.StatusFound)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// Checks combined or placed so that they do not hold.
func (s *Server) BrokenChecks(w http.ResponseWriter, r *http.Request, strict bool) {
	// The first check negated in the branch: only targets that do not start with "/" go on.
	a := r.FormValue("a")
	if !strings.HasPrefix(a, "/") && !strings.HasPrefix(a, "//") && !strings.HasPrefix(a, "/\\") {
		// ruleid: go.open-redirect
		http.Redirect(w, r, a, http.StatusFound)
	}
	// || in the branch: any target that starts with "/" goes on, "//evil.example" too.
	b := r.FormValue("b")
	if strings.HasPrefix(b, "/") || !strings.HasPrefix(b, "//") || !strings.HasPrefix(b, "/\\") {
		// ruleid: go.open-redirect
		http.Redirect(w, r, b, http.StatusFound)
	}
	// && in the exit: an absolute URL does not exit.
	d := r.FormValue("d")
	if !strings.HasPrefix(d, "/") && strings.HasPrefix(d, "//") && strings.HasPrefix(d, "/\\") {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, d, http.StatusFound)
	// The "//" check negated in the exit: "//evil.example" goes on.
	e := r.FormValue("e")
	if !strings.HasPrefix(e, "/") || !strings.HasPrefix(e, "//") || strings.HasPrefix(e, "/\\") {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, e, http.StatusFound)
	// The exit only happens in a nested branch.
	f := r.FormValue("f")
	if !strings.HasPrefix(f, "/") || strings.HasPrefix(f, "//") || strings.HasPrefix(f, "/\\") {
		if strict {
			return
		}
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, f, http.StatusFound)
	// Request data assigned again after a passing check.
	g := r.FormValue("g")
	if !strings.HasPrefix(g, "/") || strings.HasPrefix(g, "//") || strings.HasPrefix(g, "/\\") {
		return
	}
	g = r.FormValue("then")
	// ruleid: go.open-redirect
	http.Redirect(w, r, g, http.StatusFound)
	// The host compared with request data.
	h, err := url.Parse(r.FormValue("h"))
	if err != nil || h.Host != r.FormValue("allowed") {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, h.String(), http.StatusFound)
	// The checks joined with && to another condition: without it, nothing exits.
	k := r.FormValue("k")
	if strict && (!strings.HasPrefix(k, "/") || strings.HasPrefix(k, "//") || strings.HasPrefix(k, "/\\")) {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, k, http.StatusFound)
}

// Checks that are not followed.
func (s *Server) UnfollowedChecks(w http.ResponseWriter, r *http.Request) {
	// A check held in a variable.
	next := r.FormValue("next")
	rejected := !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\")
	if rejected {
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, next, http.StatusFound)
	// A check written as the case list of a switch.
	back := r.FormValue("back")
	switch {
	case !strings.HasPrefix(back, "/"), strings.HasPrefix(back, "//"), strings.HasPrefix(back, "/\\"):
		back = "/"
	}
	// todook: go.open-redirect
	http.Redirect(w, r, back, http.StatusFound)
	// The string parsed for a host check, assigned again after the check.
	to := r.FormValue("to")
	u, err := url.Parse(to)
	if err != nil || u.Host != siteDomain {
		return
	}
	to = r.FormValue("then")
	// todoruleid: go.open-redirect
	http.Redirect(w, r, to, http.StatusFound)
	// An exit body with more than two statements before its return.
	prev := r.FormValue("prev")
	if !strings.HasPrefix(prev, "/") || strings.HasPrefix(prev, "//") || strings.HasPrefix(prev, "/\\") {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Redirect", "refused")
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, prev, http.StatusFound)
	// The checks negated as one group.
	land := r.FormValue("land")
	if !(strings.HasPrefix(land, "/") && !strings.HasPrefix(land, "//") && !strings.HasPrefix(land, "/\\")) {
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, land, http.StatusFound)
	// A host compared with the result of a call (the server's configuration).
	cfgHost, err := url.Parse(r.FormValue("cfg"))
	if err != nil || cfgHost.Hostname() != os.Getenv("PUBLIC_HOST") {
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, cfgHost.String(), http.StatusFound)
	// A host held in a variable counts as fixed, wherever the variable comes from.
	wanted := r.FormValue("wanted")
	dest, err := url.Parse(r.FormValue("dest"))
	if err != nil || dest.Host != wanted {
		return
	}
	// todoruleid: go.open-redirect
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// Gin and Echo with the same checks.
func GinValidated(c *gin.Context) {
	next := c.Query("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	// ok: go.open-redirect
	c.Redirect(http.StatusFound, next)
}

func EchoValidated(c echo.Context) error {
	to, err := url.Parse(c.QueryParam("to"))
	if err != nil || to.Hostname() != siteDomain {
		return echo.ErrBadRequest
	}
	// ok: go.open-redirect
	return c.Redirect(http.StatusFound, to.String())
}

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

// URLs produced with a fixed host: a url.URL whose Host is fixed, with request data only in its
// path, query or fragment (net/url escapes them); JoinPath elements (cleaned of ../ and repeated
// "/", with "\" escaped); the OAuth 2.0 provider's consent page; presigned storage URLs.
type Links struct {
	host      string
	publicURL string
	conf    *oauth2.Config
	store   *minio.Client
	presign *s3.PresignClient
}

func (l *Links) Producers(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("p")
	u := url.URL{Scheme: "https", Host: siteDomain, Path: p, RawQuery: "from=" + r.FormValue("from")}
	// ok: go.open-redirect
	http.Redirect(w, r, u.String(), http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, (&url.URL{Scheme: "https", Host: "shop.example.com", Path: "/" + p}).String(), http.StatusFound)
	// A host from the server's configuration, and no scheme ("//host/path").
	hosted := &url.URL{Host: l.host, Path: p, Fragment: r.FormValue("section")}
	// ok: go.open-redirect
	http.Redirect(w, r, hosted.String(), http.StatusFound)
	// The path, query or fragment set after the URL is built with a fixed host, or parsed from a
	// fixed origin.
	built := url.URL{Scheme: "https", Host: siteDomain}
	built.Path = p
	q := built.Query()
	q.Set("next", r.FormValue("next"))
	built.RawQuery = q.Encode()
	// ok: go.open-redirect
	http.Redirect(w, r, built.String(), http.StatusFound)
	site, _ := url.Parse(siteRoot)
	site.Path = p
	// ok: go.open-redirect
	http.Redirect(w, r, site.String(), http.StatusFound)
	// JoinPath on a fixed base, and on a parsed URL.
	joined, err := url.JoinPath(siteRoot, "items", p)
	if err != nil {
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, joined, http.StatusFound)
	docs, _ := url.Parse("/docs")
	// ok: go.open-redirect
	http.Redirect(w, r, docs.JoinPath(p).String(), http.StatusFound)
	// The provider's consent page: the request's state and hints only go into its query.
	// ok: go.open-redirect
	http.Redirect(w, r, l.conf.AuthCodeURL(r.FormValue("state"), oauth2.SetAuthURLParam("login_hint", r.FormValue("email"))), http.StatusFound)
	// A presigned URL for an object named by the request, in a fixed bucket.
	signed, err := l.store.PresignedGetObject(r.Context(), "downloads", r.FormValue("file"), time.Hour, nil)
	if err != nil {
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, signed.String(), http.StatusTemporaryRedirect)
	object, err := l.presign.PresignGetObject(r.Context(), &s3.GetObjectInput{Bucket: aws.String("downloads"), Key: aws.String(r.FormValue("file"))})
	if err != nil {
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, object.URL, http.StatusTemporaryRedirect)
	// A client made in the handler, and request data in the response parameters of the URL.
	client, err := minio.New("s3.example.com", &minio.Options{Secure: true})
	if err != nil {
		return
	}
	params := url.Values{"response-content-disposition": {"attachment; filename=" + p}}
	named, err := client.PresignedGetObject(r.Context(), "downloads", "report.pdf", time.Hour, params)
	if err != nil {
		return
	}
	// ok: go.open-redirect
	http.Redirect(w, r, named.String(), http.StatusTemporaryRedirect)
	// A base URL from the server's configuration.
	public, _ := url.Parse(l.publicURL)
	public.Path = p
	// ok: go.open-redirect
	http.Redirect(w, r, public.String(), http.StatusFound)
}

// The same producers with a host, scheme or bucket from the request, or without a host.
func (l *Links) UnsafeProducers(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("p")
	// ruleid: go.open-redirect
	http.Redirect(w, r, (&url.URL{Scheme: "https", Host: r.FormValue("host"), Path: "/home"}).String(), http.StatusFound)
	// No host: a path "//evil.example" stays a link to another host.
	hostless := url.URL{Path: p}
	// ruleid: go.open-redirect
	http.Redirect(w, r, hostless.String(), http.StatusFound)
	// An empty host: "https:" and the path "//evil.example" give "https:////evil.example".
	empty := url.URL{Scheme: "https", Host: "", Path: p}
	// ruleid: go.open-redirect
	http.Redirect(w, r, empty.String(), http.StatusFound)
	// Opaque data replaces the host when the URL is written out.
	opaque := url.URL{Scheme: "https", Host: siteDomain, Opaque: p}
	// ruleid: go.open-redirect
	http.Redirect(w, r, opaque.String(), http.StatusFound)
	// The host set from request data after the URL is built.
	moved := url.URL{Scheme: "https", Host: siteDomain}
	moved.Host = r.FormValue("host")
	// ruleid: go.open-redirect
	http.Redirect(w, r, moved.String(), http.StatusFound)
	// A path set on a URL parsed from a relative constant: there is no host.
	login, _ := url.Parse("/login")
	login.Path = p
	// ruleid: go.open-redirect
	http.Redirect(w, r, login.String(), http.StatusFound)
	signIn, _ := url.Parse(signInPath)
	signIn.RawQuery = p
	// ruleid: go.open-redirect
	http.Redirect(w, r, signIn.String(), http.StatusFound)
	// The path set on a url.URL built with an empty host.
	bare := url.URL{Scheme: "https", Host: noHost}
	bare.Path = p
	// ruleid: go.open-redirect
	http.Redirect(w, r, bare.String(), http.StatusFound)
	// ruleid: go.open-redirect
	http.Redirect(w, r, (&url.URL{Scheme: r.FormValue("scheme"), Host: siteDomain, Path: "/"}).String(), http.StatusFound)
	// The base of JoinPath from the request.
	other, _ := url.JoinPath(r.FormValue("base"), "items")
	// ruleid: go.open-redirect
	http.Redirect(w, r, other, http.StatusFound)
	// An OAuth 2.0 endpoint chosen by the request.
	idp := &oauth2.Config{ClientID: "shop", Endpoint: oauth2.Endpoint{AuthURL: r.FormValue("idp")}}
	// ruleid: go.open-redirect
	http.Redirect(w, r, idp.AuthCodeURL("state"), http.StatusFound)
	// The bucket name is part of the host in virtual-host style: anyone can create a bucket.
	bucket, err := l.store.PresignedGetObject(r.Context(), r.FormValue("bucket"), "report.pdf", time.Hour, nil)
	if err != nil {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, bucket.String(), http.StatusTemporaryRedirect)
	theirs, err := l.presign.PresignGetObject(r.Context(), &s3.GetObjectInput{Bucket: aws.String(r.FormValue("bucket")), Key: aws.String("report.pdf")})
	if err != nil {
		return
	}
	// ruleid: go.open-redirect
	http.Redirect(w, r, theirs.URL, http.StatusTemporaryRedirect)
	// A method of the same name on another type is not the OAuth 2.0 one.
	var sso SSO
	// ruleid: go.open-redirect
	http.Redirect(w, r, sso.AuthCodeURL(r.FormValue("state")), http.StatusFound)
	// An empty constant host, and opaque data set on a parsed fixed origin.
	blank := url.URL{Scheme: "https", Host: noHost, Path: p}
	// ruleid: go.open-redirect
	http.Redirect(w, r, blank.String(), http.StatusFound)
	fixed, _ := url.Parse(siteRoot)
	fixed.Opaque = p
	// ruleid: go.open-redirect
	http.Redirect(w, r, fixed.String(), http.StatusFound)
	// An absolute reference replaces the base (net/url ResolveReference).
	ref, _ := url.Parse(p)
	// ruleid: go.open-redirect
	http.Redirect(w, r, fixed.ResolveReference(ref).String(), http.StatusFound)
}

// Look-alikes of the producers: a JoinPath method of another type, and a fixed origin with an
// empty host after "@".
type pathJoiner struct{ base string }

func (j pathJoiner) JoinPath(parts ...string) string { return j.base + strings.Join(parts, "/") }

func (l *Links) ProducerLookAlikes(w http.ResponseWriter, r *http.Request) {
	var j pathJoiner
	// ruleid: go.open-redirect
	http.Redirect(w, r, j.JoinPath(r.FormValue("p")), http.StatusFound)
	noHostAfterAt, _ := url.Parse("https://@")
	noHostAfterAt.Path = r.FormValue("p")
	// ruleid: go.open-redirect
	http.Redirect(w, r, noHostAfterAt.String(), http.StatusFound)
}

// A base URL parsed in a var declaration (here at package level) is not recognised as a
// JoinPath receiver.
var publicBase, _ = url.Parse(siteRoot)

// Producers that are not followed.
func (l *Links) UnfollowedProducers(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("p")
	// todook: go.open-redirect
	http.Redirect(w, r, publicBase.JoinPath("items", p).String(), http.StatusFound)
	// The request's own URL copied, with a fixed scheme and host (an HTTPS upgrade).
	upgrade := *r.URL
	upgrade.Scheme = "https"
	upgrade.Host = siteDomain
	// todook: go.open-redirect
	http.Redirect(w, r, upgrade.String(), http.StatusMovedPermanently)
	// The real minio client imported under another name is not recognised.
	var store *objstore.Client
	aliased, err := store.PresignedGetObject(r.Context(), "downloads", p, time.Hour, nil)
	if err != nil {
		return
	}
	// todook: go.open-redirect
	http.Redirect(w, r, aliased.String(), http.StatusTemporaryRedirect)
	// A field of an s3 input read back as the target counts as clean.
	in := s3.GetObjectInput{Bucket: aws.String("downloads"), Key: aws.String(p)}
	// todoruleid: go.open-redirect
	http.Redirect(w, r, *in.Key, http.StatusFound)
	// A package of another path whose last element is also oauth2, imported under an alias in a
	// file that imports golang.org/x/oauth2, is taken for it.
	var own *ssoclient.Config
	// todoruleid: go.open-redirect
	http.Redirect(w, r, own.AuthCodeURL(p), http.StatusFound)
	// A url.URL declared empty and given its host field by field.
	var u url.URL
	u.Scheme = "https"
	u.Host = siteDomain
	u.Path = p
	// todook: go.open-redirect
	http.Redirect(w, r, u.String(), http.StatusFound)
	// OpenGrep 1.30.0 gives the field l.conf the type of a local variable named conf, so the
	// Config's consent page is not recognised.
	conf := &url.URL{Scheme: "https", Host: siteDomain}
	conf.Path = "/consent"
	// todook: go.open-redirect
	http.Redirect(w, r, l.conf.AuthCodeURL(r.FormValue("state")), http.StatusFound)
}

type SSO struct{}

func (SSO) AuthCodeURL(state string) string { return state }

// Gin and Echo with URL producers.
func GinConsent(c *gin.Context) {
	conf := &oauth2.Config{ClientID: "shop", Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example.com/authorize"}}
	// ok: go.open-redirect
	c.Redirect(http.StatusFound, conf.AuthCodeURL(c.Query("state")))
	// ruleid: go.open-redirect
	c.Redirect(http.StatusFound, (&url.URL{Path: c.Query("p")}).String())
}

func EchoProducers(c echo.Context) error {
	u := &url.URL{Scheme: "https", Host: siteDomain, Path: c.Param("page")}
	// ok: go.open-redirect
	return c.Redirect(http.StatusFound, u.String())
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
