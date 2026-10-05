package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// A fixed origin: scheme and host, without and with the separator after the host.
const catalogHost = "https://catalog.example.com"
const catalogAPI = "https://catalog.example.com/api/"
const catalogName = "catalog.example.com"

type Proxy struct {
	client  *http.Client
	baseURL string
}

// net/http: request data as the whole URL, or as its scheme and host.
func (p *Proxy) Preview(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: go.ssrf
	resp, err := http.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// ruleid: go.ssrf
	http.Head(r.FormValue("url"))
	// ruleid: go.ssrf
	http.Post(r.PostFormValue("hook"), "application/json", strings.NewReader("{}"))
	// ruleid: go.ssrf
	http.PostForm(r.Header.Get("X-Callback"), url.Values{"status": {"done"}})
	// ruleid: go.ssrf
	http.Get("https://" + r.FormValue("host") + "/status")
	// ruleid: go.ssrf
	http.Get(fmt.Sprintf("https://%s/status", r.FormValue("host")))
	// ruleid: go.ssrf
	http.Get(fmt.Sprintf("http://%s.internal.example.com/", r.PathValue("tenant")))
	cookie, _ := r.Cookie("region")
	// ruleid: go.ssrf
	http.Get("https://" + cookie.Value + ".example.com/health")
	// No "/" after the host: "@evil.example" in the request data sets the host.
	// ruleid: go.ssrf
	http.Get(catalogHost + r.FormValue("path"))
	// ruleid: go.ssrf
	http.Get("https://catalog.example.com" + r.FormValue("path"))
	// ruleid: go.ssrf
	http.Get(fmt.Sprintf("%s%s", catalogHost, r.FormValue("path")))
	// The request data is the base the path is joined to.
	// ruleid: go.ssrf
	http.Get(r.FormValue("base") + "/api/items")
	// ruleid: go.ssrf
	http.Get(fmt.Sprintf("%s/api/items", r.FormValue("base")))
	// ruleid: go.ssrf
	http.Get(url.JoinPath(r.FormValue("base"), "items"))
	// ruleid: go.ssrf
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	p.client.Do(req)
	// ruleid: go.ssrf
	req2, _ := http.NewRequestWithContext(r.Context(), "POST", target+"/notify", nil)
	http.DefaultClient.Do(req2)
	// ruleid: go.ssrf
	p.client.Get(target)
	// ruleid: go.ssrf
	http.DefaultClient.Post(target, "text/plain", nil)
	client := &http.Client{}
	// ruleid: go.ssrf
	client.Head(target)
	// A URL parsed from request data, or a URL built with a host from it.
	parsed, _ := url.Parse(target)
	parsed.Path = "/robots.txt"
	// ruleid: go.ssrf
	http.Get(parsed.String())
	built := url.URL{Scheme: "https", Host: r.FormValue("host"), Path: "/status"}
	// ruleid: go.ssrf
	http.Get(built.String())
	base, _ := url.Parse(catalogAPI)
	ref, _ := url.Parse(r.FormValue("next"))
	// An absolute reference replaces the base (net/url ResolveReference).
	// ruleid: go.ssrf
	http.Get(base.ResolveReference(ref).String())
	fmt.Fprintln(w, "ok")
}

// The safe forms: a fixed origin followed by a path separator, numbers, allow-lists.
func (p *Proxy) Product(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ok: go.ssrf
	http.Get("https://catalog.example.com/products/" + id)
	// ok: go.ssrf
	http.Get(catalogHost + "/products/" + id + "/reviews?page=" + r.FormValue("page"))
	// ok: go.ssrf
	http.Get(catalogAPI + id)
	// ok: go.ssrf
	http.Get("https://catalog.example.com?q=" + id)
	// ok: go.ssrf
	http.Get(fmt.Sprintf("https://catalog.example.com/products/%s", id))
	// ok: go.ssrf
	http.Get(fmt.Sprintf("%s/products/%s", catalogHost, id))
	// A base from the server's configuration, then a separator and the request data.
	// ok: go.ssrf
	http.Get(p.baseURL + "/products/" + id)
	// ok: go.ssrf
	http.Get(os.Getenv("CATALOG_URL") + "/products/" + id)
	// ok: go.ssrf
	http.Get(fmt.Sprintf("%s/products/%s", p.baseURL, id))
	// The request's own path (it starts with "/") after a base, and a query after "?".
	// ok: go.ssrf
	http.Get(p.baseURL + r.URL.Path)
	// ok: go.ssrf
	http.Get(p.baseURL + "?" + r.URL.RawQuery)
	// A request path cut first and kept in a variable is not recognised.
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/proxy")
	// todook: go.ssrf
	http.Get(p.baseURL + rest)
	// url.JoinPath and URL.JoinPath add path elements (cleaned of ../) to a fixed base.
	joined, _ := url.JoinPath(catalogHost, "products", id)
	// ok: go.ssrf
	http.Get(joined)
	base, _ := url.Parse(catalogHost)
	// ok: go.ssrf
	http.Get(base.JoinPath("products", id).String())
	// The query or path of a URL with a fixed host.
	u, _ := url.Parse(catalogAPI)
	q := u.Query()
	q.Set("id", id)
	u.RawQuery = q.Encode()
	// ok: go.ssrf
	http.Get(u.String())
	fixed := &url.URL{Scheme: "https", Host: catalogName, Path: "/products/" + id}
	// ok: go.ssrf
	http.Get(fixed.String())
	// ok: go.ssrf
	req, _ := http.NewRequest("GET", catalogAPI+"products/"+id, strings.NewReader(r.FormValue("body")))
	p.client.Do(req)
	n, err := strconv.Atoi(r.FormValue("n"))
	if err != nil {
		return
	}
	// ok: go.ssrf
	http.Get(fmt.Sprintf("https://shard%d.example.com/", n))
	// ok: go.ssrf
	http.Get(catalogAPI)
	fmt.Fprintln(w, "ok")
}

// Allow-lists: a lookup in a map literal of constants, a switch that yields constants.
var mirrors = map[string]string{
	"eu": "https://eu.mirror.example.com/", // Europe
	"us": "https://us.mirror.example.com/",
}

func Mirror(w http.ResponseWriter, r *http.Request) {
	// ok: go.ssrf
	http.Get(mirrors[r.FormValue("region")])
	origin, found := mirrors[r.FormValue("region")]
	if !found {
		return
	}
	// ok: go.ssrf
	http.Get(origin + "index.json")
	local := map[string]string{"a": "https://a.example.com/", "b": "https://b.example.com/"}
	// ok: go.ssrf
	http.Get(local[r.FormValue("site")])
	var site string
	switch r.FormValue("site") {
	case "docs":
		site = "https://docs.example.com/"
	default:
		site = "https://www.example.com/"
	}
	// ok: go.ssrf
	http.Get(site)
	// A table filled with request data is not an allow-list.
	filled := map[string]string{"a": r.FormValue("a")}
	// ruleid: go.ssrf
	http.Get(filled["a"])
	extra := map[string]string{"a": "https://a.example.com/"}
	extra["b"] = r.FormValue("b")
	// ruleid: go.ssrf
	http.Get(extra[r.FormValue("site")])
	// A lookup with a request-data fallback is not an allow-list either.
	choice, ok := mirrors[r.FormValue("region")]
	if !ok {
		choice = r.FormValue("fallback")
	}
	// ruleid: go.ssrf
	http.Get(choice)
	fmt.Fprintln(w, "ok")
}

// A package-level table that a handler fills: the write in another function is not followed.
var hooks = map[string]string{"build": "https://ci.example.com/hook"}

func RegisterHook(w http.ResponseWriter, r *http.Request) {
	hooks[r.FormValue("name")] = r.FormValue("url")
}

func FireHook(w http.ResponseWriter, r *http.Request) {
	// todoruleid: go.ssrf
	http.Get(hooks[r.FormValue("name")])
}

// A URL assembled in a strings.Builder.
func Assembled(w http.ResponseWriter, r *http.Request) {
	var sb strings.Builder
	sb.WriteString("https://")
	sb.WriteString(r.FormValue("host"))
	sb.WriteString("/status")
	// ruleid: go.ssrf
	http.Get(sb.String())
	// The builder holds a fixed origin before the request data, but the builder as a whole counts.
	var path strings.Builder
	path.WriteString(catalogAPI)
	path.WriteString(r.FormValue("item"))
	// todook: go.ssrf
	http.Get(path.String())
	// A fixed origin followed by a builder that holds the path: no separator is visible.
	var rest strings.Builder
	rest.WriteString("/items/")
	rest.WriteString(r.FormValue("item"))
	// todook: go.ssrf
	http.Get(catalogHost + rest.String())
	// fmt.Fprintf into a builder is not followed.
	var formatted strings.Builder
	fmt.Fprintf(&formatted, "https://%s/status", r.FormValue("host"))
	// todoruleid: go.ssrf
	http.Get(formatted.String())
}

// A check of the parsed host before the call is not followed.
func Checked(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.FormValue("url"))
	if err != nil || u.Hostname() != "catalog.example.com" {
		http.Error(w, "host not allowed", http.StatusBadRequest)
		return
	}
	// todook: go.ssrf
	http.Get(u.String())
}

// Routers on net/http: chi and gorilla/mux route variables.
func Avatar(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.ssrf
	http.Get("https://" + chi.URLParam(r, "domain") + "/avatar.png")
	vars := mux.Vars(r)
	// ruleid: go.ssrf
	http.Get(vars["origin"])
	// ok: go.ssrf
	http.Get("https://cdn.example.com/avatars/" + vars["user"] + ".png")
	fmt.Fprintln(w, "ok")
}

// JSON bodies decoded with encoding/json.
type Webhook struct {
	URL     string `json:"url" form:"url" query:"url"`
	Path    string `json:"path" form:"path" query:"path"`
	Retries int    `json:"retries" form:"retries" query:"retries"`
}

func (p *Proxy) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	var in Webhook
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return
	}
	// ruleid: go.ssrf
	http.Post(in.URL, "application/json", strings.NewReader("{}"))
	// ok: go.ssrf
	http.Get(catalogHost + "/hooks/" + in.Path)
	// ok: go.ssrf
	http.Get(fmt.Sprintf("%s/hooks/%d", catalogHost, in.Retries))
	body, _ := io.ReadAll(r.Body)
	var raw map[string]string
	json.Unmarshal(body, &raw)
	// ruleid: go.ssrf
	http.Get(raw["url"])
	fmt.Fprintln(w, "ok")
}

// Gin: path parameters, query strings, forms and bound bodies.
func (p *Proxy) GinFetch(c *gin.Context) {
	// ruleid: go.ssrf
	http.Get(c.Query("url"))
	// ruleid: go.ssrf
	http.Get("https://" + c.Param("host") + "/feed.xml")
	// ruleid: go.ssrf
	p.client.Post(c.PostForm("callback"), "application/json", nil)
	var in Webhook
	if err := c.ShouldBindJSON(&in); err != nil {
		return
	}
	// ruleid: go.ssrf
	http.NewRequestWithContext(c.Request.Context(), "GET", in.URL, nil)
	// ok: go.ssrf
	http.Get("https://catalog.example.com/products/" + c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Echo: path parameters, query parameters, form values and bound bodies.
func (p *Proxy) EchoFetch(c echo.Context) error {
	hook := new(Webhook)
	if err := c.Bind(hook); err != nil {
		return err
	}
	// ruleid: go.ssrf
	http.Post(hook.URL, "application/json", nil)
	// ruleid: go.ssrf
	http.Get(c.QueryParam("url"))
	// ruleid: go.ssrf
	http.Get(fmt.Sprintf("https://%s/feed.xml", c.Param("host")))
	// ruleid: go.ssrf
	p.client.Get(c.FormValue("target"))
	// ok: go.ssrf
	http.Get(catalogHost + "/products/" + c.Param("id"))
	return c.NoContent(http.StatusOK)
}

// Limits of the shared request source block (go.sql-injection).
type Status int

type Target struct {
	Port   int    `query:"port"`
	Level  Status `query:"level"`
	Origin string `query:"origin"`
}

func (p *Proxy) SourceLimits(c echo.Context) error {
	// The binder of the Echo instance (an echo.Binder interface) is not followed.
	var viaEcho Webhook
	c.Echo().Binder.Bind(&viaEcho, c)
	// todoruleid: go.ssrf
	http.Get(viaEcho.URL)
	var t Target
	echo.BindQueryParams(c, &t)
	// ok: go.ssrf
	http.Get(fmt.Sprintf("http://localhost:%d/", t.Port))
	// A named numeric type is not in the list of clean types, so it stays tainted.
	// todook: go.ssrf
	http.Get(fmt.Sprintf("http://level%d.internal.example.com/", t.Level))
	// A struct declared in another package: its field types are not known here, so the whole
	// struct stays tainted.
	var ext models.Endpoint
	echo.BindQueryParams(c, &ext)
	// todook: go.ssrf
	http.Get(fmt.Sprintf("http://localhost:%d/", ext.Shard))
	// OpenGrep 1.30.0 gives a field of such a struct the type of a same-named field of a struct
	// declared here (Target.Port is an int), so a string field called Port counts as a number.
	// todoruleid: go.ssrf
	http.Get("https://" + ext.Port + ".example.com/")
	return nil
}

// Look-alikes: a Get method of another type, httptest-style request builders and a function that
// is not a handler.
type Cache struct{}

func (Cache) Get(key string) (string, error) { return "", nil }

func LookAlikes(w http.ResponseWriter, r *http.Request) {
	var cache Cache
	// ok: go.ssrf
	cache.Get(r.FormValue("key"))
	// ok: go.ssrf
	r.Header.Get(r.FormValue("name"))
	// ok: go.ssrf
	r.URL.Query().Get(r.FormValue("param"))
	fmt.Fprintln(w, "ok")
}

func fetchStatus(ctx context.Context, endpoint string) (*http.Response, error) {
	// ok: go.ssrf
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}
