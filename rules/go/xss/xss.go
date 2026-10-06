package pages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	htmltemplate "html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	. "text/template"
	mail "text/template"

	"example.com/shop/models"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
	"github.com/microcosm-cc/bluemonday"
)

// text/template does not escape: a template of it executed into the response.
var greeting = template.Must(template.New("greeting").Parse("<p>Hello, {{.}}!</p>"))

// html/template escapes the data it is given.
var safeGreeting = htmltemplate.Must(htmltemplate.New("greeting").Parse("<p>Hello, {{.}}!</p>"))

// net/http: request data written to the response, or executed by a text/template.
func Hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go.xss
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", name)
	// ruleid: go.xss
	fmt.Fprint(w, "<p>"+r.FormValue("bio")+"</p>")
	// ruleid: go.xss
	fmt.Fprintln(w, r.PostFormValue("comment"))
	// ruleid: go.xss
	io.WriteString(w, "<div>"+r.Header.Get("X-Title")+"</div>")
	// ruleid: go.xss
	w.Write([]byte(r.PathValue("slug")))
	cookie, _ := r.Cookie("theme")
	// ruleid: go.xss
	w.Write([]byte(fmt.Sprintf("<body class=%q>", cookie.Value)))
	// ruleid: go.xss
	greeting.Execute(w, name)
	page := template.Must(template.New("page").Parse("<title>{{.Title}}</title>"))
	// ruleid: go.xss
	page.Execute(w, map[string]string{"Title": r.FormValue("title")})
	// ruleid: go.xss
	greeting.ExecuteTemplate(w, "greeting", r.Referer())
	// A body read in full and written back.
	body, _ := io.ReadAll(r.Body)
	// ruleid: go.xss
	w.Write(body)
}

// html/template conversions: request data marked as safe HTML, JS, CSS or URL.
func Profile(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		// ruleid: go.xss
		"Bio": htmltemplate.HTML(r.FormValue("bio")),
		// ruleid: go.xss
		"Link": htmltemplate.URL(r.FormValue("site")),
		// ruleid: go.xss
		"Init": htmltemplate.JS(r.FormValue("init")),
		// ruleid: go.xss
		"Nick": htmltemplate.JSStr(r.FormValue("nick")),
		// ruleid: go.xss
		"Color": htmltemplate.CSS(r.FormValue("color")),
		// ruleid: go.xss
		"Extra": htmltemplate.HTMLAttr(r.FormValue("attr")),
		// ruleid: go.xss
		"Images": htmltemplate.Srcset(r.FormValue("srcset")),
	}
	safeGreeting.Execute(w, data)
}

// The safe forms: html/template with data, escaping, sanitising, JSON, plain-text responses,
// numbers and constants.
func SafeHello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ok: go.xss
	safeGreeting.Execute(w, name)
	// ok: go.xss
	safeGreeting.ExecuteTemplate(w, "greeting", map[string]string{"Name": name})
	// ok: go.xss
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", html.EscapeString(name))
	// ok: go.xss
	io.WriteString(w, "<p>"+htmltemplate.HTMLEscapeString(r.FormValue("bio"))+"</p>")
	// ok: go.xss
	io.WriteString(w, "<script>var q = '"+htmltemplate.JSEscapeString(r.FormValue("q"))+"';</script>")
	// URL escaping leaves only letters, digits, "-_.~", "%" and "+".
	// ok: go.xss
	fmt.Fprintf(w, "<a href=\"/search?q=%s\">next</a>", htmltemplate.URLQueryEscaper(name))
	// ok: go.xss
	fmt.Fprintf(w, "<a href=\"/search?q=%s\">next</a>", url.QueryEscape(name))
	// ok: go.xss
	fmt.Fprintf(w, "<a href=\"/tags/%s\">tag</a>", url.PathEscape(r.FormValue("tag")))
	// ok: go.xss
	_ = htmltemplate.HTML(html.EscapeString(r.FormValue("note")))
	policy := bluemonday.UGCPolicy()
	// ok: go.xss
	_ = htmltemplate.HTML(policy.Sanitize(r.FormValue("post")))
	// ok: go.xss
	w.Write(bluemonday.StrictPolicy().SanitizeBytes([]byte(r.FormValue("text"))))
	// ok: go.xss
	_ = htmltemplate.HTML("<em>static</em>")
	n, err := strconv.Atoi(r.FormValue("page"))
	if err != nil {
		// http.Error sends text/plain with X-Content-Type-Options: nosniff.
		// ok: go.xss
		http.Error(w, "bad page "+r.FormValue("page"), http.StatusBadRequest)
		return
	}
	// ok: go.xss
	fmt.Fprintf(w, "<p>Page %d</p>", n)
	// encoding/json escapes <, > and & in strings.
	out, _ := json.Marshal(map[string]string{"name": name})
	// ok: go.xss
	w.Write(out)
	// ok: go.xss
	json.NewEncoder(w).Encode(map[string]string{"name": name})
	// The content of a file is not request data, even when the request names the file.
	page, err := os.ReadFile(filepath.Join("/srv/pages", filepath.Base(name)+".html"))
	if err != nil {
		return
	}
	// ok: go.xss
	w.Write(page)
}

// Allow-lists: a lookup in a map literal of constants; a map filled with request data is not one.
var banners = map[string]string{
	"sale": "<b>Sale!</b>", // shown in December
	"new":  "<i>New</i>",
}

func Banner(w http.ResponseWriter, r *http.Request) {
	// ok: go.xss
	io.WriteString(w, banners[r.FormValue("kind")])
	local := map[string]htmltemplate.HTML{"a": "<b>A</b>", "b": "<b>B</b>"}
	// ok: go.xss
	safeGreeting.Execute(w, local[r.FormValue("k")])
	filled := map[string]string{"x": r.FormValue("x")}
	// ruleid: go.xss
	io.WriteString(w, filled["x"])
	text, ok := banners[r.FormValue("kind")]
	if !ok {
		text = r.FormValue("fallback")
	}
	// ruleid: go.xss
	io.WriteString(w, text)
}

// A Content-Type that browsers do not render as HTML.
func PlainEcho(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// ok: go.xss
	fmt.Fprintf(w, "you said: %s", r.FormValue("msg"))
}

func JSONEcho(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	// ok: go.xss
	w.Write([]byte(`{"echo":"` + r.FormValue("msg") + `"}`))
}

func AddedType(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	// ok: go.xss
	fmt.Fprintf(w, "{\"echo\":%q}", r.FormValue("msg"))
}

func EchoPlain(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderContentType, "text/plain; charset=utf-8")
	// ok: go.xss
	c.Response().Write([]byte(c.QueryParam("msg")))
	return nil
}

func EchoPlainConst(c echo.Context) error {
	c.Response().Header().Set("Content-Type", echo.MIMETextPlain)
	// ok: go.xss
	c.Response().Write([]byte(c.QueryParam("msg")))
	return nil
}

// Other non-HTML constants (Gin's binding.MIME*, Echo's protobuf or msgpack types) are not listed.
func EchoProtobuf(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationProtobuf)
	// todook: go.xss
	c.Response().Write([]byte(c.QueryParam("msg")))
	return nil
}

func HTMLEcho(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// ruleid: go.xss
	fmt.Fprintf(w, "you said: %s", r.FormValue("msg"))
}

// Sniffing: a first write that starts with plain text makes the response text/plain, but the
// rule does not look at the order of writes.
func Sniffed(w http.ResponseWriter, r *http.Request) {
	// todook: go.xss
	fmt.Fprintf(w, "Hello, %s", r.FormValue("name"))
}

// An html/template field with the same name as a text/template field of another struct.
type Page struct {
	body *htmltemplate.Template
}

// text/template held in a struct field, passed as a parameter, or imported under an alias.
type Notifier struct {
	body *template.Template
	page *htmltemplate.Template
}

func (n *Notifier) Notify(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.xss
	n.body.Execute(w, r.FormValue("name"))
	// ok: go.xss
	n.page.Execute(w, r.FormValue("name"))
}

func (n *Page) Notify(w http.ResponseWriter, r *http.Request) {
	// ok: go.xss
	n.body.Execute(w, r.FormValue("name"))
}

// A text/template field reached through a variable that is not the method receiver is not followed.
func NotifyAll(w http.ResponseWriter, r *http.Request, n *Notifier) {
	// todoruleid: go.xss
	n.body.Execute(w, r.FormValue("name"))
}

func WithTemplate(t *template.Template, h *htmltemplate.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ruleid: go.xss
		t.Execute(w, r.FormValue("name"))
		// ok: go.xss
		h.Execute(w, r.FormValue("name"))
	}
}

var receipt = mail.Must(mail.New("receipt").Parse("Order for {{.}}"))

func Receipt(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.xss
	receipt.Execute(w, r.FormValue("name"))
}

// A text/template field is missed when a struct declared later in the file has a field of the
// same name (of any type).
type Digest struct {
	layout *template.Template
}

type Theme struct {
	layout string
}

func (d *Digest) Send(w http.ResponseWriter, r *http.Request) {
	// todoruleid: go.xss
	d.layout.Execute(w, r.FormValue("name"))
}

// A dot import of text/template is not followed.
func DotImport(w http.ResponseWriter, r *http.Request) {
	t := Must(New("dot").Parse("<p>{{.}}</p>"))
	// todoruleid: go.xss
	t.Execute(w, r.FormValue("name"))
}

// A text/template executed into a buffer that is then written to the response.
func Buffered(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	greeting.Execute(&buf, r.FormValue("name"))
	// ruleid: go.xss
	w.Write(buf.Bytes())
	var sb strings.Builder
	page := template.Must(template.New("page").Parse("<p>{{.}}</p>"))
	page.ExecuteTemplate(&sb, "page", r.FormValue("bio"))
	// ruleid: go.xss
	io.WriteString(w, sb.String())
	out := new(bytes.Buffer)
	receipt.Execute(out, r.FormValue("name"))
	// ruleid: go.xss
	out.WriteTo(w)
	var copied bytes.Buffer
	greeting.Execute(&copied, map[string]string{"Name": r.FormValue("name")})
	// ruleid: go.xss
	io.Copy(w, &copied)
	// ruleid: go.xss
	fmt.Fprintf(w, "<main>%s</main>", buf.String())
	pointer := bytes.NewBuffer(nil)
	greeting.Execute(pointer, r.FormValue("name"))
	// ruleid: go.xss
	io.Copy(w, pointer)
	// html/template escapes what it writes into a buffer.
	var safe bytes.Buffer
	safeGreeting.Execute(&safe, r.FormValue("name"))
	// ok: go.xss
	w.Write(safe.Bytes())
	// ok: go.xss
	safe.WriteTo(w)
	// A buffer of text/template output written somewhere else, or holding constant data only.
	var logged bytes.Buffer
	greeting.Execute(&logged, r.FormValue("name"))
	// ok: go.xss
	os.Stdout.Write(logged.Bytes())
	var fixed bytes.Buffer
	greeting.Execute(&fixed, "guest")
	// ok: go.xss
	w.Write(fixed.Bytes())
}

// Request data written into a buffer directly (not by a template) is not followed.
func BufferedDirect(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	buf.WriteString("<p>" + r.FormValue("name") + "</p>")
	// todoruleid: go.xss
	w.Write(buf.Bytes())
}

// The buffer sent as plain text.
func BufferedPlain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var buf bytes.Buffer
	greeting.Execute(&buf, r.FormValue("name"))
	// ok: go.xss
	buf.WriteTo(w)
}

// Templates held in a field or passed as a parameter, executed into a buffer.
func (n *Notifier) Preview(w http.ResponseWriter, r *http.Request) {
	var text, html bytes.Buffer
	n.body.Execute(&text, r.FormValue("name"))
	// ruleid: go.xss
	w.Write(text.Bytes())
	n.page.Execute(&html, r.FormValue("name"))
	// ok: go.xss
	w.Write(html.Bytes())
}

func WithBuffer(t *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		t.Execute(&buf, r.FormValue("name"))
		// ruleid: go.xss
		io.Copy(w, &buf)
	}
}

// Gin and Echo: the buffer sent as HTML.
func GinBuffered(c *gin.Context) {
	var buf bytes.Buffer
	greeting.Execute(&buf, c.Query("name"))
	// ruleid: go.xss
	c.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
	var csv bytes.Buffer
	greeting.Execute(&csv, c.Query("name"))
	// ok: go.xss
	c.Data(http.StatusOK, "text/csv", csv.Bytes())
}

func EchoBuffered(c echo.Context) error {
	var buf bytes.Buffer
	receipt.Execute(&buf, c.QueryParam("name"))
	// ruleid: go.xss
	return c.HTML(http.StatusOK, buf.String())
}

// Routers on net/http: chi and gorilla/mux route variables.
func Tag(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.xss
	fmt.Fprintf(w, "<h2>%s</h2>", chi.URLParam(r, "tag"))
	vars := mux.Vars(r)
	// ruleid: go.xss
	io.WriteString(w, "<h2>"+vars["category"]+"</h2>")
	// ok: go.xss
	safeGreeting.Execute(w, vars["category"])
}

// JSON bodies decoded with encoding/json.
type Comment struct {
	Author string `json:"author" form:"author" query:"author"`
	Body   string `json:"body" form:"body" query:"body"`
	Stars  int    `json:"stars" form:"stars" query:"stars"`
}

func Preview(w http.ResponseWriter, r *http.Request) {
	var in Comment
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return
	}
	// ruleid: go.xss
	fmt.Fprintf(w, "<article><b>%s</b>%s</article>", in.Author, in.Body)
	// ok: go.xss
	fmt.Fprintf(w, "<span>%d stars</span>", in.Stars)
}

// Gin: c.Data with an HTML content type, the response writer, and template.HTML in c.HTML data.
func GinPreview(c *gin.Context) {
	// ruleid: go.xss
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<p>"+c.Query("text")+"</p>"))
	// ruleid: go.xss
	c.Writer.WriteString("<p>" + c.Param("name") + "</p>")
	// ruleid: go.xss
	fmt.Fprintf(c.Writer, "<p>%s</p>", c.PostForm("comment"))
	var in Comment
	if err := c.ShouldBindJSON(&in); err != nil {
		return
	}
	c.HTML(http.StatusOK, "comment.tmpl", gin.H{
		// ruleid: go.xss
		"body": htmltemplate.HTML(in.Body),
		// ok: go.xss
		"author": in.Author,
	})
	// c.String sends text/plain; c.JSON escapes HTML characters.
	// ok: go.xss
	c.String(http.StatusOK, "hello %s", c.Query("name"))
	// ok: go.xss
	c.JSON(http.StatusOK, gin.H{"text": c.Query("text")})
	// ok: go.xss
	c.Data(http.StatusOK, "application/octet-stream", []byte(c.Query("raw")))
}

// Echo: c.HTML, c.HTMLBlob, c.Blob with an HTML content type, the response writer.
func EchoPreview(c echo.Context) error {
	comment := new(Comment)
	if err := c.Bind(comment); err != nil {
		return err
	}
	// ruleid: go.xss
	c.HTML(http.StatusOK, "<p>"+comment.Body+"</p>")
	// ruleid: go.xss
	c.HTMLBlob(http.StatusOK, []byte(c.QueryParam("html")))
	// ruleid: go.xss
	c.Blob(http.StatusOK, echo.MIMETextHTMLCharsetUTF8, []byte(c.Param("name")))
	// ruleid: go.xss
	c.Response().Write([]byte(c.FormValue("text")))
	// ruleid: go.xss
	greeting.Execute(c.Response(), c.QueryParam("name"))
	// ok: go.xss
	c.HTML(http.StatusOK, "<p>"+html.EscapeString(c.QueryParam("text"))+"</p>")
	// ok: go.xss
	c.String(http.StatusOK, c.QueryParam("text"))
	// ok: go.xss
	return c.JSON(http.StatusOK, comment)
}

// Limits of the shared request source block (go.sql-injection).
type Status int

type Filter struct {
	Page  int    `query:"page"`
	Level Status `query:"level"`
	Name  string `query:"name"`
}

func SourceLimits(c echo.Context) error {
	// The binder of the Echo instance (an echo.Binder interface) is not followed.
	var viaEcho Comment
	c.Echo().Binder.Bind(&viaEcho, c)
	// todoruleid: go.xss
	c.HTML(http.StatusOK, viaEcho.Body)
	var f Filter
	echo.BindQueryParams(c, &f)
	// ok: go.xss
	c.HTML(http.StatusOK, fmt.Sprintf("<p>page %d</p>", f.Page))
	// A named numeric type is not in the list of clean types, so it stays tainted.
	// todook: go.xss
	c.HTML(http.StatusOK, fmt.Sprintf("<p>level %d</p>", f.Level))
	// A struct declared in another package: its field types are not known here, so the whole
	// struct stays tainted.
	var ext models.Review
	echo.BindQueryParams(c, &ext)
	// todook: go.xss
	c.HTML(http.StatusOK, fmt.Sprintf("<p>%d votes</p>", ext.Votes))
	// OpenGrep 1.30.0 gives a field of such a struct the type of a same-named field of a struct
	// declared here (Filter.Page is an int), so a string field called Page counts as a number.
	// todoruleid: go.xss
	c.HTML(http.StatusOK, "<p>"+ext.Page+"</p>")
	return nil
}

// Look-alikes: a Write method of another type, an HTML method of another type, and a function
// that is not a handler.
type Report struct{}

func (Report) Write(p []byte) (int, error) { return len(p), nil }
func (Report) HTML(code int, s string)      {}

func LookAlikes(w http.ResponseWriter, r *http.Request) {
	var rep Report
	// ok: go.xss
	rep.Write([]byte(r.FormValue("line")))
	// ok: go.xss
	rep.HTML(http.StatusOK, r.FormValue("html"))
	var buf bytes.Buffer
	// ok: go.xss
	fmt.Fprintf(&buf, "<p>%s</p>", r.FormValue("draft"))
	fmt.Fprintln(w, "saved")
}

func renderBanner(w http.ResponseWriter, text string) {
	// ok: go.xss
	fmt.Fprintf(w, "<div class=banner>%s</div>", text)
}
