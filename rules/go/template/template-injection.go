package views

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	texttemplate "text/template"

	"example.com/shop/models"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
)

//go:embed templates
var files embed.FS

var funcs = template.FuncMap{"upper": strings.ToUpper}

type Mailer struct {
	layout *template.Template
}

// net/http: request data in the text of a template that is parsed.
func (m *Mailer) Preview(w http.ResponseWriter, r *http.Request) {
	text := r.FormValue("template")
	// ruleid: go.template-injection
	t, err := template.New("preview").Parse(text)
	if err != nil {
		return
	}
	t.Execute(w, nil)
	// ruleid: go.template-injection
	template.Must(template.New("greeting").Parse("<p>Hello, " + r.URL.Query().Get("name") + "</p>"))
	// ruleid: go.template-injection
	template.New("x").Funcs(funcs).Parse(fmt.Sprintf("<h1>%s</h1>", r.PostFormValue("title")))
	// ruleid: go.template-injection
	template.New("x").Delims("[[", "]]").Parse(r.Header.Get("X-Template"))
	// ruleid: go.template-injection
	texttemplate.New("mail").Parse("Dear " + r.PathValue("name") + ",")
	cookie, _ := r.Cookie("layout")
	base := template.New("base")
	// ruleid: go.template-injection
	base.Parse(cookie.Value)
	// ruleid: go.template-injection
	base.New("footer").Parse(r.FormValue("footer"))
	// ruleid: go.template-injection
	m.layout.New("body").Parse(r.FormValue("body"))
	clone, _ := m.layout.Clone()
	// ruleid: go.template-injection
	clone.Parse(r.FormValue("override"))
	body, _ := io.ReadAll(r.Body)
	// ruleid: go.template-injection
	template.New("raw").Parse(string(body))
}

// The safe forms: request data given to Execute as data, templates from files or constants.
var page = template.Must(template.ParseFS(files, "templates/*.html"))

func (m *Mailer) SafePreview(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ok: go.template-injection
	t := template.Must(template.New("greeting").Parse("<p>Hello, {{.}}</p>"))
	// ok: go.template-injection
	t.Execute(w, name)
	// ok: go.template-injection
	page.ExecuteTemplate(w, "index.html", map[string]string{"Name": name})
	// ok: go.template-injection
	texttemplate.Must(texttemplate.New("mail").Parse("Dear {{.Name}},")).Execute(w, map[string]string{"Name": name})
	// ok: go.template-injection
	m.layout.Execute(w, r.FormValue("body"))
	n, err := strconv.Atoi(r.FormValue("columns"))
	if err != nil {
		return
	}
	// ok: go.template-injection
	template.New("grid").Parse(fmt.Sprintf(`<div class="grid-%d">{{.}}</div>`, n))
	// ok: go.template-injection
	template.ParseFiles("templates/report.html")
}

// Allow-lists: a map literal of constant template texts.
var layouts = map[string]string{
	"plain": "<p>{{.}}</p>",
	"bold":  "<p><b>{{.}}</b></p>", // used for alerts
}

func Layout(w http.ResponseWriter, r *http.Request) {
	// ok: go.template-injection
	t, _ := template.New("layout").Parse(layouts[r.FormValue("layout")])
	t.Execute(w, r.FormValue("message"))
	filled := map[string]string{"custom": r.FormValue("custom")}
	// ruleid: go.template-injection
	template.New("layout").Parse(filled["custom"])
	text, ok := layouts[r.FormValue("layout")]
	if !ok {
		text = r.FormValue("layout")
	}
	// ruleid: go.template-injection
	template.New("layout").Parse(text)
}

// Escaping the text for HTML does not remove template actions: "{{" passes through.
func Escaped(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.template-injection
	template.New("x").Parse(template.HTMLEscapeString(r.FormValue("text")))
}

// Look-alikes: parsers of other packages.
func Parsers(w http.ResponseWriter, r *http.Request) {
	// ok: go.template-injection
	time.Parse(time.RFC3339, r.FormValue("since"))
	var cfg map[string]any
	// ok: go.template-injection
	json.Unmarshal([]byte(r.FormValue("cfg")), &cfg)
	fmt.Fprintln(w, "ok")
}

// A template passed in as a parameter (its type is known).
func Extend(t *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ruleid: go.template-injection
		t.Parse(r.FormValue("block"))
	}
}

// A clone of a package-level template, and a template derived from one.
var shell = template.Must(template.New("shell").Parse("<main>{{template \"body\" .}}</main>"))

func Customise(w http.ResponseWriter, r *http.Request) {
	custom, err := shell.Clone()
	if err != nil {
		return
	}
	// ruleid: go.template-injection
	custom.Parse(r.FormValue("body"))
	// ruleid: go.template-injection
	shell.New("body").Parse(r.FormValue("body"))
	// ok: go.template-injection
	custom.Execute(w, r.FormValue("body"))
}

// A template returned by a function of another package is not followed.
func Override(w http.ResponseWriter, r *http.Request) {
	// todoruleid: go.template-injection
	models.Templates().Lookup("page").Parse(r.FormValue("block"))
}

// Routers on net/http: chi and gorilla/mux route variables.
func Snippet(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.template-injection
	template.New("snippet").Parse(chi.URLParam(r, "snippet"))
	vars := mux.Vars(r)
	// ruleid: go.template-injection
	texttemplate.New("snippet").Parse(vars["snippet"])
	// ok: go.template-injection
	template.Must(template.New("s").Parse("{{.}}")).Execute(w, vars["snippet"])
}

// JSON bodies decoded with encoding/json.
type Campaign struct {
	Subject  string `json:"subject" form:"subject" query:"subject"`
	Template string `json:"template" form:"template" query:"template"`
	Width    int    `json:"width" form:"width" query:"width"`
}

func CreateCampaign(w http.ResponseWriter, r *http.Request) {
	var in Campaign
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return
	}
	// ruleid: go.template-injection
	texttemplate.New(in.Subject).Parse(in.Template)
	// ok: go.template-injection
	template.New("banner").Parse(fmt.Sprintf(`<img width="%d" src="{{.}}">`, in.Width))
	// ok: go.template-injection
	template.Must(template.New("subject").Parse("{{.}}")).Execute(w, in.Subject)
}

// Gin: path parameters, query strings, forms and bound bodies.
func GinPreview(c *gin.Context) {
	// ruleid: go.template-injection
	template.New("x").Parse(c.Query("tpl"))
	// ruleid: go.template-injection
	template.New("x").Parse("<p>" + c.Param("greeting") + "</p>")
	var in Campaign
	if err := c.ShouldBindJSON(&in); err != nil {
		return
	}
	// ruleid: go.template-injection
	texttemplate.New("x").Parse(in.Template)
	// The request data as template data (Gin renders html/template).
	// ok: go.template-injection
	c.HTML(http.StatusOK, "preview.tmpl", gin.H{"subject": in.Subject})
}

// Echo: path parameters, query parameters, form values and bound bodies.
func EchoPreview(c echo.Context) error {
	campaign := new(Campaign)
	if err := c.Bind(campaign); err != nil {
		return err
	}
	// ruleid: go.template-injection
	template.New("x").Parse(campaign.Template)
	// ruleid: go.template-injection
	template.New("x").Parse(c.FormValue("tpl"))
	// ruleid: go.template-injection
	template.New("x").Parse(c.QueryParam("tpl"))
	// ok: go.template-injection
	return c.Render(http.StatusOK, "preview", campaign)
}

// Limits of the shared request source block (go.sql-injection).
type Status int

type Grid struct {
	Columns int    `query:"columns"`
	Level   Status `query:"level"`
	Title   string `query:"title"`
}

func SourceLimits(c echo.Context) error {
	// The binder of the Echo instance (an echo.Binder interface) is not followed.
	var viaEcho Campaign
	c.Echo().Binder.Bind(&viaEcho, c)
	// todoruleid: go.template-injection
	template.New("x").Parse(viaEcho.Template)
	var g Grid
	echo.BindQueryParams(c, &g)
	// ok: go.template-injection
	template.New("x").Parse(fmt.Sprintf(`<div class="cols-%d">{{.}}</div>`, g.Columns))
	// A named numeric type is not in the list of clean types, so it stays tainted.
	// todook: go.template-injection
	template.New("x").Parse(fmt.Sprintf(`<div class="level-%d">{{.}}</div>`, g.Level))
	// A struct declared in another package: its field types are not known here, so the whole
	// struct stays tainted.
	var ext models.Layout
	echo.BindQueryParams(c, &ext)
	// todook: go.template-injection
	template.New("x").Parse(fmt.Sprintf(`<div class="rows-%d">{{.}}</div>`, ext.Rows))
	// OpenGrep 1.30.0 gives a field of such a struct the type of a same-named field of a struct
	// declared here (Grid.Columns is an int), so a string field called Columns counts as a number.
	// todoruleid: go.template-injection
	template.New("x").Parse(ext.Columns)
	return nil
}

// Look-alikes: a Parse method of another type, and a function that is not a handler.
type Config struct{}

func (Config) Parse(text string) error { return nil }

func LookAlikes(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	// ok: go.template-injection
	cfg.Parse(r.FormValue("config"))
	fmt.Fprintln(w, "ok")
}

func compile(name, text string) (*template.Template, error) {
	// ok: go.template-injection
	return template.New(name).Parse(text)
}
