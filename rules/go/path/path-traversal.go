package files

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
)

const baseDir = "/srv/files"

// net/http: request data in the path of a file that is read, written or removed.
func Download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go.path-traversal
	f, _ := os.Open(filepath.Join(baseDir, name))
	defer f.Close()
	// ruleid: go.path-traversal
	data, _ := os.ReadFile(baseDir + "/" + r.FormValue("file"))
	w.Write(data)
	// ruleid: go.path-traversal
	os.OpenFile(fmt.Sprintf("%s/%s.log", baseDir, r.PathValue("day")), os.O_RDONLY, 0)
	// ruleid: go.path-traversal
	os.WriteFile(filepath.Join(baseDir, r.PostFormValue("target")), []byte("x"), 0o644)
	// ruleid: go.path-traversal
	os.Create(filepath.Join(baseDir, r.Header.Get("X-File")))
	cookie, _ := r.Cookie("draft")
	// ruleid: go.path-traversal
	os.Remove(filepath.Join(baseDir, cookie.Value))
	// ruleid: go.path-traversal
	os.RemoveAll(filepath.Join(baseDir, "users", r.FormValue("user")))
	// ruleid: go.path-traversal
	ioutil.ReadFile(filepath.Join(baseDir, r.FormValue("legacy")))
	// ruleid: go.path-traversal
	ioutil.WriteFile(baseDir+"/"+r.FormValue("out"), []byte("x"), 0o644)
	// Renaming, linking, creating directories and Stat are not followed yet.
	// todoruleid: go.path-traversal
	os.Rename(filepath.Join(baseDir, "tmp.bin"), filepath.Join(baseDir, r.FormValue("to")))
	// Clean does not stop a relative path from climbing out of the base directory.
	// ruleid: go.path-traversal
	os.Open(filepath.Join(baseDir, filepath.Clean(name)))
	// ServeFile only rejects ".." in r.URL.Path, not in a name from elsewhere.
	// ruleid: go.path-traversal
	http.ServeFile(w, r, filepath.Join(baseDir, r.URL.Query().Get("doc")))
}

// The safe forms: a base name, os.Root, a file server, constants, numbers and allow-lists.
func SafeDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ok: go.path-traversal
	os.Open(filepath.Join(baseDir, filepath.Base(name)))
	// URL escaping turns every "/" into %2F.
	// ok: go.path-traversal
	os.Open(filepath.Join(baseDir, url.QueryEscape(name)+".json"))
	// ok: go.path-traversal
	os.ReadFile(filepath.Join(baseDir, "cache", url.PathEscape(r.FormValue("key"))))
	// The base name of ".." is "..": joined to baseDir it names the parent directory.
	// todoruleid: go.path-traversal
	os.RemoveAll(filepath.Join(baseDir, filepath.Base(r.FormValue("dir"))))
	// ok: go.path-traversal
	os.OpenInRoot(baseDir, name)
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return
	}
	defer root.Close()
	// ok: go.path-traversal
	root.Open(name)
	// ok: go.path-traversal
	root.Create(r.FormValue("target"))
	// ServeFile rejects requests whose r.URL.Path holds a ".." element.
	// ok: go.path-traversal
	http.ServeFile(w, r, filepath.Join(baseDir, r.URL.Path))
	// ok: go.path-traversal
	os.ReadFile("/etc/app/config.json")
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		return
	}
	// ok: go.path-traversal
	os.Open(fmt.Sprintf("%s/reports/%d.pdf", baseDir, id))
	reports := map[string]string{"daily": "daily.csv", "weekly": "weekly.csv"}
	file, found := reports[r.FormValue("report")]
	if !found {
		return
	}
	// ok: go.path-traversal
	os.Open(filepath.Join(baseDir, file))
	// Request data as the content of a file with a fixed name.
	body, _ := io.ReadAll(r.Body)
	// ok: go.path-traversal
	os.WriteFile(filepath.Join(baseDir, "upload.bin"), body, 0o600)
	// FormFile is not a source of this rule: the multipart reader keeps only the base name of an
	// upload's file name (mime/multipart Part.FileName passes it through filepath.Base).
	_, header, err := r.FormFile("upload")
	if err != nil {
		return
	}
	// ok: go.path-traversal
	os.Create(filepath.Join(baseDir, header.Filename))
	fmt.Fprintln(w, "ok")
}

// File servers and file systems that reject ".." themselves.
//
//go:embed static
var static embed.FS

func Static(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ok: go.path-traversal
	data, _ := fs.ReadFile(static, "static/"+name)
	w.Write(data)
	// ok: go.path-traversal
	http.ServeFileFS(w, r, os.DirFS(baseDir), name)
}

func Routes(mux *http.ServeMux) {
	// ok: go.path-traversal
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/srv/static"))))
}

// A function value given request data: its result counts as request data, whatever it does.
func ReportHandler(pick func(kind string) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// todook: go.path-traversal
		os.Open(filepath.Join(baseDir, pick(r.FormValue("kind"))))
	}
}

// Checks before the call: they are not followed, so the value checked is still reported.
func Checked(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !filepath.IsLocal(name) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	// todook: go.path-traversal
	os.Open(filepath.Join(baseDir, name))
	other := r.URL.Query().Get("other")
	if strings.Contains(other, "..") {
		return
	}
	// todook: go.path-traversal
	os.Open(filepath.Join(baseDir, other))
	checked := r.URL.Query().Get("checked")
	if !fs.ValidPath(checked) {
		return
	}
	// todook: go.path-traversal
	os.Open(filepath.Join(baseDir, checked))
	// path.Base splits on "/" only, so it is not counted as clean.
	// todook: go.path-traversal
	os.Open(filepath.Join(baseDir, path.Base(r.FormValue("slash"))))
	// Clean of a rooted path drops leading ".." elements, but Clean is not a sanitizer here.
	// todook: go.path-traversal
	os.Open(filepath.Join(baseDir, filepath.Clean("/"+r.FormValue("rooted"))))
}

// Routers on net/http: chi and gorilla/mux route variables.
func Attachment(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.path-traversal
	os.Open(filepath.Join(baseDir, chi.URLParam(r, "file")))
	vars := mux.Vars(r)
	// ruleid: go.path-traversal
	os.ReadFile(filepath.Join(baseDir, vars["folder"], vars["file"]))
	// ok: go.path-traversal
	os.ReadFile(filepath.Join(baseDir, filepath.Base(vars["file"])))
	fmt.Fprintln(w, "ok")
}

// JSON bodies decoded with encoding/json.
type Export struct {
	Path  string `json:"path" form:"path" query:"path"`
	Index int    `json:"index" form:"index" query:"index"`
}

func CreateExport(w http.ResponseWriter, r *http.Request) {
	var in Export
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return
	}
	// ruleid: go.path-traversal
	os.WriteFile(in.Path, []byte("export"), 0o644)
	// ok: go.path-traversal
	os.WriteFile(fmt.Sprintf("%s/export-%d.csv", baseDir, in.Index), []byte("export"), 0o644)
	fmt.Fprintln(w, "ok")
}

// Gin: path parameters, query strings, forms and bound bodies; c.File and c.FileAttachment.
func GinFiles(c *gin.Context) {
	// ruleid: go.path-traversal
	c.File(filepath.Join(baseDir, c.Param("name")))
	// ruleid: go.path-traversal
	c.FileAttachment(baseDir+"/"+c.Query("file"), "report.pdf")
	// ruleid: go.path-traversal
	os.Remove(filepath.Join(baseDir, c.PostForm("name")))
	var in Export
	if err := c.ShouldBindJSON(&in); err != nil {
		return
	}
	// ruleid: go.path-traversal
	os.ReadFile(in.Path)
	upload, err := c.FormFile("file")
	if err != nil {
		return
	}
	// ruleid: go.path-traversal
	c.SaveUploadedFile(upload, filepath.Join(baseDir, c.PostForm("folder"), upload.Filename))
	// ok: go.path-traversal
	c.SaveUploadedFile(upload, filepath.Join(baseDir, upload.Filename))
	// The request value only names the download.
	// ok: go.path-traversal
	c.FileAttachment(filepath.Join(baseDir, "report.pdf"), c.Query("name"))
	// ok: go.path-traversal
	c.File(filepath.Join(baseDir, filepath.Base(c.Param("name"))))
}

// Echo: path parameters, query parameters, form values and bound bodies; c.File,
// c.Attachment and c.Inline.
func EchoFiles(c echo.Context) error {
	export := new(Export)
	if err := c.Bind(export); err != nil {
		return err
	}
	// ruleid: go.path-traversal
	os.Remove(export.Path)
	// ruleid: go.path-traversal
	c.File(filepath.Join(baseDir, c.Param("name")))
	// ruleid: go.path-traversal
	c.Attachment(filepath.Join(baseDir, c.QueryParam("file")), "report.pdf")
	// ruleid: go.path-traversal
	c.Inline(filepath.Join(baseDir, c.FormValue("file")), "preview.pdf")
	var in Export
	if err := c.Bind(&in); err != nil {
		return err
	}
	// ruleid: go.path-traversal
	os.Open(in.Path)
	// ok: go.path-traversal
	c.Attachment(filepath.Join(baseDir, "report.pdf"), c.QueryParam("name"))
	// ok: go.path-traversal
	return c.File(filepath.Join(baseDir, filepath.Base(c.Param("name"))))
}

// Test support: a handler inside a function that takes a *testing.T, *testing.B, *testing.F,
// *testing.M or testing.TB serves only the requests of its own test (an httptest server, a
// subtest, TestMain), in a _test.go file or in a helper package.
func NewFixtureServer(t *testing.T, dir string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ok: go.path-traversal
		data, _ := os.ReadFile(filepath.Join(dir, r.URL.Path))
		w.Write(data)
	}))
}

func recordingServer(tb testing.TB, dir string) (*httptest.Server, error) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// ok: go.path-traversal
		os.WriteFile(filepath.Join(dir, r.Method+"-"+string(body)), body, 0o644)
	}))
	return srv, nil
}

func TestDownload(t *testing.T) {
	t.Run("served", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ok: go.path-traversal
			http.ServeFile(w, r, filepath.Join("testdata", r.FormValue("name")))
		}))
		defer srv.Close()
	})
}

func BenchmarkGinFiles(b *testing.B) {
	router := gin.New()
	router.GET("/files/:name", func(c *gin.Context) {
		// ok: go.path-traversal
		c.File(filepath.Join("testdata", c.Param("name")))
	})
}

func FuzzEchoFiles(f *testing.F) {
	e := echo.New()
	e.GET("/files/:name", func(c echo.Context) error {
		// ok: go.path-traversal
		return c.File(filepath.Join("testdata", c.Param("name")))
	})
}

var fixtureCase = func(t *testing.T) {
	http.HandleFunc("/cases/", func(w http.ResponseWriter, r *http.Request) {
		// ok: go.path-traversal
		os.Open(filepath.Join("testdata", r.FormValue("case")))
	})
}

func TestMain(m *testing.M) {
	http.HandleFunc("/fixtures/", func(w http.ResponseWriter, r *http.Request) {
		// ok: go.path-traversal
		http.ServeFile(w, r, filepath.Join("testdata", r.URL.Query().Get("name")))
	})
	os.Exit(m.Run())
}

type fixtureSuite struct{ root string }

func (s *fixtureSuite) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ok: go.path-traversal
		f, _ := os.Open(filepath.Join(s.root, r.URL.Query().Get("name")))
		defer f.Close()
	}
}

// The same handlers outside test support are reported: a parameter of another type named T, or
// a handler whose name starts with Test, is not a test.
type Theme struct{ T string }

func Preview(t *Theme, w http.ResponseWriter, r *http.Request) {
	// ruleid: go.path-traversal
	os.ReadFile(filepath.Join(baseDir, t.T, r.URL.Query().Get("name")))
}

func TestPage(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.path-traversal
	os.ReadFile(filepath.Join(baseDir, r.URL.Path))
}

func ServeFixtures(dir string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ruleid: go.path-traversal
		data, _ := os.ReadFile(filepath.Join(dir, r.URL.Path))
		w.Write(data)
	}))
}

// A handler declared at the top level of a test file, outside any function that takes a testing
// parameter, is still reported.
func fixtureHandler(w http.ResponseWriter, r *http.Request) {
	// todook: go.path-traversal
	os.ReadFile(filepath.Join("testdata", r.URL.Path))
}

func TestFixtureHandler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(fixtureHandler))
	defer srv.Close()
}

// Look-alikes: an Open method of another type, and a function that is not a handler.
type Store struct{}

func (Store) Open(name string) (io.ReadCloser, error) { return nil, nil }

func LookAlikes(w http.ResponseWriter, r *http.Request) {
	var store Store
	// ok: go.path-traversal
	store.Open(r.FormValue("key"))
	fmt.Fprintln(w, "ok")
}

func readConfig(name string) ([]byte, error) {
	// ok: go.path-traversal
	return os.ReadFile(filepath.Join("/etc/app", name))
}
