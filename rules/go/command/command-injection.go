package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
	"golang.org/x/text/encoding/unicode"
)

// net/http: request data in a shell script, or choosing the program to run.
func Thumbnail(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "convert "+name+" thumb.png").Run()
	// ruleid: go.command-injection
	exec.Command("/bin/bash", "-c", fmt.Sprintf("du -sh %s", r.FormValue("dir"))).Output()
	script := "tar czf backup.tgz " + r.PostFormValue("folder")
	// ruleid: go.command-injection
	exec.CommandContext(r.Context(), "bash", "-lc", script).Run()
	// ruleid: go.command-injection
	exec.Command("cmd", "/C", "type "+r.PathValue("file")).Output()
	// ruleid: go.command-injection
	exec.Command("cmd.exe", "/c", "ping "+r.Header.Get("X-Host")).Run()
	// cmd.exe reads the whole rest of its command line after /C, not only the next argument.
	// ruleid: go.command-injection
	exec.Command("cmd", "/C", "ping", r.FormValue("host")).Run()
	// ruleid: go.command-injection
	exec.Command("C:\Windows\System32\cmd.exe", "/d", "/s", "/c", "dir "+name).Run()
	// ruleid: go.command-injection
	exec.Command("powershell", "-NoProfile", "-Command", "Get-Item "+name).Run()
	// ruleid: go.command-injection
	exec.Command("pwsh", "-c", "Get-Content", name).Run()
	// ruleid: go.command-injection
	exec.Command("/usr/bin/env", "bash", "-c", "wc -l "+name).Run()
	// ruleid: go.command-injection
	exec.Command("bash", "-e", "-c", "wc -l "+name).Run()
	tool := r.FormValue("tool")
	// ruleid: go.command-injection
	exec.Command(tool, "--version").Output()
	// ruleid: go.command-injection
	exec.CommandContext(r.Context(), r.URL.Query().Get("bin")).Run()
	line := r.FormValue("line")
	parts := strings.Fields(line)
	// ruleid: go.command-injection
	exec.Command(parts[0], parts[1:]...).Run()
	// The request data is a separate argument of a fixed program: no shell parses it.
	// ok: go.command-injection
	exec.Command("convert", name, "thumb.png").Run()
	// ok: go.command-injection
	exec.CommandContext(r.Context(), "git", "log", "--", r.FormValue("path")).Output()
	// A constant script that reads the request data as a positional parameter ($1).
	// ok: go.command-injection
	exec.Command("sh", "-c", `convert "$1" thumb.png`, "sh", name).Run()
	// ok: go.command-injection
	exec.Command("sh", "-c", "df -h /var").Output()
	// The shell's name held in a variable.
	shell := "/bin/sh"
	// ruleid: go.command-injection
	exec.Command(shell, "-c", "convert "+name+" thumb.png").Run()
	// A PowerShell script file with the request data as its parameter.
	// ok: go.command-injection
	exec.Command("pwsh", "-File", "resize.ps1", name).Run()
	// The arguments given as a slice are not followed.
	args := []string{"-c", "convert " + name + " thumb.png"}
	// todoruleid: go.command-injection
	exec.Command("sh", args...).Run()
	// A batch file runs through cmd.exe, which parses its arguments again; not followed.
	// todoruleid: go.command-injection
	exec.Command("report.bat", name).Run()
	// Request data as standard input, working directory or environment, not as a command.
	cmd := exec.Command("wc", "-l")
	cmd.Stdin = strings.NewReader(r.FormValue("text"))
	// ok: go.command-injection
	cmd.Run()
	fmt.Fprintln(w, "ok")
}

// PowerShell -EncodedCommand (-e, -ec, any case): the argument after it is the command, as
// Base64 of UTF-16LE text, so request data there, or a script built from it and then encoded,
// runs as PowerShell code.
func Encoded(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.command-injection
	exec.Command("powershell.exe", "-NoProfile", "-EncodedCommand", r.FormValue("cmd")).Run()
	// ruleid: go.command-injection
	exec.Command("pwsh", "-e", r.Header.Get("X-Job")).Run()
	// ruleid: go.command-injection
	exec.CommandContext(r.Context(), "/usr/bin/pwsh", "-NonInteractive", "-ec", r.FormValue("job")).Run()
	// ruleid: go.command-injection
	exec.Command("PowerShell", "-encodedcommand", toPowerShellBase64("Get-Item "+r.FormValue("name"))).Run()
	script := "Get-ChildItem " + r.FormValue("dir")
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	// ruleid: go.command-injection
	exec.Command("pwsh", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)).Run()
	utf16le, _ := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().String("Stop-Service " + r.FormValue("svc"))
	// ruleid: go.command-injection
	exec.Command("pwsh", "-EC", base64.StdEncoding.EncodeToString([]byte(utf16le))).Run()
	// Base64 of request data handed to a shell that decodes and runs it.
	payload := base64.StdEncoding.EncodeToString([]byte(r.FormValue("cmd")))
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "echo "+payload+" | base64 -d | sh").Run()
	// ruleid: go.command-injection
	exec.Command("powershell", "-Command", "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+payload+"')))").Run()
	// A fixed encoded command.
	// ok: go.command-injection
	exec.Command("pwsh", "-NoProfile", "-EncodedCommand", "RwBlAHQALQBEAGEAdABlAA==").Run()
	// ok: go.command-injection
	exec.Command("pwsh", "-EncodedCommand", toPowerShellBase64("Get-Date")).Run()
	// -e after -File is a parameter of the script, and its value is passed as a literal string.
	// ok: go.command-injection
	exec.Command("pwsh", "-File", "deploy.ps1", "-e", r.FormValue("env")).Run()
	// The script path given without -File: File is pwsh's default parameter.
	// ok: go.command-injection
	exec.CommandContext(r.Context(), "pwsh", "-NoProfile", "rotate.ps1", "-e", r.FormValue("stage")).Run()
	// Other options of PowerShell take request data as a value, not as code.
	// ok: go.command-injection
	exec.Command("pwsh", "-NoProfile", "-ExecutionPolicy", r.FormValue("policy"), "-File", "job.ps1").Run()
	// Base64 text has no shell syntax: decoded into a file, it is not run. Not told apart.
	// todook: go.command-injection
	exec.Command("sh", "-c", "echo "+payload+" | base64 -d > upload.bin").Run()
	// Prefixes of -EncodedCommand other than the documented -e and -ec (such as -enc) are not
	// followed: the PowerShell docs do not describe them.
	// todoruleid: go.command-injection
	exec.Command("powershell", "-enc", r.FormValue("cmd")).Run()
	fmt.Fprintln(w, "ok")
}

// toPowerShellBase64 encodes a script for -EncodedCommand: Base64 of its UTF-16LE text.
func toPowerShellBase64(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// Numbers, allow-lists and constants.
func Ping(w http.ResponseWriter, r *http.Request) {
	count, err := strconv.Atoi(r.FormValue("count"))
	if err != nil {
		return
	}
	// ok: go.command-injection
	exec.Command("sh", "-c", fmt.Sprintf("ping -c %d localhost", count)).Run()
	var program string
	switch r.FormValue("format") {
	case "png":
		program = "optipng"
	case "jpeg":
		program = "jpegoptim"
	default:
		return
	}
	// ok: go.command-injection
	exec.Command(program, "image").Run()
	optimizers := map[string]string{"png": "optipng", "jpeg": "jpegoptim"}
	chosen, found := optimizers[r.FormValue("format")]
	if !found {
		return
	}
	// ok: go.command-injection
	exec.Command(chosen, "image").Run()
	// An allow-list check followed by the request value itself: the check is not followed.
	viewer := r.FormValue("viewer")
	if viewer != "less" && viewer != "more" {
		return
	}
	// todook: go.command-injection
	exec.Command(viewer, "notes.txt").Run()
	fmt.Fprintln(w, "ok")
}

// Scripts built with a strings.Builder or a bytes.Buffer.
func Archive(w http.ResponseWriter, r *http.Request) {
	var sb strings.Builder
	sb.WriteString("zip -r out.zip ")
	sb.WriteString(r.FormValue("dir"))
	// ruleid: go.command-injection
	exec.Command("sh", "-c", sb.String()).Run()
	var buf bytes.Buffer
	buf.WriteString("ls ")
	buf.WriteString(r.URL.Query().Get("dir"))
	// ruleid: go.command-injection
	exec.Command("sh", "-c", buf.String()).Run()
	var fixed strings.Builder
	fixed.WriteString("ls /tmp")
	// ok: go.command-injection
	exec.Command("sh", "-c", fixed.String()).Run()
	fmt.Fprintln(w, "ok")
}

// A Cmd built as a struct literal: Path names the program.
func Run(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.command-injection
	c := &exec.Cmd{Path: r.FormValue("path"), Args: []string{"x"}}
	c.Run()
	// ok: go.command-injection
	d := &exec.Cmd{Path: "/usr/bin/uptime", Args: []string{"uptime", r.FormValue("flag")}}
	d.Run()
	// The lower-level os.StartProcess and syscall.Exec are not followed yet.
	// todoruleid: go.command-injection
	os.StartProcess(r.FormValue("path"), []string{"x"}, &os.ProcAttr{})
	fmt.Fprintln(w, "ok")
}

// Routers on net/http: chi and gorilla/mux route variables.
func Service(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "systemctl status "+chi.URLParam(r, "unit")).Output()
	vars := mux.Vars(r)
	// ruleid: go.command-injection
	exec.Command("bash", "-c", "journalctl -u "+vars["unit"]).Output()
	// ok: go.command-injection
	exec.Command("systemctl", "status", vars["unit"]).Output()
	fmt.Fprintln(w, "ok")
}

// JSON bodies decoded with encoding/json.
type Job struct {
	Script  string `json:"script" form:"script" query:"script"`
	Retries int    `json:"retries" form:"retries" query:"retries"`
}

func CreateJob(w http.ResponseWriter, r *http.Request) {
	var job Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		return
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", job.Script).Run()
	// ok: go.command-injection
	exec.Command("sh", "-c", fmt.Sprintf("retry %d", job.Retries)).Run()
	fmt.Fprintln(w, "ok")
}

// Gin: path parameters, query strings, forms, headers and bound bodies.
func GinTools(c *gin.Context) {
	queued := &Job{}
	if err := c.ShouldBindJSON(queued); err != nil {
		return
	}
	// ruleid: go.command-injection
	exec.Command("bash", "-c", queued.Script).Run()
	// ok: go.command-injection
	exec.Command("sh", "-c", fmt.Sprintf("retry %d", queued.Retries)).Run()
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "nslookup "+c.Param("host")).Output()
	// ruleid: go.command-injection
	exec.Command("bash", "-c", fmt.Sprintf("whois %s", c.Query("domain"))).Output()
	// ruleid: go.command-injection
	exec.Command(c.PostForm("program")).Run()
	// ruleid: go.command-injection
	exec.CommandContext(c.Request.Context(), "sh", "-c", "echo "+c.GetHeader("X-Note")).Run()
	var job Job
	if err := c.ShouldBindJSON(&job); err != nil {
		return
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", job.Script).Run()
	// ok: go.command-injection
	exec.Command("nslookup", c.Param("host")).Output()
	c.String(http.StatusOK, "ok")
}

// Echo: path parameters, query parameters, form values and bound bodies.
func EchoTools(c echo.Context) error {
	job := new(Job)
	if err := c.Bind(job); err != nil {
		return err
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", job.Script).Run()
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "dig "+c.Param("host")).Output()
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "host "+c.QueryParam("name")).Output()
	// ruleid: go.command-injection
	exec.Command(c.FormValue("program"), "-h").Run()
	var job Job
	if err := c.Bind(&job); err != nil {
		return err
	}
	// ruleid: go.command-injection
	exec.CommandContext(c.Request().Context(), "sh", "-c", job.Script).Run()
	// ok: go.command-injection
	exec.Command("dig", c.Param("host")).Output()
	return c.String(http.StatusOK, "ok")
}

// Look-alikes: a Command method of another type, and a function that is not a handler.
type Runner struct{}

func (Runner) Command(name string, args ...string) *exec.Cmd { return nil }

func LookAlikes(w http.ResponseWriter, r *http.Request) {
	var runner Runner
	// ok: go.command-injection
	runner.Command(r.FormValue("program"))
	fmt.Fprintln(w, "ok")
}

func runScript(ctx context.Context, script string) error {
	// ok: go.command-injection
	return exec.CommandContext(ctx, "sh", "-c", script).Run()
}
