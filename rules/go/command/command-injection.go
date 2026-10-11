package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
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

// PowerShell's parameters (about_pwsh, any case): the command of -CommandWithArgs (-cwa), the
// script after -File (-f), and the first positional argument (pwsh's default parameter is File)
// run what the request sends. After -File or the command of -cwa every argument belongs to the
// script or fills $args, so a later -c is no PowerShell parameter.
func PowerShellParams(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.FormValue("q")
	// ruleid: go.command-injection
	exec.Command("pwsh", "-CommandWithArgs", "Get-Item "+q, "first").Run()
	// ruleid: go.command-injection
	exec.CommandContext(ctx, "pwsh.exe", "-cwa", q).Run()
	// ruleid: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-NoProfile", "-c", "Get-Item", q).Run()
	// ruleid: go.command-injection
	exec.Command("pwsh", "-File", q).Run()
	// ruleid: go.command-injection
	exec.CommandContext(ctx, "powershell.exe", "-f", q, "-Mode", "fast").Run()
	// A request value as the first positional argument: pwsh's script, or a command for
	// powershell.exe.
	// ruleid: go.command-injection
	exec.Command("pwsh", q).Run()
	// ruleid: go.command-injection
	exec.CommandContext(ctx, "powershell", r.URL.Query().Get("script")).Run()
	// ruleid: go.command-injection
	exec.Command("pwsh", "-NoProfile", "-NonInteractive", q).Run()
	// ruleid: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-nologo", q).Run()
	// ruleid: go.command-injection
	exec.Command("pwsh", "-ExecutionPolicy", "Bypass", q).Run()
	// ruleid: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-WorkingDirectory", "/srv", q).Run()
	// powershell.exe: -Version takes a value, and no default parameter is documented, so a first
	// argument that is no parameter name starts a command that the later arguments continue.
	// ruleid: go.command-injection
	exec.Command("powershell", "-Version", "2.0", q).Run()
	// ruleid: go.command-injection
	exec.CommandContext(ctx, "powershell.exe", "-version", "5.1", q).Run()
	// ruleid: go.command-injection
	exec.Command("powershell.exe", "Get-ChildItem", q).Run()
	// ruleid: go.command-injection
	exec.CommandContext(ctx, "powershell.exe", "report.ps1", q).Run()
	// ruleid: go.command-injection
	exec.Command("powershell.exe", "report.ps1", "-c", q).Run()
	// Parameters of the script, not of PowerShell.
	// ok: go.command-injection
	exec.Command("pwsh", "-File", "resize.ps1", "-c", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-f", "resize.ps1", "-Command", q).Run()
	// ok: go.command-injection
	exec.Command("pwsh", "-cwa", "Write-Output $args", "-c", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-CommandWithArgs", "Write-Output $args", q).Run()
	// ok: go.command-injection
	exec.Command("pwsh", "resize.ps1", "-c", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-NoProfile", "resize.ps1", "-File", q).Run()
	// ok: go.command-injection
	exec.Command("pwsh", "-NoProfile", "resize.ps1", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-NoProfile", "resize.ps1", q).Run()
	// pwsh's first argument that is no parameter name is the script, with or without .ps1.
	// ok: go.command-injection
	exec.Command("pwsh", "./deploy", "-i", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "./deploy", "-c", q).Run()
	// ok: go.command-injection
	exec.Command("pwsh", "./deploy", "-File", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "./deploy", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "./deploy", "-i", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "powershell.exe", "-File", "resize.ps1", "-c", q).Run()
	// ok: go.command-injection
	exec.Command("pwsh", "-NoProfile", "resize.ps1", "-c", q).Run()
	// ok: go.command-injection
	exec.Command("powershell", "-File", "resize.ps1", "-NoLogo", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "powershell.exe", "-File", "resize.ps1", "-NoLogo", q).Run()
	// ok: go.command-injection
	exec.Command("pwsh", "-cwa", "Write-Output $args", "-NoProfile", q).Run()
	// ok: go.command-injection
	exec.Command("pwsh", "-NoProfile", "resize.ps1", "-NoLogo", q).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-NoProfile", "resize.ps1", "-NoLogo", q).Run()
	// pwsh's -Version only prints the version.
	// ok: go.command-injection
	exec.Command("pwsh", "-Version", q).Run()
	// A script without .ps1 after pwsh's own switches is not recognised: the script's switch
	// reads as pwsh's.
	// todook: go.command-injection
	exec.Command("pwsh", "-NoProfile", "./deploy", "-i", q).Run()
	// A fixed script given the request value through an argument slice.
	fixed := []string{"-NoProfile", "-File", "resize.ps1", q}
	// ok: go.command-injection
	exec.Command("pwsh", fixed...).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "powershell.exe", fixed...).Run()
	rest := []string{"-File", "resize.ps1", q}
	// ok: go.command-injection
	exec.Command("pwsh", "-NoProfile", rest...).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "powershell.exe", "-ExecutionPolicy", "Bypass", rest...).Run()
	// A slice after -File or -cwa holds the script or command and its arguments; after -Command
	// it is the command.
	cmdArgs := []string{"Get-Item", q}
	// ok: go.command-injection
	exec.Command("pwsh", "-NoProfile", "-File", rest...).Run()
	// ok: go.command-injection
	exec.CommandContext(ctx, "pwsh", "-cwa", cmdArgs...).Run()
	// ruleid: go.command-injection
	exec.Command("pwsh", "-NoProfile", "-Command", cmdArgs...).Run()
	// The arguments given as a slice are not followed, as for the POSIX shells above.
	tail := []string{"-NoProfile", "-Command", "Get-Item " + q}
	// todoruleid: go.command-injection
	exec.Command("pwsh", tail...).Run()
	// A request value as the script, followed by a spread slice: calls that end in a spread are
	// left out as a whole.
	extra := []string{"-Verbose"}
	// todoruleid: go.command-injection
	exec.Command("pwsh", q, extra...).Run()
	// todoruleid: go.command-injection
	exec.Command("powershell.exe", q, extra...).Run()
	// powershell.exe: a positional argument after its switches is not followed.
	// todoruleid: go.command-injection
	exec.Command("powershell.exe", "-NoProfile", "Get-ChildItem", q).Run()
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

// A bind or decode call inside a condition (`if c.ShouldBindJSON(&in) == nil`) fills the struct
// with request data like the `err :=` form. A bound value used only in a comparison does not
// taint what the branch chooses.
type ScriptInput struct {
	Script string   `json:"script" query:"script"`
	Dir    string   `json:"dir" query:"dir"`
	Mode   string   `json:"mode" query:"mode"`
	Tags   []string `json:"tags" query:"tags"`
}

func GinBindInCondition(c *gin.Context) {
	var in ScriptInput
	if c.ShouldBindJSON(&in) == nil {
		// ruleid: go.command-injection
		exec.Command("sh", "-c", in.Script).Run()
	}
	var query ScriptInput
	if c.ShouldBindQuery(&query) != nil {
		return
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "du -sh "+query.Dir).Output()
	target := new(ScriptInput)
	if c.ShouldBind(target) == nil && target.Dir != "" {
		// ruleid: go.command-injection
		exec.Command("bash", "-c", "ls "+target.Dir).Output()
	}
	var strict ScriptInput
	if errors.Is(c.ShouldBindJSON(&strict), io.EOF) {
		return
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", strict.Script).Run()
	var empty ScriptInput
	if c.ShouldBindJSON(&empty) == io.EOF {
		return
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", empty.Script).Run()
	var forced ScriptInput
	if c.MustBindWith(&forced, binding.JSON) != nil {
		return
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", forced.Script).Run()
	// The bound values only compared: the branches choose constants.
	tool := "gzip"
	if query.Mode == "xz" {
		tool = "xz"
	}
	// ok: go.command-injection
	exec.Command("sh", "-c", tool+" backup.tar").Run()
	verbose := in.Mode == "verbose" && in.Script != ""
	// ok: go.command-injection
	exec.Command("sh", "-c", map[bool]string{true: "make V=1", false: "make"}[verbose]).Run()
	tagged := in.Tags != nil
	// ok: go.command-injection
	exec.Command("sh", "-c", "echo tagged="+strconv.FormatBool(tagged)).Run()
	switch query.Mode {
	case "xz":
		// ok: go.command-injection
		exec.Command("sh", "-c", "xz backup.tar").Run()
	}
	// Other comparisons with nil, and calls that fill a variable, stay booleans.
	multi := c.QueryArray("file") != nil
	// ok: go.command-injection
	exec.Command("sh", "-c", "echo multi="+strconv.FormatBool(multi)).Run()
	raw, _ := c.GetRawData()
	var level uint32
	known := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &level) == nil
	// ok: go.command-injection
	exec.Command("sh", "-c", fmt.Sprintf("echo known=%t", known)).Run()
	// The success flag of a bind call is reported: the comparison holds the bind call, and
	// the call's result counts as request data.
	var draft ScriptInput
	parsed := c.ShouldBindJSON(&draft) == nil
	// todook: go.command-injection
	exec.Command("sh", "-c", fmt.Sprintf("echo valid=%t", parsed)).Run()
}

func EchoBindInCondition(c echo.Context) error {
	var in ScriptInput
	if c.Bind(&in) != nil {
		return nil
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", in.Script).Run()
	var filter ScriptInput
	if echo.BindQueryParams(c, &filter) == nil {
		// ruleid: go.command-injection
		exec.Command("bash", "-c", "ls "+filter.Dir).Output()
	}
	order := "-t"
	if filter.Mode == "name" {
		order = "-1"
	}
	// ok: go.command-injection
	exec.Command("sh", "-c", "ls "+order).Output()
	return nil
}

func DecodeInCondition(w http.ResponseWriter, r *http.Request) {
	var in ScriptInput
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		return
	}
	// ruleid: go.command-injection
	exec.Command("sh", "-c", in.Script).Run()
	body, _ := io.ReadAll(r.Body)
	var sub ScriptInput
	if json.Unmarshal(body, &sub) == nil {
		// ruleid: go.command-injection
		exec.Command("sh", "-c", sub.Script).Run()
	}
	dry := in.Mode == "dry-run"
	// ok: go.command-injection
	exec.Command("sh", "-c", fmt.Sprintf("deploy --dry-run=%t", dry)).Run()
}

// A sink called inside a comparison (`if exec.Command(...).Run() != nil`) is a boolean
// expression as a whole: the number/boolean sanitizer clears it, the sink's arguments included.
func GinSinkInComparison(c *gin.Context) {
	// todoruleid: go.command-injection
	if exec.Command("sh", "-c", "tar xf "+c.Query("archive")).Run() != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	// todoruleid: go.command-injection
	reachable := exec.Command("bash", "-c", "ping -c 1 "+c.Param("host")).Run() == nil
	if !reachable {
		c.Status(http.StatusBadGateway)
	}
}

func retryUntil(done func() bool) {}

func RetryProbe(w http.ResponseWriter, r *http.Request) {
	retryUntil(func() bool {
		// todoruleid: go.command-injection
		return exec.Command("sh", "-c", r.FormValue("probe")).Run() == nil
	})
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

// Test support: a handler inside a function that takes a *testing.T, *testing.B, *testing.F,
// *testing.M or testing.TB serves only the requests of its own test (an httptest server, a
// subtest, TestMain), in a _test.go file or in a helper package.
func NewFixtureServer(t *testing.T, dir string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ok: go.command-injection
		out, _ := exec.Command("sh", "-c", "cat "+dir+r.URL.Path).Output()
		w.Write(out)
	}))
}

func recordingServer(tb testing.TB, dir string) (*httptest.Server, error) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// ok: go.command-injection
		exec.Command("sh", "-c", "echo "+r.Method+" "+string(body)+" >> "+dir+"/requests.log").Run()
	}))
	return srv, nil
}

func TestThumbnail(t *testing.T) {
	t.Run("served", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ok: go.command-injection
			exec.Command("bash", "-c", "convert "+r.FormValue("name")+" thumb.png").Run()
		}))
		defer srv.Close()
	})
}

func BenchmarkGinTools(b *testing.B) {
	router := gin.New()
	router.GET("/tools/:tool", func(c *gin.Context) {
		// ok: go.command-injection
		exec.Command(c.Param("tool"), "--version").Run()
	})
}

func FuzzEchoTools(f *testing.F) {
	e := echo.New()
	e.GET("/usage/:dir", func(c echo.Context) error {
		// ok: go.command-injection
		return exec.Command("sh", "-c", "du -sh testdata/"+c.Param("dir")).Run()
	})
}

var fixtureCase = func(t *testing.T) {
	http.HandleFunc("/cases/", func(w http.ResponseWriter, r *http.Request) {
		// ok: go.command-injection
		exec.Command("cmd", "/C", "type testdata\\"+r.FormValue("case")).Run()
	})
}

func TestMain(m *testing.M) {
	http.HandleFunc("/fixtures/", func(w http.ResponseWriter, r *http.Request) {
		// ok: go.command-injection
		exec.CommandContext(r.Context(), "sh", "-c", "ls testdata/"+r.URL.Query().Get("dir")).Run()
	})
	os.Exit(m.Run())
}

type fixtureSuite struct{ root string }

func (s *fixtureSuite) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ok: go.command-injection
		out, _ := exec.Command("sh", "-c", "cat "+s.root+"/"+r.URL.Query().Get("name")).Output()
		w.Write(out)
	}
}

// The same handlers outside test support are reported: a parameter of another type named T, or
// a handler whose name starts with Test, is not a test.
type Theme struct{ T string }

func Preview(t *Theme, w http.ResponseWriter, r *http.Request) {
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "render "+t.T+" "+r.URL.Query().Get("name")).Run()
}

func TestPage(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.command-injection
	exec.Command("sh", "-c", "cat pages"+r.URL.Path).Run()
}

func ServeFixtures(dir string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ruleid: go.command-injection
		out, _ := exec.Command("sh", "-c", "cat "+dir+r.URL.Path).Output()
		w.Write(out)
	}))
}

// A handler declared at the top level of a test file, outside any function that takes a testing
// parameter, is still reported.
func fixtureHandler(w http.ResponseWriter, r *http.Request) {
	// todook: go.command-injection
	exec.Command("sh", "-c", "cat testdata"+r.URL.Path).Run()
}

func TestFixtureHandler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(fixtureHandler))
	defer srv.Close()
}
