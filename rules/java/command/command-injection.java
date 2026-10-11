package com.acme.ops;

import java.util.Optional;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.RequestEntity;
import org.springframework.http.HttpEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;

// An enum declared before the first class (the shared enum allow-list forms).
enum EarlierKind {
    ONE, TWO
}

// Servlet: Runtime.exec with a command string, shells, a program chosen by the request, the
// environment of the new process.
public class DiagnosticsServlet extends HttpServlet {
    private CommandBus bus;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("host");
        Runtime runtime = Runtime.getRuntime();
        // ruleid: java.command-injection
        runtime.exec("ping -c 1 " + host);
        String lookup = "nslookup " + request.getHeader("X-Domain");
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(lookup);
        // ruleid: java.command-injection
        runtime.exec(String.format("traceroute %s", host), null, new File("/tmp"));
        // ruleid: java.command-injection
        runtime.exec(new String[] {"sh", "-c", "ping -c 1 " + host});
        // ruleid: java.command-injection
        runtime.exec(new String[] {request.getParameter("tool"), "--version"});
        // ruleid: java.command-injection
        String[] shell = {"/bin/bash", "-c", "dig " + host};
        runtime.exec(shell);
        // ruleid: java.command-injection
        runtime.exec(new String[] {"printenv"}, new String[] {request.getParameter("env")});
        // ruleid: java.command-injection
        String[] env = {request.getQueryString()};
        runtime.exec("printenv", env);
        // ruleid: java.command-injection
        String[] probe = {request.getParameter("probe"), "-h"};
        Process started = runtime.exec(probe);

        // ok: java.command-injection
        runtime.exec(new String[] {"ping", "-c", "1", host});
        String[] fixed = {"dig", "+short", host};
        // ok: java.command-injection
        runtime.exec(fixed);
        // ok: java.command-injection
        runtime.exec("uptime");
        // ok: java.command-injection
        runtime.exec("ping -c " + Integer.parseInt(request.getParameter("count")) + " localhost");
        String tool = "disk".equals(request.getParameter("check")) ? "df -h" : "free -m";
        // ok: java.command-injection
        runtime.exec(tool);
        // ok: java.command-injection
        runtime.exec(new String[] {"printenv"}, new String[] {"GREETING=" + host});
        // ok: java.command-injection
        bus.exec("ping " + host);
    }
}

// Servlet: ProcessBuilder with a shell, a program from the request, a command list.
class BackupServlet extends HttpServlet {
    private final ArgumentLists lists = new ArgumentLists();

    private List<String> archiveList(String value) {
        return List.of("tar", "tf", value);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        // ruleid: java.command-injection
        new ProcessBuilder("bash", "-c", "tar czf /backups/" + name + ".tgz /data").start();
        // ruleid: java.command-injection
        new ProcessBuilder(request.getParameter("archiver"), "-r", "out.zip", "data").start();
        ProcessBuilder builder = new ProcessBuilder();
        // ruleid: java.command-injection
        builder.command("cmd.exe", "/c", "dir " + name);
        // ruleid: java.command-injection
        new ProcessBuilder(List.of("/bin/sh", "-c", "ls " + name)).start();
        // ruleid: java.command-injection
        new ProcessBuilder(Arrays.asList(request.getParameter("program"), "-v")).start();
        // ruleid: java.command-injection
        new ProcessBuilder(request.getParameter("commandLine").split(" ")).start();
        List<String> command = new ArrayList<>();
        command.add("sh");
        command.add("-c");
        // ruleid: java.command-injection
        command.add("du -sh " + name);
        new ProcessBuilder(command).start();
        ProcessBuilder withEnv = new ProcessBuilder("printenv");
        // ruleid: java.command-injection
        withEnv.environment().put(request.getParameter("var"), "1");

        // ok: java.command-injection
        new ProcessBuilder("tar", "czf", "/backups/" + name + ".tgz", "/data").start();
        // ok: java.command-injection
        new ProcessBuilder(List.of("ls", "-l", name)).start();
        // ok: java.command-injection
        builder.command("git", "log", "--", name);
        List<String> safe = new ArrayList<>();
        safe.add("du");
        safe.add("-sh");
        // ok: java.command-injection
        safe.add(name);
        // ok: java.command-injection
        new ProcessBuilder(safe).start();
        // ok: java.command-injection
        withEnv.environment().put("BACKUP_NAME", name);
        // ok: java.command-injection
        new ProcessBuilder("sh", "-c", "tar czf /backups/daily.tgz /data").start();
        // A fixed script gets the request data only as a positional parameter ($1).
        // ok: java.command-injection
        new ProcessBuilder("sh", "-c", "tar czf \"/backups/$1.tgz\" /data", "backup", name).start();
        // ok: java.command-injection
        new ProcessBuilder("/bin/bash", "/opt/scripts/backup.sh", name).start();

        // A fixed program with the request data as separate arguments, in a list variable.
        List<String> fixedList = List.of("rsync", "-a", name, "/backups/");
        // ok: java.command-injection
        new ProcessBuilder(fixedList).start();
        List<String> asList = Arrays.asList("zip", "-r", name + ".zip", "data");
        // ok: java.command-injection
        new ProcessBuilder(asList).start();
        List<String> copied = new ArrayList<>(List.of("unzip", "-o", name));
        // ok: java.command-injection
        builder.command(copied);
        // ok: java.command-injection
        new ProcessBuilder(ArgumentLists.build(name)).start();
        // ruleid: java.command-injection
        List<String> chosenProgram = List.of(request.getParameter("tool"), "--help");
        new ProcessBuilder(chosenProgram).start();
        // ruleid: java.command-injection
        List<String> argv = Arrays.asList(request.getParameterValues("argv"));
        new ProcessBuilder(argv).start();

        // The environment: a fixed name with a request value is accepted, except for variables
        // that decide what runs.
        String query = "QUERY=" + name;
        // ok: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {query});
        // ok: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {String.format("QUERY=%s", name)});
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {"PATH=" + name});
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {String.format("LD_PRELOAD=%s", name)});
        String chosenEntry = request.getParameter("entry");
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {chosenEntry});
        String searchPath = "PATH=" + name;
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {searchPath});
        String bare = "" + name;
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {bare});
        String formatted = String.format("%s", name);
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {formatted});
        String fixedName = String.format("QUERY=%s", name);
        // ok: java.command-injection
        Runtime.getRuntime().exec(new String[] {"report"}, new String[] {fixedName});

        // A whole argument vector from the request: the request chooses the program.
        // ruleid: java.command-injection
        new ProcessBuilder(request.getParameterValues("argv")).start();
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(request.getParameterValues("argv"));
        var splitLine = request.getParameter("line").split(" ");
        // ruleid: java.command-injection
        new ProcessBuilder(splitLine).start();
        String[] splitWords = request.getParameter("line").split(" ");
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(splitWords);
        // ok: java.command-injection
        new ProcessBuilder("git status --short".split(" ")).start();
        // cmd.exe and PowerShell join every argument after the flag into the command.
        // ruleid: java.command-injection
        new ProcessBuilder("cmd.exe", "/c", "type", name).start();
        // ruleid: java.command-injection
        new ProcessBuilder("pwsh", "-Command", "Get-Content", name).start();
        // A POSIX shell runs only the script after -c; later elements are positional parameters.
        // ok: java.command-injection
        new ProcessBuilder("sh", "-c", "cat -- \"$1\"", "cat", name).start();
        // ok: java.command-injection
        new ProcessBuilder("bash", "-l", "/opt/scripts/backup.sh", name).start();
        // Request values joined into a line and split.
        String[] joined = String.join(" ", request.getParameterValues("words")).split(" ");
        // ruleid: java.command-injection
        new ProcessBuilder(joined).start();
        // Argument lists the method builds in other forms, and helpers on this or on a field.
        // ok: java.command-injection
        new ProcessBuilder(this.archiveList(name)).start();
        // ok: java.command-injection
        new ProcessBuilder(lists.forArchive(name)).start();
        List<String> streamed = java.util.stream.Stream.of("tar", "tf", name).collect(java.util.stream.Collectors.toList());
        // ok: java.command-injection
        new ProcessBuilder(streamed).start();
        List<String> typedCopy = new ArrayList<String>(List.of("tar", "tf", name));
        // ok: java.command-injection
        new ProcessBuilder(typedCopy).start();
        List<String> copiedOf = List.copyOf(List.of("tar", "tf", name));
        // ok: java.command-injection
        new ProcessBuilder(copiedOf).start();
        String[] branchBuilt;
        if (name.isEmpty()) {
            branchBuilt = new String[] {"ls"};
        } else {
            branchBuilt = new String[] {"ls", "--", name};
        }
        // ok: java.command-injection
        Runtime.getRuntime().exec(branchBuilt);
        List<String> grepArgs = List.of("grep", "-F", "--", name, "/var/log/app.log");
        // ok: java.command-injection
        Runtime.getRuntime().exec(grepArgs.toArray(new String[0]));
        // A shell with options before its flag.
        // ruleid: java.command-injection
        new ProcessBuilder("bash", "-l", "-c", "ls " + name).start();
        // ruleid: java.command-injection
        new ProcessBuilder("powershell.exe", "-NoProfile", "-Command", "Get-Item " + name).start();
        // ruleid: java.command-injection
        withEnv.environment().put("PATH", name);
        // ok: java.command-injection
        withEnv.environment().put("BACKUP_LABEL", name);
    }
}

// Servlet: the shell picked by operating system in an if/else, into a list or into variables.
class ReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String folder = request.getParameter("folder");
        List<String> listing = new ArrayList<>();
        if (System.getProperty("os.name").startsWith("Windows")) {
            listing.add("cmd.exe");
            listing.add("/c");
        } else {
            listing.add("sh");
            listing.add("-c");
        }
        // ruleid: java.command-injection
        listing.add("ls " + folder);
        new ProcessBuilder(listing).start();

        String program;
        String option;
        if (System.getProperty("os.name").startsWith("Windows")) {
            program = "cmd.exe";
            option = "/c";
        } else {
            program = "/bin/sh";
            option = "-c";
        }
        // ruleid: java.command-injection
        String[] script = {program, option, "wc -l " + folder};
        new ProcessBuilder(script).start();
        // ruleid: java.command-injection
        new ProcessBuilder(program, option, "du -sh " + folder).start();

        String counter = "wc";
        // ok: java.command-injection
        new ProcessBuilder(counter, "-l", folder).start();
        // ok: java.command-injection
        String[] counted = {counter, "-c", folder};
        new ProcessBuilder(counted).start();
    }
}

// Spring MVC: path variables, request parameters and bodies.
@RestController
class ToolController {
    @GetMapping("/tools/{tool}")
    String run(@PathVariable String tool, @RequestParam String target, @RequestParam int count) throws IOException {
        // ruleid: java.command-injection
        new ProcessBuilder(tool, target).start();
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 3 " + target);
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c " + count + " localhost");
        // ok: java.command-injection
        new ProcessBuilder("ping", "-c", "3", target).start();
        return "ok";
    }

    @PostMapping("/jobs/argv")
    String argv(@RequestBody JobForm form, @RequestParam List<String> args) throws IOException {
        // A body field and a list parameter passed whole.
        // ruleid: java.command-injection
        new ProcessBuilder(form.getArguments()).start();
        // ruleid: java.command-injection
        new ProcessBuilder(args).start();
        return "ok";
    }

    @PostMapping("/jobs/parts")
    String parts(@RequestPart("argv") List<String> argv) throws IOException {
        // A list part passed whole.
        // ruleid: java.command-injection
        new ProcessBuilder(argv).start();
        return "ok";
    }

    @PostMapping("/jobs/arrays")
    String arrays(@RequestParam("argv") String[] argv, @RequestPart("steps") String[] steps) throws IOException {
        // An array parameter handed to Runtime.exec as it is.
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(argv);
        Runtime runtime = Runtime.getRuntime();
        // ruleid: java.command-injection
        runtime.exec(steps, new String[] {"LANG=C"});
        // A fixed program with an element of the array as its argument.
        // ok: java.command-injection
        Runtime.getRuntime().exec(new String[] {"echo", argv[0]});
        return "ok";
    }

    @PostMapping("/jobs/entities")
    String entities(RequestEntity<List<String>> request, HttpEntity<String[]> entity) throws IOException {
        // A decoded JSON array in the request body, passed whole.
        // ruleid: java.command-injection
        new ProcessBuilder(request.getBody()).start();
        ProcessBuilder builder = new ProcessBuilder();
        // ruleid: java.command-injection
        builder.command(request.getBody());
        Runtime runtime = Runtime.getRuntime();
        // ruleid: java.command-injection
        runtime.exec(entity.getBody());
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(entity.getBody());
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(request.getBody().toArray(new String[0]));
        // ok: java.command-injection
        new ProcessBuilder("echo", request.getBody().get(0)).start();
        return "ok";
    }

    // A request vector passed whole through a variable or a copy is not followed.
    @PostMapping("/jobs/held")
    String held(RequestEntity<List<String>> request, @RequestBody List<String> argv) throws IOException {
        List<String> fromBody = request.getBody();
        // todoruleid: java.command-injection
        new ProcessBuilder(fromBody).start();
        // todoruleid: java.command-injection
        new ProcessBuilder(new ArrayList<>(request.getBody())).start();
        List<String> bound = argv;
        // todoruleid: java.command-injection
        new ProcessBuilder(bound).start();
        return "ok";
    }

    @PostMapping("/jobs")
    String job(@RequestBody JobForm form) throws IOException {
        // ruleid: java.command-injection
        new ProcessBuilder("sh", "-c", form.getScript()).start();
        // ok: java.command-injection
        new ProcessBuilder("convert", form.getScript(), "out.png").start();
        return "ok";
    }
}

class JobForm {
    private String script;
    private List<String> arguments;

    List<String> getArguments() {
        return arguments;
    }

    String getScript() {
        return script;
    }
}

// Jakarta REST: path, query and header parameters.
@Path("/hosts")
class HostResource {
    @GET
    @Path("/{name}")
    public String check(@PathParam("name") String name, @QueryParam("port") String port,
            @HeaderParam("X-Shell") String shellName) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("nc -z " + name + " " + port);
        // ruleid: java.command-injection
        new ProcessBuilder(shellName, "-c", "true").start();
        // ok: java.command-injection
        new ProcessBuilder("nc", "-z", name, port).start();
        return "ok";
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    public String create(JobForm form) throws IOException {
        // todoruleid: java.command-injection
        Runtime.getRuntime().exec("sh " + form.getScript());
        return "ok";
    }
}

// Limits of the patterns.
class LimitsServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String file = request.getParameter("file");
        // A list filled with add, the request value first (the program).
        List<String> addedFirst = new ArrayList<>();
        addedFirst.add(file);
        addedFirst.add("--version");
        // todoruleid: java.command-injection
        new ProcessBuilder(addedFirst).start();
        // A shell put into an array element by element.
        String[] byElement = new String[3];
        byElement[0] = "/bin/sh";
        byElement[1] = "-c";
        // todoruleid: java.command-injection
        byElement[2] = "cat " + file;
        Runtime.getRuntime().exec(byElement);
        // A list copied from a fixed shell prefix, then given the script.
        List<String> prefixed = new ArrayList<>(Arrays.asList("bash", "-c"));
        // todoruleid: java.command-injection
        prefixed.add("cat " + file);
        new ProcessBuilder(prefixed).start();
        // In a list that gets a shell added, a positional parameter after a fixed script still
        // counts as shell code.
        List<String> positional = new ArrayList<>();
        positional.add("sh");
        positional.add("-c");
        positional.add("cat -- \"$1\"");
        positional.add("cat");
        // todook: java.command-injection
        positional.add(file);
        new ProcessBuilder(positional).start();
        // The shell is picked by a ternary expression, then put into the command.
        String shellPath = System.getProperty("os.name").startsWith("Windows") ? "cmd.exe" : "sh";
        String flag = shellPath.equals("sh") ? "-c" : "/c";
        // todoruleid: java.command-injection
        new ProcessBuilder(shellPath, flag, "type " + file).start();
        // A fixed program can still take a value that starts with a dash as an option
        // (argument injection, CWE-88); the rule accepts separate arguments.
        // todoruleid: java.command-injection
        new ProcessBuilder("git", "fetch", request.getParameter("remote")).start();
        // A helper of this file that returns a constant (or encodes the value) is followed.
        // ok: java.command-injection
        Runtime.getRuntime().exec(defaultCheck(request.getParameter("check")));
        // A helper of another file is not looked into: it passes the request data on.
        // todook: java.command-injection
        Runtime.getRuntime().exec(com.acme.shop.web.Checks.defaultCheck(request.getParameter("check")));
    }

    private static String defaultCheck(String requested) {
        return "uptime";
    }
}

class ArgumentLists {
    static List<String> build(String value) {
        return List.of("tar", "tf", value);
    }

    List<String> forArchive(String value) {
        return List.of("tar", "tf", value);
    }
}

class CommandBus {
    void exec(String command) {
    }

    void exec(String[] argv) {
    }
}

// Allow-lists: a constant map in a static final field or in place, and enum constants.
class MaintenanceServlet extends HttpServlet {
    private static final Map<String, String> TASKS = Map.of("disk", "df -h", "memory", "free -m");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java.command-injection
        Runtime.getRuntime().exec(TASKS.get(request.getParameter("task")));
        // ok: java.command-injection
        new ProcessBuilder(Map.of("zip", "zip", "tar", "tar").getOrDefault(request.getParameter("format"), "tar"), "-v").start();
        // ok: java.command-injection
        new ProcessBuilder(Archiver.valueOf(request.getParameter("archiver")).program(), "-v").start();
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(String.valueOf(request.getParameter("task")));
        Map<String, String> custom = new java.util.HashMap<>();
        custom.put("task", request.getParameter("task"));
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(custom.get("task"));
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(Map.of("task", request.getParameter("task")).get("task"));
    }
}

enum Archiver {
    ZIP, TAR;

    String program() {
        return name().toLowerCase();
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@RestController
class SharedLimitsController {
    private static final String DEFAULT_TARGET = "alpha";
    private static final Map<String, String> TABLE = Map.of("a", "alpha", "b", "beta");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("a", "alpha"), Map.entry("b", "beta"));
    private java.sql.Connection connection;

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback) throws IOException {
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + TABLE.getOrDefault(key, DEFAULT_TARGET));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + TABLE.getOrDefault(key, "beta"));
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + TABLE.getOrDefault(key, fallback));
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + Map.of("a", "alpha").getOrDefault(key, key));
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + javax.xml.namespace.QName.valueOf(key).getLocalPart());
        // A literal Map.ofEntries table: a lookup yields its values, which hold no request data.
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + ENTRIES.get(key));
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + java.time.DayOfWeek.valueOf(key).name());
        return "ok";
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) throws IOException {
        // todoruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + term);
        return "ok";
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry injected text, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind, @RequestParam List<Long> ids, @RequestParam Optional<Long> page)
            throws IOException {
        // todook: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + kind);
        // todook: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + ids.get(0));
        // todook: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + page.orElse(0L));
        return "ok";
    }
}

enum SharedKind {
    SMALL, LARGE
}

class SharedSwitchServlet extends HttpServlet {
    private java.sql.Connection connection;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            char mode = "abc".charAt(0);
            String chosen;
            switch (mode) {
                case 0x61:
                    chosen = "alpha";
                    break;
                default:
                    chosen = request.getParameter("chosen");
            }
            // A switch over a value computed from constants always takes the same branch.
            // todook: java.command-injection
            Runtime.getRuntime().exec("ping -c 1 " + chosen);
        } catch (Exception e) {
            response.sendError(500);
        }
    }
}

// The request body of a Spring MVC HttpEntity or RequestEntity parameter, and command text assembled in
// an append chain (StringBuilder.append(...).append(value)).
@RestController
class EntityToolController {
    @PostMapping("/entity/ping")
    String ping(HttpEntity<String> entity) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + entity.getBody());
        return "ok";
    }

    @org.springframework.web.bind.annotation.RequestMapping("/entity/trace")
    String trace(RequestEntity<String> request) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("traceroute " + request.getBody());
        return "ok";
    }

    @PostMapping
    String lookup(org.springframework.http.HttpEntity<JobForm> entity) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("nslookup " + entity.getHeaders().getFirst("X-Host"));
        return "ok";
    }

    @GetMapping("/entity/chain")
    String chain(@RequestParam String host) throws IOException {
        StringBuilder command = new StringBuilder();
        command.append("ping").append(" -c 1 ").append(host);
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(command.toString());
        StringBuilder fixed = new StringBuilder();
        fixed.append("uptime").append(" -p");
        // ok: java.command-injection
        Runtime.getRuntime().exec(fixed.toString());
        return "ok";
    }

    @PostMapping("/entity/argument")
    String argument(HttpEntity<String> entity) throws IOException {
        // ok: java.command-injection
        new ProcessBuilder("ping", "-c", "1", entity.getBody()).start();
        return "ok";
    }

    // Not a handler method: an entity it is given is not request data.
    void replay(HttpEntity<String> entity) throws IOException {
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + entity.getBody());
    }
}

// The other spellings of the shared request sources and sanitizers.
@RestController
class SharedFormsController {
    private static final Map<String, String> FORMS = Map.of("a", "alpha", "b", "alpha");

    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n) throws IOException {
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + Map.of("a", "alpha", "b", "alpha").get(key));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + Map.of("a", "alpha").getOrDefault(key, "alpha"));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + FORMS.get(key));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + FORMS.getOrDefault(key, "alpha"));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + String.valueOf(Integer.parseInt(n)));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + String.valueOf(Long.parseLong(n)));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + String.valueOf(Integer.valueOf(n)));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + String.valueOf(Long.valueOf(n)));
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + Enum.valueOf(FormKind.class, key).name());
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + java.lang.Enum.valueOf(FormKind.class, key).name());
        // An enum declared inside the class.
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + Level.valueOf(key).name());
        // An enum declared before the first class of the file.
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + EarlierKind.valueOf(key).name());
        // An enum declared after the class.
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + FormKind.valueOf(key).name());
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + single.toString());
        // Text put in with insert or replace (StringBuilder and StringBuffer), by the declared
        // type or by a builder created in the method.
        StringBuilder chosen = Boolean.getBoolean("compact") ? new StringBuilder() : new StringBuilder("a");
        chosen.insert(0, key, 0, key.length());
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + chosen.toString());
        StringBuffer typed = Boolean.getBoolean("compact") ? new StringBuffer() : new StringBuffer("a");
        typed.replace(0, 1, key);
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + typed.toString());
        var spliced = new StringBuilder();
        spliced.append("a").insert(0, key);
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + spliced.toString());
        var swapped = new StringBuffer();
        swapped.append("a").replace(0, 1, key);
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + swapped.toString());
        // Another class's replace (Map.replace) carries nothing into its object (and the map's
        // size is a number).
        java.util.Map<String, String> labels = new java.util.HashMap<>();
        labels.replace("k", "old", key);
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + String.valueOf(labels.size()));
        // OpenGrep's --taint-intrafile mode takes a two-argument insert on a class without a body
        // in this file (a MyBatis session) for a container write: what the session returns
        // afterwards is taken for request data.
        org.apache.ibatis.session.SqlSession session = MyBatisSessions.open();
        session.insert("notes.add", key);
        // todook: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + String.valueOf(session.selectOne("notes.latest")));
        return "ok";
    }

    // A part of a multipart request bound with @RequestPart (text, or a body converted with an
    // HttpMessageConverter).
    @org.springframework.web.bind.annotation.PostMapping("/shared/part")
    String part(@RequestPart("meta") String meta, @org.springframework.web.bind.annotation.RequestPart("note") PartNote note,
            @RequestPart("count") int count) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + meta);
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + note.getText());
        // A part converted to a number cannot carry injected text.
        // ok: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + String.valueOf(count));
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // Servlet request types of both namespaces.
    void jakartaRequest(jakarta.servlet.ServletRequest request) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("q"));
    }

    void javaxRequest(javax.servlet.ServletRequest request) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("q"));
    }

    void javaxHttpRequest(javax.servlet.http.HttpServletRequest request) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("q"));
    }

    void jakartaHttpRequest(jakarta.servlet.http.HttpServletRequest request) throws IOException {
        // ruleid: java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("q"));
    }
}

enum FormKind {
    SMALL, LARGE
}

class PartNote {
    private String text;

    String getText() {
        return text;
    }
}

// Each form of the command sinks once, with the values that keep it quiet (one line per form of
// the rule, so that no form goes untested).
class CommandFormsServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        ProcessBuilder builder = new ProcessBuilder();
        Runtime runtime = Runtime.getRuntime();

        // A Runtime held in a variable declared with var.
        var shared = Runtime.getRuntime();
        // ruleid: java.command-injection
        shared.exec("ping -c 1 " + name);
        // ruleid: java.command-injection
        shared.exec(new String[] {name, "--version"});
        var bus = new CommandBus();
        // ok: java.command-injection
        bus.exec("ping -c 1 " + name);
        // ok: java.command-injection
        bus.exec(new String[] {name, "--version"});

        // A whole command from a request getter or a split, in place.
        // ruleid: java.command-injection
        builder.command(request.getParameterValues("argv"));
        // ruleid: java.command-injection
        runtime.exec(request.getParameterValues("argv"));
        // ruleid: java.command-injection
        new ProcessBuilder(name.split(" "));
        // ruleid: java.command-injection
        new ProcessBuilder(name.split(" ").clone());
        // ruleid: java.command-injection
        new ProcessBuilder(Arrays.asList(name.split(" ")));
        // ruleid: java.command-injection
        new ProcessBuilder(List.of(name.split(" ")));
        // ... or through a variable (the declared list is reported too: its first element, the
        // program, is request data).
        // ruleid: java.command-injection
        List<String> words = Arrays.asList(name.split(" "));
        // ruleid: java.command-injection
        new ProcessBuilder(words);

        // The program: the first element of an array or list.
        // ruleid: java.command-injection
        builder.command(name, "--help");
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(new String[] {name, "--version"});
        // ruleid: java.command-injection
        new ProcessBuilder(List.of(name, "--version"));
        // ruleid: java.command-injection
        new ProcessBuilder(Arrays.asList(name, "--version"));
        // ruleid: java.command-injection
        builder.command(List.of(name, "--version"));
        // ruleid: java.command-injection
        builder.command(Arrays.asList(name, "--version"));
        // ruleid: java.command-injection
        String[] first = {name, "--version"};
        Runtime.getRuntime().exec(first);
        // ruleid: java.command-injection
        String[] second = {name, "--version"};
        new ProcessBuilder(second);
        // ruleid: java.command-injection
        String[] third = {name, "--version"};
        builder.command(third);
        // ruleid: java.command-injection
        List<String> listed = List.of(name, "--version");
        builder.command(listed);
        // ruleid: java.command-injection
        List<String> qualified = java.util.List.of(name, "--version");
        new ProcessBuilder(qualified);
        // ruleid: java.command-injection
        List<String> asList = Arrays.asList(name, "--version");
        new ProcessBuilder(asList);
        // ruleid: java.command-injection
        List<String> qualifiedAsList = java.util.Arrays.asList(name, "--version");
        new ProcessBuilder(qualifiedAsList);
        // ruleid: java.command-injection
        List<String> copied = new ArrayList<>(List.of(name, "--version"));
        new ProcessBuilder(copied);
        // ruleid: java.command-injection
        List<String> copiedAsList = new ArrayList<>(Arrays.asList(name, "--version"));
        new ProcessBuilder(copiedAsList);
        // ruleid: java.command-injection
        List<String> qualifiedCopy = new java.util.ArrayList<>(java.util.List.of(name, "--version"));
        new ProcessBuilder(qualifiedCopy);
        // ruleid: java.command-injection
        List<String> qualifiedCopyAsList = new java.util.ArrayList<>(java.util.Arrays.asList(name, "--version"));
        new ProcessBuilder(qualifiedCopyAsList);

        // A shell with its flag: the script right after it.
        // ruleid: java.command-injection
        builder.command("bash", "-c", "ls " + name);
        // ruleid: java.command-injection
        new ProcessBuilder(Arrays.asList("sh", "-c", "ls " + name));
        // An option that is not the command flag, or a program that is not a shell.
        // ok: java.command-injection
        builder.command("sh", "/opt/scripts/report.sh", name);
        // ok: java.command-injection
        builder.command("grep", "-c", name);
        // cmd.exe and PowerShell: every element after the flag.
        // ruleid: java.command-injection
        builder.command("cmd.exe", "/c", "type", name);
        // ruleid: java.command-injection
        runtime.exec(new String[] {"cmd", "/c", "type", name});
        // ruleid: java.command-injection
        String[] typed = {"cmd", "/c", "type", name};
        runtime.exec(typed);
        // ruleid: java.command-injection
        new ProcessBuilder(List.of("cmd", "/c", "type", name));
        // ruleid: java.command-injection
        new ProcessBuilder(Arrays.asList("cmd", "/c", "type", name));
        // A cmd.exe option other than /c or /k runs no command.
        // ok: java.command-injection
        new ProcessBuilder("cmd.exe", "/q", "type", name);

        // The environment: an entry in an array variable, an entry in a variable.
        // ruleid: java.command-injection
        String[] env = {request.getParameter("entry")};
        Runtime.getRuntime().exec("printenv", env);
        String entry = "PATH=" + name;
        // ruleid: java.command-injection
        runtime.exec("printenv", new String[] {entry});
        // ProcessBuilder's environment map held in a variable.
        Map<String, String> variables = builder.environment();
        // ruleid: java.command-injection
        variables.put(name, "1");
        // ruleid: java.command-injection
        variables.put("PATH", name);
        // ok: java.command-injection
        variables.put("BACKUP_LABEL", name);
        // Another map is no environment.
        Map<String, String> labels = new java.util.HashMap<>();
        // ok: java.command-injection
        labels.put(name, "1");
        // Reads of the map change nothing.
        // ok: java.command-injection
        variables.getOrDefault(name, "1");
        // ok: java.command-injection
        variables.getOrDefault("PATH", name);
    }

    void shellVariables(HttpServletRequest request, boolean windows) throws IOException {
        String name = request.getParameter("name");
        String program;
        String option;
        if (windows) {
            program = "cmd.exe";
            option = "/c";
        } else {
            program = "sh";
            option = "-c";
        }
        // ruleid: java.command-injection
        new ProcessBuilder().command(program, option, "ls " + name);
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(new String[] {program, option, "ls " + name});
    }

    void requestTypes(javax.servlet.ServletRequest plain, jakarta.servlet.ServletRequest jakartaPlain,
            jakarta.servlet.http.HttpServletRequest jakartaHttp) throws IOException {
        // ruleid: java.command-injection
        new ProcessBuilder(plain.getParameterValues("argv"));
        // ruleid: java.command-injection
        new ProcessBuilder(jakartaPlain.getParameterValues("argv"));
        // ruleid: java.command-injection
        new ProcessBuilder(jakartaHttp.getParameterValues("argv"));
        String[] fromPlain = plain.getParameterValues("argv");
        // ruleid: java.command-injection
        new ProcessBuilder(fromPlain);
        String[] fromJakartaPlain = jakartaPlain.getParameterValues("argv");
        // ruleid: java.command-injection
        new ProcessBuilder(fromJakartaPlain);
        String[] fromJakartaHttp = jakartaHttp.getParameterValues("argv");
        // ruleid: java.command-injection
        new ProcessBuilder(fromJakartaHttp);
    }

    void variableRequests(javax.servlet.http.HttpServletRequest request) throws IOException {
        String[] fromRequest = request.getParameterValues("argv");
        // ruleid: java.command-injection
        new ProcessBuilder(fromRequest);
    }
}

@RestController
class CommandFormsController {
    // A bound parameter (or a field of it) passed as the whole command.
    @PostMapping("/forms/bound")
    String bound(@RequestParam List<String> argv, @RequestBody JobForm form) throws IOException {
        ProcessBuilder builder = new ProcessBuilder();
        Runtime runtime = Runtime.getRuntime();
        // ruleid: java.command-injection
        new ProcessBuilder(argv.toArray(new String[0]));
        // ruleid: java.command-injection
        new ProcessBuilder(form.getArguments().toArray(new String[0]));
        // ruleid: java.command-injection
        builder.command(argv);
        // ruleid: java.command-injection
        builder.command(form.getArguments());
        // ruleid: java.command-injection
        runtime.exec(argv.toArray(new String[0]));
        // ruleid: java.command-injection
        runtime.exec(form.getArguments().toArray(new String[0]));
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(argv.toArray(new String[0]));
        // ruleid: java.command-injection
        Runtime.getRuntime().exec(form.getArguments().toArray(new String[0]));
        return "ok";
    }

    // An annotation written without parentheses.
    @PostMapping("/forms/bare")
    String bare(@RequestBody JobForm form) throws IOException {
        // ruleid: java.command-injection
        new ProcessBuilder(form.getArguments());
        return "ok";
    }

    // A String body is no list of words.
    @PostMapping("/forms/text")
    String text(HttpEntity<String> entity) throws IOException {
        // ok: java.command-injection
        new ProcessBuilder(entity.getBody());
        return "ok";
    }

    // Helpers in the same file that get request data: their parameters are no handler
    // parameters, and an object that merely has a getBody() is no request entity.
    @PostMapping("/forms/helpers")
    String helpers(@RequestParam("argv") String[] argv) throws IOException {
        runList(Arrays.asList(argv));
        runArray(argv);
        runHeld(new Held(Arrays.asList(argv)));
        return "ok";
    }

    void runList(@org.springframework.lang.Nullable List<String> words) throws IOException {
        // ok: java.command-injection
        new ProcessBuilder(words);
    }

    void runArray(@org.springframework.lang.Nullable String[] words) throws IOException {
        // ok: java.command-injection
        Runtime.getRuntime().exec(words);
    }

    void runHeld(Held held) throws IOException {
        // ok: java.command-injection
        new ProcessBuilder(held.getBody());
    }
}

class Held {
    private final List<String> body;

    Held(List<String> body) {
        this.body = body;
    }

    List<String> getBody() {
        return body;
    }
}

class MyBatisSessions {
    static org.apache.ibatis.session.SqlSession open() {
        return null;
    }
}
