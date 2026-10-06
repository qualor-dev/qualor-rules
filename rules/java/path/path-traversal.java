package com.acme.files;

import java.util.Optional;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import org.apache.commons.io.FilenameUtils;
import org.springframework.http.RequestEntity;
import org.springframework.http.HttpEntity;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

// An enum declared before the first class (the shared enum allow-list forms).
enum EarlierKind {
    ONE, TWO
}

// Servlet: request parameters into java.io and java.nio paths, uploaded file names.
public class DownloadServlet extends HttpServlet {
    private static final String BASE = "/srv/files";
    private static final Map<String, String> PAGES = Map.of("help", "help.html", "terms", "terms.html");
    private Map<String, String> documents;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        // ruleid: java.path-traversal
        File file = new File(BASE + "/" + name);
        // ruleid: java.path-traversal
        File child = new File(BASE, request.getParameter("doc"));
        // ruleid: java.path-traversal
        File nested = new File(new File(BASE), name);
        // ruleid: java.path-traversal
        InputStream in = new FileInputStream(BASE + "/" + name);
        // ruleid: java.path-traversal
        FileReader reader = new FileReader(request.getHeader("X-Template"));
        // ruleid: java.path-traversal
        byte[] bytes = Files.readAllBytes(Paths.get(BASE, name));
        // ruleid: java.path-traversal
        Path direct = Path.of(String.format("%s/%s", BASE, name));
        Path base = Paths.get(BASE);
        // ruleid: java.path-traversal
        Path resolved = base.resolve(name);
        // ruleid: java.path-traversal
        Path sibling = base.resolveSibling(request.getPathInfo());
        // ruleid: java.path-traversal
        RandomAccessFile raf = new RandomAccessFile(name, "r");

        // ok: java.path-traversal
        File fixed = new File(BASE, "index.html");
        // ok: java.path-traversal
        Path onlyName = base.resolve(Paths.get(name).getFileName());
        // ok: java.path-traversal
        File plain = new File(BASE, FilenameUtils.getName(name));
        // ok: java.path-traversal
        File justName = new File(BASE, new File(name).getName());
        // ok: java.path-traversal
        File numbered = new File(BASE, "report-" + Integer.parseInt(request.getParameter("id")) + ".pdf");
        String section = "help".equals(request.getParameter("section")) ? "help.html" : "index.html";
        // ok: java.path-traversal
        File chosen = new File(BASE, section);
        // ok: java.path-traversal
        String title = documents.get(name);
        // ok: java.path-traversal
        File page = new File(BASE, PAGES.get(request.getParameter("page")));
        // ok: java.path-traversal
        File inline = new File(BASE, Map.of("a", "a.txt", "b", "b.txt").getOrDefault(name, "a.txt"));
        // ok: java.path-traversal
        File byKind = new File(BASE, ReportKind.valueOf(request.getParameter("kind")).fileName());
        // ruleid: java.path-traversal
        File unchecked = new File(BASE, String.valueOf(request.getParameter("raw")));
        Map<String, String> pages = new java.util.HashMap<>();
        pages.put("page", request.getParameter("page"));
        // ruleid: java.path-traversal
        File filled = new File(BASE, pages.get("page"));
        // ruleid: java.path-traversal
        File inPlace = new File(BASE, Map.of("page", request.getParameter("page")).get("page"));
        // ok: java.path-traversal
        Path temp = Files.createTempFile("upload", ".bin");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Part upload = request.getPart("file");
        // ruleid: java.path-traversal
        FileOutputStream out = new FileOutputStream(BASE + "/" + upload.getSubmittedFileName());
        // ruleid: java.path-traversal
        upload.write(BASE + "/" + upload.getSubmittedFileName());
        // ok: java.path-traversal
        upload.write(BASE + "/" + java.util.UUID.randomUUID() + ".bin");
        for (Part part : request.getParts()) {
            // ruleid: java.path-traversal
            part.write(BASE + "/" + part.getSubmittedFileName());
        }
        // ok: java.path-traversal
        upload.write(Paths.get(upload.getSubmittedFileName()).getFileName().toString());
    }

    // Limits of a taint analysis that sees one method at a time and does not evaluate
    // conditions.
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // A helper of the same class that returns a constant whatever it is given.
        // todook: java.path-traversal
        File help = new File(BASE, defaultPage(request.getParameter("page")));
        char mode = "abc".charAt(0);
        String folder;
        switch (mode) {
            case 0x61:
                folder = "archive";
                break;
            default:
                folder = request.getParameter("folder");
        }
        // A switch over a value computed from constants always takes the same branch.
        // todook: java.path-traversal
        File dir = new File(BASE, folder);
    }

    private static String defaultPage(String requested) {
        return "index.html";
    }

    // Not a handler: the parameter is not request data.
    void archive(String request) throws IOException {
        // ok: java.path-traversal
        new FileWriter(request).close();
    }
}

// Spring MVC: path variables, uploads, bodies and the ResourceLoader.
@RestController
class FileController {
    private ResourceLoader resourceLoader;
    private final Path storage = Paths.get("/srv/uploads");

    @GetMapping("/files/{filename}")
    Resource download(@PathVariable String filename) {
        // ruleid: java.path-traversal
        Resource fs = new FileSystemResource("/srv/files/" + filename);
        // ruleid: java.path-traversal
        Resource loaded = resourceLoader.getResource("file:/srv/files/" + filename);
        // ok: java.path-traversal
        Resource bundled = resourceLoader.getResource("classpath:static/index.html");
        return loaded;
    }

    @PostMapping("/files")
    String upload(@RequestParam("file") MultipartFile file) throws IOException {
        // ruleid: java.path-traversal
        file.transferTo(storage.resolve(file.getOriginalFilename()));
        // ok: java.path-traversal
        file.transferTo(storage.resolve(Paths.get(file.getOriginalFilename()).getFileName()));
        // ok: java.path-traversal
        file.transferTo(storage.resolve(java.util.UUID.randomUUID().toString()));
        return "ok";
    }

    // Spring binds a MultipartFile parameter by name, without an annotation.
    @PostMapping("/avatars")
    String avatar(MultipartFile avatar) throws IOException {
        // ruleid: java.path-traversal
        avatar.transferTo(new File("/srv/avatars/" + avatar.getOriginalFilename()));
        return "ok";
    }

    @PostMapping("/exports")
    String export(@RequestBody ExportForm form, @RequestParam long id) throws IOException {
        // A body getter named getFileName is not Path.getFileName.
        // ruleid: java.path-traversal
        File named = new File("/srv/exports", form.getFileName());
        // ruleid: java.path-traversal
        Path namedPath = Path.of("/srv/exports", form.getFileName());
        // ruleid: java.path-traversal
        Path chained = Paths.get("/srv/exports").resolve(form.getTarget());
        var exportBase = Paths.get("/srv/exports");
        // ruleid: java.path-traversal
        Path fromVar = exportBase.resolve(form.getTarget());
        // ruleid: java.path-traversal
        Path fromFileSystem = java.nio.file.FileSystems.getDefault().getPath("/srv/exports", form.getTarget());
        // ok: java.path-traversal
        Path lastName = exportBase.resolve(Paths.get(form.getTarget()).getFileName());
        // A path built only to take its file name in a later statement.
        // todook: java.path-traversal
        var requested = Paths.get(form.getTarget());
        // ok: java.path-traversal
        Path lastOfVar = exportBase.resolve(requested.getFileName());
        // ruleid: java.path-traversal
        FileWriter writer = new FileWriter("/srv/exports/" + form.getTarget());
        // ok: java.path-traversal
        FileWriter numbered = new FileWriter("/srv/exports/" + id + ".csv");
        return "ok";
    }

    @GetMapping("/checked")
    String checked(@RequestParam String name) throws IOException {
        // The check that follows (normalize, then startsWith the base) is not seen: the path is
        // reported where it is built.
        // todook: java.path-traversal
        Path target = storage.resolve(name).normalize();
        if (!target.startsWith(storage)) {
            throw new IOException("outside the storage directory");
        }
        return "ok";
    }
}

enum ReportKind {
    DAILY, WEEKLY;

    String fileName() {
        return name().toLowerCase() + ".pdf";
    }
}

class ExportForm {
    private String target;
    private String fileName;

    String getFileName() {
        return fileName;
    }

    String getTarget() {
        return target;
    }
}

// Jakarta REST: path and query parameters.
@jakarta.ws.rs.Path("/reports")
class ReportResource {
    @GET
    @jakarta.ws.rs.Path("/{name}")
    public byte[] report(@PathParam("name") String name, @QueryParam("dir") String dir) throws IOException {
        // ruleid: java.path-traversal
        File file = new File("/srv/reports", name);
        // ruleid: java.path-traversal
        InputStream in = Files.newInputStream(java.nio.file.Paths.get("/srv/reports", dir, "summary.pdf"));
        // ok: java.path-traversal
        File summary = new File("/srv/reports", "summary.pdf");
        return new byte[0];
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    public String save(ExportForm form) throws IOException {
        // todoruleid: java.path-traversal
        new FileOutputStream("/srv/reports/" + form.getTarget()).close();
        return "ok";
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
        // ok: java.path-traversal
        new File("/srv/files", TABLE.getOrDefault(key, DEFAULT_TARGET)).delete();
        // ok: java.path-traversal
        new File("/srv/files", TABLE.getOrDefault(key, "beta")).delete();
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.path-traversal
        new File("/srv/files", TABLE.getOrDefault(key, fallback)).delete();
        // ruleid: java.path-traversal
        new File("/srv/files", Map.of("a", "alpha").getOrDefault(key, key)).delete();
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.path-traversal
        new File("/srv/files", javax.xml.namespace.QName.valueOf(key).getLocalPart()).delete();
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.path-traversal
        new File("/srv/files", ENTRIES.get(key)).delete();
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.path-traversal
        new File("/srv/files", java.time.DayOfWeek.valueOf(key).name()).delete();
        return "ok";
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) throws IOException {
        // todoruleid: java.path-traversal
        new File("/srv/files", term).delete();
        return "ok";
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry injected text, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind, @RequestParam List<Long> ids, @RequestParam Optional<Long> page)
            throws IOException {
        // todook: java.path-traversal
        new File("/srv/files", kind).delete();
        // todook: java.path-traversal
        new File("/srv/files", ids.get(0)).delete();
        // todook: java.path-traversal
        new File("/srv/files", page.orElse(0L)).delete();
        return "ok";
    }
}

enum SharedKind {
    SMALL, LARGE
}

// The request body of a Spring MVC HttpEntity or RequestEntity parameter, and path text assembled in
// an append chain (StringBuilder.append(...).append(value)).
@RestController
class EntityFileController {
    @PostMapping("/entity/delete")
    String delete(HttpEntity<String> entity) {
        // ruleid: java.path-traversal
        new File("/srv/files", entity.getBody()).delete();
        return "ok";
    }

    @org.springframework.web.bind.annotation.RequestMapping("/entity/read")
    String read(RequestEntity<String> request) throws IOException {
        // ruleid: java.path-traversal
        return Files.readString(Path.of("/srv/files/" + request.getBody()));
    }

    @PostMapping
    String touch(org.springframework.http.HttpEntity<ExportForm> entity) throws IOException {
        // ruleid: java.path-traversal
        new File("/srv/files/" + entity.getHeaders().getFirst("X-Name")).createNewFile();
        return "ok";
    }

    @GetMapping("/entity/chain")
    String chain(@RequestParam String name) throws IOException {
        StringBuilder path = new StringBuilder();
        path.append("/srv/files").append("/").append(name);
        // ruleid: java.path-traversal
        new File(path.toString()).delete();
        StringBuilder fixed = new StringBuilder();
        fixed.append("/srv/files").append("/index.txt");
        // ok: java.path-traversal
        new File(fixed.toString()).delete();
        return "ok";
    }

    @PostMapping("/entity/basename")
    String basename(HttpEntity<String> entity) {
        // ok: java.path-traversal
        new File("/srv/files", FilenameUtils.getName(entity.getBody())).delete();
        return "ok";
    }

    // Not a handler method: an entity it is given is not request data.
    void replay(HttpEntity<String> entity) {
        // ok: java.path-traversal
        new File("/srv/files", entity.getBody()).delete();
    }
}

// The other spellings of the shared request sources and sanitizers.
@RestController
class SharedFormsController {
    private static final Map<String, String> FORMS = Map.of("a", "alpha.txt", "b", "alpha.txt");

    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n) {
        // ok: java.path-traversal
        new File("/srv/files", Map.of("a", "alpha.txt", "b", "alpha.txt").get(key)).delete();
        // ok: java.path-traversal
        new File("/srv/files", Map.of("a", "alpha.txt").getOrDefault(key, "alpha.txt")).delete();
        // ok: java.path-traversal
        new File("/srv/files", FORMS.get(key)).delete();
        // ok: java.path-traversal
        new File("/srv/files", FORMS.getOrDefault(key, "alpha.txt")).delete();
        // ok: java.path-traversal
        new File("/srv/files", String.valueOf(Integer.parseInt(n))).delete();
        // ok: java.path-traversal
        new File("/srv/files", String.valueOf(Long.parseLong(n))).delete();
        // ok: java.path-traversal
        new File("/srv/files", String.valueOf(Integer.valueOf(n))).delete();
        // ok: java.path-traversal
        new File("/srv/files", String.valueOf(Long.valueOf(n))).delete();
        // ok: java.path-traversal
        new File("/srv/files", Enum.valueOf(FormKind.class, key).name()).delete();
        // ok: java.path-traversal
        new File("/srv/files", java.lang.Enum.valueOf(FormKind.class, key).name()).delete();
        // An enum declared inside the class.
        // ok: java.path-traversal
        new File("/srv/files", Level.valueOf(key).name()).delete();
        // An enum declared before the first class of the file.
        // ok: java.path-traversal
        new File("/srv/files", EarlierKind.valueOf(key).name()).delete();
        // An enum declared after the class.
        // ok: java.path-traversal
        new File("/srv/files", FormKind.valueOf(key).name()).delete();
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.path-traversal
        new File("/srv/files", single.toString()).delete();
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // Servlet request types of both namespaces.
    void jakartaRequest(jakarta.servlet.ServletRequest request) {
        // ruleid: java.path-traversal
        new File("/srv/files", request.getParameter("q")).delete();
    }

    void javaxRequest(javax.servlet.ServletRequest request) {
        // ruleid: java.path-traversal
        new File("/srv/files", request.getParameter("q")).delete();
    }

    void javaxHttpRequest(javax.servlet.http.HttpServletRequest request) {
        // ruleid: java.path-traversal
        new File("/srv/files", request.getParameter("q")).delete();
    }

    void jakartaHttpRequest(jakarta.servlet.http.HttpServletRequest request) {
        // ruleid: java.path-traversal
        new File("/srv/files", request.getParameter("q")).delete();
    }
}

enum FormKind {
    SMALL, LARGE
}
