package com.acme.pages;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.owasp.encoder.Encode;
import org.springframework.http.RequestEntity;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

// An enum declared before the first class (the shared enum allow-list forms).
enum EarlierKind {
    ONE, TWO
}

// Servlet: the response writer and output stream, with no content type or text/html.
public class SearchServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String term = request.getParameter("q");
        // ruleid: java.xss
        response.getWriter().println("<p>Results for " + term + "</p>");
        PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.print(request.getHeader("Referer"));
        // ruleid: java.xss
        out.write(String.format("<h1>%s</h1>", term));
        // ruleid: java.xss
        out.printf("<li>%s</li>", request.getQueryString());
        // ruleid: java.xss
        out.append("<span>").append(request.getPathInfo());
        // ruleid: java.xss
        response.getWriter().append("<em>").append(term);
        StringBuilder page = new StringBuilder("<ul>");
        page.append("<li>").append(term).append("</li>");
        // ruleid: java.xss
        out.write(page.toString());
        var writer = response.getWriter();
        // ruleid: java.xss
        writer.format("<b>%s</b>", request.getRequestURI());
        ServletOutputStream stream = response.getOutputStream();
        // ruleid: java.xss
        stream.println(term);
        // ruleid: java.xss
        stream.write(term.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        // ok: java.xss
        out.println("<p>Results for " + Encode.forHtml(term) + "</p>");
        // ok: java.xss
        out.println("<p>" + Encode.forHtmlContent(term) + "</p>");
        // ok: java.xss
        out.println("<a title=\"" + Encode.forHtmlAttribute(term) + "\">");
        // ok: java.xss
        out.println("<p>" + HtmlUtils.htmlEscape(term) + "</p>");
        // ok: java.xss
        out.println("<p>" + org.apache.commons.text.StringEscapeUtils.escapeHtml4(term) + "</p>");
        // ok: java.xss
        out.println("<p>" + org.apache.commons.lang3.StringEscapeUtils.escapeHtml4(term) + "</p>");
        // ok: java.xss
        out.println("<p>" + org.apache.commons.lang.StringEscapeUtils.escapeHtml(term) + "</p>");
        // ok: java.xss
        out.println("<p>" + org.springframework.web.util.HtmlUtils.htmlEscapeHex(term) + "</p>");
        // ok: java.xss
        out.println("<p>" + org.owasp.esapi.ESAPI.encoder().encodeForHTML(term) + "</p>");
        org.owasp.esapi.Encoder encoder = org.owasp.esapi.ESAPI.encoder();
        // ok: java.xss
        out.println("<a title=\"" + encoder.encodeForHTMLAttribute(term) + "\">");
        // The encoding happens in a helper method, which the rule does not look into.
        // todook: java.xss
        out.println("<p>" + escaped(term) + "</p>");
        // ok: java.xss
        out.println("<p>Page " + Integer.parseInt(request.getParameter("page")) + "</p>");
        // ok: java.xss
        out.println("<p>No results</p>");
        // Request data written to the server's own console or a log, not to the response.
        // ok: java.xss
        System.out.println("search: " + term);
        // ok: java.xss
        new PrintWriter(System.err).println(term);
        java.io.StringWriter buffer = new java.io.StringWriter();
        PrintWriter local = new PrintWriter(buffer);
        // ok: java.xss
        local.println(term);
        // Writing request data once does not make later constant output a finding.
        // ruleid: java.xss
        out.append(term);
        // ok: java.xss
        out.println("<footer>Acme</footer>");
        // ok: java.xss
        new com.fasterxml.jackson.databind.ObjectMapper().writeValue(out, Map.of("term", term));
        PrintWriter wrapped = new PrintWriter(new java.io.OutputStreamWriter(response.getOutputStream(), java.nio.charset.StandardCharsets.UTF_8), true);
        // ruleid: java.xss
        wrapped.println("<p>" + term + "</p>");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        try (PrintWriter out = response.getWriter()) {
            // ruleid: java.xss
            out.println("<p>Saved " + request.getParameter("title") + "</p>");
        }
    }

    private static String escaped(String text) {
        return HtmlUtils.htmlEscape(text);
    }
}

// Servlet: responses declared as JSON or plain text before they are written.
class ExportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        // ok: java.xss
        response.getWriter().write("{\"term\":\"" + request.getParameter("q") + "\"}");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/plain; charset=UTF-8");
        PrintWriter out = response.getWriter();
        // ok: java.xss
        out.println(request.getParameter("note"));
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setHeader("Content-Type", "text/csv");
        // ok: java.xss
        response.getOutputStream().print(request.getParameter("row"));
    }
}

class ReplyServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.addHeader("content-type", "text/plain");
        // ok: java.xss
        response.getWriter().write("Updated " + request.getReader().readLine());
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("image/svg+xml");
        // ruleid: java.xss
        response.getWriter().print(request.getParameter("shape"));
    }
}

// Spring MVC: a String returned from a @RestController or @ResponseBody method is written by
// the String converter, which supports every media type, so a browser that accepts text/html
// gets text/html.
@RestController
@RequestMapping("/api")
class GreetingController {
    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        // ruleid: java.xss
        return "<h1>Hello " + name + "</h1>";
    }

    @GetMapping
    String echo(@RequestHeader("User-Agent") String agent) {
        // ruleid: java.xss
        return agent;
    }

    @PostMapping(path = "/notes", consumes = "application/json")
    String note(@RequestBody NoteForm form) {
        String text = form.getText();
        // ruleid: java.xss
        return "<p>" + text + "</p>";
    }

    @GetMapping(value = "/users/{id}", produces = "text/html")
    String user(@PathVariable String id) {
        // ruleid: java.xss
        return "<p>" + id + "</p>";
    }

    @GetMapping("/theme")
    String theme(@CookieValue("theme") String theme) {
        // ruleid: java.xss
        return String.format("<body class=\"%s\">", theme);
    }

    @GetMapping("/page")
    ResponseEntity<String> page(@RequestParam String title) {
        // ruleid: java.xss
        return ResponseEntity.ok("<title>" + title + "</title>");
    }

    @GetMapping("/page2")
    ResponseEntity<String> page2(@RequestParam String title) {
        // ruleid: java.xss
        return ResponseEntity.ok().header("Cache-Control", "no-store").body("<title>" + title + "</title>");
    }

    @GetMapping("/page3")
    ResponseEntity<String> page3(@RequestParam String title) {
        // ruleid: java.xss
        return new ResponseEntity<>("<title>" + title + "</title>", org.springframework.http.HttpStatus.OK);
    }

    @GetMapping("/page4")
    ResponseEntity<?> page4(@RequestParam String title) {
        // ruleid: java.xss
        return ResponseEntity.ok().contentType(org.springframework.http.MediaType.TEXT_HTML).body("<title>" + title + "</title>");
    }

    @GetMapping("/safe")
    String safe(@RequestParam String name) {
        // ok: java.xss
        return "<h1>Hello " + HtmlUtils.htmlEscape(name) + "</h1>";
    }

    @GetMapping("/safe2")
    String safe2(@RequestParam String name) {
        // ok: java.xss
        return "<h1>Hello " + Encode.forHtml(name) + "</h1>";
    }

    @RequestMapping(value = "/legacy", method = org.springframework.web.bind.annotation.RequestMethod.GET)
    String legacy(@RequestParam String name) {
        // ruleid: java.xss
        return "<p>" + name + "</p>";
    }

    @GetMapping(produces = org.springframework.http.MediaType.APPLICATION_JSON_VALUE)
    String jsonOnly(@RequestParam String name) {
        // ok: java.xss
        return "{\"name\":\"" + name + "\"}";
    }

    @GetMapping(value = "/json", produces = org.springframework.http.MediaType.APPLICATION_JSON_VALUE)
    String json(@RequestParam String name) {
        // ok: java.xss
        return "{\"name\":\"" + name + "\"}";
    }

    @GetMapping(path = "/text", produces = "text/plain")
    String text(@RequestParam String name) {
        // ok: java.xss
        return "Hello " + name;
    }

    @GetMapping("/dto")
    NoteForm dto(@RequestParam String text) {
        NoteForm form = new NoteForm();
        form.setText(text);
        // ok: java.xss
        return form;
    }

    @GetMapping("/map")
    Map<String, String> map(@RequestParam String text) {
        // ok: java.xss
        return Map.of("text", text);
    }

    @GetMapping("/json-entity")
    ResponseEntity<String> jsonEntity(@RequestParam String name) {
        // ok: java.xss
        return ResponseEntity.ok().contentType(org.springframework.http.MediaType.APPLICATION_JSON).body("{\"name\":\"" + name + "\"}");
    }

    @GetMapping("/json-header")
    ResponseEntity<String> jsonHeader(@RequestParam String name) {
        // ok: java.xss
        return ResponseEntity.ok().header("Content-Type", "application/json").body("{\"name\":\"" + name + "\"}");
    }

    // A browser runs scripts in XHTML-namespaced XML.
    @GetMapping(path = "/xml", produces = "application/xml")
    String xml(@RequestParam String name) {
        // ruleid: java.xss
        return "<name>" + name + "</name>";
    }

    @GetMapping("/xml-entity")
    ResponseEntity<String> xmlEntity(@RequestParam String name) {
        // ruleid: java.xss
        return ResponseEntity.ok().header(org.springframework.http.HttpHeaders.CONTENT_TYPE, "image/svg+xml").body("<svg>" + name + "</svg>");
    }

    @GetMapping("/count")
    String count(@RequestParam int count) {
        // ok: java.xss
        return "<p>" + count + "</p>";
    }

    @GetMapping("/constant")
    String constant(@RequestParam String name) {
        // ok: java.xss
        return "<p>Hello</p>";
    }

    private String describe(String text) {
        // ok: java.xss
        return "<p>" + text + "</p>";
    }
}

// A Spring MVC class whose produces is JSON for every method.
@RestController
@RequestMapping(path = "/v2", produces = "application/json")
class JsonController {
    @GetMapping("/echo")
    String echo(@RequestParam String text) {
        // ok: java.xss
        return "{\"text\":\"" + text + "\"}";
    }

    // A method-level produces overrides the class-level one.
    @GetMapping(value = "/page", produces = org.springframework.http.MediaType.TEXT_HTML_VALUE)
    String page(@RequestParam String text) {
        // ruleid: java.xss
        return "<p>" + text + "</p>";
    }
}

// The same with produces given as an array.
@RestController
@RequestMapping(path = "/v3", produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE})
class JsonArrayController {
    @GetMapping("/echo")
    String echo(@RequestParam String text) {
        // ok: java.xss
        return "{\"text\":\"" + text + "\"}";
    }
}

// Spring MVC: a ResponseEntity whose body type is not String, and @ResponseBody on the class.
@Controller
@ResponseBody
class ClassLevelBodyController {
    @GetMapping("/class-body")
    String body(@RequestParam String text) {
        // todoruleid: java.xss
        return "<p>" + text + "</p>";
    }

    @GetMapping("/object-entity")
    ResponseEntity<Object> entity(@RequestParam String text) {
        // todoruleid: java.xss
        return ResponseEntity.ok("<p>" + text + "</p>");
    }

    // A content type set through an HttpHeaders object is not seen.
    @GetMapping("/headers")
    ResponseEntity<String> headers(@RequestParam String text) {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        // todook: java.xss
        return new ResponseEntity<>("{\"text\":\"" + text + "\"}", headers, org.springframework.http.HttpStatus.OK);
    }
}

// Spring MVC @Controller: a String return value is a view name, and the model is rendered by
// the template engine; only @ResponseBody methods write the String itself.
@Controller
class ViewController {
    @GetMapping("/greeting")
    String greeting(@RequestParam String name, Model model) {
        model.addAttribute("name", name);
        // ok: java.xss
        return "greeting";
    }

    @GetMapping("/view/{name}")
    String view(@PathVariable String name) {
        // ok: java.xss
        return "pages/" + Map.of("a", "about", "c", "contact").get(name);
    }

    @GetMapping("/raw")
    @ResponseBody
    String raw(@RequestParam String name) {
        // ruleid: java.xss
        return "<p>" + name + "</p>";
    }

    @GetMapping("/servlet")
    void servlet(@RequestParam String name, HttpServletResponse response) throws IOException {
        // ruleid: java.xss
        response.getWriter().write("<p>" + name + "</p>");
    }
}

class NoteForm {
    private String text;

    String getText() {
        return text;
    }

    void setText(String text) {
        this.text = text;
    }
}

// Jakarta REST: a resource method that produces text/html.
@Path("/pages")
class PageResource {
    @GET
    @Path("/{name}")
    @Produces(MediaType.TEXT_HTML)
    public String page(@PathParam("name") String name) {
        // ruleid: java.xss
        return "<h1>" + name + "</h1>";
    }

    @GET
    @Path("/search")
    @Produces("text/html; charset=UTF-8")
    public Response search(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.ok("<p>" + q + "</p>").build();
    }

    @GET
    @Path("/typed")
    public Response typed(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.ok("<p>" + q + "</p>", MediaType.TEXT_HTML).build();
    }

    @GET
    @Path("/typed2")
    public Response typed2(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.ok("<p>" + q + "</p>").type("text/html").build();
    }

    @GET
    @Path("/escaped")
    @Produces(MediaType.TEXT_HTML)
    public String escaped(@QueryParam("q") String q) {
        // ok: java.xss
        return "<p>" + Encode.forHtml(q) + "</p>";
    }

    @GET
    @Path("/feed")
    @Produces(MediaType.APPLICATION_XML)
    public String feed(@QueryParam("q") String q) {
        // ruleid: java.xss
        return "<feed>" + q + "</feed>";
    }

    @GET
    @Path("/plain")
    @Produces(MediaType.TEXT_PLAIN)
    public String plain(@QueryParam("q") String q) {
        // ok: java.xss
        return "Hello " + q;
    }

    @GET
    @Path("/json")
    @Produces(MediaType.APPLICATION_JSON)
    public Response json(@QueryParam("q") String q) {
        // ok: java.xss
        return Response.ok(Map.of("q", q)).build();
    }

    // Without @Produces the media type is negotiated: the specification lets a browser's Accept
    // header pick text/html, while Quarkus REST picks text/plain for a String.
    @GET
    @Path("/negotiated")
    public String negotiated(@QueryParam("q") String q) {
        // todoruleid: java.xss
        return "<p>" + q + "</p>";
    }
}

// A Jakarta REST class that produces XML or JSON: entities are serialised (and escaped) by
// JAXB or JSON-B; only markup the code builds itself is a sink.
@Path("/items")
@Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
class ItemResource {
    @GET
    @Path("/{name}")
    public Response item(@PathParam("name") String name) {
        // ok: java.xss
        return Response.ok(new ItemView(name)).build();
    }

    @GET
    @Path("/typed/{name}")
    public Response typed(@PathParam("name") String name) {
        // ok: java.xss
        return Response.ok(new ItemView(name), MediaType.APPLICATION_XML).build();
    }

    @GET
    @Path("/missing/{name}")
    public Response missing(@PathParam("name") String name) {
        // ok: java.xss
        return Response.status(404).entity(new ItemView(name)).build();
    }

    @GET
    @Path("/raw/{name}")
    public Response raw(@PathParam("name") String name) {
        // ruleid: java.xss
        return Response.ok("<item>" + name + "</item>").build();
    }

    @GET
    @Path("/raw-typed/{name}")
    public Response rawTyped(@PathParam("name") String name) {
        String body = String.format("<item>%s</item>", name);
        // ruleid: java.xss
        return Response.ok(body, MediaType.APPLICATION_XML).build();
    }

    // Markup returned by a call (here a StringBuilder) is not told apart from a serialised DTO.
    @GET
    @Path("/built/{name}")
    public Response built(@PathParam("name") String name) {
        StringBuilder markup = new StringBuilder("<item>").append(name).append("</item>");
        // todoruleid: java.xss
        return Response.ok(markup.toString()).build();
    }
}

class ItemView {
    private final String name;

    ItemView(String name) {
        this.name = name;
    }

    String getName() {
        return name;
    }
}

// A Jakarta REST class whose methods all produce text/html.
@Path("/html")
@Produces(MediaType.TEXT_HTML)
class HtmlResource {
    @GET
    public String index(@QueryParam("q") String q) {
        // ruleid: java.xss
        return "<p>" + q + "</p>";
    }

    @GET
    @Path("/json")
    @Produces(MediaType.APPLICATION_JSON)
    public String json(@QueryParam("q") String q) {
        // ok: java.xss
        return "{\"q\":\"" + q + "\"}";
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    public String post(NoteForm form) {
        // todoruleid: java.xss
        return "<p>" + form.getText() + "</p>";
    }
}

// Servlet: names chosen by the client, the request URL, multipart parts; values kept in a map.
class EchoServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        PrintWriter out = response.getWriter();
        java.util.Enumeration<String> names = request.getParameterNames();
        // ruleid: java.xss
        out.println("<p>" + names.nextElement() + "</p>");
        java.util.Enumeration<String> headers = request.getHeaderNames();
        // ruleid: java.xss
        out.println("<p>" + headers.nextElement() + "</p>");
        // ruleid: java.xss
        out.println("<a href=\"" + request.getRequestURL() + "\">here</a>");
        // ruleid: java.xss
        out.println("<p>" + request.getPart("file").getSubmittedFileName() + "</p>");
        // ruleid: java.xss
        out.println("<p>" + request.getParts().iterator().next().getName() + "</p>");
        // ruleid: java.xss
        out.println("<p>" + request.getCookies()[0].getValue() + "</p>");
        java.util.Map<String, String> fields = new java.util.HashMap<>();
        fields.put("owner", request.getParameter("owner"));
        fields.put("site", "Acme");
        // ruleid: java.xss
        out.println("<p>" + fields.get("owner") + "</p>");
        // ok: java.xss
        out.println("<p>" + fields.get("site") + "</p>");
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@RestController
class SharedLimitsController {
    private static final String DEFAULT_LABEL = "<b>none</b>";
    private static final Map<String, String> LABELS = Map.of("new", "<b>New</b>", "old", "<i>Old</i>");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("new", "<b>New</b>"), Map.entry("old", "<i>Old</i>"));

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback, HttpServletResponse response)
            throws IOException {
        PrintWriter out = response.getWriter();
        // ok: java.xss
        out.println(LABELS.get(key));
        // ok: java.xss
        out.println(LABELS.getOrDefault(key, DEFAULT_LABEL));
        // ok: java.xss
        out.println(LABELS.getOrDefault(key, "<b>none</b>"));
        // ok: java.xss
        out.println(Map.of("a", "<b>A</b>").get(key));
        // ok: java.xss
        out.println(Shade.valueOf(key).name());
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.xss
        out.println(LABELS.getOrDefault(key, fallback));
        // ruleid: java.xss
        out.println(Map.of("a", "<b>A</b>").getOrDefault(key, key));
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.xss
        out.println(javax.xml.namespace.QName.valueOf(key).getLocalPart());
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.xss
        out.println(ENTRIES.get(key));
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.xss
        out.println(java.time.DayOfWeek.valueOf(key).name());
        return "ok";
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) {
        // todoruleid: java.xss
        return "<p>" + term + "</p>";
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry markup, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam Shade shade, @RequestParam List<Long> ids, @RequestParam Optional<Long> page) {
        // todook: java.xss
        return "<p>" + shade + "</p>";
    }

    @GetMapping("/shared/ids")
    String ids(@RequestParam List<Long> ids) {
        // todook: java.xss
        return "<p>" + ids.get(0) + "</p>";
    }

    @GetMapping("/shared/page")
    String page(@RequestParam Optional<Long> page) {
        // todook: java.xss
        return "<p>" + page.orElse(0L) + "</p>";
    }
}

enum Shade {
    LIGHT, DARK
}

class SharedSwitchServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        char mode = "abc".charAt(0);
        String chosen;
        switch (mode) {
            case 0x61:
                chosen = "<p>default</p>";
                break;
            default:
                chosen = request.getParameter("chosen");
        }
        // A switch over a value computed from constants always takes the same branch.
        // todook: java.xss
        response.getWriter().println(chosen);
    }
}

// The request body of a Spring MVC HttpEntity or RequestEntity parameter, and HTML assembled in
// an append chain (StringBuilder.append(...).append(value)).
@RestController
class EntityPageController {
    @PostMapping("/entity/echo")
    String echo(HttpEntity<String> entity) {
        // ruleid: java.xss
        return "<p>" + entity.getBody() + "</p>";
    }

    @RequestMapping("/entity/preview")
    String preview(RequestEntity<String> request) {
        // ruleid: java.xss
        return "<div>" + request.getBody() + "</div>";
    }

    @PostMapping
    String agent(org.springframework.http.HttpEntity<NoteForm> entity) {
        // ruleid: java.xss
        return "<em>" + entity.getHeaders().getFirst("User-Agent") + "</em>";
    }

    @GetMapping("/entity/chain")
    String chain(@RequestParam String term) {
        StringBuilder html = new StringBuilder();
        html.append("<ul>").append("<li>").append(term).append("</li></ul>");
        // ruleid: java.xss
        return html.toString();
    }

    @GetMapping("/entity/fixed")
    String fixed(@RequestParam String term) {
        StringBuilder html = new StringBuilder();
        html.append("<ul>").append("<li>").append(HtmlUtils.htmlEscape(term)).append("</li></ul>");
        // ok: java.xss
        return html.toString();
    }

    // Not a handler method: an entity it is given is not request data.
    void replay(HttpEntity<String> entity, HttpServletResponse response) throws IOException {
        // ok: java.xss
        response.getWriter().println(entity.getBody());
    }
}

// The other spellings of the shared request sources and sanitizers.
@RestController
class SharedFormsController {
    private static final Map<String, String> FORMS = Map.of("a", "<b>A</b>", "b", "<b>A</b>");

    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        // ok: java.xss
        out.println("<p>" + Map.of("a", "<b>A</b>", "b", "<b>A</b>").get(key) + "</p>");
        // ok: java.xss
        out.println("<p>" + Map.of("a", "<b>A</b>").getOrDefault(key, "<b>A</b>") + "</p>");
        // ok: java.xss
        out.println("<p>" + FORMS.get(key) + "</p>");
        // ok: java.xss
        out.println("<p>" + FORMS.getOrDefault(key, "<b>A</b>") + "</p>");
        // ok: java.xss
        out.println("<p>" + String.valueOf(Integer.parseInt(n)) + "</p>");
        // ok: java.xss
        out.println("<p>" + String.valueOf(Long.parseLong(n)) + "</p>");
        // ok: java.xss
        out.println("<p>" + String.valueOf(Integer.valueOf(n)) + "</p>");
        // ok: java.xss
        out.println("<p>" + String.valueOf(Long.valueOf(n)) + "</p>");
        // ok: java.xss
        out.println("<p>" + Enum.valueOf(FormKind.class, key).name() + "</p>");
        // ok: java.xss
        out.println("<p>" + java.lang.Enum.valueOf(FormKind.class, key).name() + "</p>");
        // An enum declared inside the class.
        // ok: java.xss
        out.println("<p>" + Level.valueOf(key).name() + "</p>");
        // An enum declared before the first class of the file.
        // ok: java.xss
        out.println("<p>" + EarlierKind.valueOf(key).name() + "</p>");
        // An enum declared after the class.
        // ok: java.xss
        out.println("<p>" + FormKind.valueOf(key).name() + "</p>");
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.xss
        out.println("<p>" + single.toString() + "</p>");
        return "ok";
    }

    // A part of a multipart request bound with @RequestPart (text, or a body converted with an
    // HttpMessageConverter).
    @org.springframework.web.bind.annotation.PostMapping("/shared/part")
    String part(@RequestPart("meta") String meta, @org.springframework.web.bind.annotation.RequestPart("note") PartNote note,
            @RequestPart("count") int count, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.println("<p>" + meta + "</p>");
        // ruleid: java.xss
        out.println("<p>" + note.getText() + "</p>");
        // A part converted to a number cannot carry injected text.
        // ok: java.xss
        out.println("<p>" + String.valueOf(count) + "</p>");
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // Servlet request types of both namespaces.
    void jakartaRequest(jakarta.servlet.ServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.println("<p>" + request.getParameter("q") + "</p>");
    }

    void javaxRequest(javax.servlet.ServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.println("<p>" + request.getParameter("q") + "</p>");
    }

    void javaxHttpRequest(javax.servlet.http.HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.println("<p>" + request.getParameter("q") + "</p>");
    }

    void jakartaHttpRequest(jakarta.servlet.http.HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.println("<p>" + request.getParameter("q") + "</p>");
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
