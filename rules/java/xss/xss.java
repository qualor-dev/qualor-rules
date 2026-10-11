package com.acme.pages;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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

// The first class of the file: an enum nested in it, used after its declaration, by its simple
// name and by its qualified name.
@RestController
class NestedEnumController {
    static class Sizes {
        enum Size {
            SMALL, LARGE
        }
    }

    enum Column {
        NAME, PRICE;

        static String valueOf(String text, boolean lenient) {
            return lenient ? text.toUpperCase() : text;
        }
    }

    @GetMapping("/shared/nested-enum")
    String nestedEnum(@RequestParam String key, @RequestParam String n, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        // ok: java.xss
        out.println("<p>" + Column.valueOf(key).name() + "</p>");
        // ok: java.xss
        out.println("<p>" + NestedEnumController.Column.valueOf(key).name() + "</p>");
        // An overload of valueOf that the enum declares itself may hand the text back.
        // ruleid: java.xss
        out.println("<p>" + Column.valueOf(key, true) + "</p>");
        // A class of another package with the same simple name is not this file's enum.
        // ruleid: java.xss
        out.println("<p>" + com.acme.other.Column.valueOf(key).name() + "</p>");
        // An enum nested in a class or an interface declared later in the file, qualified.
        // ok: java.xss
        out.println("<p>" + SharedFormsController.Level.valueOf(key).name() + "</p>");
        // ok: java.xss
        out.println("<p>" + LateKinds.Kind.valueOf(key).name() + "</p>");
        // An enum nested in a nested class, named from outside that class, is not recognised.
        // todook: java.xss
        out.println("<p>" + Sizes.Size.valueOf(key).name() + "</p>");
        return "ok";
    }
}

// Enums nested in interfaces, before and after the classes that use them.
interface EarlyKinds {
    enum Kind {
        SMALL, LARGE
    }
}

// An enum declared before the other classes (the shared enum allow-list forms).
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
        // A helper of this file that returns a constant (or encodes the value) is followed.
        // ok: java.xss
        out.println("<p>" + escaped(term) + "</p>");
        // A helper of another file is not looked into: it passes the request data on.
        // todook: java.xss
        out.println("<p>" + com.acme.shop.web.Html.escaped(term) + "</p>");
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

    private final com.fasterxml.jackson.dataformat.xml.XmlMapper xmlMapper = new com.fasterxml.jackson.dataformat.xml.XmlMapper();

    // A serialiser's output kept in a String variable: the mapper escapes the DTO's text.
    @GET
    @Path("/mapped/{name}")
    public Response mapped(@PathParam("name") String name) throws Exception {
        String xml = xmlMapper.writeValueAsString(new ItemView(name));
        // ok: java.xss
        return Response.ok(xml, MediaType.APPLICATION_XML).build();
    }

    @GET
    @Path("/mapped-entity/{name}")
    public Response mappedEntity(@PathParam("name") String name) throws Exception {
        String xml = xmlMapper.writeValueAsString(new ItemView(name));
        // ok: java.xss
        return Response.status(200).entity(xml).type(MediaType.APPLICATION_XML_TYPE).build();
    }

    @GET
    @Path("/mapped-plain/{name}")
    public Response mappedPlain(@PathParam("name") String name) throws Exception {
        String xml = xmlMapper.writeValueAsString(new ItemView(name));
        // ok: java.xss
        return Response.ok(xml).build();
    }

    // Markup the method builds in a String variable: a concatenation or String.format.
    @GET
    @Path("/joined/{name}")
    public Response joined(@PathParam("name") String name) {
        String body = "<item>" + name + "</item>";
        // ruleid: java.xss
        return Response.ok(body).build();
    }

    @GET
    @Path("/joined-entity/{name}")
    public Response joinedEntity(@PathParam("name") String name) {
        String body = "<item>" + name + "</item>";
        // ruleid: java.xss
        return Response.status(201).entity(body).type(MediaType.APPLICATION_XML_TYPE).build();
    }

    @GET
    @Path("/formatted/{name}")
    public Response formatted(@PathParam("name") String name) {
        String body;
        body = String.format("<item>%s</item>", name);
        // ruleid: java.xss
        return Response.ok(body).build();
    }

    @GET
    @Path("/appended/{name}")
    public Response appended(@PathParam("name") String name) {
        String body = "<item>";
        body += name;
        // ruleid: java.xss
        return Response.ok(body, MediaType.APPLICATION_XML).build();
    }

    @GET
    @Path("/concatenated/{name}")
    public Response concatenated(@PathParam("name") String name) {
        String body = "<item>".concat(name).concat("</item>");
        // ruleid: java.xss
        return Response.ok(body, MediaType.APPLICATION_XML).build();
    }

    // Constant text joined to a serialiser's output counts as markup the method builds.
    @GET
    @Path("/declared/{name}")
    public Response declared(@PathParam("name") String name) throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + xmlMapper.writeValueAsString(new ItemView(name));
        // todook: java.xss
        return Response.ok(xml, MediaType.APPLICATION_XML).build();
    }

    // Request text sent as an XML entity as it is (in place or through a variable) is not
    // markup the method builds, and is not reported.
    @GET
    @Path("/as-is/{name}")
    public Response asIs(@PathParam("name") String name) {
        String body = name;
        // todoruleid: java.xss
        return Response.ok(body, MediaType.APPLICATION_XML).build();
    }
}

// A String return under an XML type counts as markup, also when it is a serialiser's output.
@Path("/mapped-items")
class MappedItemResource {
    private final com.fasterxml.jackson.dataformat.xml.XmlMapper xmlMapper = new com.fasterxml.jackson.dataformat.xml.XmlMapper();

    @GET
    @Path("/{name}")
    @Produces(MediaType.APPLICATION_XML)
    public String item(@PathParam("name") String name) throws Exception {
        // todook: java.xss
        return xmlMapper.writeValueAsString(new ItemView(name));
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
        // A literal Map.ofEntries table: a lookup yields its values, which hold no request data.
        // ok: java.xss
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
        // An enum nested in the first class, or in an interface declared before this class, qualified.
        // ok: java.xss
        out.println("<p>" + NestedEnumController.Column.valueOf(key).name() + "</p>");
        // ok: java.xss
        out.println("<p>" + EarlyKinds.Kind.valueOf(key).name() + "</p>");
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
        // Text put in with insert or replace (StringBuilder and StringBuffer), by the declared
        // type or by a builder created in the method.
        StringBuilder chosen = Boolean.getBoolean("compact") ? new StringBuilder() : new StringBuilder("a");
        chosen.insert(0, key, 0, key.length());
        // ruleid: java.xss
        out.println("<p>" + chosen.toString() + "</p>");
        StringBuffer typed = Boolean.getBoolean("compact") ? new StringBuffer() : new StringBuffer("a");
        typed.replace(0, 1, key);
        // ruleid: java.xss
        out.println("<p>" + typed.toString() + "</p>");
        var spliced = new StringBuilder();
        spliced.append("a").insert(0, key);
        // ruleid: java.xss
        out.println("<p>" + spliced.toString() + "</p>");
        var swapped = new StringBuffer();
        swapped.append("a").replace(0, 1, key);
        // ruleid: java.xss
        out.println("<p>" + swapped.toString() + "</p>");
        // Another class's replace (Map.replace) carries nothing into its object (and the map's
        // size is a number).
        java.util.Map<String, String> labels = new java.util.HashMap<>();
        labels.replace("k", "old", key);
        // ok: java.xss
        out.println("<p>" + String.valueOf(labels.size()) + "</p>");
        // OpenGrep's --taint-intrafile mode takes a two-argument insert on a class without a body
        // in this file (a MyBatis session) for a container write: what the session returns
        // afterwards is taken for request data.
        org.apache.ibatis.session.SqlSession session = MyBatisSessions.open();
        session.insert("notes.add", key);
        // todook: java.xss
        out.println("<p>" + String.valueOf(session.selectOne("notes.latest")) + "</p>");
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

// Results of calls that other rules check as sinks (a database query, a command, a file read, a
// URL fetched by the server, a directory search, an XPath selection) are data from that store,
// not request data: when request data built the call, that rule reports it.
class SinkResultsServlet extends HttpServlet {
    private java.sql.Connection connection;
    private javax.sql.DataSource dataSource;
    private org.springframework.jdbc.core.JdbcTemplate jdbc;
    private jakarta.persistence.EntityManager em;
    private org.springframework.web.client.RestTemplate rest;
    private java.net.http.HttpClient http;
    private javax.naming.directory.DirContext directory;
    private javax.xml.xpath.XPath xpath;
    private org.w3c.dom.Document catalog;
    private EchoService echo;
    private org.springframework.jdbc.core.JdbcOperations jdbcOps;
    private org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate named;
    private org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations namedOps;
    private javax.persistence.EntityManager legacyEm;
    private org.hibernate.Session session;
    private org.springframework.web.client.RestOperations restOps;
    private org.springframework.ldap.core.LdapTemplate ldap;
    private org.springframework.web.client.RestClient restClient;
    private UserRepository users;
    private com.acme.shop.data.BioRepository bios;
    private String notePath = "/order/note";
    private String configuredPath;
    private static final String PROFILES = "https://api.example.com/profiles/";
    private static final String API_HOST = "https://api.example.com";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        String name = request.getParameter("name");
        try {
            java.sql.Statement stmt = connection.createStatement();
            java.sql.ResultSet rs = stmt.executeQuery("SELECT bio FROM users WHERE name = '" + name + "'");
            while (rs.next()) {
                // ok: java.xss
                out.println("<p>" + rs.getString(1) + "</p>");
            }
            java.sql.PreparedStatement ps = connection.prepareStatement("SELECT bio FROM users WHERE name = '" + name + "'");
            java.sql.ResultSet prepared = ps.executeQuery();
            prepared.next();
            // ok: java.xss
            out.println("<p>" + prepared.getString("bio") + "</p>");
            var conn = dataSource.getConnection();
            var st = conn.createStatement();
            var rows = st.executeQuery("SELECT bio FROM users WHERE name = '" + name + "'");
            rows.next();
            // ok: java.xss
            out.println("<p>" + rows.getString(1) + "</p>");
            // The request value printed next to the row is still request data.
            // ruleid: java.xss
            out.println("<p>" + name + ": " + rs.getString(1) + "</p>");
            // ok: java.xss
            out.println("<p>" + connection.createStatement().executeQuery("SELECT bio FROM users WHERE name = '" + name + "'").getString(1) + "</p>");
            // ok: java.xss
            out.println("<p>" + connection.prepareStatement("SELECT bio FROM users WHERE name = '" + name + "'").executeQuery().getString(1) + "</p>");
            java.sql.CallableStatement call = connection.prepareCall("{call find_bio('" + name + "')}");
            // ok: java.xss
            out.println("<p>" + call.executeQuery().getString(1) + "</p>");
        } catch (java.sql.SQLException e) {
            throw new IOException(e);
        }
        // ok: java.xss
        out.println("<p>" + jdbcOps.queryForList("SELECT bio FROM users WHERE name = '" + name + "'") + "</p>");
        // ok: java.xss
        out.println("<p>" + named.queryForList("SELECT bio FROM users WHERE name = '" + name + "'", Map.of()) + "</p>");
        // ok: java.xss
        out.println("<p>" + namedOps.queryForList("SELECT bio FROM users WHERE name = '" + name + "'", Map.of()) + "</p>");
        // ok: java.xss
        out.println("<p>" + legacyEm.createQuery("SELECT u.bio FROM User u WHERE u.name = '" + name + "'").getResultList() + "</p>");
        // ok: java.xss
        out.println("<p>" + session.createQuery("SELECT u.bio FROM User u WHERE u.name = '" + name + "'").list() + "</p>");
        jakarta.persistence.Query nativeBios = em.createNativeQuery("SELECT bio FROM users WHERE name = '" + name + "'");
        // ok: java.xss
        out.println("<p>" + nativeBios.getResultList() + "</p>");
        javax.persistence.Query legacyBios = legacyEm.createNativeQuery("SELECT bio FROM users WHERE name = '" + name + "'");
        // ok: java.xss
        out.println("<p>" + legacyBios.getSingleResult() + "</p>");
        javax.persistence.TypedQuery<String> legacyTyped = legacyEm.createQuery("SELECT u.bio FROM User u WHERE u.name = '" + name + "'", String.class);
        // ok: java.xss
        out.println("<p>" + legacyTyped.getResultList() + "</p>");
        // A repository interface of this file: its method passes nothing on.
        // ok: java.xss
        out.println("<p>" + users.findBioByName(name) + "</p>");
        // A repository of another file or a client of another library: its result is still taken
        // for request data when the request value is its argument.
        // todook: java.xss
        out.println("<p>" + bios.findBioByName(name) + "</p>");
        // todook: java.xss
        out.println(restClient.get().uri("https://api.example.com/profiles/" + name).retrieve().body(String.class));
        // ok: java.xss
        out.println("<p>" + jdbc.queryForObject("SELECT bio FROM users WHERE name = ?", String.class, name) + "</p>");
        // ok: java.xss
        out.println("<p>" + jdbc.queryForList("SELECT bio FROM users WHERE name = '" + name + "'") + "</p>");
        // ok: java.xss
        out.println("<p>" + em.createQuery("SELECT u.bio FROM User u WHERE u.name = '" + name + "'").getResultList() + "</p>");
        // ok: java.xss
        out.println("<p>" + em.createQuery("SELECT u.bio FROM User u WHERE u.name = :n", String.class).setParameter("n", name).getSingleResult() + "</p>");
        jakarta.persistence.TypedQuery<String> bios = em.createQuery("SELECT u.bio FROM User u WHERE u.name = '" + name + "'", String.class);
        // ok: java.xss
        out.println("<p>" + bios.getResultList() + "</p>");
        // A method of another class with a sink's name returns what it is given.
        // ruleid: java.xss
        out.println("<p>" + echo.executeQuery(name) + "</p>");
    }

    // Command output, file content, fetched responses, directory entries, XPath selections.
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        String host = request.getParameter("host");
        String file = request.getParameter("file");
        Process ping = Runtime.getRuntime().exec("ping -c 1 " + host);
        // ok: java.xss
        out.println("<pre>" + new String(ping.getInputStream().readAllBytes()) + "</pre>");
        Runtime runtime = Runtime.getRuntime();
        Process uptime = runtime.exec("uptime -p " + host);
        // ok: java.xss
        out.println("<pre>" + new String(uptime.getInputStream().readAllBytes()) + "</pre>");
        // A fixed program given request data as arguments (no command-injection finding): its
        // output can echo the request data back.
        Process trace = runtime.exec(new String[] {"traceroute", host});
        // ruleid: java.xss
        out.println("<pre>" + new String(trace.getInputStream().readAllBytes()) + "</pre>");
        String[] argv = {"whois", host};
        Process whois = runtime.exec(argv);
        // ruleid: java.xss
        out.println("<pre>" + new String(whois.getInputStream().readAllBytes()) + "</pre>");
        Process dig = Runtime.getRuntime().exec(List.of("dig", host).toArray(new String[0]));
        // ruleid: java.xss
        out.println("<pre>" + new String(dig.getInputStream().readAllBytes()) + "</pre>");
        Process echoed = new ProcessBuilder("echo", host).redirectErrorStream(true).start();
        // ruleid: java.xss
        out.println("<pre>" + new String(echoed.getInputStream().readAllBytes()) + "</pre>");
        var lookup = new ProcessBuilder("nslookup", host).start();
        // ruleid: java.xss
        out.println("<pre>" + lookup.inputReader().readLine() + "</pre>");
        // A shell started by ProcessBuilder with request data in its script: command-injection
        // reports it, and its output is still request data here (a second finding).
        Process shell = new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();
        // todook: java.xss
        out.println("<pre>" + new String(shell.getInputStream().readAllBytes()) + "</pre>");
        // ok: java.xss
        out.println("<pre>" + java.nio.file.Files.readString(java.nio.file.Path.of("/srv/docs", file)) + "</pre>");
        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader("/srv/docs/" + file));
        // ok: java.xss
        out.println("<pre>" + reader.readLine() + "</pre>");
        // ok: java.xss
        out.println(rest.getForObject("https://api.example.com/profiles/" + host, String.class));
        // A body fetched from a URL the request chooses is the requester's own content.
        // ruleid: java.xss
        out.println(new String(new java.net.URL("https://" + host + "/status").openStream().readAllBytes()));
        java.net.URL statusUrl = new java.net.URL("https://" + host + "/health");
        // ruleid: java.xss
        out.println(new String(statusUrl.openStream().readAllBytes()));
        java.net.URLConnection opened = statusUrl.openConnection();
        // ruleid: java.xss
        out.println(new String(opened.getInputStream().readAllBytes()));
        java.net.HttpURLConnection httpConn = (java.net.HttpURLConnection) statusUrl.openConnection();
        // ruleid: java.xss
        out.println(new String(httpConn.getErrorStream().readAllBytes()));
        // ruleid: java.xss
        out.println(rest.getForObject(request.getParameter("url"), String.class));
        // ruleid: java.xss
        out.println(rest.getForObject("https://" + host + "/profile", String.class));
        // From a fixed origin: the request data only reaches the path.
        // ok: java.xss
        out.println(new String(new java.net.URL("https://status.example.com/hosts/" + host).openStream().readAllBytes()));
        // ok: java.xss
        out.println(new String(new java.net.URL("https://status.example.com/hosts?name=" + host).openConnection().getInputStream().readAllBytes()));
        java.net.URL fixedUrl = new java.net.URL("https://status.example.com/hosts/" + host);
        // ok: java.xss
        out.println(new String(fixedUrl.openStream().readAllBytes()));
        // ok: java.xss
        out.println(new String(fixedUrl.openConnection().getInputStream().readAllBytes()));
        // ok: java.xss
        out.println(rest.getForObject("https://api.example.com/profiles/{id}", String.class, host));
        // A scheme and a host from the request, or "//" after the origin, are not a fixed origin.
        // ruleid: java.xss
        out.println(rest.getForObject("https://api.example.com" + host, String.class));
        // ruleid: java.xss
        out.println(rest.getForObject("https://api.example.com//" + host, String.class));
        // A base held in a static final String that ends with the separator.
        // ok: java.xss
        out.println(rest.getForObject(PROFILES + host, String.class));
        // ok: java.xss
        out.println(restOps.getForObject(PROFILES + host + "/card", String.class));
        // ok: java.xss
        out.println(rest.getForObject(PROFILES + host + "/card", String.class));
        // ok: java.xss
        out.println(restOps.getForObject(PROFILES + host, String.class));
        // A constant without the separator does not fix the host.
        // ruleid: java.xss
        out.println(rest.getForObject(API_HOST + host, String.class));
        // A java.net.URL from such a base, in place or through a variable.
        // ok: java.xss
        out.println(new String(new java.net.URL(PROFILES + host).openStream().readAllBytes()));
        // ok: java.xss
        out.println(new String(new java.net.URL(PROFILES + host + "/card").openConnection().getInputStream().readAllBytes()));
        // ok: java.xss
        out.println(new String(new java.net.URL(PROFILES + host + "/card").openStream().readAllBytes()));
        // ok: java.xss
        out.println(new String(new java.net.URL(PROFILES + host).openConnection().getInputStream().readAllBytes()));
        java.net.URL profileUrl = new java.net.URL(PROFILES + host);
        // ok: java.xss
        out.println(new String(profileUrl.openStream().readAllBytes()));
        java.net.URL cardUrl = new java.net.URL(PROFILES + host + "/card");
        // ok: java.xss
        out.println(new String(cardUrl.openConnection().getInputStream().readAllBytes()));
        // ... not from a constant without the separator.
        // ruleid: java.xss
        out.println(new String(new java.net.URL(API_HOST + host).openStream().readAllBytes()));
        // The URL itself, from a fixed origin too, still holds the request data.
        // ruleid: java.xss
        out.println("<p>" + new java.net.URL(PROFILES + host).getPath() + "</p>");
        // ruleid: java.xss
        out.println("<p>" + fixedUrl.getQuery() + "</p>");
        java.net.URL apiUrl = new java.net.URL(API_HOST + host + "/card");
        // ruleid: java.xss
        out.println(new String(apiUrl.openConnection().getInputStream().readAllBytes()));
        // ok: java.xss
        out.println(restOps.getForObject("https://api.example.com/profiles/" + host, String.class));
        // ok: java.xss
        out.println(ldap.search("ou=people", "(uid=" + host + ")", (org.springframework.ldap.core.AttributesMapper<String>) a -> "x"));
        // ok: java.xss
        out.println(ldap.searchForObject("ou=people", "(uid=" + host + ")", ctx -> ctx));
        try {
            java.net.http.HttpResponse<String> fetched = http.send(
                    java.net.http.HttpRequest.newBuilder(java.net.URI.create("https://" + host + "/status")).build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            // ruleid: java.xss
            out.println(fetched.body());
            java.net.http.HttpResponse<String> fixedFetch = http.send(
                    java.net.http.HttpRequest.newBuilder(java.net.URI.create("https://status.example.com/hosts/" + host)).build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            // An HttpClient fetch from a fixed origin: the request data only reaches the path.
            // ok: java.xss
            out.println(fixedFetch.body());
            javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> found =
                    directory.search("ou=people,dc=example,dc=com", "(uid=" + host + ")", new javax.naming.directory.SearchControls());
            // ok: java.xss
            out.println("<p>" + found.next().getAttributes().get("cn") + "</p>");
            javax.naming.directory.InitialDirContext initial = new javax.naming.directory.InitialDirContext();
            // ok: java.xss
            out.println("<p>" + initial.search("ou=people,dc=example,dc=com", "(uid=" + host + ")", new javax.naming.directory.SearchControls()).next() + "</p>");
            javax.xml.xpath.XPathExpression price = xpath.compile("/catalog/book[title='" + file + "']/price");
            // A compiled expression: xpath-injection reports the compile, and its result is still
            // taken for request data here.
            // todook: java.xss
            out.println("<p>" + price.evaluate(catalog) + "</p>");
            org.xml.sax.InputSource uploaded = new org.xml.sax.InputSource(new java.io.StringReader(request.getParameter("xml")));
            // A constant expression over a document the request supplies selects request data.
            // ruleid: java.xss
            out.println("<p>" + xpath.evaluate("/order/note", uploaded) + "</p>");
            // ... also with an expression from a field that holds a literal.
            // ruleid: java.xss
            out.println("<p>" + xpath.evaluate(notePath, uploaded) + "</p>");
            // An expression from a field set elsewhere is not seen as constant.
            // todoruleid: java.xss
            out.println("<p>" + xpath.evaluate(configuredPath, uploaded) + "</p>");
            // ok: java.xss
            out.println("<p>" + xpath.evaluate("/catalog/book[title='" + file + "']/price", catalog) + "</p>");
        } catch (InterruptedException | javax.naming.NamingException | javax.xml.xpath.XPathExpressionException e) {
            throw new IOException(e);
        }
        // The file name itself is still request data.
        // ruleid: java.xss
        out.println("<p>Showing " + file + "</p>");
    }
}

// A Statement handed in by the caller: only its declared type tells what it is.
class StatementHelper {
    static void print(java.sql.Statement stmt, HttpServletRequest request, HttpServletResponse response) throws java.sql.SQLException, IOException {
        PrintWriter out = response.getWriter();
        java.sql.ResultSet rs = stmt.executeQuery("SELECT bio FROM users WHERE name = '" + request.getParameter("name") + "'");
        rs.next();
        // ok: java.xss
        out.println("<p>" + rs.getString(1) + "</p>");
    }
}

interface UserRepository {
    String findBioByName(String name);
}

class EchoService {
    String executeQuery(String text) {
        return text;
    }
}

// Each form of the response sinks once, with the values that keep it quiet (one line per form of
// the rule, so that no form goes untested).
class ResponseFormsServlet {
    void javaxHttp(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        // ruleid: java.xss
        response.getWriter().print(name);
        // ruleid: java.xss
        response.getWriter().append("<p>").print(name);
        java.io.PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.println(name);
        try (java.io.PrintWriter scoped = response.getWriter()) {
            // ruleid: java.xss
            scoped.write(name);
        }
        java.io.PrintStream wrapped = new java.io.PrintStream(response.getOutputStream());
        // ruleid: java.xss
        wrapped.print(name);
    }

    void javaxPlain(javax.servlet.ServletRequest request, javax.servlet.ServletResponse response) throws IOException {
        String name = request.getParameter("name");
        // ruleid: java.xss
        response.getWriter().print(name);
        // ruleid: java.xss
        response.getWriter().append("<p>").print(name);
        java.io.PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.println(name);
        try (java.io.PrintWriter scoped = response.getWriter()) {
            // ruleid: java.xss
            scoped.write(name);
        }
        java.io.PrintStream wrapped = new java.io.PrintStream(response.getOutputStream());
        // ruleid: java.xss
        wrapped.print(name);
    }

    void jakartaPlain(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) throws IOException {
        String name = request.getParameter("name");
        // ruleid: java.xss
        response.getWriter().print(name);
        // ruleid: java.xss
        response.getWriter().append("<p>").print(name);
        java.io.PrintWriter out = response.getWriter();
        // ruleid: java.xss
        out.println(name);
        try (java.io.PrintWriter scoped = response.getWriter()) {
            // ruleid: java.xss
            scoped.write(name);
        }
        java.io.PrintStream wrapped = new java.io.PrintStream(response.getOutputStream());
        // ruleid: java.xss
        wrapped.print(name);
    }
}

@RestController
class ResponseFormsController {
    // Not a request mapping: what it returns goes to no response.
    @Deprecated
    String label(@RequestParam String q) {
        // ok: java.xss
        return q;
    }

    @Deprecated
    ResponseEntity<String> labelEntity(@RequestParam String q) {
        // ok: java.xss
        return ResponseEntity.ok(q);
    }

    @GetMapping("/forms/created")
    ResponseEntity<String> created(@RequestParam String q) {
        // ruleid: java.xss
        return new ResponseEntity<String>(q, org.springframework.http.HttpStatus.CREATED);
    }

    // A ResponseEntity<String> handler whose mapping produces JSON.
    @GetMapping(value = "/forms/json", produces = "application/json")
    ResponseEntity<String> json(@RequestParam String q) {
        // ok: java.xss
        return ResponseEntity.ok(q);
    }

    // ... and one whose mapping produces HTML.
    @GetMapping(value = "/forms/page", produces = "text/html")
    ResponseEntity<String> page(@RequestParam String q) {
        // ruleid: java.xss
        return ResponseEntity.ok(q);
    }

    @GetMapping(value = "/forms/page-json", produces = "text/html")
    ResponseEntity<String> pageJson(@RequestParam String q) {
        // ok: java.xss
        return ResponseEntity.ok().contentType(org.springframework.http.MediaType.APPLICATION_JSON).body(q);
    }
}

@Path("/forms")
class ResponseFormsResource {
    private final com.fasterxml.jackson.dataformat.xml.XmlMapper xmlMapper = new com.fasterxml.jackson.dataformat.xml.XmlMapper();

    // A number written as HTML or XML carries no markup.
    @GET
    @Path("/length")
    @Produces(MediaType.TEXT_HTML)
    public int length(@QueryParam("q") String q) {
        // ok: java.xss
        return q.length();
    }

    @GET
    @Path("/length-xml")
    @Produces(MediaType.APPLICATION_XML)
    public int lengthXml(@QueryParam("q") String q) {
        // ok: java.xss
        return q.length();
    }

    @GET
    @Path("/status")
    @Produces(MediaType.TEXT_HTML)
    public Response status(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.status(200).entity("<p>" + q + "</p>").build();
    }

    @GET
    @Path("/status-xml")
    @Produces(MediaType.APPLICATION_XML)
    public Response statusXml(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.status(200).entity("<item>" + q + "</item>").build();
    }

    @GET
    @Path("/status-formatted")
    @Produces(MediaType.APPLICATION_XML)
    public Response statusFormatted(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.status(200).entity(String.format("<item>%s</item>", q)).build();
    }

    @GET
    @Path("/formatted")
    @Produces(MediaType.APPLICATION_XML)
    public Response formatted(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.ok(String.format("<item>%s</item>", q)).build();
    }

    @GET
    @Path("/appended")
    @Produces(MediaType.APPLICATION_XML)
    public Response appended(@QueryParam("q") String q) {
        String body = "<item>";
        body += q;
        // ruleid: java.xss
        return Response.ok(body).build();
    }

    @GET
    @Path("/concatenated")
    @Produces(MediaType.APPLICATION_XML)
    public Response concatenated(@QueryParam("q") String q) {
        String body = "<item>".concat(q);
        // ruleid: java.xss
        return Response.ok(body).build();
    }

    // An annotation that names HTML or XML but is no @Produces: the response is plain text.
    @POST
    @Path("/echo")
    @jakarta.ws.rs.Consumes(MediaType.TEXT_HTML)
    @Produces(MediaType.TEXT_PLAIN)
    public String echo(@QueryParam("q") String q) {
        // ok: java.xss
        return q;
    }

    @POST
    @Path("/echo-xml")
    @jakarta.ws.rs.Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.TEXT_PLAIN)
    public String echoXml(@QueryParam("q") String q) {
        // ok: java.xss
        return q;
    }

    // A response given its type: HTML, or XML and SVG for markup the method builds.
    @GET
    @Path("/typed-entity")
    public Response typedEntity(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.status(200).entity(q).type("text/html").build();
    }

    @GET
    @Path("/typed-first")
    public Response typedFirst(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.status(200).type("text/html").entity(q).build();
    }

    @GET
    @Path("/xml-in-place")
    public Response xmlInPlace(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.ok("<item>" + q + "</item>", "application/xml").build();
    }

    @GET
    @Path("/xml-formatted")
    public Response xmlFormatted(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.ok(String.format("<item>%s</item>", q)).type("application/xml").build();
    }

    @GET
    @Path("/xml-entity")
    public Response xmlEntity(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.status(200).entity("<item>" + q + "</item>").type("application/xml").build();
    }

    @GET
    @Path("/svg-entity")
    public Response svgEntity(@QueryParam("q") String q) {
        // ruleid: java.xss
        return Response.status(200).type("image/svg+xml").entity(String.format("<svg>%s</svg>", q)).build();
    }

    @GET
    @Path("/xml-forms")
    public Response xmlForms(@QueryParam("q") String q, int kind) {
        if (kind == 1) {
            // ruleid: java.xss
            return Response.ok(String.format("<item>%s</item>", q), "application/xml").build();
        }
        if (kind == 2) {
            // ruleid: java.xss
            return Response.status(200).entity(String.format("<item>%s</item>", q)).type("application/xml").build();
        }
        if (kind == 3) {
            // ruleid: java.xss
            return Response.status(200).type("application/xml").entity("<item>" + q + "</item>").build();
        }
        // ruleid: java.xss
        return Response.ok("<item>" + q + "</item>").type("application/xml").build();
    }

    @GET
    @Path("/xml-formatted-variable")
    public Response xmlFormattedVariable(@QueryParam("q") String q) {
        String body = String.format("<item>%s</item>", q);
        // ruleid: java.xss
        return Response.ok(body).type("application/xml").build();
    }

    @GET
    @Path("/xml-joined")
    public Response xmlJoined(@QueryParam("q") String q) {
        String body = "<item>" + q + "</item>";
        // ruleid: java.xss
        return Response.ok(body).type("application/xml").build();
    }

    @GET
    @Path("/xml-concatenated")
    public Response xmlConcatenated(@QueryParam("q") String q) {
        String body = "<item>".concat(q);
        // ruleid: java.xss
        return Response.ok(body).type("application/xml").build();
    }

    @GET
    @Path("/xml-appended")
    public Response xmlAppended(@QueryParam("q") String q) {
        String body = "<item>";
        body += q;
        // ruleid: java.xss
        return Response.ok(body).type("application/xml").build();
    }

    // The same markup sent as JSON, and a serialiser's output sent as XML.
    @GET
    @Path("/json-in-place")
    public Response jsonInPlace(@QueryParam("q") String q) {
        // ok: java.xss
        return Response.ok("<item>" + q + "</item>", "application/json").build();
    }

    @GET
    @Path("/xml-mapped")
    public Response xmlMapped(@QueryParam("q") String q) throws Exception {
        String xml = xmlMapper.writeValueAsString(new ItemView(q));
        // ok: java.xss
        return Response.ok(xml).type("application/xml").build();
    }

    @GET
    @Path("/xml-mapped-entity")
    public Response xmlMappedEntity(@QueryParam("q") String q) throws Exception {
        String xml = xmlMapper.writeValueAsString(new ItemView(q));
        // ok: java.xss
        return Response.status(200).type("application/xml").entity(xml).build();
    }
}

// Classes whose @Produces names HTML or XML, with a method that sets its own type.
@Path("/forms-html")
@Produces(MediaType.TEXT_HTML)
class ResponseFormsHtmlResource {
    @GET
    @Path("/length")
    public int length(@QueryParam("q") String q) {
        // ok: java.xss
        return q.length();
    }

    @GET
    @Path("/json")
    @javax.ws.rs.Produces("application/json")
    public String json(@QueryParam("q") String q) {
        // ok: java.xss
        return "{\"q\":\"" + q + "\"}";
    }
}

@Path("/forms-xml")
@Produces(MediaType.APPLICATION_XML)
class ResponseFormsXmlResource {
    @GET
    @Path("/name")
    public String name(@QueryParam("q") String q) {
        // ruleid: java.xss
        return "<name>" + q + "</name>";
    }

    @GET
    @Path("/length")
    public int length(@QueryParam("q") String q) {
        // ok: java.xss
        return q.length();
    }

    @GET
    @Path("/json")
    @Produces(MediaType.APPLICATION_JSON)
    public String json(@QueryParam("q") String q) {
        // ok: java.xss
        return "{\"q\":\"" + q + "\"}";
    }

    @GET
    @Path("/json-javax")
    @javax.ws.rs.Produces("application/json")
    public String jsonJavax(@QueryParam("q") String q) {
        // ok: java.xss
        return "{\"q\":\"" + q + "\"}";
    }
}

// A class that consumes HTML or XML and produces plain text or JSON.
@Path("/forms-consumes")
@jakarta.ws.rs.Consumes(MediaType.TEXT_HTML)
@Produces(MediaType.TEXT_PLAIN)
class ResponseFormsConsumesResource {
    @POST
    public String echo(@QueryParam("q") String q) {
        // ok: java.xss
        return q;
    }
}

@Path("/forms-consumes-xml")
@jakarta.ws.rs.Consumes(MediaType.APPLICATION_XML)
@Produces(MediaType.APPLICATION_JSON)
class ResponseFormsConsumesXmlResource {
    @POST
    public String echo(@QueryParam("q") String q) {
        // ok: java.xss
        return "{\"q\":\"" + q + "\"}";
    }
}

// The java.net.http HttpClient: a response from a fixed origin is that origin's content, as
// for java.net.URL and RestTemplate above; a response from a URL the request chooses is not.
class FixedOriginFetchServlet extends HttpServlet {
    private static final String PROFILES = "https://api.example.com/profiles/";
    private static final String API_HOST = "https://api.example.com";
    private HttpClient http;
    private com.acme.audit.RequestLog log;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        String host = request.getParameter("host");
        try {
            // A literal fixed origin: newBuilder(uri) or uri(uri), URI.create or new URI, the request
            // built in the call or in a variable, sent with send or sendAsync.
            // ok: java.xss
            out.println(http.send(HttpRequest.newBuilder(URI.create("https://status.example.com/hosts/" + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest fetch2 = HttpRequest.newBuilder(URI.create("https://status.example.com/hosts?name=" + host)).GET().build();
            // ok: java.xss
            out.println(http.sendAsync(fetch2, HttpResponse.BodyHandlers.ofString()).join().body());
            // ok: java.xss
            out.println(http.send(HttpRequest.newBuilder(new URI("https://status.example.com/hosts/" + host)).header("Accept", "text/html").build(), HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest fetch4 = HttpRequest.newBuilder(new URI("https://status.example.com/hosts?name=" + host)).timeout(java.time.Duration.ofSeconds(5)).build();
            // ok: java.xss
            out.println(http.sendAsync(fetch4, HttpResponse.BodyHandlers.ofString()).join().body());
            // ok: java.xss
            out.println(http.send(HttpRequest.newBuilder().uri(URI.create("https://status.example.com/hosts/" + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest fetch6 = HttpRequest.newBuilder().uri(URI.create("https://status.example.com/hosts?name=" + host)).GET().build();
            // ok: java.xss
            out.println(http.sendAsync(fetch6, HttpResponse.BodyHandlers.ofString()).join().body());
            // ok: java.xss
            out.println(http.send(HttpRequest.newBuilder().uri(new URI("https://status.example.com/hosts/" + host)).header("Accept", "text/html").build(), HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest fetch8 = HttpRequest.newBuilder().uri(new URI("https://status.example.com/hosts?name=" + host)).timeout(java.time.Duration.ofSeconds(5)).build();
            // ok: java.xss
            out.println(http.sendAsync(fetch8, HttpResponse.BodyHandlers.ofString()).join().body());
            // A base held in a static final String that ends with the separator, followed by one
            // or two terms.
            // ok: java.xss
            out.println(http.send(HttpRequest.newBuilder(URI.create(PROFILES + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ok: java.xss
            out.println(http.sendAsync(HttpRequest.newBuilder(URI.create(PROFILES + host + "/card")).GET().build(), HttpResponse.BodyHandlers.ofString()).join().body());
            HttpRequest fetch11 = HttpRequest.newBuilder(URI.create(PROFILES + host)).header("Accept", "text/html").build();
            // ok: java.xss
            out.println(http.send(fetch11, HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest fetch12 = HttpRequest.newBuilder(URI.create(PROFILES + host + "/card")).timeout(java.time.Duration.ofSeconds(5)).build();
            // ok: java.xss
            out.println(http.sendAsync(fetch12, HttpResponse.BodyHandlers.ofString()).join().body());
            // ok: java.xss
            out.println(http.send(HttpRequest.newBuilder(new URI(PROFILES + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ok: java.xss
            out.println(http.sendAsync(HttpRequest.newBuilder(new URI(PROFILES + host + "/card")).GET().build(), HttpResponse.BodyHandlers.ofString()).join().body());
            HttpRequest fetch15 = HttpRequest.newBuilder(new URI(PROFILES + host)).header("Accept", "text/html").build();
            // ok: java.xss
            out.println(http.send(fetch15, HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest fetch16 = HttpRequest.newBuilder(new URI(PROFILES + host + "/card")).timeout(java.time.Duration.ofSeconds(5)).build();
            // ok: java.xss
            out.println(http.sendAsync(fetch16, HttpResponse.BodyHandlers.ofString()).join().body());
            // ok: java.xss
            out.println(http.send(HttpRequest.newBuilder().uri(URI.create(PROFILES + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ok: java.xss
            out.println(http.sendAsync(HttpRequest.newBuilder().uri(URI.create(PROFILES + host + "/card")).GET().build(), HttpResponse.BodyHandlers.ofString()).join().body());
            HttpRequest fetch19 = HttpRequest.newBuilder().uri(URI.create(PROFILES + host)).header("Accept", "text/html").build();
            // ok: java.xss
            out.println(http.send(fetch19, HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest fetch20 = HttpRequest.newBuilder().uri(URI.create(PROFILES + host + "/card")).timeout(java.time.Duration.ofSeconds(5)).build();
            // ok: java.xss
            out.println(http.sendAsync(fetch20, HttpResponse.BodyHandlers.ofString()).join().body());
            // ok: java.xss
            out.println(http.send(HttpRequest.newBuilder().uri(new URI(PROFILES + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ok: java.xss
            out.println(http.sendAsync(HttpRequest.newBuilder().uri(new URI(PROFILES + host + "/card")).GET().build(), HttpResponse.BodyHandlers.ofString()).join().body());
            HttpRequest fetch23 = HttpRequest.newBuilder().uri(new URI(PROFILES + host)).header("Accept", "text/html").build();
            // ok: java.xss
            out.println(http.send(fetch23, HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest fetch24 = HttpRequest.newBuilder().uri(new URI(PROFILES + host + "/card")).timeout(java.time.Duration.ofSeconds(5)).build();
            // ok: java.xss
            out.println(http.sendAsync(fetch24, HttpResponse.BodyHandlers.ofString()).join().body());
            // ok: java.xss
            out.println(HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("https://status.example.com/ping#" + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // Another class's method given the request is not a fetch: what it returns may hold the
            // request data.
            // ruleid: java.xss
            out.println(log.describe(HttpRequest.newBuilder(URI.create("https://status.example.com/hosts/" + host)).build()));
            HttpRequest logged = HttpRequest.newBuilder().uri(URI.create(PROFILES + host)).build();
            // ruleid: java.xss
            out.println(log.describe(logged, "html"));
            // A URI kept in a variable first, or a base followed by three terms, is not recognised.
            URI statusUri = URI.create("https://status.example.com/hosts/" + host);
            // todook: java.xss
            out.println(http.send(HttpRequest.newBuilder(statusUri).build(), HttpResponse.BodyHandlers.ofString()).body());
            // todook: java.xss
            out.println(http.send(HttpRequest.newBuilder(URI.create(PROFILES + host + "/cards/" + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // A host from the request, a base without the separator, "//" after the origin, a URL
            // the request chooses, or a fixed URI replaced later in the chain: no fixed origin.
            // ruleid: java.xss
            out.println(http.send(HttpRequest.newBuilder(URI.create(API_HOST + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ruleid: java.xss
            out.println(http.sendAsync(HttpRequest.newBuilder().uri(new URI(API_HOST + host + "/card")).build(), HttpResponse.BodyHandlers.ofString()).join().body());
            // ruleid: java.xss
            out.println(http.send(HttpRequest.newBuilder().uri(URI.create("https://status.example.com" + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ruleid: java.xss
            out.println(http.send(HttpRequest.newBuilder(new URI("https://status.example.com//" + host)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ruleid: java.xss
            out.println(http.send(HttpRequest.newBuilder(URI.create("https://" + host + "/status")).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ruleid: java.xss
            out.println(http.send(HttpRequest.newBuilder(URI.create(host + PROFILES)).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ruleid: java.xss
            out.println(http.send(HttpRequest.newBuilder(URI.create("https://status.example.com/")).uri(URI.create(request.getParameter("url"))).build(), HttpResponse.BodyHandlers.ofString()).body());
            // ruleid: java.xss
            out.println(http.send(HttpRequest.newBuilder().uri(URI.create(PROFILES + host)).GET().uri(URI.create("https://" + host + "/")).build(), HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest chosenRequest = HttpRequest.newBuilder().uri(URI.create(request.getParameter("url"))).build();
            // ruleid: java.xss
            out.println(http.sendAsync(chosenRequest, HttpResponse.BodyHandlers.ofString()).join().body());
            HttpRequest apiRequest = HttpRequest.newBuilder().uri(URI.create(API_HOST + host)).build();
            // ruleid: java.xss
            out.println(http.send(apiRequest, HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest movedRequest = HttpRequest.newBuilder(URI.create("https://status.example.com/hosts/" + host)).uri(URI.create("https://" + host + "/")).build();
            // ruleid: java.xss
            out.println(http.send(movedRequest, HttpResponse.BodyHandlers.ofString()).body());
            HttpRequest twiceRequest = HttpRequest.newBuilder().uri(new URI(PROFILES + host)).uri(new URI(host)).build();
            // ruleid: java.xss
            out.println(http.sendAsync(twiceRequest, HttpResponse.BodyHandlers.ofString()).join().body());
        } catch (InterruptedException | java.net.URISyntaxException e) {
            throw new IOException(e);
        }
    }
}

class MyBatisSessions {
    static org.apache.ibatis.session.SqlSession open() {
        return null;
    }
}

interface LateKinds {
    enum Kind {
        SMALL, LARGE
    }
}
