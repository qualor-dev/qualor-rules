package com.acme.catalog;

import java.io.IOException;
import java.io.StringReader;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.springframework.http.HttpEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

enum EarlierKind {
    FIRST, SECOND
}

// Servlet: XPath expressions built from request parameters, headers and cookies.
public class CatalogServlet extends HttpServlet {
    private static final Map<String, String> SECTIONS = Map.of("books", "/catalog/books", "music", "/catalog/music");
    private Document catalog;
    private XPath xpath = XPathFactory.newInstance().newXPath();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String title = request.getParameter("title");
            // ruleid: java.xpath-injection
            xpath.evaluate("/catalog/book[title='" + title + "']/price", catalog);
            String query = "/catalog/book[author='" + request.getParameter("author") + "']";
            // ruleid: java.xpath-injection
            NodeList books = (NodeList) xpath.evaluate(query, catalog, XPathConstants.NODESET);
            // ruleid: java.xpath-injection
            XPathExpression compiled = xpath.compile(String.format("//book[@isbn='%s']", request.getHeader("X-Isbn")));
            StringBuilder sb = new StringBuilder("//book[");
            sb.append("@lang='").append(request.getParameter("lang")).append("']");
            // ruleid: java.xpath-injection
            xpath.evaluate(sb.toString(), catalog);
            for (Cookie c : request.getCookies()) {
                // ruleid: java.xpath-injection
                xpath.evaluateExpression("//book[@shelf='" + c.getValue() + "']", catalog, String.class);
            }
            // ruleid: java.xpath-injection
            xpath.evaluateExpression("//book[@q='" + request.getQueryString() + "']", catalog);
            // The source is an InputSource rather than a node.
            // ruleid: java.xpath-injection
            xpath.evaluate("//book[title='" + title + "']", new InputSource(new StringReader("<catalog/>")));
            // A whole expression chosen by the client.
            // ruleid: java.xpath-injection
            xpath.compile(request.getParameter("expr")).evaluate(catalog);

            // ok: java.xpath-injection
            xpath.evaluate("/catalog/book[1]/title", catalog);
            // ok: java.xpath-injection
            xpath.evaluate("/catalog/book[@id=" + Integer.parseInt(request.getParameter("id")) + "]/title", catalog);
            // ok: java.xpath-injection
            xpath.evaluate(SECTIONS.get(request.getParameter("section")) + "/book[1]", catalog);
            String order = "desc".equals(request.getParameter("order")) ? "last()" : "1";
            // ok: java.xpath-injection
            xpath.evaluate("/catalog/book[" + order + "]/title", catalog);
            // ok: java.xpath-injection
            xpath.evaluate("/catalog/book[title='" + ESAPI.encoder().encodeForXPath(title) + "']", catalog);
            // The request data is the node evaluated against, not the expression.
            // ok: java.xpath-injection
            xpath.evaluate("/catalog/book[1]/title", new InputSource(new StringReader(request.getParameter("xml"))));
            // A compiled constant expression evaluated on any item.
            XPathExpression firstTitle = xpath.compile("/catalog/book[1]/title");
            // ok: java.xpath-injection
            firstTitle.evaluate(catalog);
        } catch (XPathExpressionException e) {
            throw new IOException(e);
        }
    }

    // An XPath variable ($title) resolved by an XPathVariableResolver: the expression is constant.
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String title = request.getParameter("title");
        XPath resolving = XPathFactory.newInstance().newXPath();
        resolving.setXPathVariableResolver(name -> "title".equals(name.getLocalPart()) ? title : null);
        try {
            // ok: java.xpath-injection
            resolving.evaluate("/catalog/book[title=$title]/price", catalog);
            // ok: java.xpath-injection
            resolving.compile("/catalog/book[title=$title]").evaluate(catalog, XPathConstants.NODE);
            Encoder encoder = ESAPI.encoder();
            // ok: java.xpath-injection
            resolving.evaluate("/catalog/book[author='" + encoder.encodeForXPath(request.getParameter("a")) + "']", catalog);
        } catch (XPathExpressionException e) {
            throw new IOException(e);
        }
    }

    // XPath objects without a declared type: `var`, in place, from a factory variable.
    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String title = request.getParameter("title");
        try {
            var inferred = XPathFactory.newInstance().newXPath();
            // ruleid: java.xpath-injection
            inferred.evaluate("//book[title='" + title + "']", catalog);
            // ruleid: java.xpath-injection
            XPathFactory.newInstance().newXPath().evaluate("//book[title='" + title + "']", catalog);
            var factory = XPathFactory.newDefaultInstance();
            var fromFactory = factory.newXPath();
            // ruleid: java.xpath-injection
            fromFactory.compile("//book[title='" + title + "']");
            // ok: java.xpath-injection
            inferred.evaluate("//book[1]/title", catalog);
        } catch (XPathExpressionException e) {
            throw new IOException(e);
        }
    }

    // Limits of a taint analysis that sees one method at a time and does not evaluate
    // conditions.
    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // A helper of the same class that returns a constant whatever it is given.
            // todook: java.xpath-injection
            xpath.evaluate(defaultQuery(request.getParameter("q")), catalog);
            char mode = "abc".charAt(0);
            String field;
            switch (mode) {
                case 0x61:
                    field = "title";
                    break;
                default:
                    field = request.getParameter("field");
            }
            // A switch over a value computed from constants always takes the same branch.
            // todook: java.xpath-injection
            xpath.evaluate("//book/" + field, catalog);
            // A wrapper class that reads the request is not followed into.
            RequestWrapper wrapper = new RequestWrapper(request);
            // todoruleid: java.xpath-injection
            xpath.evaluate("//book[title='" + wrapper.value("title") + "']", catalog);
        } catch (XPathExpressionException e) {
            throw new IOException(e);
        }
    }

    private static String defaultQuery(String requested) {
        return "/catalog/book[1]";
    }

    // Not a handler: the parameter is not request data.
    String audit(String request) throws XPathExpressionException {
        // ok: java.xpath-injection
        return xpath.evaluate("//book[title='" + request + "']", catalog);
    }
}

// Spring MVC: path, query, header, cookie and body parameters.
@RestController
class CatalogController {
    private final XPath xpath = XPathFactory.newInstance().newXPath();
    private Document catalog;
    private ScriptEngine engine;
    private java.util.regex.Pattern pattern;
    // An XPath handed in by the caller: only its declared type tells what it is.
    private final XPath injected;

    CatalogController(XPath injected) {
        this.injected = injected;
    }

    @GetMapping("/books/{isbn}")
    String book(@PathVariable String isbn, @RequestParam("lang") String lang, @RequestHeader("X-Shelf") String shelf)
            throws XPathExpressionException {
        // ruleid: java.xpath-injection
        String title = xpath.evaluate("//book[@isbn='" + isbn + "']/title", catalog);
        // ruleid: java.xpath-injection
        xpath.evaluate("//book[@lang='" + lang + "' and @shelf='" + shelf + "']", catalog, XPathConstants.NODESET);
        // ruleid: java.xpath-injection
        xpath.compile("//book[@lang='" + lang + "']").evaluate(catalog);
        // ruleid: java.xpath-injection
        injected.evaluate("//book[@isbn='" + isbn + "']/price", catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book[1]/title", catalog);
        // A method of another library with the same name.
        // ok: java.xpath-injection
        engine.evaluate("title == '" + lang + "'", catalog);
        // ok: java.xpath-injection
        java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(lang));
        return title;
    }

    @PostMapping("/books/search")
    String search(@RequestBody BookQuery query, @CookieValue("shelf") String shelf, HttpEntity<String> entity)
            throws XPathExpressionException {
        // ruleid: java.xpath-injection
        xpath.evaluate("//book[author='" + query.getAuthor() + "']", catalog);
        // ruleid: java.xpath-injection
        xpath.evaluate("//book[@shelf='" + shelf + "']", catalog);
        // ruleid: java.xpath-injection
        xpath.evaluate(entity.getBody(), catalog);
        XPath resolving = XPathFactory.newInstance().newXPath();
        resolving.setXPathVariableResolver(new BookVariables(query.getAuthor()));
        // ok: java.xpath-injection
        return resolving.evaluate("//book[author=$author]/title", catalog);
    }
}

class BookVariables implements XPathVariableResolver {
    private final String author;

    BookVariables(String author) {
        this.author = author;
    }

    @Override
    public Object resolveVariable(QName name) {
        return "author".equals(name.getLocalPart()) ? author : null;
    }
}

class BookQuery {
    private String author;

    String getAuthor() {
        return author;
    }
}

class ScriptEngine {
    Object evaluate(String script, Object context) {
        return null;
    }
}

class RequestWrapper {
    private final HttpServletRequest request;

    RequestWrapper(HttpServletRequest request) {
        this.request = request;
    }

    String value(String name) {
        return request.getParameter(name);
    }
}

// Jakarta REST: path, query, header and form parameters.
@jakarta.ws.rs.Path("/catalog")
class CatalogResource {
    private final XPath xpath = XPathFactory.newInstance().newXPath();
    private Document catalog;

    @GET
    @jakarta.ws.rs.Path("/{isbn}")
    public String lookup(@PathParam("isbn") String isbn, @QueryParam("field") String field, @HeaderParam("X-Lang") String lang)
            throws XPathExpressionException {
        // ruleid: java.xpath-injection
        xpath.evaluate("//book[@isbn='" + isbn + "']/title", catalog);
        // ruleid: java.xpath-injection
        return xpath.evaluate("//book[@lang='" + lang + "']/" + field, catalog);
    }

    @POST
    public String find(@FormParam("title") String title) throws XPathExpressionException {
        // ruleid: java.xpath-injection
        xpath.evaluate("//book[title='" + title + "']", catalog);
        // ok: java.xpath-injection
        return xpath.evaluate("count(//book)", catalog);
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    @jakarta.ws.rs.Path("/raw")
    public String raw(String body) throws XPathExpressionException {
        // todoruleid: java.xpath-injection
        return xpath.evaluate("//book[title='" + body + "']", catalog);
    }

    // Other XPath libraries (dom4j, JDOM, Jaxen) are not checked.
    @GET
    @jakarta.ws.rs.Path("/dom4j")
    public Object dom4j(@QueryParam("title") String title, org.dom4j.Document tree) {
        // todoruleid: java.xpath-injection
        return tree.selectNodes("//book[title='" + title + "']");
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@RestController
class SharedLimitsController {
    private static final String DEFAULT_FIELD = "title";
    private static final Map<String, String> TABLE = Map.of("t", "title", "a", "author");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("t", "title"), Map.entry("a", "author"));
    private final XPath xpath = XPathFactory.newInstance().newXPath();
    private Document catalog;

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback) throws XPathExpressionException {
        // ok: java.xpath-injection
        xpath.evaluate("//book/" + TABLE.getOrDefault(key, DEFAULT_FIELD), catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book/" + TABLE.getOrDefault(key, "title"), catalog);
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.xpath-injection
        xpath.evaluate("//book/" + TABLE.getOrDefault(key, fallback), catalog);
        // ruleid: java.xpath-injection
        xpath.evaluate("//book/" + Map.of("t", "title").getOrDefault(key, key), catalog);
        Map<String, String> filled = new java.util.HashMap<>();
        filled.put("k", key);
        // ruleid: java.xpath-injection
        xpath.evaluate("//book/" + filled.get("k"), catalog);
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.xpath-injection
        xpath.evaluate("//book/" + QName.valueOf(key).getLocalPart(), catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book/" + SharedKind.valueOf(key).name().toLowerCase(), catalog);
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.xpath-injection
        xpath.evaluate("//book/" + ENTRIES.get(key), catalog);
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.xpath-injection
        xpath.evaluate("//book[@day='" + java.time.DayOfWeek.valueOf(key).name() + "']", catalog);
        return "ok";
    }

    // The other spellings of the shared request sources and sanitizers.
    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n) throws XPathExpressionException {
        // ok: java.xpath-injection
        xpath.evaluate("//book/" + Map.of("t", "title", "a", "author").get(key), catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book/" + Map.of("t", "title").getOrDefault(key, "title"), catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book[" + Long.parseLong(n) + "]", catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book[" + Integer.valueOf(n) + "]", catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book[" + Long.valueOf(n) + "]", catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book[@kind='" + Enum.valueOf(SharedKind.class, key).name() + "']", catalog);
        // ok: java.xpath-injection
        xpath.evaluate("//book[@kind='" + java.lang.Enum.valueOf(SharedKind.class, key).name() + "']", catalog);
        // An enum declared inside the class.
        // ok: java.xpath-injection
        xpath.evaluate("//book[@level='" + Level.valueOf(key).name() + "']", catalog);
        // An enum declared before the class.
        // ok: java.xpath-injection
        xpath.evaluate("//book[@kind='" + EarlierKind.valueOf(key).name() + "']", catalog);
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.xpath-injection
        xpath.evaluate("//book/" + single.toString(), catalog);
        return "ok";
    }

    // A part of a multipart request bound with @RequestPart (text, or a body converted with an
    // HttpMessageConverter).
    @org.springframework.web.bind.annotation.PostMapping("/shared/part")
    String part(@RequestPart("meta") String meta, @org.springframework.web.bind.annotation.RequestPart("note") PartNote note,
            @RequestPart("count") int count) throws XPathExpressionException {
        // ruleid: java.xpath-injection
        xpath.evaluate("//book[title='" + meta + "']", catalog);
        // ruleid: java.xpath-injection
        xpath.evaluate("//book[title='" + note.getText() + "']", catalog);
        // A part converted to a number cannot carry injected text.
        // ok: java.xpath-injection
        xpath.evaluate("//book[" + String.valueOf(count) + "]", catalog);
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // A mapping annotation without arguments.
    @PostMapping
    String bare(HttpEntity<String> entity) throws XPathExpressionException {
        // ruleid: java.xpath-injection
        return xpath.evaluate("//book[title='" + entity.getBody() + "']", catalog);
    }

    // Servlet request types of both namespaces.
    String filterJakarta(jakarta.servlet.ServletRequest request) throws XPathExpressionException {
        // ruleid: java.xpath-injection
        return xpath.evaluate("//book[title='" + request.getParameter("q") + "']", catalog);
    }

    String filterJavax(javax.servlet.ServletRequest request) throws XPathExpressionException {
        // ruleid: java.xpath-injection
        return xpath.evaluate("//book[title='" + request.getParameter("q") + "']", catalog);
    }

    String legacy(javax.servlet.http.HttpServletRequest request) throws XPathExpressionException {
        // ruleid: java.xpath-injection
        return xpath.evaluate("//book[title='" + request.getParameter("q") + "']", catalog);
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) throws XPathExpressionException {
        // todoruleid: java.xpath-injection
        return xpath.evaluate("//book[title='" + term + "']", catalog);
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry XPath syntax, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind, @RequestParam List<Long> ids, @RequestParam Optional<Long> page)
            throws XPathExpressionException {
        // todook: java.xpath-injection
        xpath.evaluate("//book[@kind='" + kind + "']", catalog);
        // todook: java.xpath-injection
        xpath.evaluate("//book[" + ids.get(0) + "]", catalog);
        // todook: java.xpath-injection
        xpath.evaluate("//book[" + page.orElse(1L) + "]", catalog);
        // ok: java.xpath-injection
        return xpath.evaluate("//book[" + Long.parseLong(String.valueOf(ids.get(0))) + "]", catalog);
    }
}

enum SharedKind {
    SMALL, LARGE
}

class PartNote {
    private String text;

    String getText() {
        return text;
    }
}
