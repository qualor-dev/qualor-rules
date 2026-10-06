package com.acme.search;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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

enum EarlierKind {
    FIRST, SECOND
}

// Servlet: patterns built from request parameters, headers and cookies.
public class SearchServlet extends HttpServlet {
    private static final Map<String, String> SHAPES = Map.of("digits", "\\d+", "word", "\\w+");
    private String catalog = "red apple, green pear, yellow lemon";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String word = request.getParameter("word");
        // ruleid: java.regex-injection
        Pattern found = Pattern.compile(word);
        // ruleid: java.regex-injection
        Pattern folded = Pattern.compile(request.getParameter("pattern"), Pattern.CASE_INSENSITIVE);
        String around = ".*" + request.getHeader("X-Term") + ".*";
        // ruleid: java.regex-injection
        boolean hit = Pattern.matches(around, catalog);
        // ruleid: java.regex-injection
        Pattern formatted = Pattern.compile(String.format("^%s-\\d+$", request.getParameter("prefix")));
        StringBuilder sb = new StringBuilder("(?i)");
        sb.append("\\b").append(request.getParameter("stem")).append("\\w*");
        // ruleid: java.regex-injection
        Pattern built = Pattern.compile(sb.toString());
        for (Cookie c : request.getCookies()) {
            // ruleid: java.regex-injection
            Pattern.compile(c.getValue()).matcher(catalog).find();
        }
        // ruleid: java.regex-injection
        java.util.regex.Pattern.compile(request.getQueryString());

        // The pattern is constant; the request data is only the text it is matched against.
        // ok: java.regex-injection
        Pattern.compile("[a-z]+").matcher(word).matches();
        // ok: java.regex-injection
        boolean plain = Pattern.matches("[\\w ]+", word);
        // Pattern.quote makes the text a literal pattern.
        // ok: java.regex-injection
        Pattern.compile(Pattern.quote(word));
        // ok: java.regex-injection
        Pattern.compile("\\b" + Pattern.quote(word) + "\\b", Pattern.CASE_INSENSITIVE);
        // The LITERAL flag: metacharacters have no special meaning.
        // ok: java.regex-injection
        Pattern.compile(word, Pattern.LITERAL);
        // ok: java.regex-injection
        Pattern.compile(word, Pattern.CASE_INSENSITIVE | Pattern.LITERAL);
        // ok: java.regex-injection
        Pattern.compile("\\d{" + Integer.parseInt(request.getParameter("len")) + "}");
        // ok: java.regex-injection
        Pattern.compile(SHAPES.get(request.getParameter("shape")));
        String mode = "loose".equals(request.getParameter("mode")) ? ".*" : "^\\w+$";
        // ok: java.regex-injection
        Pattern.compile(mode);
        response.getWriter().println(found.pattern() + folded + hit + formatted + built + plain);
    }

    // String methods that take a regular expression.
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String sep = request.getParameter("sep");
        String text = catalog;
        // ruleid: java.regex-injection
        String[] parts = text.split(sep);
        // ruleid: java.regex-injection
        String[] limited = catalog.split(request.getParameter("delim"), 3);
        // ruleid: java.regex-injection
        boolean whole = text.matches(request.getParameter("shape"));
        // ruleid: java.regex-injection
        String masked = text.replaceAll(request.getHeader("X-Secret"), "***");
        // ruleid: java.regex-injection
        String first = text.replaceFirst("^" + sep, "");
        // ruleid: java.regex-injection
        String[] kept = text.splitWithDelimiters(sep, 0);

        // The request data is the string the constant pattern is applied to.
        // ok: java.regex-injection
        String[] words = request.getParameter("words").split(",");
        String q = request.getParameter("q");
        // ok: java.regex-injection
        boolean digits = q.matches("\\d+");
        // ok: java.regex-injection
        String squashed = q.replaceAll("\\s+", " ");
        // The replacement text is not a pattern.
        // ok: java.regex-injection
        String renamed = text.replaceAll("apple", Matcher.quoteReplacement(q));
        // String.replace takes a literal target.
        // ok: java.regex-injection
        String literal = text.replace(sep, ";");
        // ok: java.regex-injection
        String[] quoted = text.split(Pattern.quote(sep));
        response.getWriter().println(parts.length + limited.length + words.length + kept.length + (whole ? 1 : 0) + masked + first + digits + squashed + renamed + literal + quoted.length);
    }

    // Limits of a taint analysis that sees one method at a time and does not evaluate
    // conditions.
    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // A helper of the same class that returns a constant whatever it is given.
        // todook: java.regex-injection
        Pattern.compile(defaultPattern(request.getParameter("q")));
        char mode = "abc".charAt(0);
        String expr;
        switch (mode) {
            case 0x61:
                expr = "\\w+";
                break;
            default:
                expr = request.getParameter("expr");
        }
        // A switch over a value computed from constants always takes the same branch.
        // todook: java.regex-injection
        Pattern.compile(expr);
        // A wrapper class that reads the request is not followed into.
        RequestWrapper wrapper = new RequestWrapper(request);
        // todoruleid: java.regex-injection
        Pattern.compile(wrapper.value("expr"));
        // A pattern first checked against a constant pattern of word characters cannot hold
        // metacharacters, but the check is not followed.
        String checked = request.getParameter("checked");
        if (!checked.matches("[\\w ]+")) {
            return;
        }
        // todook: java.regex-injection
        Pattern.compile(checked);
    }

    // A String whose type is not visible (a call result, a `var`) is not checked as a receiver.
    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        var line = catalog.trim();
        // todoruleid: java.regex-injection
        line.split(request.getParameter("sep"));
    }

    private static String defaultPattern(String requested) {
        return "\\w+";
    }

    // Not a handler: the parameter is not request data.
    Pattern audit(String request) {
        // ok: java.regex-injection
        return Pattern.compile(request);
    }
}

// Spring MVC: path, query, header, cookie and body parameters.
@RestController
class SearchController {
    private final String catalog = "red apple, green pear";
    private final PasswordEncoder encoder = new PasswordEncoder();
    private final Splitter splitter = new Splitter();
    private final List<String> names = new java.util.ArrayList<>();

    @GetMapping("/search/{stem}")
    String search(@PathVariable String stem, @RequestParam("q") String q, @RequestHeader("X-Delim") String delim) {
        // ruleid: java.regex-injection
        Pattern byStem = Pattern.compile("^" + stem);
        // ruleid: java.regex-injection
        boolean any = catalog.matches(".*" + q + ".*");
        // ruleid: java.regex-injection
        String[] cells = catalog.split(delim);
        // ok: java.regex-injection
        Pattern.compile("^" + Pattern.quote(stem));
        // Methods of other libraries with the same name.
        // ok: java.regex-injection
        boolean same = encoder.matches(q, "{bcrypt}hash");
        // ok: java.regex-injection
        splitter.split(q);
        // ok: java.regex-injection
        names.replaceAll(UnaryOperator.identity());
        return byStem.pattern() + any + cells.length + same;
    }

    @PostMapping("/search/filter")
    String filter(@RequestBody SearchFilter filter, @CookieValue("saved") String saved, HttpEntity<String> entity) {
        // ruleid: java.regex-injection
        Pattern.compile(filter.getPattern());
        // ruleid: java.regex-injection
        Pattern.compile(saved);
        // ruleid: java.regex-injection
        Pattern.compile(entity.getBody());
        // ok: java.regex-injection
        return catalog.replaceAll("pear", "plum");
    }
}

class SearchFilter {
    private String pattern;

    String getPattern() {
        return pattern;
    }
}

class PasswordEncoder {
    boolean matches(CharSequence raw, String encoded) {
        return false;
    }
}

class Splitter {
    Iterable<String> split(CharSequence text) {
        return List.of();
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
    private final String catalog = "red apple, green pear";

    @GET
    @jakarta.ws.rs.Path("/{expr}")
    public String lookup(@PathParam("expr") String expr, @QueryParam("sep") String sep, @HeaderParam("X-Mask") String mask) {
        // ruleid: java.regex-injection
        Pattern byPath = Pattern.compile(expr);
        // ruleid: java.regex-injection
        String[] cells = catalog.split(sep);
        // ruleid: java.regex-injection
        return byPath.pattern() + cells.length + catalog.replaceFirst(mask, "");
    }

    @POST
    public String find(@FormParam("pattern") String pattern) {
        // ruleid: java.regex-injection
        boolean b = Pattern.matches(pattern, catalog);
        // ok: java.regex-injection
        return b + catalog.replaceAll("\\s+", "");
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    @jakarta.ws.rs.Path("/raw")
    public String raw(String body) {
        // todoruleid: java.regex-injection
        return Pattern.compile(body).pattern();
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@RestController
class SharedLimitsController {
    private static final String DEFAULT_SHAPE = "\\w+";
    private static final Map<String, String> TABLE = Map.of("d", "\\d+", "w", "\\w+");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("d", "\\d+"), Map.entry("w", "\\w+"));

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback) {
        // ok: java.regex-injection
        Pattern.compile(TABLE.getOrDefault(key, DEFAULT_SHAPE));
        // ok: java.regex-injection
        Pattern.compile(TABLE.getOrDefault(key, "\\w+"));
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.regex-injection
        Pattern.compile(TABLE.getOrDefault(key, fallback));
        // ruleid: java.regex-injection
        Pattern.compile(Map.of("d", "\\d+").getOrDefault(key, key));
        Map<String, String> filled = new java.util.HashMap<>();
        filled.put("k", key);
        // ruleid: java.regex-injection
        Pattern.compile(filled.get("k"));
        // ok: java.regex-injection
        Pattern.compile(SharedKind.valueOf(key).regex());
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.regex-injection
        Pattern.compile(ENTRIES.get(key));
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.regex-injection
        Pattern.compile(java.time.DayOfWeek.valueOf(key).name());
        return "ok";
    }

    // The other spellings of the shared request sources and sanitizers.
    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n) {
        // ok: java.regex-injection
        Pattern.compile(Map.of("d", "\\d+", "w", "\\w+").get(key));
        // ok: java.regex-injection
        Pattern.compile(Map.of("d", "\\d+").getOrDefault(key, "\\w+"));
        // ok: java.regex-injection
        Pattern.compile("\\d{" + Long.parseLong(n) + "}");
        // ok: java.regex-injection
        Pattern.compile("\\d{" + Integer.valueOf(n) + "}");
        // ok: java.regex-injection
        Pattern.compile("\\d{" + Long.valueOf(n) + "}");
        // ok: java.regex-injection
        Pattern.compile(Enum.valueOf(SharedKind.class, key).regex());
        // ok: java.regex-injection
        Pattern.compile(java.lang.Enum.valueOf(SharedKind.class, key).regex());
        // An enum declared inside the class.
        // ok: java.regex-injection
        Pattern.compile(Level.valueOf(key).name());
        // An enum declared before the class.
        // ok: java.regex-injection
        Pattern.compile(EarlierKind.valueOf(key).name());
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.regex-injection
        Pattern.compile(single.toString());
        return "ok";
    }

    // A part of a multipart request bound with @RequestPart (text, or a body converted with an
    // HttpMessageConverter).
    @org.springframework.web.bind.annotation.PostMapping("/shared/part")
    String part(@RequestPart("meta") String meta, @org.springframework.web.bind.annotation.RequestPart("note") PartNote note,
            @RequestPart("count") int count) {
        // ruleid: java.regex-injection
        Pattern.compile(meta);
        // ruleid: java.regex-injection
        Pattern.compile(note.getText());
        // A part converted to a number cannot carry a pattern.
        // ok: java.regex-injection
        Pattern.compile("\\d{" + String.valueOf(count) + "}");
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // A mapping annotation without arguments.
    @PostMapping
    String bare(HttpEntity<String> entity) {
        // ruleid: java.regex-injection
        return Pattern.compile(entity.getBody()).pattern();
    }

    // Servlet request types of both namespaces.
    String filterJakarta(jakarta.servlet.ServletRequest request) {
        // ruleid: java.regex-injection
        return Pattern.compile(request.getParameter("q")).pattern();
    }

    String filterJavax(javax.servlet.ServletRequest request) {
        // ruleid: java.regex-injection
        return Pattern.compile(request.getParameter("q")).pattern();
    }

    String legacy(javax.servlet.http.HttpServletRequest request) {
        // ruleid: java.regex-injection
        return Pattern.compile(request.getParameter("q")).pattern();
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) {
        // todoruleid: java.regex-injection
        return Pattern.compile(term).pattern();
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry a pattern, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind, @RequestParam List<Long> ids, @RequestParam Optional<Long> page) {
        // todook: java.regex-injection
        Pattern.compile("\\w{" + kind + "}");
        // todook: java.regex-injection
        Pattern.compile("\\w{" + ids.get(0) + "}");
        // todook: java.regex-injection
        Pattern.compile("\\w{" + page.orElse(1L) + "}");
        // ok: java.regex-injection
        return Pattern.compile("\\w{" + Long.parseLong(String.valueOf(ids.get(0))) + "}").pattern();
    }
}

enum SharedKind {
    DIGITS("\\d+"), WORD("\\w+");

    private final String regex;

    SharedKind(String regex) {
        this.regex = regex;
    }

    String regex() {
        return regex;
    }
}

class PartNote {
    private String text;

    String getText() {
        return text;
    }
}
