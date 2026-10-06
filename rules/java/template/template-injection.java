package com.acme.templates;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import freemarker.cache.StringTemplateLoader;
import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.app.VelocityEngine;
import org.springframework.http.HttpEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.TemplateSpec;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

enum EarlierKind {
    FIRST, SECOND
}

// Servlet: FreeMarker templates built from request text.
public class GreetingServlet extends HttpServlet {
    private static final Map<String, String> LAYOUTS = Map.of("plain", "<p>${name}</p>", "bold", "<b>${name}</b>");
    private Configuration cfg;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String body = request.getParameter("template");
            // ruleid: java.template-injection
            Template fromReader = new Template("greeting", new StringReader(body), cfg);
            // ruleid: java.template-injection
            Template fromString = new Template("greeting", "<h1>" + request.getHeader("X-Title") + "</h1>", cfg);
            StringReader reader = new StringReader("Hello " + request.getParameter("name"));
            // ruleid: java.template-injection
            Template fromVariable = new Template("greeting", reader, cfg);
            // ruleid: java.template-injection
            Template withEncoding = new Template("greeting", new StringReader(request.getQueryString()), cfg, "UTF-8");
            // ruleid: java.template-injection
            Template withSourceName = new Template("greeting", "greeting.ftl", new StringReader(body), cfg);
            // The source name is only the name shown in error messages.
            // ok: java.template-injection
            Template labelled = new Template("greeting", request.getParameter("label"), new StringReader("<p>${name}</p>"), cfg);
            java.io.Reader fixedReader = new StringReader("<p>${name}</p>");
            // ok: java.template-injection
            Template labelledReader = new Template("greeting", request.getHeader("X-Label"), fixedReader, cfg);
            StringReader fixedStringReader = new StringReader("<p>${name}</p>");
            // ok: java.template-injection
            Template labelledStringReader = new Template("greeting", request.getHeader("X-Label"), fixedStringReader, cfg);
            // ok: java.template-injection
            Template labelledBuffered = new Template("greeting", request.getHeader("X-Label"), new java.io.BufferedReader(fixedReader), cfg);
            // ok: java.template-injection
            Template labelledStream = new Template("greeting", request.getHeader("X-Label"), new java.io.InputStreamReader(System.in), cfg);
            // A reader returned by a call is not known to be one: the request source name is reported.
            // todook: java.template-injection
            Template labelledCall = new Template("greeting", request.getHeader("X-Label"), openLayout(), cfg);
            // ruleid: java.template-injection
            Template labelledBody =new Template("greeting", "greeting.ftl", new java.io.BufferedReader(new StringReader(body)), cfg, "UTF-8");
            StringTemplateLoader loader = new StringTemplateLoader();
            // ruleid: java.template-injection
            loader.putTemplate("custom", body);
            // ruleid: java.template-injection
            new StringTemplateLoader().putTemplate("custom", String.format("<p>%s</p>", body), 0L);
            var inferredLoader = new StringTemplateLoader();
            // ruleid: java.template-injection
            inferredLoader.putTemplate("custom", body);
            // A class resolver alone does not make an untrusted template safe (FreeMarker FAQ: the
            // object wrapper, the template loader and denial of service also need care).
            cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
            // ruleid: java.template-injection
            new Template("restricted", new StringReader(body), cfg).process(Map.of(), response.getWriter());

            // Request data in the data-model of a template the application owns.
            Map<String, Object> model = new HashMap<>();
            model.put("name", request.getParameter("name"));
            // ok: java.template-injection
            Template owned = cfg.getTemplate("greeting.ftl");
            // ok: java.template-injection
            owned.process(model, response.getWriter());
            // ok: java.template-injection
            Template inline = new Template("greeting", new StringReader("<p>Hello ${name}</p>"), cfg);
            // ok: java.template-injection
            inline.process(model, response.getWriter());
            // ok: java.template-injection
            Template layout = new Template("layout", LAYOUTS.get(request.getParameter("layout")), cfg);
            // ok: java.template-injection
            loader.putTemplate("custom", "<p>${name}</p>");
            // ok: java.template-injection
            Template numbered = new Template("n", "<p>" + Integer.parseInt(request.getParameter("n")) + "</p>", cfg);
            // A template chosen by name is loaded by the template loader from its own directory.
            // ok: java.template-injection
            Template byName = cfg.getTemplate(request.getParameter("page") + ".ftl");
        } catch (TemplateException e) {
            throw new IOException(e);
        }
    }

    // Velocity: VTL evaluated from request text.
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        VelocityContext context = new VelocityContext();
        context.put("user", request.getParameter("user"));
        Writer out = response.getWriter();
        String vtl = request.getParameter("vtl");
        // ruleid: java.template-injection
        Velocity.evaluate(context, out, "greeting", vtl);
        // ruleid: java.template-injection
        Velocity.evaluate(context, out, "greeting", new StringReader("Hello " + vtl));
        VelocityEngine engine = new VelocityEngine();
        // ruleid: java.template-injection
        engine.evaluate(context, out, "greeting", "#set($x = 1)" + request.getHeader("X-Footer"));
        var inferred = new VelocityEngine();
        // ruleid: java.template-injection
        inferred.evaluate(context, out, "greeting", vtl);
        // ruleid: java.template-injection
        new VelocityEngine().evaluate(context, out, "greeting", vtl);
        // A secure uberspector restricts introspection; the template is still the request's.
        engine.setProperty("introspector.uberspect.class", "org.apache.velocity.util.introspection.SecureUberspector");
        // ruleid: java.template-injection
        engine.evaluate(context, out, "greeting", vtl);

        // ok: java.template-injection
        Velocity.evaluate(context, out, "greeting", "Hello $user");
        // ok: java.template-injection
        engine.evaluate(context, out, "greeting", new StringReader("Hello $user"));
        // ok: java.template-injection
        engine.mergeTemplate("greeting.vm", "UTF-8", context, out);
        // The log tag is only used in error messages.
        // ok: java.template-injection
        Velocity.evaluate(context, out, request.getParameter("tag"), "Hello $user");
    }

    // Limits of a taint analysis that sees one method at a time and does not evaluate
    // conditions.
    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        VelocityContext context = new VelocityContext();
        Writer out = response.getWriter();
        // A helper of the same class that returns a constant whatever it is given.
        // todook: java.template-injection
        Velocity.evaluate(context, out, "t", defaultTemplate(request.getParameter("t")));
        char mode = "abc".charAt(0);
        String vtl;
        switch (mode) {
            case 0x61:
                vtl = "Hello";
                break;
            default:
                vtl = request.getParameter("vtl");
        }
        // A switch over a value computed from constants always takes the same branch.
        // todook: java.template-injection
        Velocity.evaluate(context, out, "t", vtl);
        // A wrapper class that reads the request is not followed into.
        RequestWrapper wrapper = new RequestWrapper(request);
        // todoruleid: java.template-injection
        Velocity.evaluate(context, out, "t", wrapper.value("vtl"));
    }

    private static java.io.Reader openLayout() {
        return new StringReader("<p>layout</p>");
    }

    private static String defaultTemplate(String requested) {
        return "Hello $user";
    }

    // Not a handler: the parameter is not request data.
    Template compile(String request) throws IOException {
        // ok: java.template-injection
        return new Template("stored", new StringReader(request), cfg);
    }
}

// Spring MVC: Thymeleaf templates processed from request text.
@RestController
class PreviewController {
    private TemplateEngine templateEngine;
    private SpringTemplateEngine springTemplateEngine;
    private org.thymeleaf.ITemplateEngine engineApi;
    private org.thymeleaf.spring5.SpringTemplateEngine spring5Engine;
    private org.thymeleaf.spring4.SpringTemplateEngine spring4Engine;
    private PaymentProcessor payments;

    @PostMapping("/preview/{kind}")
    String preview(@PathVariable String kind, @RequestBody PreviewForm form, @RequestHeader("X-Lang") String lang) {
        Context ctx = new Context(Locale.ENGLISH);
        ctx.setVariable("kind", kind);
        // ruleid: java.template-injection
        String html = templateEngine.process(form.getBody(), ctx);
        // ruleid: java.template-injection
        springTemplateEngine.process("<p th:text=\"${kind}\">" + kind + "</p>", ctx);
        // ruleid: java.template-injection
        templateEngine.process(new TemplateSpec(form.getBody(), TemplateMode.HTML), ctx);
        // ruleid: java.template-injection
        templateEngine.processThrottled(form.getBody(), ctx);
        TemplateEngine local = new TemplateEngine();
        // ruleid: java.template-injection
        local.process("[[${kind}]] " + lang, ctx, new StringWriter());
        var inferred = new TemplateEngine();
        // ruleid: java.template-injection
        inferred.process(form.getBody(), ctx);
        // ruleid: java.template-injection
        engineApi.process(form.getBody(), ctx);
        // ruleid: java.template-injection
        spring5Engine.process(form.getBody(), ctx);
        // ruleid: java.template-injection
        spring4Engine.process(form.getBody(), ctx);
        // ruleid: java.template-injection
        new SpringTemplateEngine().process(form.getBody(), ctx);

        // ok: java.template-injection
        String safe = templateEngine.process("<p th:text=\"${kind}\">kind</p>", ctx);
        // ok: java.template-injection
        templateEngine.process("emails/preview", ctx);
        ctx.setVariable("body", form.getBody());
        // ok: java.template-injection
        springTemplateEngine.process("emails/preview", ctx, new StringWriter());
        // A process method of another library.
        // ok: java.template-injection
        payments.process(form.getBody(), ctx);
        return html + safe;
    }

    @GetMapping("/preview")
    String byCookie(@CookieValue("layout") String layout, @RequestParam("text") String text, HttpEntity<String> entity) {
        Context ctx = new Context();
        // ruleid: java.template-injection
        templateEngine.process(layout, ctx);
        // ruleid: java.template-injection
        templateEngine.process(entity.getBody(), ctx);
        // The engine's template resolver is not seen: with a file or class-path resolver the value is
        // a template name, not template text.
        TemplateEngine named = new TemplateEngine();
        named.setTemplateResolver(new ClassLoaderTemplateResolver());
        // todook: java.template-injection
        return named.process(text, ctx);
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

class PreviewForm {
    private String body;

    String getBody() {
        return body;
    }
}

class PaymentProcessor {
    String process(String order, Context ctx) {
        return order;
    }
}

// Spring MVC view names: a name with a fragment selector (`::`) is parsed as a Thymeleaf fragment
// expression. Thymeleaf 3.0.12 and later refuse to execute view names found in the URL path or
// query and run fragment expressions in restricted mode, and the rule cannot see which view
// technology resolves the name, so view names are not sinks.
@Controller
class PageController {
    @GetMapping("/pages")
    String page(@RequestHeader("X-Section") String section, Model model) {
        model.addAttribute("section", section);
        // todoruleid: java.template-injection
        return "pages/index :: " + section;
    }

    @GetMapping("/pages/{name}")
    String named(@PathVariable String name, Model model) {
        model.addAttribute("name", name);
        // ok: java.template-injection
        return "pages/show";
    }
}

// Jakarta REST: path, query and form parameters.
@jakarta.ws.rs.Path("/render")
class RenderResource {
    private Configuration cfg;
    private VelocityEngine velocity;

    @GET
    @jakarta.ws.rs.Path("/{name}")
    public String render(@PathParam("name") String name, @QueryParam("t") String t) throws IOException {
        StringWriter out = new StringWriter();
        // ruleid: java.template-injection
        velocity.evaluate(new VelocityContext(), out, "render", t);
        // ruleid: java.template-injection
        new Template(name, new StringReader("<p>" + t + "</p>"), cfg);
        // The template name is only a name.
        // ok: java.template-injection
        new Template(name, new StringReader("<p>${t}</p>"), cfg);
        return out.toString();
    }

    @POST
    public String save(@FormParam("body") String body) throws IOException {
        // ruleid: java.template-injection
        new Template("saved", body, cfg);
        return body;
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    @jakarta.ws.rs.Path("/raw")
    public String raw(String body) throws IOException {
        // todoruleid: java.template-injection
        new Template("raw", body, cfg);
        return body;
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@RestController
class SharedLimitsController {
    private static final String DEFAULT_TEMPLATE = "<p>${name}</p>";
    private static final Map<String, String> TABLE = Map.of("a", "<p>${name}</p>", "b", "<b>${name}</b>");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("a", "<p>a</p>"), Map.entry("b", "<p>b</p>"));
    private TemplateEngine templateEngine;

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback) {
        Context ctx = new Context();
        // ok: java.template-injection
        templateEngine.process(TABLE.getOrDefault(key, DEFAULT_TEMPLATE), ctx);
        // ok: java.template-injection
        templateEngine.process(TABLE.getOrDefault(key, "<p>none</p>"), ctx);
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.template-injection
        templateEngine.process(TABLE.getOrDefault(key, fallback), ctx);
        // ruleid: java.template-injection
        templateEngine.process(Map.of("a", "<p>a</p>").getOrDefault(key, key), ctx);
        Map<String, String> filled = new HashMap<>();
        filled.put("k", key);
        // ruleid: java.template-injection
        templateEngine.process(filled.get("k"), ctx);
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.template-injection
        templateEngine.process(javax.xml.namespace.QName.valueOf(key).getLocalPart(), ctx);
        // ok: java.template-injection
        templateEngine.process("<p>" + SharedKind.valueOf(key).name() + "</p>", ctx);
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.template-injection
        templateEngine.process(ENTRIES.get(key), ctx);
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.template-injection
        templateEngine.process("<p>" + java.time.DayOfWeek.valueOf(key).name() + "</p>", ctx);
        return "ok";
    }

    // The other spellings of the shared request sources and sanitizers.
    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n) {
        // ok: java.template-injection
        templateEngine.process("<p>" + Map.of("a", "x", "b", "y").get(key) + "</p>", new Context());
        // ok: java.template-injection
        templateEngine.process("<p>" + Map.of("a", "x").getOrDefault(key, "x") + "</p>", new Context());
        // ok: java.template-injection
        templateEngine.process("<p>" + Long.parseLong(n) + "</p>", new Context());
        // ok: java.template-injection
        templateEngine.process("<p>" + Integer.valueOf(n) + "</p>", new Context());
        // ok: java.template-injection
        templateEngine.process("<p>" + Long.valueOf(n) + "</p>", new Context());
        // ok: java.template-injection
        templateEngine.process("<p>" + Enum.valueOf(SharedKind.class, key).name() + "</p>", new Context());
        // ok: java.template-injection
        templateEngine.process("<p>" + java.lang.Enum.valueOf(SharedKind.class, key).name() + "</p>", new Context());
        // An enum declared inside the class.
        // ok: java.template-injection
        templateEngine.process("<p>" + Level.valueOf(key).name() + "</p>", new Context());
        // An enum declared before the class.
        // ok: java.template-injection
        templateEngine.process("<p>" + EarlierKind.valueOf(key).name() + "</p>", new Context());
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.template-injection
        templateEngine.process(single.toString(), new Context());
        StringBuilder chained = new StringBuilder();
        chained.append("<p>").append(key).append("</p>");
        // ruleid: java.template-injection
        templateEngine.process(chained.toString(), new Context());
        StringBuilder fixed = new StringBuilder();
        fixed.append("<p>").append("Hello").append("</p>");
        // ok: java.template-injection
        templateEngine.process(fixed.toString(), new Context());
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // A mapping annotation without arguments.
    @PostMapping
    String bare(HttpEntity<String> entity) {
        // ruleid: java.template-injection
        templateEngine.process("<p>" + entity.getBody() + "</p>", new Context());
        return "ok";
    }

    // Servlet request types of both namespaces.
    void filterJakarta(jakarta.servlet.ServletRequest request) {
        // ruleid: java.template-injection
        templateEngine.process("<p>" + request.getParameter("q") + "</p>", new Context());
    }

    void filterJavax(javax.servlet.ServletRequest request) {
        // ruleid: java.template-injection
        templateEngine.process("<p>" + request.getParameter("q") + "</p>", new Context());
    }

    void legacy(javax.servlet.http.HttpServletRequest request) {
        // ruleid: java.template-injection
        templateEngine.process("<p>" + request.getParameter("q") + "</p>", new Context());
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) {
        // todoruleid: java.template-injection
        return templateEngine.process(term, new Context());
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry template syntax, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind, @RequestParam List<Long> ids, @RequestParam Optional<Long> page) {
        Context ctx = new Context();
        // todook: java.template-injection
        templateEngine.process("<p>" + kind + "</p>", ctx);
        // todook: java.template-injection
        templateEngine.process("<p>" + ids.get(0) + "</p>", ctx);
        // todook: java.template-injection
        templateEngine.process("<p>" + page.orElse(0L) + "</p>", ctx);
        return "ok";
    }
}

enum SharedKind {
    SMALL, LARGE
}
