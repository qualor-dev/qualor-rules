package com.acme.login;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.springframework.http.RequestEntity;
import org.springframework.http.HttpEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

// An enum declared before the first class (the shared enum allow-list forms).
enum EarlierKind {
    ONE, TWO
}

// Servlet: sendRedirect and the Location header.
public class LoginServlet extends HttpServlet {
    private static final String SITE = "https://www.example.com";
    private static final String SITE_ROOT = "https://www.example.com/";
    private static final String SCHEME = "https:";
    private static final Map<String, String> TARGETS = Map.of("home", "/", "orders", "/orders");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String next = request.getParameter("next");
        // ruleid: java.open-redirect
        response.sendRedirect(next);
        // ruleid: java.open-redirect
        response.sendRedirect(request.getHeader("Referer"));
        // ruleid: java.open-redirect
        response.setHeader("Location", next);
        // ruleid: java.open-redirect
        response.addHeader("location", "https://" + request.getParameter("host") + "/welcome");
        // ruleid: java.open-redirect
        response.sendRedirect(response.encodeRedirectURL(next));
        // A path that starts with "//" or "/\" is another host to a browser.
        // ruleid: java.open-redirect
        response.sendRedirect("/" + next);
        // ruleid: java.open-redirect
        response.sendRedirect("/\\" + next);
        // ruleid: java.open-redirect
        response.sendRedirect("//" + next);
        // After a fixed host, "//" only starts the path.
        // ok: java.open-redirect
        response.sendRedirect(SITE + "//" + next);
        // A base without a separator after the host: "@evil.example" changes the host.
        // ruleid: java.open-redirect
        response.sendRedirect(SITE + next);
        // A scheme alone is not an origin.
        // ruleid: java.open-redirect
        response.sendRedirect(SCHEME + "//" + next);
        // ruleid: java.open-redirect
        response.sendRedirect(String.format("%s%s", SITE, next));

        // ok: java.open-redirect
        response.sendRedirect("/account/orders?id=" + next);
        // ok: java.open-redirect
        response.sendRedirect("orders/" + next);
        // ok: java.open-redirect
        response.sendRedirect("?tab=" + next);
        // ok: java.open-redirect
        response.sendRedirect("https://www.example.com/welcome?from=" + next);
        // ok: java.open-redirect
        response.sendRedirect(SITE + "/welcome?from=" + next);
        // ok: java.open-redirect
        response.sendRedirect(SITE_ROOT + next);
        // ok: java.open-redirect
        response.sendRedirect(String.format("%s/welcome/%s", SITE, next));
        // ok: java.open-redirect
        response.sendRedirect(String.format("/welcome/%s", next));
        // ok: java.open-redirect
        response.sendRedirect(UriComponentsBuilder.fromHttpUrl(SITE).path("/welcome").queryParam("from", next).toUriString());
        // ok: java.open-redirect
        response.sendRedirect("/orders/" + Long.parseLong(request.getParameter("id")));
        // ok: java.open-redirect
        response.sendRedirect(TARGETS.get(next));
        // ok: java.open-redirect
        response.sendRedirect(TARGETS.getOrDefault(next, "/"));
        // ok: java.open-redirect
        response.sendRedirect("/home");
        // ok: java.open-redirect
        response.sendRedirect(request.getContextPath() + "/orders/" + next);
        // With an empty context path, "/" + "/evil.example" is another host.
        // ruleid: java.open-redirect
        response.sendRedirect(request.getContextPath() + "/" + next);
        // A header other than Location.
        // ok: java.open-redirect
        response.setHeader("X-Next", next);
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.open-redirect
        response.sendRedirect(TARGETS.getOrDefault(next, next));
        // ruleid: java.open-redirect
        response.sendRedirect(UriComponentsBuilder.fromHttpUrl(SITE).host(next).toUriString());
        // A check that the target is a local path is not recognised.
        if (next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\")) {
            // todook: java.open-redirect
            response.sendRedirect(next);
        }
    }
}

// Spring MVC: "redirect:" view names, RedirectView, ResponseEntity and HttpHeaders locations.
@Controller
class LoginController {
    private static final String HOME = "/app";

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    @PostMapping("/login")
    String login(@RequestParam String returnTo) {
        // ruleid: java.open-redirect
        return "redirect:" + returnTo;
    }

    @GetMapping("/go/{target}")
    String go(@PathVariable String target) {
        // ruleid: java.open-redirect
        return "redirect:/" + target;
    }

    @GetMapping("/view")
    ModelAndView view(@RequestParam String next) {
        // ruleid: java.open-redirect
        return new ModelAndView("redirect:" + next);
    }

    @GetMapping("/redirect-view")
    RedirectView redirectView(@RequestHeader("X-Return") String back) {
        // ruleid: java.open-redirect
        return new RedirectView(back);
    }

    @GetMapping("/redirect-view-url")
    RedirectView redirectViewUrl(@RequestParam String back) {
        RedirectView view = new RedirectView();
        // ruleid: java.open-redirect
        view.setUrl(back);
        return view;
    }

    @GetMapping("/entity")
    ResponseEntity<Void> entity(@RequestParam String next) {
        // ruleid: java.open-redirect
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(next)).build();
    }

    @GetMapping("/headers")
    ResponseEntity<Void> headers(@RequestParam String next) {
        HttpHeaders headers = new HttpHeaders();
        // ruleid: java.open-redirect
        headers.setLocation(URI.create(next));
        return new ResponseEntity<>(headers, HttpStatus.SEE_OTHER);
    }

    @GetMapping("/entity-header")
    ResponseEntity<Void> entityHeader(@RequestParam String next) {
        // ruleid: java.open-redirect
        return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, next).build();
    }

    @PostMapping("/form")
    String form(@RequestBody LoginForm form) {
        // ruleid: java.open-redirect
        return "redirect:" + form.getReturnTo();
    }

    @PostMapping("/orders/{id}")
    String order(@PathVariable String id) {
        // ok: java.open-redirect
        return "redirect:/orders/" + id;
    }

    @GetMapping("/search")
    String search(@RequestParam String q) {
        // ok: java.open-redirect
        return "redirect:/search?q=" + q;
    }

    @GetMapping("/base")
    String base(@RequestParam String page) {
        // ok: java.open-redirect
        return "redirect:" + baseUrl + "/pages/" + page;
    }

    @GetMapping("/forward")
    String forward(@RequestParam String page) {
        // A forward stays on the server.
        // ok: java.open-redirect
        return "forward:/pages/" + Map.of("a", "about", "c", "contact").get(page);
    }

    @GetMapping("/plain-view")
    String plainView(@RequestParam String name) {
        // ok: java.open-redirect
        return "users/" + "profile";
    }

    @GetMapping("/fixed-entity")
    ResponseEntity<Void> fixedEntity(@RequestParam String id) {
        // ok: java.open-redirect
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create("/orders/" + id)).build();
    }

    @GetMapping("/created")
    ResponseEntity<Void> created(@RequestParam String id) {
        // ok: java.open-redirect
        return ResponseEntity.ok().header("X-Request", id).build();
    }

    @GetMapping("/base-joined")
    String baseJoined(@RequestParam String page) {
        // A configured base followed directly by request data.
        // ruleid: java.open-redirect
        return "redirect:" + baseUrl + page;
    }

    // A configured base may be empty (a context path): "/" + "/evil.example" is another host.
    @GetMapping("/context-joined")
    String contextJoined(@RequestParam String next) {
        // ruleid: java.open-redirect
        return "redirect:" + contextPath + "/" + next;
    }

    @GetMapping("/context-servlet")
    void contextServlet(@RequestParam String next, HttpServletResponse response) throws IOException {
        // ruleid: java.open-redirect
        response.sendRedirect(contextPath + "/" + next);
        // ruleid: java.open-redirect
        response.sendRedirect(String.format("%s/%s", contextPath, next));
        // ok: java.open-redirect
        response.sendRedirect(contextPath + "/orders/" + next);
        // ok: java.open-redirect
        response.sendRedirect(String.format("%s/orders/%s", contextPath, next));
        // ok: java.open-redirect
        response.sendRedirect(contextPath + "?next=" + next);
    }

    // A local path held in a static final field is not recognised as a base.
    @GetMapping("/home-base")
    String homeBase(@RequestParam String next) {
        // todook: java.open-redirect
        return "redirect:" + HOME + "/" + next;
    }

    // A local path built with UriComponentsBuilder.fromPath is not recognised.
    @GetMapping("/from-path")
    String fromPath(@RequestParam String q) {
        // todook: java.open-redirect
        return "redirect:" + UriComponentsBuilder.fromPath("/search").queryParam("q", q).toUriString();
    }

    // A Location set in a headers lambda is not followed.
    @GetMapping("/headers-lambda")
    ResponseEntity<Void> headersLambda(@RequestParam String next) {
        // todoruleid: java.open-redirect
        return ResponseEntity.status(HttpStatus.FOUND).headers(h -> h.setLocation(URI.create(next))).build();
    }
}

class LoginForm {
    private String returnTo;

    String getReturnTo() {
        return returnTo;
    }
}

// Jakarta REST: seeOther, temporaryRedirect and a Location set on a response.
@Path("/auth")
class AuthResource {
    private static final String SITE = "https://www.example.com";

    @GET
    @Path("/callback")
    public Response callback(@QueryParam("next") String next) {
        // ruleid: java.open-redirect
        return Response.seeOther(URI.create(next)).build();
    }

    @GET
    @Path("/moved")
    public Response moved(@QueryParam("next") String next) {
        // ruleid: java.open-redirect
        return Response.temporaryRedirect(URI.create(next)).build();
    }

    @GET
    @Path("/status")
    public Response status(@QueryParam("next") String next) {
        // ruleid: java.open-redirect
        return Response.status(Response.Status.FOUND).location(URI.create(next)).build();
    }

    @GET
    @Path("/header")
    public Response header(@QueryParam("next") String next) {
        // ruleid: java.open-redirect
        return Response.status(302).header("Location", next).build();
    }

    @GET
    @Path("/safe")
    public Response safe(@QueryParam("id") String id) {
        // ok: java.open-redirect
        return Response.seeOther(URI.create(SITE + "/orders/" + id)).build();
    }

    @GET
    @Path("/fixed")
    public Response fixed(@QueryParam("id") String id) {
        // ok: java.open-redirect
        return Response.seeOther(URI.create("/orders/" + id)).build();
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    public Response post(LoginForm form) {
        // todoruleid: java.open-redirect
        return Response.seeOther(URI.create(form.getReturnTo())).build();
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@Controller
class SharedLimitsController {
    private static final Map<String, String> PAGES = Map.of("home", "/", "help", "/help");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("home", "/"), Map.entry("help", "/help"));

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback) {
        // ok: java.open-redirect
        String a = "redirect:" + PAGES.get(key);
        // ok: java.open-redirect
        String b = "redirect:" + Map.of("home", "/").get(key);
        // ruleid: java.open-redirect
        String c = "redirect:" + PAGES.getOrDefault(key, fallback);
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.open-redirect
        String d = "redirect:" + javax.xml.namespace.QName.valueOf(key).getLocalPart();
        // ok: java.open-redirect
        String e = "redirect:" + Section.valueOf(key).path;
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.open-redirect
        String f = "redirect:" + ENTRIES.get(key);
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.open-redirect
        String g = "redirect:" + java.time.DayOfWeek.valueOf(key).name();
        return a + b + c + d + e + f + g;
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String next) {
        // todoruleid: java.open-redirect
        return "redirect:" + next;
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry a URL, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam Section section) {
        // todook: java.open-redirect
        return "redirect:" + section;
    }

    @GetMapping("/shared/ids")
    String ids(@RequestParam List<Long> ids) {
        // todook: java.open-redirect
        return "redirect:" + ids.get(0);
    }

    @GetMapping("/shared/page")
    String page(@RequestParam Optional<Long> page) {
        // todook: java.open-redirect
        return "redirect:" + page.orElse(0L);
    }
}

enum Section {
    HOME("/"), HELP("/help");

    final String path;

    Section(String path) {
        this.path = path;
    }
}

class SharedSwitchServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        char mode = "abc".charAt(0);
        String chosen;
        switch (mode) {
            case 0x61:
                chosen = "/home";
                break;
            default:
                chosen = request.getParameter("chosen");
        }
        // A switch over a value computed from constants always takes the same branch.
        // todook: java.open-redirect
        response.sendRedirect(chosen);
    }
}

// The request body of a Spring MVC HttpEntity or RequestEntity parameter, and the target assembled in
// an append chain (StringBuilder.append(...).append(value)).
@Controller
class EntityLoginController {
    @PostMapping("/entity/next")
    String next(HttpEntity<String> entity) {
        // ruleid: java.open-redirect
        return "redirect:" + entity.getBody();
    }

    @org.springframework.web.bind.annotation.RequestMapping("/entity/back")
    String back(RequestEntity<String> request) {
        // ruleid: java.open-redirect
        return "redirect:" + request.getBody();
    }

    @PostMapping
    String referer(org.springframework.http.HttpEntity<LoginForm> entity) {
        // ruleid: java.open-redirect
        return "redirect:" + entity.getHeaders().getFirst("Referer");
    }

    @GetMapping("/entity/chain")
    String chain(@RequestParam String host) {
        StringBuilder target = new StringBuilder();
        target.append("https://").append(host).append("/home");
        // ruleid: java.open-redirect
        return "redirect:" + target.toString();
    }

    @GetMapping("/entity/fixed")
    String fixed(@RequestParam String host) {
        StringBuilder target = new StringBuilder();
        target.append("/account").append("?tab=profile");
        // ok: java.open-redirect
        return "redirect:" + target.toString();
    }

    // Not a handler method: an entity it is given is not request data.
    String replay(HttpEntity<String> entity) {
        // ok: java.open-redirect
        return "redirect:" + entity.getBody();
    }
}

// The other spellings of the shared request sources and sanitizers.
@Controller
class SharedFormsController {
    private static final Map<String, String> FORMS = Map.of("a", "/home", "b", "/home");

    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n, HttpServletResponse response) throws IOException {
        // ok: java.open-redirect
        response.sendRedirect("https://" + Map.of("a", "/home", "b", "/home").get(key) + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + Map.of("a", "/home").getOrDefault(key, "/home") + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + FORMS.get(key) + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + FORMS.getOrDefault(key, "/home") + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + String.valueOf(Integer.parseInt(n)) + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + String.valueOf(Long.parseLong(n)) + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + String.valueOf(Integer.valueOf(n)) + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + String.valueOf(Long.valueOf(n)) + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + Enum.valueOf(FormKind.class, key).name() + "/");
        // ok: java.open-redirect
        response.sendRedirect("https://" + java.lang.Enum.valueOf(FormKind.class, key).name() + "/");
        // An enum declared inside the class.
        // ok: java.open-redirect
        response.sendRedirect("https://" + Level.valueOf(key).name() + "/");
        // An enum declared before the first class of the file.
        // ok: java.open-redirect
        response.sendRedirect("https://" + EarlierKind.valueOf(key).name() + "/");
        // An enum declared after the class.
        // ok: java.open-redirect
        response.sendRedirect("https://" + FormKind.valueOf(key).name() + "/");
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.open-redirect
        response.sendRedirect("https://" + single.toString() + "/");
        return "ok";
    }

    // A part of a multipart request bound with @RequestPart (text, or a body converted with an
    // HttpMessageConverter).
    @org.springframework.web.bind.annotation.PostMapping("/shared/part")
    String part(@RequestPart("meta") String meta, @org.springframework.web.bind.annotation.RequestPart("note") PartNote note,
            @RequestPart("count") int count, HttpServletResponse response) throws IOException {
        // ruleid: java.open-redirect
        response.sendRedirect("https://" + meta + "/");
        // ruleid: java.open-redirect
        response.sendRedirect("https://" + note.getText() + "/");
        // A part converted to a number cannot carry injected text.
        // ok: java.open-redirect
        response.sendRedirect("https://" + String.valueOf(count) + "/");
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // Servlet request types of both namespaces.
    void jakartaRequest(jakarta.servlet.ServletRequest request, HttpServletResponse response) throws IOException {
        // ruleid: java.open-redirect
        response.sendRedirect("https://" + request.getParameter("q") + "/");
    }

    void javaxRequest(javax.servlet.ServletRequest request, HttpServletResponse response) throws IOException {
        // ruleid: java.open-redirect
        response.sendRedirect("https://" + request.getParameter("q") + "/");
    }

    void javaxHttpRequest(javax.servlet.http.HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ruleid: java.open-redirect
        response.sendRedirect("https://" + request.getParameter("q") + "/");
    }

    void jakartaHttpRequest(jakarta.servlet.http.HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ruleid: java.open-redirect
        response.sendRedirect("https://" + request.getParameter("q") + "/");
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
