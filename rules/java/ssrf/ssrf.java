package com.acme.fetch;

import java.util.Optional;
import java.util.List;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

// Servlet: java.net.URL and java.net.http with a URL, a scheme or a host from the request.
public class PreviewServlet extends HttpServlet {
    private static final String API = "https://api.example.com";
    private static final URI API_URI = URI.create("https://api.example.com/");
    private static final Map<String, String> MIRRORS = Map.of("eu", "https://eu.example.com", "us", "https://us.example.com");
    private final HttpClient client = HttpClient.newHttpClient();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String target = request.getParameter("url");
        // ruleid: java.ssrf
        InputStream page = new URL(target).openStream();
        URL feed = new URL(request.getParameter("feed"));
        // ruleid: java.ssrf
        HttpURLConnection connection = (HttpURLConnection) feed.openConnection();
        String host = request.getHeader("X-Backend");
        // ruleid: java.ssrf
        new URL("http://" + host + "/status").openConnection();
        // ruleid: java.ssrf
        new URL("https", host, "/health").openStream();
        // ruleid: java.ssrf
        HttpRequest direct = HttpRequest.newBuilder(URI.create(target)).build();
        // ruleid: java.ssrf
        HttpRequest built = HttpRequest.newBuilder().uri(URI.create(String.format("%s://%s/", request.getParameter("scheme"), host))).GET().build();
        // ruleid: java.ssrf
        URI.create(target).toURL().openConnection();

        String id = request.getParameter("id");
        // ok: java.ssrf
        new URL(String.format("%s/items/%s", API, id)).openStream();
        // ok: java.ssrf
        new URL(UriComponentsBuilder.fromHttpUrl(API).pathSegment("items", id).toUriString()).openStream();
        // ok: java.ssrf
        new URL(new URL("https://api.example.com/"), "items/" + id).openStream();
        // ok: java.ssrf
        new URL(new URL("https://api.example.com/search"), "?q=" + id).openStream();
        // An absolute or "//host" spec replaces the base's host.
        // ruleid: java.ssrf
        new URL(new URL("https://api.example.com/"), target).openStream();
        // ruleid: java.ssrf
        new URL(new URL("https://api.example.com/"), "//" + host + "/status").openStream();
        // ruleid: java.ssrf
        new URL(UriComponentsBuilder.fromHttpUrl("https://api.example.com").host("api" + id).toUriString()).openStream();
        // ok: java.ssrf
        new URL(UriComponentsBuilder.fromHttpUrl(API).path("/items").pathSegment(id).queryParam("a", id).queryParam("b", id).fragment(id).toUriString()).openStream();
        // More than eight calls between the factory and the end of the chain.
        // todook: java.ssrf
        new URL(UriComponentsBuilder.fromHttpUrl(API).path("/a").path("/b").path("/c").path("/d").path("/e").path("/f").path("/g").path("/h").pathSegment(id).toUriString()).openStream();
        // ok: java.ssrf
        new URL(UriComponentsBuilder.newInstance().scheme("https").host("api.example.com").path("/items/" + id).toUriString()).openStream();
        // A base followed directly by request data: "@evil.example" would change the host.
        // ruleid: java.ssrf
        new URL(API + id).openStream();
        // ruleid: java.ssrf
        new URL(UriComponentsBuilder.fromHttpUrl("https://api.example.com/").host(id).toUriString()).openStream();
        // ruleid: java.ssrf
        new URL(UriComponentsBuilder.fromHttpUrl(API).uri(URI.create(target)).toUriString()).openStream();
        // ruleid: java.ssrf
        HttpRequest withHeader = HttpRequest.newBuilder().header("Accept", "text/html").uri(URI.create(target)).build();
        // A constant URI resolved against a relative reference.
        // todook: java.ssrf
        new URL(API_URI.resolve("items/" + id).toString()).openStream();
        // ok: java.ssrf
        new URL("https://api.example.com/items/" + id).openStream();
        // ok: java.ssrf
        HttpRequest item = HttpRequest.newBuilder(URI.create(API + "/items/" + id)).build();
        // ok: java.ssrf
        new URL("https", "api.example.com", "/items/" + id).openConnection();
        // ok: java.ssrf
        HttpRequest formatted = HttpRequest.newBuilder(URI.create(String.format("https://api.example.com/items/%s", id))).build();
        // ok: java.ssrf
        new URL(MIRRORS.get(request.getParameter("region")) + "/status").openStream();
        Map<String, String> endpoints = new java.util.HashMap<>();
        endpoints.put("callback", request.getParameter("callback"));
        // ruleid: java.ssrf
        new URL(endpoints.get("callback")).openStream();
        // ruleid: java.ssrf
        new URL(Map.of("callback", request.getParameter("callback")).get("callback")).openStream();
        // ok: java.ssrf
        new URL("https://api.example.com/status").openStream();
        // ok: java.ssrf
        URL parsed = new URL(target);
        // ok: java.ssrf
        boolean internal = parsed.getHost().endsWith(".internal");
    }
}

// Spring MVC: RestTemplate, RestClient and WebClient.
@RestController
class ProxyController {
    private RestTemplate restTemplate;
    private RestClient restClient;
    private WebClient webClient;

    @Value("${billing.base-url}")
    private String billingUrl;

    @GetMapping("/proxy/{service}")
    String proxy(@PathVariable String service, @RequestParam String url, @RequestHeader("X-Callback") String callback) {
        // ruleid: java.ssrf
        String body = restTemplate.getForObject(url, String.class);
        // ruleid: java.ssrf
        restTemplate.postForObject(callback, "ping", String.class);
        // ruleid: java.ssrf
        restClient.get().uri("http://" + service + ".internal/info").retrieve().body(String.class);
        // ruleid: java.ssrf
        webClient.get().uri(url).retrieve().bodyToMono(String.class).block();
        // ruleid: java.ssrf
        RestClient.create(url).get().retrieve().body(String.class);
        // ruleid: java.ssrf
        WebClient.builder().baseUrl(callback).build();
        // ruleid: java.ssrf
        restTemplate.getForObject(UriComponentsBuilder.fromHttpUrl(url).path("/info").toUriString(), String.class);

        // ok: java.ssrf
        restTemplate.getForObject("https://api.example.com/services/{name}", String.class, service);
        // ok: java.ssrf
        restClient.get().uri("/services/{name}", service).retrieve().body(String.class);
        // ok: java.ssrf
        restClient.get().uri("/services/" + service).retrieve().body(String.class);
        // ok: java.ssrf
        webClient.get().uri(builder -> builder.path("/services/{name}").build(service)).retrieve().bodyToMono(String.class).block();
        // ok: java.ssrf
        restTemplate.getForObject(billingUrl + "/invoices/" + service, String.class);
        // ok: java.ssrf
        restTemplate.getForObject(String.format("%s/invoices/%s", billingUrl, service), String.class);
        // ok: java.ssrf
        restTemplate.getForObject(UriComponentsBuilder.fromHttpUrl(billingUrl).pathSegment("invoices", service).toUriString(), String.class);
        // ruleid: java.ssrf
        restTemplate.getForObject(billingUrl + service, String.class);
        var dynamic = WebClient.create();
        // ruleid: java.ssrf
        dynamic.get().uri(callback).retrieve().bodyToMono(String.class).block();
        // ok: java.ssrf
        restTemplate.getForObject(UriComponentsBuilder.fromHttpUrl("https://api.example.com").path("/services/" + service).toUriString(), String.class);
        // ok: java.ssrf
        restTemplate.getForObject(UriComponentsBuilder.fromUriString("https://api.example.com/services/{name}").buildAndExpand(service).toUri(), String.class);
        return body;
    }

    @PostMapping("/webhooks")
    String webhook(@RequestBody WebhookForm form) {
        // ruleid: java.ssrf
        restTemplate.postForEntity(form.getTarget(), form, String.class);
        // ok: java.ssrf
        restTemplate.postForEntity("https://hooks.example.com/relay", form.getTarget(), String.class);
        return "ok";
    }
}

class WebhookForm {
    private String target;

    String getTarget() {
        return target;
    }
}

// Jakarta REST: path and query parameters.
@Path("/fetch")
class FetchResource {
    private final HttpClient client = HttpClient.newHttpClient();

    @GET
    @Path("/{host}")
    public String fetch(@PathParam("host") String host, @QueryParam("path") String path) throws IOException, InterruptedException {
        // ruleid: java.ssrf
        HttpRequest request = HttpRequest.newBuilder(URI.create("https://" + host + "/" + path)).build();
        // ok: java.ssrf
        HttpRequest fixed = HttpRequest.newBuilder(URI.create("https://static.example.com/" + path)).build();
        return client.send(fixed, HttpResponse.BodyHandlers.ofString()).body();
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    public String post(WebhookForm form) throws IOException {
        // todoruleid: java.ssrf
        new URL(form.getTarget()).openStream();
        return "ok";
    }
}

// Limits.
class LimitsController {
    private static final String HOST = "static.example.com";
    private RestTemplate restTemplate;

    @GetMapping("/limits")
    String limits(@RequestParam String path) {
        // The host comes from a constant, but in the middle of the string.
        // todook: java.ssrf
        restTemplate.getForObject("https://" + HOST + "/" + path, String.class);
        return "ok";
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@RestController
class SharedLimitsController {
    private static final String DEFAULT_TARGET = "https://a.example.com/";
    private static final Map<String, String> TABLE = Map.of("a", "https://a.example.com/", "b", "https://b.example.com/");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("a", "https://a.example.com/"), Map.entry("b", "https://b.example.com/"));
    private java.sql.Connection connection;

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback) throws IOException {
        // ok: java.ssrf
        new URL(TABLE.getOrDefault(key, DEFAULT_TARGET)).openStream();
        // ok: java.ssrf
        new URL(TABLE.getOrDefault(key, "https://b.example.com/")).openStream();
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.ssrf
        new URL(TABLE.getOrDefault(key, fallback)).openStream();
        // ruleid: java.ssrf
        new URL(Map.of("a", "https://a.example.com/").getOrDefault(key, key)).openStream();
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.ssrf
        new URL(javax.xml.namespace.QName.valueOf(key).getLocalPart()).openStream();
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.ssrf
        new URL(ENTRIES.get(key)).openStream();
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.ssrf
        new URL(java.time.DayOfWeek.valueOf(key).name()).openStream();
        return "ok";
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) throws IOException {
        // todoruleid: java.ssrf
        new URL(term).openStream();
        return "ok";
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry injected text, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind, @RequestParam List<Long> ids, @RequestParam Optional<Long> page)
            throws IOException {
        // todook: java.ssrf
        new URL(kind).openStream();
        // todook: java.ssrf
        new URL(ids.get(0)).openStream();
        // todook: java.ssrf
        new URL(page.orElse(0L)).openStream();
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
                    chosen = "https://a.example.com/";
                    break;
                default:
                    chosen = request.getParameter("chosen");
            }
            // A switch over a value computed from constants always takes the same branch.
            // todook: java.ssrf
            new URL(chosen).openStream();
        } catch (Exception e) {
            response.sendError(500);
        }
    }
}
