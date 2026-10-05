package com.acme.directory;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

import java.io.IOException;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
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
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapClient;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.ldap.filter.HardcodedFilter;
import org.springframework.ldap.filter.LikeFilter;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.support.LdapEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

enum EarlierKind {
    FIRST, SECOND
}

// Servlet: JNDI search filters built from request parameters, headers and cookies.
public class PeopleServlet extends HttpServlet {
    private static final String BASE = "ou=people,dc=example,dc=com";
    private static final Map<String, String> CLASSES = Map.of("person", "inetOrgPerson", "group", "groupOfNames");
    private DirContext ctx;
    private LdapContext ldapCtx;
    private InitialLdapContext initialLdapCtx;
    private javax.naming.event.EventDirContext eventCtx;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            SearchControls controls = new SearchControls();
            String uid = request.getParameter("uid");
            // ruleid: java.ldap-injection
            ctx.search(BASE, "(uid=" + uid + ")", controls);
            String filter = "(&(objectClass=person)(cn=" + request.getParameter("cn") + "))";
            // ruleid: java.ldap-injection
            NamingEnumeration<SearchResult> byName = ctx.search(BASE, filter, controls);
            // ruleid: java.ldap-injection
            ctx.search(BASE, String.format("(mail=%s)", request.getHeader("X-Mail")), controls);
            StringBuilder sb = new StringBuilder("(|");
            sb.append("(uid=").append(uid).append(")");
            sb.append(")");
            // ruleid: java.ldap-injection
            ctx.search(BASE, sb.toString(), controls);
            // The filter expression is still text: only the filterArgs are escaped.
            // ruleid: java.ldap-injection
            ctx.search(BASE, "(&(uid={0})(ou=" + request.getParameter("ou") + "))", new Object[] { uid }, controls);
            for (Cookie c : request.getCookies()) {
                // ruleid: java.ldap-injection
                ldapCtx.search(BASE, "(sn=" + c.getValue() + ")", controls);
            }
            // ruleid: java.ldap-injection
            ctx.search(BASE, "(description=*" + request.getQueryString() + "*)", controls);
            // ruleid: java.ldap-injection
            initialLdapCtx.search(BASE, "(uid=" + uid + ")", controls);
            // ruleid: java.ldap-injection
            eventCtx.search(BASE, "(uid=" + uid + ")", controls);

            // ok: java.ldap-injection
            ctx.search(BASE, "(uid={0})", new Object[] { uid }, controls);
            // ok: java.ldap-injection
            ctx.search(BASE, "(&(objectClass={0})(uid={1}))", new Object[] { "person", uid }, controls);
            // ok: java.ldap-injection
            ctx.search(BASE, "(objectClass=person)", controls);
            // ok: java.ldap-injection
            ctx.search(BASE, "(uid=" + LdapEncoder.filterEncode(uid) + ")", controls);
            // ok: java.ldap-injection
            ctx.search(BASE, "(uid=" + ESAPI.encoder().encodeForLDAP(uid) + ")", controls);
            // ok: java.ldap-injection
            ctx.search(BASE, "(employeeNumber=" + Integer.parseInt(request.getParameter("no")) + ")", controls);
            // ok: java.ldap-injection
            ctx.search(BASE, "(objectClass=" + CLASSES.get(request.getParameter("kind")) + ")", controls);
            String kind = "group".equals(request.getParameter("kind")) ? "groupOfNames" : "inetOrgPerson";
            // ok: java.ldap-injection
            ctx.search(BASE, "(objectClass=" + kind + ")", controls);
            // Attribute matching takes values, not filter text.
            // ok: java.ldap-injection
            ctx.search(BASE, new BasicAttributes("uid", uid));
            // ok: java.ldap-injection
            ctx.search(BASE, new BasicAttributes("mail", request.getParameter("mail")), new String[] { "cn" });
            javax.naming.directory.Attributes matching = new BasicAttributes(true);
            matching.put("uid", uid);
            // ok: java.ldap-injection
            ctx.search(BASE, matching, new String[] { "cn" });
        } catch (NamingException e) {
            throw new IOException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.provider.url", "ldap://ldap.example.com");
        try {
            String login = request.getParameter("login");
            DirContext initial = new InitialDirContext(env);
            // ruleid: java.ldap-injection
            initial.search(BASE, "(uid=" + login + ")", new SearchControls());
            var inferred = new InitialDirContext(env);
            // ruleid: java.ldap-injection
            inferred.search(BASE, "(uid=" + login + ")", new SearchControls());
            var ldap = new InitialLdapContext(env, null);
            // ruleid: java.ldap-injection
            ldap.search(BASE, "(cn=" + login + ")", new SearchControls());
            // ruleid: java.ldap-injection
            new InitialDirContext(env).search(BASE, "(mail=" + login + ")", new SearchControls());
            // ok: java.ldap-injection
            inferred.search(BASE, "(uid={0})", new Object[] { login }, new SearchControls());
            Encoder encoder = ESAPI.encoder();
            // ok: java.ldap-injection
            inferred.search(BASE, "(uid=" + encoder.encodeForLDAP(login) + ")", new SearchControls());
        } catch (NamingException e) {
            throw new IOException(e);
        }
    }

    // Limits of a taint analysis that sees one method at a time and does not evaluate
    // conditions.
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // A helper of the same class that returns a constant whatever it is given.
            // todook: java.ldap-injection
            ctx.search(BASE, defaultFilter(request.getParameter("f")), new SearchControls());
            char mode = "abc".charAt(0);
            String attribute;
            switch (mode) {
                case 0x61:
                    attribute = "uid";
                    break;
                default:
                    attribute = request.getParameter("attribute");
            }
            // A switch over a value computed from constants always takes the same branch.
            // todook: java.ldap-injection
            ctx.search(BASE, "(" + attribute + "=*)", new SearchControls());
            // A wrapper class that reads the request is not followed into.
            RequestWrapper wrapper = new RequestWrapper(request);
            // todoruleid: java.ldap-injection
            ctx.search(BASE, "(uid=" + wrapper.value("uid") + ")", new SearchControls());
            // The search base (a distinguished name) is not a sink: only the filter is.
            // todoruleid: java.ldap-injection
            ctx.search("uid=" + request.getParameter("uid") + "," + BASE, "(objectClass=*)", new SearchControls());
        } catch (NamingException e) {
            throw new IOException(e);
        }
    }

    private static String defaultFilter(String requested) {
        return "(objectClass=person)";
    }

    // Not a handler: the parameter is not request data.
    void audit(String request) throws NamingException {
        // ok: java.ldap-injection
        ctx.search(BASE, "(uid=" + request + ")", new SearchControls());
    }
}

// Spring MVC and Spring LDAP: LdapTemplate filters, the query builder and filter classes.
@RestController
class DirectoryController {
    private LdapTemplate ldapTemplate;
    private LdapClient ldapClient;
    private org.springframework.ldap.core.LdapOperations ldapOperations;
    private org.springframework.ldap.core.ContextSource contextSource;
    private SearchIndex index;
    private static final AttributesMapper<String> CN = attrs -> (String) attrs.get("cn").get();

    @GetMapping("/people/{uid}")
    List<String> person(@PathVariable String uid, @RequestParam("dept") String dept) {
        // ruleid: java.ldap-injection
        List<String> found = ldapTemplate.search("ou=people", "(uid=" + uid + ")", CN);
        // ruleid: java.ldap-injection
        ldapTemplate.searchForObject("ou=people", "(&(uid=" + uid + ")(ou=" + dept + "))", ctx -> ctx);
        // ruleid: java.ldap-injection
        ldapTemplate.search(query().filter("(departmentNumber=" + dept + ")"), CN);
        // ruleid: java.ldap-injection
        ldapTemplate.search(LdapQueryBuilder.query().base("ou=people").filter("(ou=" + dept + ")"), CN);
        // The format is text too: only the parameters are encoded.
        // ruleid: java.ldap-injection
        ldapTemplate.search(query().filter("(&(uid={0})(ou=" + dept + "))", uid), CN);
        // ruleid: java.ldap-injection
        ldapTemplate.find(query().base("ou=people").filter(new HardcodedFilter("(uid=" + uid + ")")), Person.class);
        // ruleid: java.ldap-injection
        ldapClient.search().query(q -> q.filter("(uid=" + uid + ")")).toList(CN);
        // ruleid: java.ldap-injection
        ldapOperations.search("ou=people", "(uid=" + uid + ")", CN);
        LdapQueryBuilder builder = LdapQueryBuilder.query();
        // ruleid: java.ldap-injection
        builder.filter("(uid=" + uid + ")");
        AndFilter combined = new AndFilter();
        // ruleid: java.ldap-injection
        combined.and(new HardcodedFilter("(ou=" + dept + ")"));
        try {
            var dirContext = contextSource.getReadOnlyContext();
            // ruleid: java.ldap-injection
            dirContext.search("ou=people", "(uid=" + uid + ")", new SearchControls());
        } catch (NamingException e) {
            throw new IllegalStateException(e);
        }
        // The attribute name given to where(...) is not a sink.
        // todoruleid: java.ldap-injection
        ldapTemplate.search(query().where(dept).is("x"), CN);

        // ok: java.ldap-injection
        ldapTemplate.search(query().where("uid").is(uid), CN);
        // ok: java.ldap-injection
        ldapTemplate.search(query().where("objectclass").is("person").and("ou").is(dept), CN);
        // ok: java.ldap-injection
        ldapTemplate.search(query().filter("(uid={0})", uid), CN);
        // ok: java.ldap-injection
        ldapClient.search().query(q -> q.where("uid").is(uid)).toList(CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=people", new EqualsFilter("uid", uid).encode(), CN);
        AndFilter and = new AndFilter();
        and.and(new EqualsFilter("objectclass", "person"));
        and.and(new LikeFilter("cn", dept));
        // ok: java.ldap-injection
        ldapTemplate.search("ou=people", and.encode(), CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=people", "(uid=" + LdapEncoder.filterEncode(uid) + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=people", "(objectClass=person)", CN);
        // A search method of another library.
        // ok: java.ldap-injection
        index.search("people", "title:" + dept, 10);
        return found;
    }

    @PostMapping("/login")
    boolean login(@RequestBody Credentials credentials, @RequestHeader("X-Realm") String realm) {
        // ruleid: java.ldap-injection
        boolean ok = ldapTemplate.authenticate("ou=people", "(uid=" + credentials.getUsername() + ")", credentials.getPassword());
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=" + "people", "(&(uid=" + credentials.getUsername() + ")(o=" + realm + "))", CN);
        // The password is a bound credential, not filter text.
        // ok: java.ldap-injection
        ldapTemplate.authenticate(query().where("uid").is(credentials.getUsername()), credentials.getPassword());
        LdapQuery byUid = query().where("uid").is(credentials.getUsername());
        // ok: java.ldap-injection
        ldapTemplate.authenticate(byUid, credentials.getPassword(), (ctx, entry) -> entry);
        // ok: java.ldap-injection
        ldapTemplate.authenticate("ou=people", new EqualsFilter("uid", credentials.getUsername()).encode(),credentials.getPassword());
        return ok;
    }

    @GetMapping("/groups")
    List<String> groups(@CookieValue("group") String group, HttpEntity<String> entity) {
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=groups", "(cn=" + group + ")", CN);
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=groups", "(description=" + entity.getBody() + ")", CN);
        // An attribute name chosen by the request is not encoded by the filter classes.
        // ruleid: java.ldap-injection
        return ldapTemplate.search("ou=groups", new EqualsFilter(group, "x").encode(), CN);
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

class Credentials {
    private String username;
    private String password;

    String getUsername() {
        return username;
    }

    String getPassword() {
        return password;
    }
}

class Person {
}

class SearchIndex {
    List<String> search(String index, String query, int limit) {
        return List.of();
    }
}

// Jakarta REST: path, query, header and form parameters.
@jakarta.ws.rs.Path("/directory")
class DirectoryResource {
    private DirContext ctx;

    @GET
    @jakarta.ws.rs.Path("/{uid}")
    public String lookup(@PathParam("uid") String uid, @QueryParam("attr") String attr, @HeaderParam("X-Org") String org)
            throws NamingException {
        // ruleid: java.ldap-injection
        ctx.search("ou=people", "(uid=" + uid + ")", new SearchControls());
        // ruleid: java.ldap-injection
        ctx.search("ou=people", "(&(o=" + org + ")(" + attr + "=*))", new SearchControls());
        // ok: java.ldap-injection
        ctx.search("ou=people", "(&(o={0})(uid={1}))", new Object[] { org, uid }, new SearchControls());
        return uid;
    }

    @POST
    public String find(@FormParam("mail") String mail) throws NamingException {
        // ruleid: java.ldap-injection
        ctx.search("ou=people", "(mail=" + mail + ")", new SearchControls());
        // ok: java.ldap-injection
        ctx.search("ou=people", "(mail={0})", new Object[] { mail }, new SearchControls());
        return mail;
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    @jakarta.ws.rs.Path("/raw")
    public String raw(String body) throws NamingException {
        // todoruleid: java.ldap-injection
        ctx.search("ou=people", "(cn=" + body + ")", new SearchControls());
        return body;
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@RestController
class SharedLimitsController {
    private static final String DEFAULT_CLASS = "person";
    private static final Map<String, String> TABLE = Map.of("a", "person", "b", "group");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("a", "person"), Map.entry("b", "group"));
    private LdapTemplate ldapTemplate;
    private static final AttributesMapper<String> CN = attrs -> (String) attrs.get("cn").get();

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback) {
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(objectClass=" + TABLE.getOrDefault(key, DEFAULT_CLASS) + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(objectClass=" + TABLE.getOrDefault(key, "person") + ")", CN);
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(objectClass=" + TABLE.getOrDefault(key, fallback) + ")", CN);
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(objectClass=" + Map.of("a", "person").getOrDefault(key, key) + ")", CN);
        Map<String, String> filled = new java.util.HashMap<>();
        filled.put("k", key);
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(objectClass=" + filled.get("k") + ")", CN);
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + javax.xml.namespace.QName.valueOf(key).getLocalPart() + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(objectClass=" + SharedKind.valueOf(key).name() + ")", CN);
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.ldap-injection
        ldapTemplate.search("ou=x", "(objectClass=" + ENTRIES.get(key) + ")", CN);
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.ldap-injection
        ldapTemplate.search("ou=x", "(day=" + java.time.DayOfWeek.valueOf(key).name() + ")", CN);
        return "ok";
    }

    // The other spellings of the shared request sources and sanitizers.
    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n) {
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + Map.of("a", "x", "b", "y").get(key) + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + Map.of("a", "x").getOrDefault(key, "x") + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + Long.parseLong(n) + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + Integer.valueOf(n) + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + Long.valueOf(n) + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + Enum.valueOf(SharedKind.class, key).name() + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + java.lang.Enum.valueOf(SharedKind.class, key).name() + ")", CN);
        // An enum declared inside the class.
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + Level.valueOf(key).name() + ")", CN);
        // An enum declared before the class.
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + EarlierKind.valueOf(key).name() + ")", CN);
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // A mapping annotation without arguments.
    @PostMapping
    String bare(HttpEntity<String> entity) {
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + entity.getBody() + ")", CN);
        return "ok";
    }

    // Servlet request types of both namespaces.
    void filterJakarta(jakarta.servlet.ServletRequest request) {
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + request.getParameter("q") + ")", CN);
    }

    void filterJavax(javax.servlet.ServletRequest request) {
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + request.getParameter("q") + ")", CN);
    }

    void legacy(javax.servlet.http.HttpServletRequest request) {
        // ruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + request.getParameter("q") + ")", CN);
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) {
        // todoruleid: java.ldap-injection
        ldapTemplate.search("ou=x", "(cn=" + term + ")", CN);
        return "ok";
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry filter syntax, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind, @RequestParam List<Long> ids, @RequestParam Optional<Long> page) {
        // todook: java.ldap-injection
        ldapTemplate.search("ou=x", "(kind=" + kind + ")", CN);
        // todook: java.ldap-injection
        ldapTemplate.search("ou=x", "(employeeNumber=" + ids.get(0) + ")", CN);
        // todook: java.ldap-injection
        ldapTemplate.search("ou=x", "(employeeNumber=" + page.orElse(0L) + ")", CN);
        // ok: java.ldap-injection
        ldapTemplate.search("ou=x", "(employeeNumber=" + Long.parseLong(String.valueOf(ids.get(0))) + ")", CN);
        return "ok";
    }
}

enum SharedKind {
    SMALL, LARGE
}
