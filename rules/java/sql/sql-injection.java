package com.acme.shop;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import org.hibernate.Session;
import javax.servlet.http.HttpServlet;
import javax.sql.DataSource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.RequestEntity;
import org.springframework.http.HttpEntity;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;

// An enum declared before the first class (the shared enum allow-list forms).
enum EarlierKind {
    ONE, TWO
}

public class OrderServlet extends HttpServlet {
    private Connection connection;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String customer = request.getParameter("customer");
        try (Statement statement = connection.createStatement()) {
            // ruleid: java.sql-injection
            ResultSet a = statement.executeQuery("SELECT * FROM orders WHERE customer = '" + customer + "'");
            String sql = "DELETE FROM orders WHERE note = '" + request.getHeader("X-Note") + "'";
            // ruleid: java.sql-injection
            statement.executeUpdate(sql);
            // ruleid: java.sql-injection
            PreparedStatement p = connection.prepareStatement(String.format("SELECT * FROM orders WHERE id = %s", request.getParameter("id")));
            // ruleid: java.sql-injection
            statement.addBatch("INSERT INTO log VALUES ('" + request.getQueryString() + "')");
            // ok: java.sql-injection
            PreparedStatement q = connection.prepareStatement("SELECT * FROM orders WHERE customer = ?");
            q.setString(1, customer);
            // ok: java.sql-injection
            statement.execute("SELECT count(*) FROM orders");
            String column = "price".equals(request.getParameter("sort")) ? "price" : "name";
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM items ORDER BY " + column);
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM items WHERE id = " + Integer.parseInt(request.getParameter("id")));
        } catch (SQLException e) {
            response.sendError(500);
        }
    }
}

@RestController
class ItemController {
    private Connection connection;

    @GetMapping("/items")
    String items(@RequestParam String name, @RequestParam long id) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM items WHERE name = '" + name + "'");
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM items WHERE id = " + id);
        }
        return "ok";
    }
}

// Spring MVC: URI template variables, headers and request bodies; Spring JDBC and JPA.
@RestController
class AccountController {
    private Connection connection;
    private JdbcTemplate jdbcTemplate;
    private NamedParameterJdbcTemplate namedJdbc;
    private JdbcClient jdbcClient;
    private EntityManager entityManager;
    private ExecutorService executor;

    @GetMapping("/accounts/{id}")
    String account(@PathVariable String id, @RequestHeader("X-Tenant") String tenant) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM accounts WHERE id = '" + id + "'");
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM accounts WHERE tenant = '" + tenant + "'");
        }
        try (PreparedStatement ps = connection.prepareStatement("SELECT * FROM accounts WHERE id = ?")) {
            // ok: java.sql-injection
            ps.setString(1, id);
            ps.executeQuery();
        }
        // ok: java.sql-injection
        jdbcTemplate.queryForObject("select count(*) from accounts where id = ?", Integer.class, id);
        // ok: java.sql-injection
        jdbcTemplate.update("update accounts set tenant = ? where id = ?", tenant, id);
        // ok: java.sql-injection
        namedJdbc.queryForObject("select count(*) from accounts where id = :id", Map.of("id", id), Integer.class);
        // ok: java.sql-injection
        jdbcClient.sql("select count(*) from accounts where id = :id").param("id", id).query(Integer.class).single();
        // ruleid: java.sql-injection
        jdbcTemplate.queryForList("select * from accounts where id = '" + id + "'");
        // ruleid: java.sql-injection
        namedJdbc.update("delete from accounts where tenant = '" + tenant + "'", Map.of());
        // ruleid: java.sql-injection
        jdbcClient.sql("select * from accounts where tenant = '" + tenant + "'").query().listOfRows();
        // ok: java.sql-injection
        entityManager.createQuery("SELECT a FROM Account a WHERE a.id = :id").setParameter("id", id).getResultList();
        // ok: java.sql-injection
        entityManager.createNativeQuery("SELECT * FROM accounts WHERE id = ?1").setParameter(1, id).getResultList();
        // ruleid: java.sql-injection
        entityManager.createQuery("SELECT a FROM Account a WHERE a.id = '" + id + "'").getResultList();
        // ruleid: java.sql-injection
        entityManager.createNativeQuery("SELECT * FROM accounts WHERE tenant = '" + tenant + "'").getResultList();
        // ok: java.sql-injection
        executor.execute(() -> System.out.println(id));
        return "ok";
    }

    @PostMapping("/accounts/{id}/notes")
    String note(@PathVariable("id") long id, @RequestBody NoteForm form) {
        // ruleid: java.sql-injection
        jdbcTemplate.execute("INSERT INTO notes VALUES (" + id + ", '" + form.getText() + "')");
        // ok: java.sql-injection
        jdbcTemplate.update("INSERT INTO notes VALUES (?, ?)", id, form.getText());
        // ok: java.sql-injection
        jdbcTemplate.execute("DELETE FROM notes WHERE account = " + id);
        return "ok";
    }
}

class NoteForm {
    private String text;

    String getText() {
        return text;
    }
}

// Jakarta RESTful Web Services: path, query, header and form parameters.
@Path("/reports")
class ReportResource {
    private Connection connection;

    @GET
    @Path("/{name}")
    public String report(@PathParam("name") String name, @QueryParam("year") String year,
            @QueryParam("limit") int limit, @jakarta.ws.rs.HeaderParam("X-Region") String region)
            throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM reports WHERE name = '" + name + "'");
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM reports WHERE year = " + year);
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM reports WHERE region = '" + region + "'");
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM reports FETCH FIRST " + limit + " ROWS ONLY");
        }
        try (PreparedStatement ps = connection.prepareStatement("SELECT * FROM reports WHERE name = ? AND year = ?")) {
            ps.setString(1, name);
            ps.setString(2, year);
            // ok: java.sql-injection
            ps.executeQuery();
        }
        return "ok";
    }
}

// Hibernate's Session and Spring's JdbcOperations interface.
@RestController
class TagController {
    private Session session;
    private JdbcOperations jdbc;

    @GetMapping("/tags/{tag}")
    String tag(@PathVariable String tag, @RequestParam String page) {
        // ruleid: java.sql-injection
        session.createSelectionQuery("from Tag t where t.name = '" + tag + "'", Tag.class).getResultList();
        // ok: java.sql-injection
        session.createSelectionQuery("from Tag t where t.name = :name", Tag.class).setParameter("name", tag).getResultList();
        // ruleid: java.sql-injection
        jdbc.queryForList("select * from tags where name = '" + tag + "'");
        // ok: java.sql-injection
        jdbc.queryForList("select * from tags offset " + Long.valueOf(page));
        return "ok";
    }

    @GetMapping("/tags")
    String tags(@RequestParam String name, java.sql.Connection connection) throws SQLException {
        var statement = connection.createStatement();
        // ruleid: java.sql-injection
        statement.executeQuery("SELECT * FROM tags WHERE name = '" + name + "'");
        // ok: java.sql-injection
        statement.executeQuery("SELECT count(*) FROM tags");
        return "ok";
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/tags/search")
    String search(String term, java.sql.Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // todoruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM tags WHERE name LIKE '%" + term + "%'");
        }
        return "ok";
    }
}

class Tag {
}

// SQL text assembled with a StringBuilder, a Statement used in a chain, and connections from a
// DataSource or DriverManager.
@RestController
class SearchController {
    private Connection connection;
    private DataSource dataSource;

    @GetMapping("/search")
    String search(@RequestParam String q, @ModelAttribute SearchForm form) throws SQLException {
        StringBuilder sql = new StringBuilder("SELECT * FROM items WHERE name = '");
        sql.append(q).append("'");
        try (Statement statement = connection.createStatement()) {
            // ruleid: java.sql-injection
            statement.executeQuery(sql.toString());
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM items WHERE category = '" + form.getCategory() + "'");
            StringBuilder fixed = new StringBuilder("SELECT * FROM items WHERE name = ?");
            fixed.append(" ORDER BY name");
            // ok: java.sql-injection
            statement.executeQuery(fixed.toString());
        }
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + q + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT count(*) FROM items");
        var pooled = dataSource.getConnection();
        // ruleid: java.sql-injection
        pooled.prepareStatement("SELECT * FROM items WHERE name = '" + q + "'");
        // ok: java.sql-injection
        pooled.prepareStatement("SELECT * FROM items WHERE name = ?").setString(1, q);
        var direct = DriverManager.getConnection("jdbc:h2:mem:shop");
        // ruleid: java.sql-injection
        direct.prepareStatement("DELETE FROM items WHERE name = '" + q + "'");
        return "ok";
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry SQL, but the rule only knows the scalar types it lists.
    @GetMapping("/search/sorted")
    String sorted(@RequestParam SortOrder order, @RequestParam List<Long> ids, @RequestParam Optional<Long> page)
            throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // todook: java.sql-injection
            statement.executeQuery("SELECT * FROM items ORDER BY name " + order);
            // todook: java.sql-injection
            statement.executeQuery("SELECT * FROM items WHERE id IN (" + ids.get(0) + ")");
            // todook: java.sql-injection
            statement.executeQuery("SELECT * FROM items OFFSET " + page.orElse(0L));
        }
        return "ok";
    }
}

enum SortOrder {
    ASC, DESC
}

class SearchForm {
    private String category;

    String getCategory() {
        return category;
    }
}

// Jakarta REST: the entity parameter (the request body) has no annotation.
@Path("/notes")
class NoteResource {
    private Connection connection;

    @POST
    public String create(NoteForm form) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // todoruleid: java.sql-injection
            statement.executeUpdate("INSERT INTO notes (text) VALUES ('" + form.getText() + "')");
        }
        return "ok";
    }
}

// Servlet: parameter and header names are chosen by the client too; values kept in a list or a
// map on the way; Spring's JdbcTemplate reached through a static field of a class in another
// file, whose type the scanner cannot see (recognised by the SQL text it is given).
class ArchiveServlet extends HttpServlet {
    private Connection connection;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        java.util.Enumeration<String> names = request.getParameterNames();
        String first = names.nextElement();
        java.util.Enumeration<String> headers = request.getHeaderNames();
        String header = headers.nextElement();
        java.util.List<String> filters = new java.util.ArrayList<>();
        filters.add(request.getParameter("filter"));
        java.util.Map<String, String> fields = new java.util.HashMap<>();
        fields.put("owner", request.getParameter("owner"));
        try (Statement statement = connection.createStatement()) {
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM archive WHERE field = '" + first + "'");
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM archive WHERE header = '" + header + "'");
            // List.add does not carry taint into the list (a propagator for it reported constant
            // elements of the same list as often as request data).
            // todoruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM archive WHERE kind = '" + filters.get(0) + "'");
            // ruleid: java.sql-injection
            statement.executeUpdate("DELETE FROM archive WHERE owner = '" + fields.get("owner") + "'");
            java.util.List<String> columns = new java.util.ArrayList<>();
            columns.add("created");
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM archive ORDER BY " + columns.get(0));
        } catch (SQLException e) {
            response.sendError(500);
        }

        String year = request.getParameter("year");
        String sql = "SELECT * FROM archive WHERE year = '" + year + "'";
        // ruleid: java.sql-injection
        com.acme.shop.db.Database.TEMPLATE.queryForList(sql);
        // ruleid: java.sql-injection
        com.acme.shop.db.Database.TEMPLATE.batchUpdate("DELETE FROM archive WHERE year = '" + year + "'");
        // ruleid: java.sql-injection
        com.acme.shop.db.Database.TEMPLATE.execute(String.format("UPDATE archive SET seen = 1 WHERE year = '%s'", year));
        // ok: java.sql-injection
        com.acme.shop.db.Database.TEMPLATE.queryForList("SELECT * FROM archive WHERE year = ?", year);
        String graph = "{ archive(year: \"" + year + "\") { id } }";
        // ok: java.sql-injection
        com.acme.shop.search.Graph.CLIENT.execute(graph);
        // ok: java.sql-injection
        com.acme.shop.search.Index.CLIENT.query("title:" + year);
        // ok: java.sql-injection
        com.acme.shop.ui.Status.LINE.update("Select a row for " + year);
        // ok: java.sql-injection
        com.acme.shop.jobs.Pool.MAIN.execute("Delete requested by " + year);
        String block = """
                SELECT * FROM archive WHERE label = '""" + year + "'";
        // ruleid: java.sql-injection
        com.acme.shop.db.Database.TEMPLATE.queryForList(block);
        StringBuilder assembled = new StringBuilder("SELECT * FROM archive WHERE year = '");
        assembled.append(year).append("'");
        // A query assembled with a StringBuilder for a JdbcTemplate of unknown type.
        // todoruleid: java.sql-injection
        com.acme.shop.db.Database.TEMPLATE.queryForList(assembled.toString());

        try (Statement statement = connection.createStatement()) {
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM visits WHERE url = '" + request.getRequestURL() + "'");
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM uploads WHERE name = '" + request.getPart("file").getSubmittedFileName() + "'");
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM uploads WHERE field = '" + request.getParts().iterator().next().getName() + "'");
        } catch (SQLException | jakarta.servlet.ServletException e) {
            response.sendError(500);
        }
    }
}

// Map keys; and the limits of a taint analysis that sees one method at a time.
class ArchiveLimitsServlet extends HttpServlet {
    private Connection connection;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        java.util.Map<String, String> parts = new java.util.HashMap<>();
        parts.put("current", "2026");
        parts.put("requested", request.getParameter("part"));
        String label = constantLabel(request.getParameter("label"));
        // A wrapper class from another file that reads the request.
        String region = new com.acme.shop.web.RequestValues(request).get("region");
        try (Statement statement = connection.createStatement()) {
            // Map entries are told apart by a constant key: "current" holds a constant.
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM archive WHERE part = '" + parts.get("current") + "'");
            // A helper method that returns a constant for any argument.
            // todook: java.sql-injection
            statement.executeQuery("SELECT * FROM archive WHERE label = '" + label + "'");
            // todoruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM archive WHERE region = '" + region + "'");
        } catch (SQLException e) {
            response.sendError(500);
        }
    }

    private static String constantLabel(String requested) {
        return "default";
    }
}

// Allow-lists: a constant map in a static final field or in place, and enum constants.
class SortedServlet extends HttpServlet {
    private static final Map<String, String> SORT_COLUMNS = Map.of("name", "name", "price", "price");
    private Connection connection;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try (Statement statement = connection.createStatement()) {
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM items ORDER BY " + SORT_COLUMNS.get(request.getParameter("sort")));
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM items ORDER BY name " + Map.of("up", "ASC", "down", "DESC").getOrDefault(request.getParameter("dir"), "ASC"));
            // ok: java.sql-injection
            statement.executeQuery("SELECT * FROM items ORDER BY name " + SortOrder.valueOf(request.getParameter("order")));
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM items WHERE name = '" + String.valueOf(request.getParameter("name")) + "'");
            java.util.Map<String, String> chosen = new java.util.HashMap<>();
            chosen.put("sort", request.getParameter("sort"));
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM items ORDER BY " + chosen.get("sort"));
            // ruleid: java.sql-injection
            statement.executeQuery("SELECT * FROM items ORDER BY " + Map.of("sort", request.getParameter("sort")).get("sort"));
        } catch (SQLException e) {
            response.sendError(500);
        }
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
    String lookups(@RequestParam String key, @RequestParam String fallback) throws java.sql.SQLException {
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + TABLE.getOrDefault(key, DEFAULT_TARGET) + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + TABLE.getOrDefault(key, "beta") + "'");
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + TABLE.getOrDefault(key, fallback) + "'");
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + Map.of("a", "alpha").getOrDefault(key, key) + "'");
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + javax.xml.namespace.QName.valueOf(key).getLocalPart() + "'");
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + ENTRIES.get(key) + "'");
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + java.time.DayOfWeek.valueOf(key).name() + "'");
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
            // todook: java.sql-injection
            connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + chosen + "'");
        } catch (Exception e) {
            response.sendError(500);
        }
    }
}

// The request body of a Spring MVC HttpEntity or RequestEntity parameter, and SQL text assembled in
// an append chain (StringBuilder.append(...).append(value)).
@RestController
class EntityNotesController {
    private JdbcTemplate jdbc;

    @PostMapping("/entity/notes")
    List<Map<String, Object>> notes(HttpEntity<String> entity) {
        // ruleid: java.sql-injection
        return jdbc.queryForList("SELECT * FROM notes WHERE body = '" + entity.getBody() + "'");
    }

    @org.springframework.web.bind.annotation.RequestMapping("/entity/tags")
    List<Map<String, Object>> tags(RequestEntity<String> request) {
        // ruleid: java.sql-injection
        return jdbc.queryForList("SELECT * FROM tags WHERE name = '" + request.getBody() + "'");
    }

    @PostMapping
    List<Map<String, Object>> labels(org.springframework.http.HttpEntity<NoteForm> entity) {
        // ruleid: java.sql-injection
        return jdbc.queryForList("SELECT * FROM labels WHERE owner = '" + entity.getHeaders().getFirst("X-Owner") + "'");
    }

    @GetMapping("/entity/chain")
    List<Map<String, Object>> chain(@RequestParam String term) {
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT * FROM notes WHERE title = '").append(term).append("'");
        // ruleid: java.sql-injection
        jdbc.queryForList(sql.toString());
        StringBuilder fixed = new StringBuilder();
        fixed.append("SELECT * FROM notes WHERE title = ?").append(" ORDER BY title");
        // ok: java.sql-injection
        return jdbc.queryForList(fixed.toString(), term);
    }

    @PostMapping("/entity/bound")
    List<Map<String, Object>> bound(HttpEntity<String> entity) {
        // ok: java.sql-injection
        return jdbc.queryForList("SELECT * FROM notes WHERE body = ?", entity.getBody());
    }

    // Not a handler method: an entity it is given is not request data.
    List<Map<String, Object>> replay(HttpEntity<String> entity) {
        // ok: java.sql-injection
        return jdbc.queryForList("SELECT * FROM notes WHERE body = '" + entity.getBody() + "'");
    }
}

// The other spellings of the shared request sources and sanitizers.
@RestController
class SharedFormsController {
    private static final Map<String, String> FORMS = Map.of("a", "alpha", "b", "alpha");
    private Connection connection;

    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n) throws SQLException {
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + Map.of("a", "alpha", "b", "alpha").get(key) + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + Map.of("a", "alpha").getOrDefault(key, "alpha") + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + FORMS.get(key) + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + FORMS.getOrDefault(key, "alpha") + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + String.valueOf(Integer.parseInt(n)) + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + String.valueOf(Long.parseLong(n)) + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + String.valueOf(Integer.valueOf(n)) + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + String.valueOf(Long.valueOf(n)) + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + Enum.valueOf(FormKind.class, key).name() + "'");
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + java.lang.Enum.valueOf(FormKind.class, key).name() + "'");
        // An enum declared inside the class.
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + Level.valueOf(key).name() + "'");
        // An enum declared before the first class of the file.
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + EarlierKind.valueOf(key).name() + "'");
        // An enum declared after the class.
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + FormKind.valueOf(key).name() + "'");
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + single.toString() + "'");
        return "ok";
    }

    // A part of a multipart request bound with @RequestPart (text, or a body converted with an
    // HttpMessageConverter).
    @org.springframework.web.bind.annotation.PostMapping("/shared/part")
    String part(@RequestPart("meta") String meta, @org.springframework.web.bind.annotation.RequestPart("note") PartNote note,
            @RequestPart("count") int count) throws SQLException {
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + meta + "'");
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + note.getText() + "'");
        // A part converted to a number cannot carry injected text.
        // ok: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + String.valueOf(count) + "'");
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // Servlet request types of both namespaces.
    void jakartaRequest(jakarta.servlet.ServletRequest request) throws SQLException {
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + request.getParameter("q") + "'");
    }

    void javaxRequest(javax.servlet.ServletRequest request) throws SQLException {
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + request.getParameter("q") + "'");
    }

    void javaxHttpRequest(javax.servlet.http.HttpServletRequest request) throws SQLException {
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + request.getParameter("q") + "'");
    }

    void jakartaHttpRequest(jakarta.servlet.http.HttpServletRequest request) throws SQLException {
        // ruleid: java.sql-injection
        connection.createStatement().executeQuery("SELECT * FROM items WHERE name = '" + request.getParameter("q") + "'");
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
