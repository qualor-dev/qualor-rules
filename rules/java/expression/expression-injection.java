package com.acme.rules;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.el.ELContext;
import jakarta.el.ELManager;
import jakarta.el.ELProcessor;
import jakarta.el.ExpressionFactory;
import jakarta.el.ValueExpression;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import ognl.Ognl;
import ognl.OgnlException;
import org.mvel2.MVEL;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.HttpEntity;
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

// Spring MVC: SpEL expressions parsed from request data and evaluated.
@RestController
class PricingController {
    private final ExpressionParser parser = new SpelExpressionParser();
    private SpelExpressionParser spel;
    private SettingsStore settings;

    private static EvaluationContext readOnly() {
        return SimpleEvaluationContext.forReadOnlyDataBinding().build();
    }

    private Expression compile(String text) {
        return parser.parseExpression(text);
    }
    private SimpleEvaluationContext readOnlyContext;

    @GetMapping("/price/{formula}")
    Object price(@PathVariable String formula, @RequestParam("discount") String discount, @RequestHeader("X-Rule") String rule) {
        // ruleid: java.expression-injection
        Object value = parser.parseExpression(formula).getValue();
        Expression expression = parser.parseExpression("price * " + discount);
        // ruleid: java.expression-injection
        expression.getValue(new StandardEvaluationContext(new Order()));
        StandardEvaluationContext standard = new StandardEvaluationContext();
        // ruleid: java.expression-injection
        spel.parseExpression(rule).getValue(standard, Boolean.class);
        // ruleid: java.expression-injection
        parser.parseExpression("Total: #{" + rule + "}", new TemplateParserContext()).getValue(new Order(), String.class);
        var inferred = new SpelExpressionParser().parseExpression(rule);
        // ruleid: java.expression-injection
        inferred.setValue(standard, new Order(), "1");
        // ruleid: java.expression-injection
        new SpelExpressionParser().parseExpression(formula).getValueType();
        // ruleid: java.expression-injection
        spel.parseRaw(formula).getValue();
        var fromInterface = parser.parseExpression(rule);
        // ruleid: java.expression-injection
        fromInterface.getValue();
        var fromSpel = spel.parseExpression(rule);
        // ruleid: java.expression-injection
        fromSpel.getValue(standard);
        Expression fromHelper = compile(rule);
        // ruleid: java.expression-injection
        fromHelper.getValue();

        // SimpleEvaluationContext leaves out type references, constructors and bean references.
        EvaluationContext simple = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        // ok: java.expression-injection
        parser.parseExpression(formula).getValue(simple, new Order());
        // ok: java.expression-injection
        parser.parseExpression(rule).getValue(SimpleEvaluationContext.forReadOnlyDataBinding().withInstanceMethods().build());
        SimpleEvaluationContext typed = SimpleEvaluationContext.forReadWriteDataBinding().build();
        // ok: java.expression-injection
        expression.getValue(typed, Double.class);
        var built = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        var parsedVar = parser.parseExpression(formula);
        // ok: java.expression-injection
        parsedVar.getValue(built);
        // ok: java.expression-injection
        parser.parseExpression(formula).getValue(readOnlyContext, new Order());
        // A SimpleEvaluationContext returned by a helper method is not recognised.
        // todook: java.expression-injection
        parser.parseExpression(formula).getValue(readOnly(), new Order());
        // A constant expression with the request data as a variable.
        StandardEvaluationContext withVariable = new StandardEvaluationContext();
        withVariable.setVariable("discount", discount);
        // ok: java.expression-injection
        parser.parseExpression("#discount").getValue(withVariable);
        // ok: java.expression-injection
        parser.parseExpression("price * 0.9").getValue(new Order());
        // ok: java.expression-injection
        parser.parseExpression("price * " + Integer.parseInt(discount)).getValue(new Order());
        // Parsing alone evaluates nothing.
        // ok: java.expression-injection
        Expression parsedOnly = parser.parseExpression(formula);
        // A getValue method of another class.
        // ok: java.expression-injection
        settings.getValue(formula);
        return value;
    }

    @PostMapping("/price")
    Object fromBody(@RequestBody PriceRequest request, @CookieValue("segment") String segment, HttpEntity<String> entity) {
        // ruleid: java.expression-injection
        parser.parseExpression(request.getFormula()).getValue(new Order());
        // ruleid: java.expression-injection
        parser.parseExpression("segment == '" + segment + "'").getValue(new StandardEvaluationContext(), Boolean.class);
        // ruleid: java.expression-injection
        return parser.parseExpression(entity.getBody()).getValue();
    }
}

class Order {
    public double price = 10;
}

class PriceRequest {
    private String formula;

    String getFormula() {
        return formula;
    }
}

class SettingsStore {
    Object getValue(String key) {
        return key;
    }
}

// Servlet: Jakarta Expression Language, OGNL and MVEL.
public class ScriptServlet extends HttpServlet {
    private static final Map<String, String> FORMULAS = Map.of("net", "price * 0.8", "gross", "price");
    private ExpressionFactory factory;
    private javax.el.ExpressionFactory legacyFactory;
    private javax.el.ELContext legacyContext;
    private javax.el.ELProcessor legacyProcessor;
    private ELContext elContext;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String expr = request.getParameter("expr");
        ELProcessor elp = new ELProcessor();
        // ruleid: java.expression-injection
        Object a = elp.eval(expr);
        // ruleid: java.expression-injection
        elp.getValue("order." + request.getHeader("X-Field"), Object.class);
        // ruleid: java.expression-injection
        elp.setValue(request.getParameter("target"), "1");
        // ruleid: java.expression-injection
        elp.setVariable("total", expr);
        // ruleid: java.expression-injection
        ValueExpression ve = factory.createValueExpression(elContext, "${" + expr + "}", Object.class);
        // ruleid: java.expression-injection
        ExpressionFactory.newInstance().createMethodExpression(elContext, "#{" + expr + "}", Object.class, new Class<?>[0]);
        var inferred = new ELProcessor();
        // ruleid: java.expression-injection
        inferred.eval(request.getQueryString());
        // ruleid: java.expression-injection
        new ELProcessor().getValue(expr, Object.class);
        // ruleid: java.expression-injection
        legacyProcessor.eval(expr);
        // ruleid: java.expression-injection
        legacyProcessor.setVariable("total", expr);
        // ruleid: java.expression-injection
        inferred.setVariable("total", expr);
        // ruleid: java.expression-injection
        legacyFactory.createValueExpression(legacyContext, "${" + expr + "}", Object.class);
        // ruleid: java.expression-injection
        ExpressionFactory.newInstance().createValueExpression(elContext, "${" + expr + "}", Object.class);
        // ruleid: java.expression-injection
        javax.el.ExpressionFactory.newInstance().createValueExpression(legacyContext, "${" + expr + "}", Object.class);
        // ruleid: java.expression-injection
        factory.createMethodExpression(elContext, "#{" + expr + "}", Object.class, new Class<?>[0]);
        // ruleid: java.expression-injection
        legacyFactory.createMethodExpression(legacyContext, "#{" + expr + "}", Object.class, new Class<?>[0]);
        // ruleid: java.expression-injection
        javax.el.ExpressionFactory.newInstance().createMethodExpression(legacyContext, "#{" + expr + "}", Object.class, new Class<?>[0]);

        // ok: java.expression-injection
        elp.eval("order.total * 2");
        // The request data is a value, not an expression.
        // ok: java.expression-injection
        elp.setValue("order.note", expr);
        elp.defineBean("input", expr);
        // ok: java.expression-injection
        elp.eval("input.length()");
        // ok: java.expression-injection
        factory.createValueExpression(elContext, "${order.total}", Object.class);
        // The two-argument form wraps an object; it parses nothing.
        // ok: java.expression-injection
        factory.createValueExpression(expr, String.class);
        // ok: java.expression-injection
        elp.eval(FORMULAS.get(request.getParameter("formula")));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String expr = request.getParameter("expr");
            Map<String, Object> context = new HashMap<>();
            Order root = new Order();
            // ruleid: java.expression-injection
            Object v = Ognl.getValue(expr, context, root);
            Object tree = Ognl.parseExpression("price + " + request.getParameter("delta"));
            // ruleid: java.expression-injection
            Ognl.getValue(tree, context, root);
            // ruleid: java.expression-injection
            Ognl.setValue(request.getHeader("X-Property"), context, root, "1");
            // ruleid: java.expression-injection
            MVEL.eval(expr, root);
            // ruleid: java.expression-injection
            MVEL.evalToBoolean("price > " + request.getParameter("min"), root);
            java.io.Serializable compiled = MVEL.compileExpression(expr);
            // ruleid: java.expression-injection
            MVEL.executeExpression(compiled, root);

            // ok: java.expression-injection
            Ognl.getValue("price", context, root);
            context.put("input", expr);
            // ok: java.expression-injection
            Ognl.getValue("#input.length()", context, root);
            // ok: java.expression-injection
            Ognl.setValue("price", context, root, expr);
            // ok: java.expression-injection
            MVEL.eval("price * 2", Map.of("input", expr));
            // ok: java.expression-injection
            MVEL.executeExpression(MVEL.compileExpression("price * 2"), root);
            // Parsing alone evaluates nothing.
            // ok: java.expression-injection
            Object parsedOnly = Ognl.parseExpression(expr);
        } catch (OgnlException e) {
            throw new IOException(e);
        }
    }

    // Limits of a taint analysis that sees one method at a time and does not evaluate
    // conditions.
    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ELProcessor elp = new ELProcessor();
        // A helper of the same class that returns a constant whatever it is given.
        // todook: java.expression-injection
        elp.eval(defaultFormula(request.getParameter("f")));
        char mode = "abc".charAt(0);
        String formula;
        switch (mode) {
            case 0x61:
                formula = "price";
                break;
            default:
                formula = request.getParameter("formula");
        }
        // A switch over a value computed from constants always takes the same branch.
        // todook: java.expression-injection
        elp.eval(formula);
        // A wrapper class that reads the request is not followed into.
        RequestWrapper wrapper = new RequestWrapper(request);
        // todoruleid: java.expression-injection
        elp.eval(wrapper.value("expr"));
        // An expression parsed here and evaluated in another method is not followed.
        // todoruleid: java.expression-injection
        Expression later = new SpelExpressionParser().parseExpression(request.getParameter("rule"));
        evaluateLater(later);
    }

    private static String defaultFormula(String requested) {
        return "price";
    }

    private static Object evaluateLater(Expression expression) {
        return expression.getValue();
    }

    // Not a handler: the parameter is not request data.
    Object stored(String request) {
        // ok: java.expression-injection
        return new ELProcessor().eval(request);
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

// Jakarta REST: path, query and form parameters.
@jakarta.ws.rs.Path("/eval")
class EvalResource {
    private final ExpressionParser parser = new SpelExpressionParser();

    @GET
    @jakarta.ws.rs.Path("/{expr}")
    public Object eval(@PathParam("expr") String expr, @QueryParam("field") String field) {
        // ruleid: java.expression-injection
        Object a = parser.parseExpression(expr).getValue(new Order());
        // ruleid: java.expression-injection
        Object b = new ELProcessor().getValue("order." + field, Object.class);
        // ok: java.expression-injection
        Object c = parser.parseExpression(field).getValue(SimpleEvaluationContext.forReadOnlyDataBinding().build(), new Order());
        return a;
    }

    @POST
    public Object form(@FormParam("rule") String rule) throws OgnlException {
        // ruleid: java.expression-injection
        return Ognl.getValue(rule, new HashMap<String, Object>(), new Order());
    }

    // The entity parameter (the request body) has no annotation.
    @POST
    @jakarta.ws.rs.Path("/raw")
    public Object raw(String body) {
        // todoruleid: java.expression-injection
        return new ELProcessor().eval(body);
    }
}

// Allow-list lookups and their limits; the limits of the shared request sources.
@RestController
class SharedLimitsController {
    private static final String DEFAULT_FORMULA = "price";
    private static final Map<String, String> TABLE = Map.of("a", "price", "b", "price * 2");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("a", "price"), Map.entry("b", "price * 2"));
    private final ELProcessor elp = new ELProcessor();

    @GetMapping("/shared/lookups")
    String lookups(@RequestParam String key, @RequestParam String fallback) {
        // ok: java.expression-injection
        elp.eval(TABLE.getOrDefault(key, DEFAULT_FORMULA));
        // ok: java.expression-injection
        elp.eval(TABLE.getOrDefault(key, "price"));
        // A lookup whose fallback is request data is not an allow-list.
        // ruleid: java.expression-injection
        elp.eval(TABLE.getOrDefault(key, fallback));
        // ruleid: java.expression-injection
        elp.eval(Map.of("a", "price").getOrDefault(key, key));
        Map<String, String> filled = new HashMap<>();
        filled.put("k", key);
        // ruleid: java.expression-injection
        elp.eval(filled.get("k"));
        // valueOf of a class that is not an enum hands the text back.
        // ruleid: java.expression-injection
        elp.eval(javax.xml.namespace.QName.valueOf(key).getLocalPart());
        // ok: java.expression-injection
        elp.eval("price * " + SharedKind.valueOf(key).ordinal());
        // A literal Map.ofEntries table is an allow-list, but only Map.of is recognised.
        // todook: java.expression-injection
        elp.eval(ENTRIES.get(key));
        // valueOf of an enum declared in another file (java.time.DayOfWeek) is not recognised.
        // todook: java.expression-injection
        elp.eval("'" + java.time.DayOfWeek.valueOf(key).name() + "'");
        return "ok";
    }

    // The other spellings of the shared request sources and sanitizers.
    @GetMapping("/shared/forms")
    String sharedForms(@RequestParam String key, @RequestParam String n) {
        // ok: java.expression-injection
        elp.eval("price * " + Map.of("a", "x", "b", "y").get(key));
        // ok: java.expression-injection
        elp.eval("price * " + Map.of("a", "x").getOrDefault(key, "x"));
        // ok: java.expression-injection
        elp.eval("price * " + Long.parseLong(n));
        // ok: java.expression-injection
        elp.eval("price * " + Integer.valueOf(n));
        // ok: java.expression-injection
        elp.eval("price * " + Long.valueOf(n));
        // ok: java.expression-injection
        elp.eval("price * " + Enum.valueOf(SharedKind.class, key).name());
        // ok: java.expression-injection
        elp.eval("price * " + java.lang.Enum.valueOf(SharedKind.class, key).name());
        // An enum declared inside the class.
        // ok: java.expression-injection
        elp.eval("price * " + Level.valueOf(key).name());
        // An enum declared before the class.
        // ok: java.expression-injection
        elp.eval("price * " + EarlierKind.valueOf(key).name());
        StringBuilder single = new StringBuilder();
        single.append(key);
        // A single append, not in a chain.
        // ruleid: java.expression-injection
        elp.eval(single.toString());
        StringBuilder chained = new StringBuilder();
        chained.append("price * ").append(key);
        // ruleid: java.expression-injection
        elp.eval(chained.toString());
        StringBuilder fixed = new StringBuilder();
        fixed.append("price * ").append("2");
        // ok: java.expression-injection
        elp.eval(fixed.toString());
        return "ok";
    }

    enum Level {
        LOW, HIGH
    }

    // A mapping annotation without arguments.
    @PostMapping
    String bare(HttpEntity<String> entity) {
        // ruleid: java.expression-injection
        elp.eval("price * " + entity.getBody());
        return "ok";
    }

    // Servlet request types of both namespaces.
    void filterJakarta(jakarta.servlet.ServletRequest request) {
        // ruleid: java.expression-injection
        elp.eval("price * " + request.getParameter("q"));
    }

    void filterJavax(javax.servlet.ServletRequest request) {
        // ruleid: java.expression-injection
        elp.eval("price * " + request.getParameter("q"));
    }

    void legacy(javax.servlet.http.HttpServletRequest request) {
        // ruleid: java.expression-injection
        elp.eval("price * " + request.getParameter("q"));
    }

    // Spring binds a simple-type parameter without an annotation as a request parameter.
    @GetMapping("/shared/plain")
    String plain(String term) {
        // todoruleid: java.expression-injection
        return String.valueOf(elp.eval(term));
    }

    // Parameters the framework converts to an enum, a number list or an optional number cannot
    // carry an expression, but the rule only knows the scalar types it lists.
    @GetMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind, @RequestParam List<Long> ids, @RequestParam Optional<Long> page) {
        // todook: java.expression-injection
        elp.eval("'" + kind + "'");
        // todook: java.expression-injection
        elp.eval("price * " + ids.get(0));
        // todook: java.expression-injection
        elp.eval("price * " + page.orElse(1L));
        return "ok";
    }
}

enum SharedKind {
    SMALL, LARGE
}
