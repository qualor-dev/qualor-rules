package com.acme.sessions;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

// Servlet: the request body, a multipart part and a cookie.
public class SessionServlet extends HttpServlet {
    private static final ObjectInputFilter ALLOWED = ObjectInputFilter.Config.createFilter("com.acme.sessions.Cart;java.base/*;!*");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        try {
            // ruleid: java.unsafe-deserialization
            Object cart = in.readObject();
            // ruleid: java.unsafe-deserialization
            Object next = new ObjectInputStream(request.getPart("cart").getInputStream()).readObject();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        byte[] state = Base64.getDecoder().decode(cookies[0].getValue());
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(state))) {
            // ruleid: java.unsafe-deserialization
            Object cart = in.readUnshared();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
        var stream = new ObjectInputStream(request.getInputStream());
        try {
            // ruleid: java.unsafe-deserialization
            stream.readObject();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        XMLDecoder decoder = new XMLDecoder(request.getInputStream());
        // ruleid: java.unsafe-deserialization
        Object settings = decoder.readObject();
        // ruleid: java.unsafe-deserialization
        Object other = new XMLDecoder(request.getPart("settings").getInputStream()).readObject();
        try (XMLDecoder scoped = new XMLDecoder(request.getInputStream())) {
            // ruleid: java.unsafe-deserialization
            scoped.readObject();
        }
        byte[] body = request.getInputStream().readAllBytes();
        // ruleid: java.unsafe-deserialization
        org.springframework.util.SerializationUtils.deserialize(body);
        // ruleid: java.unsafe-deserialization
        org.apache.commons.lang3.SerializationUtils.deserialize(request.getInputStream());
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            ObjectInputStream filtered = new ObjectInputStream(request.getInputStream());
            filtered.setObjectInputFilter(ALLOWED);
            // ok: java.unsafe-deserialization
            Object cart = filtered.readObject();
            try (ObjectInputStream scoped = new ObjectInputStream(request.getInputStream())) {
                scoped.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.sessions.Cart;!*"));
                // ok: java.unsafe-deserialization
                scoped.readObject();
            }
            ValidatingObjectInputStream validating = ValidatingObjectInputStream.builder()
                    .accept(Cart.class)
                    .setInputStream(request.getInputStream())
                    .get();
            // ok: java.unsafe-deserialization
            validating.readObject();
            ValidatingObjectInputStream legacy = new ValidatingObjectInputStream(request.getInputStream());
            legacy.accept(Cart.class);
            // ok: java.unsafe-deserialization
            legacy.readObject();
            // An ObjectInputStream that checks each class before it is resolved.
            ObjectInputStream lookAhead = new ObjectInputStream(request.getInputStream()) {
                @Override
                protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    if (!desc.getName().equals(Cart.class.getName())) {
                        throw new java.io.InvalidClassException("unexpected class", desc.getName());
                    }
                    return super.resolveClass(desc);
                }
            };
            // ok: java.unsafe-deserialization
            lookAhead.readObject();
            // Data the application wrote itself.
            ObjectInputStream local = new ObjectInputStream(new FileInputStream("/var/lib/acme/cache.bin"));
            // ok: java.unsafe-deserialization
            local.readObject();
            // ok: java.unsafe-deserialization
            new XMLDecoder(SessionServlet.class.getResourceAsStream("/defaults.xml")).readObject();
            // A JSON reader's readObject builds JSON values only.
            // ok: java.unsafe-deserialization
            JsonObject json = Json.createReader(request.getInputStream()).readObject();
            var jsonReader = Json.createReader(request.getReader());
            // ok: java.unsafe-deserialization
            jsonReader.readObject();
            // A filter set after the first object was read does not apply to it.
            ObjectInputStream late = new ObjectInputStream(request.getInputStream());
            // ruleid: java.unsafe-deserialization
            late.readObject();
            late.setObjectInputFilter(ALLOWED);
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
    }
}

class Cart implements java.io.Serializable {
}

// Spring MVC: a byte[] body, the raw body stream, a multipart file and a cookie.
@RestController
class SessionController {
    @PostMapping("/sessions/bytes")
    String bytes(@RequestBody byte[] body) throws IOException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body));
        // ruleid: java.unsafe-deserialization
        in.readObject();
        return "ok";
    }

    @PostMapping("/sessions/stream")
    String stream(InputStream body) throws IOException, ClassNotFoundException {
        // ruleid: java.unsafe-deserialization
        new ObjectInputStream(body).readObject();
        return "ok";
    }

    @PostMapping("/sessions/upload")
    String upload(@RequestParam("file") MultipartFile file) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(file.getInputStream())) {
            // ruleid: java.unsafe-deserialization
            in.readObject();
        }
        return "ok";
    }

    @PostMapping("/sessions/part")
    String part(@RequestPart("state") MultipartFile state) throws IOException {
        // ruleid: java.unsafe-deserialization
        org.apache.commons.lang3.SerializationUtils.deserialize(state.getBytes());
        return "ok";
    }

    @PostMapping("/sessions/cookie")
    String cookie(@CookieValue("state") String state) throws IOException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(state)));
        // ruleid: java.unsafe-deserialization
        in.readObject();
        return "ok";
    }

    @PostMapping("/sessions/entity")
    String entity(org.springframework.http.HttpEntity<byte[]> entity) throws IOException, ClassNotFoundException {
        // ruleid: java.unsafe-deserialization
        new ObjectInputStream(new ByteArrayInputStream(entity.getBody())).readObject();
        return "ok";
    }

    @PostMapping("/sessions/filtered")
    String filtered(@RequestBody byte[] body) throws IOException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body));
        in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.sessions.Cart;!*"));
        // ok: java.unsafe-deserialization
        in.readObject();
        return "ok";
    }

    // A raw body stream parameter of a method that is not a handler.
    String notHandler(InputStream body) throws IOException, ClassNotFoundException {
        // ok: java.unsafe-deserialization
        new ObjectInputStream(body).readObject();
        return "ok";
    }

    // A parameter the framework converts to an enum cannot carry a serialized object, but the
    // rule only knows the scalar types it lists.
    @PostMapping("/shared/typed")
    String typed(@RequestParam SharedKind kind) {
        // todook: java.unsafe-deserialization
        new XMLDecoder(new ByteArrayInputStream(kind.name().getBytes())).readObject();
        return "ok";
    }
}

enum SharedKind {
    SMALL, LARGE
}

// Jakarta REST: the entity stream and a query parameter.
@Path("/sessions")
class SessionResource {
    @POST
    @Consumes("application/x-java-serialized-object")
    public String post(InputStream entity) throws IOException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(entity);
        // ruleid: java.unsafe-deserialization
        in.readObject();
        return "ok";
    }

    @PUT
    public String put(@QueryParam("state") String state) throws IOException {
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(state.getBytes()));
        // ruleid: java.unsafe-deserialization
        decoder.readObject();
        return "ok";
    }
}

// Limits.
class SessionLimitsServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // A filter for the whole JVM (ObjectInputFilter.Config.setSerialFilter or jdk.serialFilter).
        ObjectInputFilter.Config.setSerialFilter(ObjectInputFilter.Config.createFilter("com.acme.sessions.Cart;!*"));
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        try {
            // todook: java.unsafe-deserialization
            in.readObject();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
        // A subclass whose resolveClass accepts only the expected class.
        ObjectInputStream named = new CartOnlyInputStream(request.getInputStream());
        try {
            // ok: java.unsafe-deserialization
            named.readObject();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
        // A named subclass is trusted whether or not it checks: this one only picks a class loader.
        ObjectInputStream loader = new LoaderInputStream(request.getInputStream(), getClass().getClassLoader());
        try {
            // todoruleid: java.unsafe-deserialization
            loader.readObject();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
        // An anonymous subclass whose resolveClass checks nothing reads any class.
        ObjectInputStream anyClass = new ObjectInputStream(request.getInputStream()) {
            @Override
            protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                return Class.forName(desc.getName(), false, Thread.currentThread().getContextClassLoader());
            }
        };
        try {
            // ruleid: java.unsafe-deserialization
            anyClass.readObject();
            // The same in place.
            // ruleid: java.unsafe-deserialization
            new ObjectInputStream(request.getInputStream()) {
                @Override
                protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    return super.resolveClass(desc);
                }
            }.readObject();
            // In place with a resolveClass that accepts only the expected class.
            // ok: java.unsafe-deserialization
            new ObjectInputStream(request.getInputStream()) {
                @Override
                protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    if (!Cart.class.getName().equals(desc.getName())) {
                        throw new java.io.InvalidClassException("not allowed", desc.getName());
                    }
                    return super.resolveClass(desc);
                }
            }.readObject();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
        // A resolveClass that refuses only one named class (a deny-list) lets every other class
        // through, but any throw counts as a check.
        ObjectInputStream denyList = new ObjectInputStream(request.getInputStream()) {
            @Override
            protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                if (desc.getName().startsWith("org.apache.commons.collections.functors.")) {
                    throw new java.io.InvalidClassException("refused", desc.getName());
                }
                return super.resolveClass(desc);
            }
        };
        try {
            // todoruleid: java.unsafe-deserialization
            denyList.readObject();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
        // The stream is opened by a helper method.
        ObjectInputStream opened = open(request);
        try {
            // todoruleid: java.unsafe-deserialization
            opened.readObject();
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
    }

    private static ObjectInputStream open(HttpServletRequest request) throws IOException {
        return new ObjectInputStream(request.getInputStream());
    }
}

class CartOnlyInputStream extends ObjectInputStream {
    CartOnlyInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!Cart.class.getName().equals(desc.getName())) {
            throw new java.io.InvalidClassException("not allowed", desc.getName());
        }
        return super.resolveClass(desc);
    }
}

class LoaderInputStream extends ObjectInputStream {
    private final ClassLoader loader;

    LoaderInputStream(InputStream in, ClassLoader loader) throws IOException {
        super(in);
        this.loader = loader;
    }

    @Override
    protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        return Class.forName(desc.getName(), false, loader);
    }
}

// Limits of the shared request sources.
@RestController
class SharedLimitsController {
    // Spring binds a MultipartFile parameter without an annotation as a request parameter.
    @PostMapping("/shared/plain")
    String plain(MultipartFile file) throws IOException, ClassNotFoundException {
        // todoruleid: java.unsafe-deserialization
        new ObjectInputStream(file.getInputStream()).readObject();
        return "ok";
    }
}

// XML assembled in an append chain (StringBuilder.append(...).append(value)).
@RestController
class ChainController {
    @PostMapping("/chain/settings")
    String settings(@RequestBody String body) throws IOException {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version='1.0'?>").append(body);
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xml.toString().getBytes()));
        // ruleid: java.unsafe-deserialization
        decoder.readObject();
        StringBuilder fixed = new StringBuilder();
        fixed.append("<?xml version='1.0'?>").append("<java/>");
        XMLDecoder empty = new XMLDecoder(new ByteArrayInputStream(fixed.toString().getBytes()));
        // ok: java.unsafe-deserialization
        empty.readObject();
        return "ok";
    }

    // Not a handler method: an entity it is given is not request data.
    String replay(org.springframework.http.HttpEntity<byte[]> entity) throws IOException, ClassNotFoundException {
        // ok: java.unsafe-deserialization
        new ObjectInputStream(new ByteArrayInputStream(entity.getBody())).readObject();
        return "ok";
    }
}
