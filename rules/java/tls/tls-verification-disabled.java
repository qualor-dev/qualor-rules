package com.acme.client;

import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

// A trust manager that accepts every server certificate: checkServerTrusted returns without
// checking anything.
class TrustEverything implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    // ruleid: java.tls-verification-disabled
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

// The same with the interface written out, and a body that only logs.
class LoggingTrustManager implements javax.net.ssl.X509TrustManager {
    private static final Logger LOG = Logger.getLogger("tls");

    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
    }

    // ruleid: java.tls-verification-disabled
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
        LOG.fine("accepting a " + authType + " server chain of " + chain.length + " certificates");
    }

    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}

// An extended trust manager: each of its server checks accepts everything.
class LenientExtendedTrustManager extends X509ExtendedTrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
    }

    // ruleid: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    // ruleid: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
    }

    // Checking only the validity dates accepts any self-signed certificate for any host.
    // ruleid: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        chain[0].checkValidity();
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

// A host name verifier that accepts every host.
class AnyHost implements HostnameVerifier {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        // ruleid: java.tls-verification-disabled
        return true;
    }
}

public class InsecureClients {
    private static final Logger LOG = Logger.getLogger("tls");
    private static final Set<String> INTERNAL = Set.of("billing.internal.example.com", "auth.internal.example.com");

    // A trust-all manager written in place and given to SSLContext.init.
    SSLContext inline() throws GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                // ruleid: java.tls-verification-disabled
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        };
        context.init(null, trustAll, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
        return context;
    }

    // Host name verifiers that accept every host: anonymous classes and lambdas.
    void hostnames(URL url) throws IOException {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                // ruleid: java.tls-verification-disabled
                return true;
            }
        });
        // ruleid: java.tls-verification-disabled
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        // ruleid: java.tls-verification-disabled
        connection.setHostnameVerifier((String hostname, SSLSession session) -> true);
        connection.setHostnameVerifier((h, s) -> {
            // ruleid: java.tls-verification-disabled
            return true;
        });
        connection.setHostnameVerifier((h, s) -> {
            LOG.fine("accepting " + h);
            // ruleid: java.tls-verification-disabled
            return true;
        });
        // ruleid: java.tls-verification-disabled
        HostnameVerifier trustAny = (h, s) -> true;
        // ruleid: java.tls-verification-disabled
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
        // A lambda cast to HostnameVerifier, here to keep it as an Object.
        // ruleid: java.tls-verification-disabled
        Object fallback = (HostnameVerifier) (h, s) -> true;
        connection.setHostnameVerifier(trustAny);
        connection.setHostnameVerifier(new AnyHost());
    }

    // Safe: the platform's checks, a narrower check, or a check of our own that can fail.
    void safeHostnames(URL url) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        HostnameVerifier platform = HttpsURLConnection.getDefaultHostnameVerifier();
        // ok: java.tls-verification-disabled
        connection.setHostnameVerifier((h, s) -> platform.verify(h, s));
        // ok: java.tls-verification-disabled
        connection.setHostnameVerifier((h, s) -> INTERNAL.contains(h) && platform.verify(h, s));
        // ok: java.tls-verification-disabled
        connection.setHostnameVerifier((h, s) -> false);
        connection.setHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                if (INTERNAL.contains(hostname)) {
                    // ok: java.tls-verification-disabled
                    return true;
                }
                return false;
            }
        });
        connection.setHostnameVerifier((h, s) -> {
            if (!INTERNAL.contains(h)) {
                return false;
            }
            // ok: java.tls-verification-disabled
            return true;
        });
        connection.setHostnameVerifier((h, s) -> {
            if ("localhost".equals(h))
                // ok: java.tls-verification-disabled
                return true;
            return platform.verify(h, s);
        });
        connection.setHostnameVerifier((h, s) -> {
            if (INTERNAL.contains(h)) {
                // ok: java.tls-verification-disabled
                return true;
            }
            return platform.verify(h, s);
        });
        connection.setHostnameVerifier((h, s) -> {
            if (!INTERNAL.contains(h)) {
                return platform.verify(h, s);
            } else {
                // ok: java.tls-verification-disabled
                return true;
            }
        });
        connection.setHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                boolean known = INTERNAL.contains(hostname);
                if (!known) {
                    return false;
                }
                // ok: java.tls-verification-disabled
                return true;
            }
        });
        connection.setHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                if (!INTERNAL.contains(hostname)) {
                    throw new IllegalStateException("unexpected host " + hostname);
                }
                // ok: java.tls-verification-disabled
                return true;
            }
        });
        connection.setHostnameVerifier((h, s) -> {
            if (!INTERNAL.contains(h)) {
                throw new IllegalStateException("unexpected host " + h);
            }
            // ok: java.tls-verification-disabled
            return true;
        });
    }

    // Safe: the default trust managers, from a TrustManagerFactory over a key store.
    SSLContext safeContexts(KeyStore trusted) throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trusted);
        SSLContext context = SSLContext.getInstance("TLS");
        // ok: java.tls-verification-disabled
        context.init(null, tmf.getTrustManagers(), null);
        SSLContext defaults = SSLContext.getInstance("TLSv1.3");
        // ok: java.tls-verification-disabled
        defaults.init(null, null, null);
        return context;
    }

    // A server context: checkServerTrusted is never called by a server, and an empty
    // checkClientTrusted only means that clients need no certificate.
    SSLContext serverContext(KeyManagerFactory kmf) throws GeneralSecurityException {
        SSLContext server = SSLContext.getInstance("TLS");
        server.init(kmf.getKeyManagers(), new TrustManager[] {
            new X509TrustManager() {
                // ok: java.tls-verification-disabled
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                // todook: java.tls-verification-disabled
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        }, null);
        server.getServerSocketFactory();
        return server;
    }
}

// A signature check whose failure is only logged: every chain is still accepted.
class SwallowingTrustManager implements X509TrustManager {
    private static final Logger LOG = Logger.getLogger("tls");
    private final PublicKey issuer;

    SwallowingTrustManager(PublicKey issuer) {
        this.issuer = issuer;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    // ruleid: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        try {
            chain[0].verify(issuer);
        } catch (GeneralSecurityException e) {
            LOG.warning("server certificate not signed by our CA: " + e.getMessage());
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

// Safe trust managers: they delegate to the default one, or throw when the chain is not trusted.
class DelegatingTrustManager implements X509TrustManager {
    private final X509TrustManager platform;

    DelegatingTrustManager(X509TrustManager platform) {
        this.platform = platform;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkClientTrusted(chain, authType);
    }

    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkServerTrusted(chain, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return platform.getAcceptedIssuers();
    }
}

class PinningTrustManager implements X509TrustManager {
    private static final String PIN = "3f1c...";
    private final PublicKey issuer;
    private final X509TrustManager platform;

    PinningTrustManager(PublicKey issuer, X509TrustManager platform) {
        this.issuer = issuer;
        this.platform = platform;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("client certificates are not accepted");
    }

    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(chain[0].getPublicKey().getEncoded());
            if (!PIN.equals(HexFormat.of().formatHex(digest))) {
                throw new CertificateException("unexpected server key");
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

class SignedByTrustManager extends X509ExtendedTrustManager {
    private final PublicKey issuer;
    private final X509ExtendedTrustManager platform;

    SignedByTrustManager(PublicKey issuer, X509ExtendedTrustManager platform) {
        this.issuer = issuer;
        this.platform = platform;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
    }

    // The chain is checked by a helper of this class.
    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        requireSignedBy(chain);
    }

    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        try {
            chain[0].verify(issuer);
        } catch (GeneralSecurityException e) {
            throw new CertificateException(e);
        }
    }

    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        platform.checkServerTrusted(chain, authType, engine);
    }

    private void requireSignedBy(X509Certificate[] chain) throws CertificateException {
        if (chain.length == 0) {
            throw new CertificateException("empty chain");
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

// Safe trust managers that check one certificate of the chain, or a copy of it.
class LeafCheckingTrustManager implements X509TrustManager {
    private static final String PIN = "9d2e...";
    private final X509TrustManager platform;

    LeafCheckingTrustManager(X509TrustManager platform) {
        this.platform = platform;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkClientTrusted(chain, authType);
    }

    // The server certificate goes to a pin check of this class, which throws on a mismatch.
    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        requirePinned(chain[0]);
    }

    private static void requirePinned(X509Certificate server) throws CertificateException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(server.getPublicKey().getEncoded());
            if (!PIN.equals(HexFormat.of().formatHex(digest))) {
                throw new CertificateException("unexpected server key");
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return platform.getAcceptedIssuers();
    }
}

class CopyingTrustManager extends X509ExtendedTrustManager {
    private final X509ExtendedTrustManager platform;

    CopyingTrustManager(X509ExtendedTrustManager platform) {
        this.platform = platform;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkClientTrusted(chain, authType);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        platform.checkClientTrusted(chain, authType, socket);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        platform.checkClientTrusted(chain, authType, engine);
    }

    // A copy of the chain, held in a variable.
    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        X509Certificate[] own = chain.clone();
        platform.checkServerTrusted(own, authType);
    }

    // Only the server certificate, in a new array.
    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        X509Certificate server = chain[0];
        platform.checkServerTrusted(new X509Certificate[] {server}, authType, socket);
    }

    // Every certificate of the chain, one by one.
    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        for (X509Certificate certificate : chain) {
            requireKnown(certificate);
        }
    }

    private static void requireKnown(X509Certificate certificate) throws CertificateException {
        if (certificate.getSubjectX500Principal() == null) {
            throw new CertificateException("no subject");
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return platform.getAcceptedIssuers();
    }
}

class LeafVariantsTrustManager extends X509ExtendedTrustManager {
    private final X509ExtendedTrustManager platform;

    LeafVariantsTrustManager(X509ExtendedTrustManager platform) {
        this.platform = platform;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkClientTrusted(chain, authType);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        platform.checkClientTrusted(chain, authType, socket);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        platform.checkClientTrusted(chain, authType, engine);
    }

    // Only the server certificate, in a new array written in place.
    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkServerTrusted(new X509Certificate[] {chain[0]}, authType);
    }

    // The server certificate through a variable, to a check of this class.
    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        X509Certificate server = chain[0];
        requireCurrent(server);
    }

    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        platform.checkServerTrusted(chain, authType, engine);
    }

    private static void requireCurrent(X509Certificate server) throws CertificateException {
        server.checkValidity();
        if (server.getBasicConstraints() != -1) {
            throw new CertificateException("a CA certificate cannot be the server certificate");
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return platform.getAcceptedIssuers();
    }
}

class CopyOfTrustManager implements X509TrustManager {
    private final X509TrustManager platform;

    CopyOfTrustManager(X509TrustManager platform) {
        this.platform = platform;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkClientTrusted(chain, authType);
    }

    // The chain cut to its first two certificates, in place.
    // ok: java.tls-verification-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkServerTrusted(Arrays.copyOf(chain, Math.min(2, chain.length)), authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return platform.getAcceptedIssuers();
    }
}

// Look-alikes: methods with the same names on other types.
class TokenChecker {
    // ok: java.tls-verification-disabled
    boolean verify(String token, String signature) {
        return true;
    }

    // ok: java.tls-verification-disabled
    void checkServerTrusted(String[] names, String authType) {
    }
}

// Limits.
class Limits {
    private static final Logger LOG = Logger.getLogger("tls");

    // A body that hands the chain to any call (here a log message) counts as a check.
    X509TrustManager logsChain() {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            // todoruleid: java.tls-verification-disabled
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                LOG.fine("server chain " + Arrays.toString(chain));
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    // A delegation whose CertificateException is caught and only logged trusts every chain, but
    // the call to the default manager counts as the check.
    X509TrustManager swallows(X509TrustManager platform) {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            // todoruleid: java.tls-verification-disabled
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                try {
                    platform.checkServerTrusted(chain, authType);
                } catch (CertificateException e) {
                    LOG.warning("untrusted server certificate ignored: " + e.getMessage());
                }
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    // The only throw is the argument check the javadoc describes (a null or empty chain); any
    // other chain is trusted, but every throw counts as a check.
    X509TrustManager argumentCheckOnly() {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            // todoruleid: java.tls-verification-disabled
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                if (chain == null || chain.length == 0) {
                    throw new IllegalArgumentException("no server certificate");
                }
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    // A lambda given to another library's setter is not known to be a HostnameVerifier
    // (OkHttp's OkHttpClient.Builder.hostnameVerifier).
    void okhttp(okhttp3.OkHttpClient.Builder builder) {
        // todoruleid: java.tls-verification-disabled
        builder.hostnameVerifier((h, s) -> true);
    }

    // Apache HttpClient's own trust-all and no-op verifier classes are not checked.
    void apache(org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder builder) {
        // todoruleid: java.tls-verification-disabled
        builder.setHostnameVerifier(org.apache.hc.client5.http.ssl.NoopHostnameVerifier.INSTANCE);
    }
}
