package com.acme.vault;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NullCipher;
import javax.crypto.SecretKey;

public class Ciphers {
    private static final String LEGACY = "DESede/CBC/PKCS5Padding";
    private static final String MODERN = "AES/GCM/NoPadding";
    private final Properties settings = new Properties();

    // Broken or legacy algorithms: DES, Triple DES, RC2, RC4 (ARCFOUR) and Blowfish, in any mode.
    void brokenAlgorithms() throws GeneralSecurityException {
        // ruleid: java.weak-cipher
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: java.weak-cipher
        Cipher.getInstance("DES");
        // ruleid: java.weak-cipher
        Cipher.getInstance("DESede/CBC/NoPadding");
        // ruleid: java.weak-cipher
        Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
        // ruleid: java.weak-cipher
        Cipher.getInstance("DESedeWrap");
        // ruleid: java.weak-cipher
        Cipher.getInstance("RC2/CBC/PKCS5Padding");
        // ruleid: java.weak-cipher
        Cipher.getInstance("RC4");
        // ruleid: java.weak-cipher
        Cipher.getInstance("ARCFOUR");
        // ruleid: java.weak-cipher
        Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        // RC5 (a 64-bit block in its RC5-32 form) from the Bouncy Castle provider.
        // ruleid: java.weak-cipher
        Cipher.getInstance("RC5/CBC/PKCS5Padding", "BC");
        // Algorithm names are not case-sensitive.
        // ruleid: java.weak-cipher
        Cipher.getInstance("des/cbc/pkcs5padding");
        // With a provider name.
        // ruleid: java.weak-cipher
        Cipher.getInstance("DES/CBC/PKCS5Padding", "SunJCE");
        // ruleid: java.weak-cipher
        javax.crypto.Cipher.getInstance("RC4");
        // A constant, a local variable, and a name built from literals.
        // ruleid: java.weak-cipher
        Cipher.getInstance(LEGACY);
        String algorithm = "Blowfish";
        // ruleid: java.weak-cipher
        Cipher cipher = Cipher.getInstance(algorithm);
        // ruleid: java.weak-cipher
        Cipher.getInstance("DES" + "/ECB/PKCS5Padding");
    }

    // A weak cipher as the default of a configuration lookup is used whenever the key is unset,
    // but the configured value decides, and it is not in the code.
    void weakDefaults() throws GeneralSecurityException {
        // todoruleid: java.weak-cipher
        Cipher.getInstance(settings.getProperty("vault.cipher", "DESede/ECB/PKCS5Padding"));
        String fallback = System.getProperty("vault.cipher", "Blowfish");
        // todoruleid: java.weak-cipher
        Cipher.getInstance(fallback);
    }

    // Password-based encryption built on DES, Triple DES, RC2 or RC4.
    void weakPasswordBased() throws GeneralSecurityException {
        // ruleid: java.weak-cipher
        Cipher.getInstance("PBEWithMD5AndDES");
        // ruleid: java.weak-cipher
        Cipher.getInstance("PBEWithMD5AndTripleDES");
        // ruleid: java.weak-cipher
        Cipher.getInstance("PBEWithSHA1AndDESede");
        // ruleid: java.weak-cipher
        Cipher.getInstance("PBEWithSHA1AndRC2_40");
        // ruleid: java.weak-cipher
        Cipher.getInstance("PBEWithSHA1AndRC4_128");
        // The full transformation, with the mode and padding the providers use.
        // ruleid: java.weak-cipher
        Cipher.getInstance("PBEWithMD5AndDES/CBC/PKCS5Padding");
        // ruleid: java.weak-cipher
        Cipher.getInstance("PBEWithSHA1AndRC2_40/CBC/PKCS5Padding");
        // ok: java.weak-cipher
        Cipher.getInstance("PBEWithHmacSHA256AndAES_256");
        // ok: java.weak-cipher
        Cipher.getInstance("PBEWithHmacSHA256AndAES_256/CBC/PKCS5Padding");
    }

    // ECB mode: equal plaintext blocks give equal ciphertext blocks. "AES" alone is ECB too: the
    // SunJCE provider's default mode.
    void ecb() throws GeneralSecurityException {
        // ruleid: java.weak-cipher
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: java.weak-cipher
        Cipher.getInstance("AES");
        // ruleid: java.weak-cipher
        Cipher.getInstance("AES_256");
        // ruleid: java.weak-cipher
        Cipher.getInstance("AES_128/ECB/NoPadding");
        // ruleid: java.weak-cipher
        Cipher.getInstance("Camellia/ECB/PKCS5Padding", "BC");
    }

    // RSA without padding is textbook RSA: deterministic and malleable.
    void rsa() throws GeneralSecurityException {
        // ruleid: java.weak-cipher
        Cipher.getInstance("RSA/ECB/NoPadding");
        // ruleid: java.weak-cipher
        Cipher.getInstance("RSA/NONE/NoPadding", "BC");
        // The ECB in RSA names is nominal: RSA encrypts one block.
        // ok: java.weak-cipher
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // ok: java.weak-cipher
        Cipher.getInstance("RSA/ECB/OAEPPadding");
        // PKCS #1 v1.5 padding (also the default of "RSA") is not reported.
        // ok: java.weak-cipher
        Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // ok: java.weak-cipher
        Cipher.getInstance("RSA");
    }

    // NullCipher does not encrypt at all.
    Cipher nothing() {
        // ruleid: java.weak-cipher
        return new NullCipher();
    }

    // Safe ciphers and modes.
    void safe() throws GeneralSecurityException {
        // ok: java.weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding");
        // ok: java.weak-cipher
        Cipher.getInstance(MODERN);
        // ok: java.weak-cipher
        Cipher.getInstance("ChaCha20-Poly1305");
        // ok: java.weak-cipher
        Cipher.getInstance("AES_256/GCM/NoPadding");
        // Unauthenticated modes are not what this rule is about.
        // ok: java.weak-cipher
        Cipher.getInstance("AES/CBC/PKCS5Padding");
        // ok: java.weak-cipher
        Cipher.getInstance("AES/CTR/NoPadding");
        // Key wrapping.
        // ok: java.weak-cipher
        Cipher.getInstance("AESWrap");
        // ok: java.weak-cipher
        Cipher.getInstance("AES/KW/NoPadding");
        // The name comes from configuration: the deployment decides.
        // ok: java.weak-cipher
        Cipher.getInstance(settings.getProperty("vault.cipher"));
        // ok: java.weak-cipher
        Cipher.getInstance(settings.getProperty("vault.cipher", "AES/GCM/NoPadding"));
        String configured = System.getProperty("vault.cipher", MODERN);
        // ok: java.weak-cipher
        Cipher.getInstance(configured);
        // A key generator for DES: the cipher that uses the key is what is reported.
        // ok: java.weak-cipher
        KeyGenerator.getInstance("DES");
        // Another API with a getInstance method.
        // ok: java.weak-cipher
        MessageDigest.getInstance("SHA-256");
        // ok: java.weak-cipher
        LegacyCodec.getInstance("DES");
    }

    // Limits.
    void limits(boolean compatible, SecretKey key) throws GeneralSecurityException {
        // A name chosen by a condition is not a constant.
        String chosen = compatible ? "DES/CBC/PKCS5Padding" : "AES/GCM/NoPadding";
        // todoruleid: java.weak-cipher
        Cipher.getInstance(chosen);
        // A name passed to a helper that creates the cipher.
        // todoruleid: java.weak-cipher
        create("RC4");
        // Bouncy Castle's lightweight API is not checked.
        // todoruleid: java.weak-cipher
        new org.bouncycastle.crypto.engines.DESEngine();
        // ECB on a single block (wrapping one 128-bit key) is what the JCA names page allows,
        // but it cannot be told apart from ECB on many blocks.
        Cipher single = Cipher.getInstance("AES/GCM/NoPadding");
        // todook: java.weak-cipher
        Cipher wrap = Cipher.getInstance("AES/ECB/NoPadding");
        wrap.init(Cipher.ENCRYPT_MODE, key);
        wrap.doFinal(new byte[16]);
    }

    private static Cipher create(String transformation) throws GeneralSecurityException {
        return Cipher.getInstance(transformation);
    }
}

class LegacyCodec {
    static LegacyCodec getInstance(String name) {
        return new LegacyCodec();
    }
}
