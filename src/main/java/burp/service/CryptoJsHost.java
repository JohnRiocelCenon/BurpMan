package burp.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Java facade exposing the crypto-js API surface that real-world Postman /
 * Bruno pre-request scripts rely on for JWT/HMAC signing. Only the subset
 * actually used in the wild is implemented — enough to keep scripts like
 * <pre>
 *   let CryptoJS = require("crypto-js");
 *   let stringifiedHeader = CryptoJS.enc.Utf8.parse(JSON.stringify(header));
 *   let encodedHeader = CryptoJS.enc.Base64.stringify(stringifiedHeader);
 *   var signature = CryptoJS.HmacSHA256(token, jwtSecret);
 * </pre>
 * running without the {@code ReferenceError: "require" is not defined} that
 * Rhino throws for Node/CommonJS APIs.
 *
 * <p>Rhino wraps this object as a {@code NativeJavaObject} and reflects
 * property access onto the public final fields ({@link #enc}, {@link #AES})
 * and public methods (HmacXxx, Xxx, digests). WordArray is a thin
 * {@code byte[]} wrapper — scripts pass it around opaquely and only call
 * {@code CryptoJS.enc.*.stringify(...)} on it, matching the way CryptoJS's
 * own JS implementation works.
 */
public final class CryptoJsHost {

    public final EncNamespace enc = new EncNamespace();

    public WordArray HmacSHA256(Object message, Object key) { return hmac("HmacSHA256", message, key); }
    public WordArray HmacSHA1(Object message, Object key)   { return hmac("HmacSHA1",   message, key); }
    public WordArray HmacSHA512(Object message, Object key) { return hmac("HmacSHA512", message, key); }
    public WordArray HmacMD5(Object message, Object key)    { return hmac("HmacMD5",    message, key); }

    public WordArray SHA256(Object message) { return digest("SHA-256", message); }
    public WordArray SHA1(Object message)   { return digest("SHA-1",   message); }
    public WordArray SHA512(Object message) { return digest("SHA-512", message); }
    public WordArray MD5(Object message)    { return digest("MD5",     message); }

    private static WordArray hmac(String algo, Object message, Object key) {
        byte[] msgBytes = toBytes(message);
        byte[] keyBytes = toBytes(key);
        // Real crypto-js in Node/Bruno accepts an empty key and still produces
        // a deterministic HMAC (the HMAC spec allows keys of any length; the
        // ipad/opad simply XOR against zero-padded bytes). Java's
        // {@code SecretKeySpec} throws {@code IllegalArgumentException: Empty key}
        // for a zero-length key. To match crypto-js behaviour and stop legitimate
        // JWT-signing scripts from aborting when the env variable that holds
        // the shared secret is missing / blank (e.g. the user hasn't populated
        // {@code VarArrowJWTKEY} yet), substitute a single NUL byte before
        // handing it to {@code SecretKeySpec}.
        if (keyBytes.length == 0) {
            keyBytes = new byte[]{0};
        }
        try {
            Mac mac = Mac.getInstance(algo);
            mac.init(new SecretKeySpec(keyBytes, algo));
            return new WordArray(mac.doFinal(msgBytes));
        } catch (Exception e) {
            throw new RuntimeException("CryptoJS." + algo + " failed: " + e.getMessage(), e);
        }
    }

    private static WordArray digest(String algo, Object message) {
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            return new WordArray(md.digest(toBytes(message)));
        } catch (Exception e) {
            throw new RuntimeException("CryptoJS." + algo + " failed: " + e.getMessage(), e);
        }
    }

    /** Coerce any script argument (String, byte[], WordArray, Rhino wrapper)
     *  to raw bytes the way CryptoJS treats string arguments — UTF-8 encoding. */
    static byte[] toBytes(Object o) {
        if (o == null) return new byte[0];
        if (o instanceof WordArray) return ((WordArray) o).bytes();
        if (o instanceof byte[]) return (byte[]) o;
        if (o instanceof org.mozilla.javascript.Wrapper) {
            Object unwrapped = ((org.mozilla.javascript.Wrapper) o).unwrap();
            if (unwrapped instanceof WordArray) return ((WordArray) unwrapped).bytes();
            if (unwrapped instanceof byte[]) return (byte[]) unwrapped;
            if (unwrapped == null) return new byte[0];
            return unwrapped.toString().getBytes(StandardCharsets.UTF_8);
        }
        return o.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** CryptoJS WordArray equivalent — an opaque byte carrier that scripts
     *  pass to {@code enc.Base64.stringify}, {@code enc.Hex.stringify}, etc.
     *  {@code toString()} defaults to hex, matching CryptoJS. */
    public static final class WordArray {
        private final byte[] bytes;
        public WordArray(byte[] b) { this.bytes = b == null ? new byte[0] : b; }
        public byte[] bytes() { return bytes; }
        public int getSigBytes() { return bytes.length; }
        @Override public String toString() {
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        }
    }

    public static final class EncNamespace {
        public final Utf8Codec Utf8 = new Utf8Codec();
        public final Base64Codec Base64 = new Base64Codec();
        public final HexCodec Hex = new HexCodec();
        public final Latin1Codec Latin1 = new Latin1Codec();
    }

    public static final class Utf8Codec {
        public WordArray parse(String s) {
            return new WordArray(s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8));
        }
        public String stringify(Object wa) {
            return new String(toBytes(wa), StandardCharsets.UTF_8);
        }
    }

    public static final class Base64Codec {
        public WordArray parse(String s) {
            if (s == null || s.isEmpty()) return new WordArray(new byte[0]);
            // Match browser/Node atob() forgiveness — strip whitespace, accept
            // URL-safe (- and _), and re-pad to length%4 == 0. Real crypto-js
            // in Bruno silently accepts inputs Java's strict decoder rejects.
            String cleaned = s.replaceAll("\\s+", "")
                              .replace('-', '+')
                              .replace('_', '/');
            String stripped = cleaned.replaceAll("=+$", "");
            int rem = stripped.length() % 4;
            if (rem == 2) stripped = stripped + "==";
            else if (rem == 3) stripped = stripped + "=";
            else if (rem == 1) stripped = stripped.substring(0, stripped.length() - 1);
            try { return new WordArray(Base64.getDecoder().decode(stripped)); }
            catch (IllegalArgumentException ignore) {}
            try { return new WordArray(Base64.getMimeDecoder().decode(stripped)); }
            catch (IllegalArgumentException ignore) {}
            return new WordArray(new byte[0]);
        }
        public String stringify(Object wa) {
            return Base64.getEncoder().encodeToString(toBytes(wa));
        }
    }

    public static final class HexCodec {
        public WordArray parse(String s) {
            if (s == null || s.isEmpty()) return new WordArray(new byte[0]);
            int n = s.length() / 2;
            byte[] out = new byte[n];
            for (int i = 0; i < n; i++) {
                out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
            }
            return new WordArray(out);
        }
        public String stringify(Object wa) {
            byte[] b = toBytes(wa);
            StringBuilder sb = new StringBuilder(b.length * 2);
            for (byte x : b) sb.append(String.format("%02x", x & 0xff));
            return sb.toString();
        }
    }

    public static final class Latin1Codec {
        public WordArray parse(String s) {
            return new WordArray(s == null ? new byte[0] : s.getBytes(StandardCharsets.ISO_8859_1));
        }
        public String stringify(Object wa) {
            return new String(toBytes(wa), StandardCharsets.ISO_8859_1);
        }
    }
}
