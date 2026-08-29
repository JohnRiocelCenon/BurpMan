package burp.auth.signers;

import java.net.URI;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;

public final class DigestSigner implements Signer {
   private final String username;
   private final String password;
   private final String realm;
   private final String nonce;
   private final String opaque;
   private final String algorithm;
   private final String qop;
   private final SecureRandom rng = new SecureRandom();
   private int nonceCount = 0;

   public DigestSigner(String username, String password, String realm, String nonce, String opaque, String algorithm, String qop) {
      this.username = username == null ? "" : username;
      this.password = password == null ? "" : password;
      this.realm = realm == null ? "" : realm;
      this.nonce = nonce == null ? this.randomHex(16) : nonce;
      this.opaque = opaque;
      this.algorithm = algorithm != null && !algorithm.isEmpty() ? algorithm : "MD5";
      this.qop = qop != null && !qop.isEmpty() ? qop : "auth";
   }

   @Override
   public void sign(String method, String url, List<String> headers, byte[] body) {
      SignerUtils.removeAuthorization(headers);
      URI uri = SignerUtils.uri(url);
      String uriPath = SignerUtils.path(uri);
      String q = SignerUtils.query(uri);
      if (!q.isEmpty()) {
         uriPath = uriPath + "?" + q;
      }

      String cnonce = this.randomHex(8);
      String nc = String.format("%08x", ++this.nonceCount);
      String a1Hash = this.hash(this.username + ":" + this.realm + ":" + this.password);
      String a2Hash = this.hash(method + ":" + uriPath);
      String responseHash = this.hash(a1Hash + ":" + this.nonce + ":" + nc + ":" + cnonce + ":" + this.qop + ":" + a2Hash);
      StringBuilder sb = new StringBuilder("Authorization: Digest ");
      appendParam(sb, "username", this.username, true);
      appendParam(sb, "realm", this.realm, true);
      appendParam(sb, "nonce", this.nonce, true);
      appendParam(sb, "uri", uriPath, true);
      appendParam(sb, "algorithm", this.algorithm, false);
      appendParam(sb, "response", responseHash, true);
      appendParam(sb, "qop", this.qop, false);
      appendParam(sb, "nc", nc, false);
      appendParam(sb, "cnonce", cnonce, true);
      if (this.opaque != null && !this.opaque.isEmpty()) {
         appendParam(sb, "opaque", this.opaque, true);
      }

      headers.add(sb.toString().replaceAll(", $", ""));
   }

   private String hash(String s) {
      byte[] bytes = SignerUtils.utf8(s);
      return "SHA-256".equalsIgnoreCase(this.algorithm) ? SignerUtils.hex(SignerUtils.sha256(bytes)) : SignerUtils.hex(SignerUtils.md5(bytes));
   }

   private static void appendParam(StringBuilder sb, String name, String value, boolean quoted) {
      if (value != null) {
         sb.append(name).append('=');
         if (quoted) {
            sb.append('"').append(value.replace("\"", "\\\"")).append('"');
         } else {
            sb.append(value);
         }

         sb.append(", ");
      }
   }

   private String randomHex(int bytes) {
      byte[] b = new byte[bytes];
      this.rng.nextBytes(b);
      return SignerUtils.hex(b);
   }

   public static DigestSigner fromChallenge(String challenge, String username, String password) {
      if (challenge == null) {
         return new DigestSigner(username, password, "", null, null, "MD5", "auth");
      } else {
         String c = challenge.trim();
         if (c.toLowerCase(Locale.ROOT).startsWith("digest ")) {
            c = c.substring(7).trim();
         }

         String realm = extract(c, "realm");
         String nonce = extract(c, "nonce");
         String opaque = extract(c, "opaque");
         String algorithm = extract(c, "algorithm");
         String qop = extract(c, "qop");
         if (qop != null && qop.contains(",")) {
            qop = qop.contains("auth-int") ? "auth-int" : "auth";
         }

         return new DigestSigner(username, password, realm, nonce, opaque, algorithm == null ? "MD5" : algorithm, qop == null ? "auth" : qop);
      }
   }

   private static String extract(String raw, String key) {
      int i = raw.toLowerCase(Locale.ROOT).indexOf(key.toLowerCase(Locale.ROOT) + "=");
      if (i < 0) {
         return null;
      } else {
         int s = i + key.length() + 1;
         if (s >= raw.length()) {
            return null;
         } else {
            char first = raw.charAt(s);
            if (first == '"') {
               int end = raw.indexOf(34, s + 1);
               return end < 0 ? null : raw.substring(s + 1, end);
            } else {
               int end = raw.indexOf(44, s);
               return end < 0 ? raw.substring(s).trim() : raw.substring(s, end).trim();
            }
         }
      }
   }
}
