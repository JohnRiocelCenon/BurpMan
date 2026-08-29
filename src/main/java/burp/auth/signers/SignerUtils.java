package burp.auth.signers;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class SignerUtils {
   private static final char[] HEX = "0123456789abcdef".toCharArray();

   private SignerUtils() {
   }

   public static String hex(byte[] bytes) {
      char[] out = new char[bytes.length * 2];

      for (int i = 0; i < bytes.length; i++) {
         int v = bytes[i] & 255;
         out[i * 2] = HEX[v >>> 4];
         out[i * 2 + 1] = HEX[v & 15];
      }

      return new String(out);
   }

   public static byte[] sha256(byte[] data) {
      try {
         return MessageDigest.getInstance("SHA-256").digest(data);
      } catch (Exception var2) {
         throw new RuntimeException("SHA-256 not available", var2);
      }
   }

   public static byte[] md5(byte[] data) {
      try {
         return MessageDigest.getInstance("MD5").digest(data);
      } catch (Exception var2) {
         throw new RuntimeException("MD5 not available", var2);
      }
   }

   public static byte[] sha1(byte[] data) {
      try {
         return MessageDigest.getInstance("SHA-1").digest(data);
      } catch (Exception var2) {
         throw new RuntimeException("SHA-1 not available", var2);
      }
   }

   public static byte[] hmac(String algo, byte[] key, byte[] data) {
      try {
         Mac mac = Mac.getInstance(algo);
         mac.init(new SecretKeySpec(key, algo));
         return mac.doFinal(data);
      } catch (Exception var4) {
         throw new RuntimeException(algo + " HMAC failed", var4);
      }
   }

   public static byte[] hmacSha256(byte[] key, byte[] data) {
      return hmac("HmacSHA256", key, data);
   }

   public static byte[] hmacSha1(byte[] key, byte[] data) {
      return hmac("HmacSHA1", key, data);
   }

   public static byte[] hmacSha512(byte[] key, byte[] data) {
      return hmac("HmacSHA512", key, data);
   }

   public static byte[] utf8(String s) {
      return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
   }

   public static String pctEncode(String s) {
      if (s == null) {
         return "";
      } else {
         StringBuilder out = new StringBuilder(s.length() * 3);
         byte[] bytes = s.getBytes(StandardCharsets.UTF_8);

         for (byte b : bytes) {
            int v = b & 255;
            boolean unreserved = v >= 65 && v <= 90 || v >= 97 && v <= 122 || v >= 48 && v <= 57 || v == 45 || v == 46 || v == 95 || v == 126;
            if (unreserved) {
               out.append((char)v);
            } else {
               out.append('%');
               out.append(HEX[v >>> 4]);
               out.append(HEX[v & 15]);
            }
         }

         return out.toString().toUpperCase(Locale.ROOT).replaceAll("%([0-9A-F]{2})", "%$1");
      }
   }

   public static void removeAuthorization(List<String> headers) {
      if (headers != null) {
         Iterator<String> it = headers.iterator();

         while (it.hasNext()) {
            String h = it.next();
            if (h != null && h.toLowerCase(Locale.ROOT).startsWith("authorization:")) {
               it.remove();
            }
         }
      }
   }

   public static URI uri(String url) {
      try {
         return new URI(url);
      } catch (Exception var2) {
         return null;
      }
   }

   public static String path(URI uri) {
      if (uri == null) {
         return "/";
      } else {
         String p = uri.getRawPath();
         return p != null && !p.isEmpty() ? p : "/";
      }
   }

   public static String query(URI uri) {
      if (uri == null) {
         return "";
      } else {
         String q = uri.getRawQuery();
         return q == null ? "" : q;
      }
   }

   public static String host(URI uri) {
      if (uri == null) {
         return "";
      } else {
         String h = uri.getHost();
         return h == null ? "" : h.toLowerCase(Locale.ROOT);
      }
   }

   public static List<String[]> parseQuery(String query) {
      List<String[]> out = new ArrayList<>();
      if (query != null && !query.isEmpty()) {
         String[] var5;
         for (String pair : var5 = query.split("&")) {
            int eq = pair.indexOf(61);
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 ? pair.substring(eq + 1) : "";
            out.add(new String[]{k, v});
         }

         return out;
      } else {
         return out;
      }
   }
}
