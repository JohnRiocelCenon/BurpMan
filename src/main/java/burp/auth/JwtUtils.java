package burp.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class JwtUtils {
   private JwtUtils() {
   }

   public static long getExpiryEpochSeconds(String token) {
      if (token == null) {
         return -1L;
      } else {
         String t = token.trim();
         if (t.toLowerCase().startsWith("bearer ")) {
            t = t.substring(7).trim();
         }

         String[] parts = t.split("\\.");
         if (parts.length < 2) {
            return -1L;
         } else {
            try {
               byte[] payload = Base64.getUrlDecoder().decode(padBase64(parts[1]));
               String json = new String(payload, StandardCharsets.UTF_8);
               int idx = json.indexOf("\"exp\"");
               if (idx < 0) {
                  return -1L;
               } else {
                  int colon = json.indexOf(58, idx);
                  if (colon < 0) {
                     return -1L;
                  } else {
                     int i = colon + 1;

                     while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
                        i++;
                     }

                     int start = i;

                     while (i < json.length() && (Character.isDigit(json.charAt(i)) || json.charAt(i) == '.')) {
                        i++;
                     }

                     if (start == i) {
                        return -1L;
                     } else {
                        String num = json.substring(start, i);
                        return (long)Double.parseDouble(num);
                     }
                  }
               }
            } catch (Exception var10) {
               return -1L;
            }
         }
      }
   }

   public static boolean isExpiredOrAboutTo(String token, long skewSeconds) {
      if (token != null && !token.trim().isEmpty()) {
         long exp = getExpiryEpochSeconds(token);
         if (exp <= 0L) {
            return false;
         } else {
            long now = System.currentTimeMillis() / 1000L;
            return exp - skewSeconds <= now;
         }
      } else {
         return true;
      }
   }

   private static String padBase64(String s) {
      int rem = s.length() % 4;
      if (rem == 0) {
         return s;
      } else {
         StringBuilder sb = new StringBuilder(s);

         for (int i = 0; i < 4 - rem; i++) {
            sb.append('=');
         }

         return sb.toString();
      }
   }
}
