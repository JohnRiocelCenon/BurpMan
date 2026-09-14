package burp.auth;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Extracts OAuth 2.0 authorization-response values out of a redirect URL.
 *
 * <p>Accepts anything a user or a browser can realistically hand us: a full redirect URL,
 * a bare query string, a fragment response, or just the code on its own.
 */
public final class OAuthCallbackParser {

   private OAuthCallbackParser() {
   }

   public static final class Result {
      public final String code;
      public final String state;
      public final String error;
      public final String errorDescription;
      public final String accessToken;
      public final String idToken;
      public final String raw;

      Result(String code, String state, String error, String errorDescription,
             String accessToken, String idToken, String raw) {
         this.code = code;
         this.state = state;
         this.error = error;
         this.errorDescription = errorDescription;
         this.accessToken = accessToken;
         this.idToken = idToken;
         this.raw = raw;
      }

      public boolean hasCode() {
         return this.code != null && !this.code.isEmpty();
      }

      public boolean hasError() {
         return this.error != null && !this.error.isEmpty();
      }

      public boolean hasToken() {
         return this.accessToken != null && !this.accessToken.isEmpty();
      }

      public boolean isEmpty() {
         return !this.hasCode() && !this.hasError() && !this.hasToken();
      }

      public String errorMessage() {
         if (!this.hasError()) return null;
         return this.errorDescription == null || this.errorDescription.isEmpty()
            ? this.error
            : this.error + ": " + this.errorDescription;
      }
   }

   private static final Result EMPTY = new Result(null, null, null, null, null, null, null);

   public static Result parse(String input) {
      if (input == null) return EMPTY;
      String text = input.trim();
      if (text.isEmpty()) return EMPTY;

      // Users copy from address bars and mail clients; both love to wrap and quote.
      text = text.replace("\r", "").replace("\n", "").trim();
      if (text.length() > 1
         && ((text.startsWith("\"") && text.endsWith("\"")) || (text.startsWith("<") && text.endsWith(">")))) {
         text = text.substring(1, text.length() - 1).trim();
      }
      if (text.isEmpty()) return EMPTY;

      Map<String, String> params = collectParams(text);
      if (params.isEmpty()) {
         // No key=value structure at all, so the user most likely pasted the bare code.
         return looksLikeBareCode(text)
            ? new Result(text, null, null, null, null, null, text)
            : EMPTY;
      }

      String code = params.get("code");
      String state = params.get("state");
      String error = params.get("error");
      String errorDescription = params.get("error_description");
      String accessToken = params.get("access_token");
      String idToken = params.get("id_token");

      boolean anything = notBlank(code) || notBlank(error) || notBlank(accessToken) || notBlank(idToken);
      if (!anything) {
         return looksLikeBareCode(text)
            ? new Result(text, null, null, null, null, null, text)
            : EMPTY;
      }
      return new Result(blankToNull(code), blankToNull(state), blankToNull(error),
         blankToNull(errorDescription), blankToNull(accessToken), blankToNull(idToken), text);
   }

   /**
    * True when the URL is an authorization response we should act on, i.e. it carries a code,
    * an error or a token rather than just being another step of the login journey.
    */
   public static boolean isAuthorizationResponse(String url) {
      return !parse(url).isEmpty();
   }

   /**
    * True when {@code url} points at the same endpoint as {@code callbackUrl}, ignoring the
    * query string, the fragment and any trailing slash.
    */
   public static boolean matchesCallback(String url, String callbackUrl) {
      String a = endpointOf(url);
      String b = endpointOf(callbackUrl);
      return a != null && b != null && a.equals(b);
   }

   private static String endpointOf(String url) {
      if (url == null) return null;
      String s = url.trim();
      if (s.isEmpty()) return null;
      int cut = indexOfAny(s, '?', '#');
      if (cut >= 0) s = s.substring(0, cut);
      while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
      return s.isEmpty() ? null : s.toLowerCase(Locale.ROOT);
   }

   /**
    * Reads parameters out of both the query and the fragment. The query wins on conflict,
    * which is what an authorization-code response uses.
    */
   private static Map<String, String> collectParams(String text) {
      Map<String, String> out = new LinkedHashMap<>();
      String query = null;
      String fragment = null;

      int hash = text.indexOf('#');
      int question = text.indexOf('?');

      if (question >= 0 && (hash < 0 || question < hash)) {
         query = hash >= 0 ? text.substring(question + 1, hash) : text.substring(question + 1);
      }
      if (hash >= 0) {
         fragment = text.substring(hash + 1);
         int fragQuestion = fragment.indexOf('?');
         if (query == null && fragQuestion >= 0) {
            // e.g. #/callback?code=... as used by SPA hash routers
            query = fragment.substring(fragQuestion + 1);
            fragment = fragment.substring(0, fragQuestion);
         }
      }
      if (query == null && fragment == null && text.indexOf('=') >= 0 && !text.contains("://")) {
         query = text.startsWith("&") ? text.substring(1) : text;
      }

      // Fragment first so the query can overwrite it.
      putPairs(out, fragment);
      putPairs(out, query);
      return out;
   }

   private static void putPairs(Map<String, String> out, String blob) {
      if (blob == null || blob.isEmpty()) return;
      for (String pair : blob.split("&")) {
         if (pair.isEmpty()) continue;
         int eq = pair.indexOf('=');
         if (eq <= 0) continue;
         String key = pair.substring(0, eq).trim().toLowerCase(Locale.ROOT);
         String value = urlDecode(pair.substring(eq + 1).trim());
         if (!key.isEmpty()) out.put(key, value);
      }
   }

   private static boolean looksLikeBareCode(String text) {
      if (text.length() < 8 || text.length() > 4096) return false;
      if (text.contains("://") || text.contains(" ")) return false;
      for (int i = 0; i < text.length(); i++) {
         char c = text.charAt(i);
         boolean ok = Character.isLetterOrDigit(c)
            || c == '-' || c == '_' || c == '.' || c == '~' || c == '=' || c == '%' || c == '/' || c == '+';
         if (!ok) return false;
      }
      return true;
   }

   private static int indexOfAny(String s, char a, char b) {
      int i = s.indexOf(a);
      int j = s.indexOf(b);
      if (i < 0) return j;
      if (j < 0) return i;
      return Math.min(i, j);
   }

   private static String urlDecode(String value) {
      if (value == null || value.isEmpty()) return value;
      try {
         return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8.name());
      } catch (Exception ex) {
         return value;
      }
   }

   private static boolean notBlank(String s) {
      return s != null && !s.trim().isEmpty();
   }

   private static String blankToNull(String s) {
      return notBlank(s) ? s : null;
   }
}
