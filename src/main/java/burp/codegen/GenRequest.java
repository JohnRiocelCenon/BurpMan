package burp.codegen;

import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class GenRequest {
   public String method = "GET";
   public String url = "";
   public final Map<String, String> headers = new LinkedHashMap<>();
   public String body = "";
   public String bodyMode = "";
   public final List<String[]> formFields = new ArrayList<>();
   public String displayName = "request";

   public static GenRequest from(PostmanCollection.Request req, String displayName, VariableResolver resolver) {
      GenRequest g = new GenRequest();
      if (req == null) {
         return g;
      } else {
         g.displayName = displayName == null ? "request" : displayName;
         g.method = req.method == null ? "GET" : req.method.toUpperCase(Locale.ROOT);
         String rawUrl = req.url == null ? "" : req.url.toString();
         g.url = resolver != null ? resolver.resolve(rawUrl) : rawUrl;
         if (req.header != null) {
            for (PostmanCollection.Header h : req.header) {
               if (h != null && !h.disabled && h.key != null) {
                  String k = resolver != null ? resolver.resolve(h.key) : h.key;
                  String v = resolver != null ? resolver.resolve(h.value) : h.value;
                  if (k != null && !k.trim().isEmpty()) {
                     g.headers.put(k.trim(), v == null ? "" : v);
                  }
               }
            }
         }

         if (req.body != null) {
            String mode = req.body.mode == null ? "" : req.body.mode.toLowerCase(Locale.ROOT);
            g.bodyMode = mode;
            switch (mode.hashCode()) {
               case 112680:
                  if (mode.equals("raw")) {
                     g.body = resolver != null ? resolver.resolve(req.body.raw) : req.body.raw;
                     if (g.body == null) {
                        g.body = "";
                     }
                  }
                  break;
               case 280343529:
                  if (mode.equals("graphql") && req.body.graphql != null) {
                     String query = resolver != null ? resolver.resolve(req.body.graphql.query) : req.body.graphql.query;
                     String vars = resolver != null ? resolver.resolve(req.body.graphql.variables) : req.body.graphql.variables;
                     StringBuilder gql = new StringBuilder("{");
                     gql.append("\"query\":").append(jsonQuote(query == null ? "" : query));
                     if (vars != null && !vars.trim().isEmpty()) {
                        gql.append(",\"variables\":").append(vars);
                     }

                     gql.append("}");
                     g.body = gql.toString();
                     g.bodyMode = "raw";
                  }
                  break;
               case 474151534:
                  if (mode.equals("formdata") && req.body.formdata != null) {
                     for (PostmanCollection.FormData f : req.body.formdata) {
                        if (f != null && !f.disabled && f.key != null) {
                           g.formFields
                              .add(
                                 new String[]{
                                    resolver != null ? resolver.resolve(f.key) : f.key,
                                    resolver != null ? resolver.resolve(f.value) : (f.value == null ? "" : f.value)
                                 }
                              );
                        }
                     }
                  }
                  break;
               case 523932863:
                  if (mode.equals("urlencoded") && req.body.urlencoded != null) {
                     for (PostmanCollection.UrlEncoded u : req.body.urlencoded) {
                        if (u != null && !u.disabled && u.key != null) {
                           g.formFields
                              .add(
                                 new String[]{
                                    resolver != null ? resolver.resolve(u.key) : u.key,
                                    resolver != null ? resolver.resolve(u.value) : (u.value == null ? "" : u.value)
                                 }
                              );
                        }
                     }
                  }
            }
         }

         return g;
      }
   }

   public byte[] bodyBytes() {
      return this.body != null && !this.body.isEmpty() ? this.body.getBytes(StandardCharsets.UTF_8) : new byte[0];
   }

   public boolean hasBody() {
      return this.body != null && !this.body.isEmpty() || !this.formFields.isEmpty();
   }

   public static String jsonQuote(String s) {
      if (s == null) {
         return "null";
      } else {
         StringBuilder sb = new StringBuilder(s.length() + 2);
         sb.append('"');

         for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
               case '\b':
                  sb.append("\\b");
                  break;
               case '\t':
                  sb.append("\\t");
                  break;
               case '\n':
                  sb.append("\\n");
                  break;
               case '\f':
                  sb.append("\\f");
                  break;
               case '\r':
                  sb.append("\\r");
                  break;
               case '"':
                  sb.append("\\\"");
                  break;
               case '\\':
                  sb.append("\\\\");
                  break;
               default:
                  if (c < ' ') {
                     sb.append(String.format("\\u%04x", Integer.valueOf(c)));
                  } else {
                     sb.append(c);
                  }
            }
         }

         sb.append('"');
         return sb.toString();
      }
   }

   public static String shellSingleQuote(String s) {
      return s == null ? "''" : "'" + s.replace("'", "'\\''") + "'";
   }
}
