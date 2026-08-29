package burp.auth;

import burp.models.PostmanCollection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class FolderAuthApplier {
   public static void apply(FolderAuthOverride o, PostmanCollection.Request req) {
      if (o != null && req != null) {
         if (req.header == null) {
            req.header = new ArrayList<>();
         }

         switch (o.type) {
            case NO_AUTH:
            case INHERIT:
               return;
            case BEARER:
            case OAUTH2:
            case JWT_BEARER:
               String token = o.get("token");
               if (isBlank(token)) {
                  return;
               }

               setHeader(req.header, "Authorization", "Bearer " + token.trim());
               return;
            case BASIC: {
               String u = nz(o.get("username"));
               String p = nz(o.get("password"));
               String enc = Base64.getEncoder().encodeToString((u + ":" + p).getBytes(StandardCharsets.UTF_8));
               setHeader(req.header, "Authorization", "Basic " + enc);
               return;
            }
            case DIGEST: {
               String u = nz(o.get("username"));
               String realm = nz(o.get("realm"));
               setHeader(req.header, "Authorization", "Digest username=\"" + u + "\", realm=\"" + realm + "\" /* requires server challenge */");
               return;
            }
            case APIKEY:
               String key = nz(o.get("key"));
               String value = nz(o.get("value"));
               String addTo = nz(o.get("addTo"));
               if (key.isEmpty()) {
                  return;
               }

               if ("query".equalsIgnoreCase(addTo)) {
                  if (req.url != null) {
                     String ux = req.url.toString();
                     String sep = ux.contains("?") ? "&" : "?";
                     req.url = ux + sep + urlEnc(key) + "=" + urlEnc(value);
                  }
               } else {
                  setHeader(req.header, key, value);
               }

               return;
            case OAUTH1:
            case HAWK:
            case AWS:
            case NTLM:
            case AKAMAI:
            case ASAP:
               setHeader(req.header, "Authorization", "/* " + o.type.label + " — signing not implemented; edit manually */");
               return;
         }
      }
   }

   private static void setHeader(List<PostmanCollection.Header> headers, String key, String value) {
      for (PostmanCollection.Header h : headers) {
         if (key.equalsIgnoreCase(h.key)) {
            h.value = value;
            return;
         }
      }

      PostmanCollection.Header hx = new PostmanCollection.Header();
      hx.key = key;
      hx.value = value;
      headers.add(hx);
   }

   private static boolean isBlank(String s) {
      return s == null || s.trim().isEmpty();
   }

   private static String nz(String s) {
      return s == null ? "" : s;
   }

   private static String urlEnc(String s) {
      try {
         return URLEncoder.encode(s, "UTF-8");
      } catch (Exception var2) {
         return s;
      }
   }
}
