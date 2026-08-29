package burp.auth;

import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import java.util.ArrayList;
import java.util.List;

public class JwtStaticTokenDetector {
   public List<String> detect(PostmanCollection collection, VariableResolver resolver) {
      List<String> list = new ArrayList<>();
      this.walk(collection.item, resolver, list);
      return list;
   }

   private void walk(List<PostmanCollection.Item> items, VariableResolver resolver, List<String> out) {
      if (items != null) {
         for (PostmanCollection.Item i : items) {
            if (i.request != null && i.request.header != null) {
               for (PostmanCollection.Header h : i.request.header) {
                  if (h != null && !h.disabled && "Authorization".equalsIgnoreCase(h.key) && h.value != null) {
                     String resolved = resolver.resolve(h.value);
                     if (resolved != null && resolved.startsWith("Bearer ")) {
                        String token = resolved.substring(7).trim();
                        if (token.split("\\.").length == 3) {
                           out.add(token);
                        }
                     }
                  }
               }
            }

            this.walk(i.item, resolver, out);
         }
      }
   }
}
