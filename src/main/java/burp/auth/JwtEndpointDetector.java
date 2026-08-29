package burp.auth;

import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import burp.utils.RequestUrlResolver;
import com.google.gson.Gson;
import java.util.ArrayList;
import java.util.List;

public class JwtEndpointDetector {
   public List<JwtEndpointCandidate> detect(PostmanCollection collection, VariableResolver resolver) {
      List<JwtEndpointCandidate> out = new ArrayList<>();
      if (collection == null) {
         return out;
      } else {
         this.walk(collection.item, out, resolver, collection != null && collection.info != null ? collection.info.name : "", "");
         out.sort((a, b) -> b.score - a.score);
         return out;
      }
   }

   private void walk(List<PostmanCollection.Item> items, List<JwtEndpointCandidate> out, VariableResolver resolver, String collectionName, String parentPath) {
      if (items != null) {
         for (PostmanCollection.Item item : items) {
            if (item != null) {
               String itemName = item.name != null ? item.name : "";
               String currentPath = parentPath.isEmpty() ? itemName : parentPath + "/" + itemName;
               String effectiveCollection = item.isCollectionWrapper && itemName != null && !itemName.isEmpty() ? itemName : collectionName;
               if (item.request != null) {
                  String rawUrl = RequestUrlResolver.extractRawUrl(item.request.url);
                  String resolvedUrl = resolver.resolve(rawUrl);
                  if (resolvedUrl == null || resolvedUrl.trim().isEmpty()) {
                     resolvedUrl = rawUrl;
                  }

                  if (resolvedUrl == null) {
                     resolvedUrl = "";
                  }

                  String urlLower = resolvedUrl.toLowerCase();
                  int score = 0;
                  if (urlLower.contains("login")) {
                     score += 40;
                  }

                  if (urlLower.contains("auth")) {
                     score += 40;
                  }

                  if (urlLower.contains("token")) {
                     score += 50;
                  }

                  if ("POST".equalsIgnoreCase(item.request.method)) {
                     score += 10;
                  }

                  if (score >= 40) {
                     PostmanCollection.Request resolvedRequest = this.deepCopy(item.request);
                     resolvedRequest.url = resolvedUrl;
                     this.resolveRequestFields(resolvedRequest, resolver);
                     JwtEndpointCandidate cand = new JwtEndpointCandidate(resolvedRequest, resolvedUrl, item.request.method, score);
                     cand.path = currentPath;
                     cand.collectionName = effectiveCollection;
                     out.add(cand);
                  }
               }

               if (item.item != null && !item.item.isEmpty()) {
                  this.walk(item.item, out, resolver, effectiveCollection, currentPath);
               }
            }
         }
      }
   }

   private PostmanCollection.Request deepCopy(PostmanCollection.Request req) {
      Gson gson = new Gson();
      return (PostmanCollection.Request)gson.fromJson(gson.toJson(req), PostmanCollection.Request.class);
   }

   private void resolveRequestFields(PostmanCollection.Request req, VariableResolver resolver) {
      if (req.header != null) {
         for (PostmanCollection.Header h : req.header) {
            if (h.key != null) {
               h.key = resolver.resolve(h.key);
            }

            if (h.value != null) {
               h.value = resolver.resolve(h.value);
            }
         }
      }

      if (req.body != null && req.body.raw != null) {
         req.body.raw = resolver.resolve(req.body.raw);
      }
   }
}
