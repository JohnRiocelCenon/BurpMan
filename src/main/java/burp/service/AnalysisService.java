package burp.service;

import burp.auth.JwtEndpointCandidate;
import burp.auth.JwtEndpointDetector;
import burp.auth.OAuth2Config;
import burp.auth.OAuth2Detector;
import burp.models.AnalyzedCollection;
import burp.models.AnalyzedRequest;
import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import com.google.gson.Gson;
import java.util.ArrayList;
import java.util.List;

public class AnalysisService {
   private final VariableResolver resolver;
   private final JwtEndpointDetector jwtDetector;
   private final OAuth2Detector oauthDetector;

   public AnalysisService(VariableResolver resolver) {
      this.resolver = resolver;
      this.jwtDetector = new JwtEndpointDetector();
      this.oauthDetector = new OAuth2Detector(resolver);
   }

   public AnalyzedCollection analyze(PostmanCollection collection) {
      List<AnalyzedRequest> analyzedRequests = new ArrayList<>();
      String collectionName = collection != null && collection.info != null ? collection.info.name : "Collection";
      this.flatten(
         collection.item,
         "",
         analyzedRequests,
         collectionName,
         AnalyzedRequest.extractScriptFromEvents(collection != null ? collection.event : null, "prerequest"),
         AnalyzedRequest.extractScriptFromEvents(collection != null ? collection.event : null, "test")
      );
      List<JwtEndpointCandidate> jwt = this.jwtDetector.detect(collection, this.resolver);
      List<OAuth2Config> oauth = this.oauthDetector.detect(collection);
      return new AnalyzedCollection(null, jwt, oauth);
   }

   private void flatten(
      List<PostmanCollection.Item> items, String path, List<AnalyzedRequest> out, String collectionName, String ancestorPreScript, String ancestorPostScript
   ) {
      if (items != null) {
         for (PostmanCollection.Item item : items) {
            String currentPath = path.isEmpty() ? item.name : path + "/" + item.name;
            String ownPre = AnalyzedRequest.extractScriptFromEvents(item.event, "prerequest");
            String ownPost = AnalyzedRequest.extractScriptFromEvents(item.event, "test");
            if (item.request != null) {
               PostmanCollection.Request resolved = this.deepCopy(item.request);
               String rawUrl = item.request.url != null ? item.request.url.toString() : "";
               String resolvedUrl = this.resolver.resolve(rawUrl);
               resolved.url = resolvedUrl;
               this.resolveFields(resolved);
               AnalyzedRequest ar = new AnalyzedRequest(item.name, currentPath, resolved, collectionName, resolvedUrl);
               ar.setPreScript(ancestorPreScript + ownPre);
               ar.setPostScript(ancestorPostScript + ownPost);
               out.add(ar);
            }

            if (item.item != null) {
               this.flatten(item.item, currentPath, out, collectionName, ancestorPreScript + ownPre, ancestorPostScript + ownPost);
            }
         }
      }
   }

   private PostmanCollection.Request deepCopy(PostmanCollection.Request req) {
      Gson gson = new Gson();
      return (PostmanCollection.Request)gson.fromJson(gson.toJson(req), PostmanCollection.Request.class);
   }

   private void resolveFields(PostmanCollection.Request req) {
      if (req.header != null) {
         for (PostmanCollection.Header h : req.header) {
            if (h.key != null) {
               h.key = this.resolver.resolve(h.key);
            }

            if (h.value != null) {
               h.value = this.resolver.resolve(h.value);
            }
         }
      }

      if (req.body != null && req.body.raw != null) {
         req.body.raw = this.resolver.resolve(req.body.raw);
      }
   }
}
