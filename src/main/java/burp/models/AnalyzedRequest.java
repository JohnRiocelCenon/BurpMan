package burp.models;

import java.util.List;

public class AnalyzedRequest {
   private final PostmanCollection.Request request;
   private final String name;
   private final String path;
   private final String collectionName;
   private final String resolvedUrl;
   private String preScript = "";
   private String postScript = "";

   public AnalyzedRequest(String name, String path, PostmanCollection.Request request, String collectionName, String resolvedUrl) {
      this.name = name;
      this.path = path;
      this.request = request;
      this.collectionName = collectionName;
      this.resolvedUrl = resolvedUrl;
   }

   public PostmanCollection.Request getRequest() {
      return this.request;
   }

   public String getName() {
      return this.name;
   }

   public String getPath() {
      return this.path;
   }

   public String getCollectionName() {
      return this.collectionName;
   }

   public String getResolvedUrl() {
      return this.resolvedUrl;
   }

   public String getPreScript() {
      return this.preScript;
   }

   public String getPostScript() {
      return this.postScript;
   }

   public void setPreScript(String s) {
      this.preScript = s == null ? "" : s;
   }

   public void setPostScript(String s) {
      this.postScript = s == null ? "" : s;
   }

   public static String extractScriptFromEvents(List<PostmanCollection.Event> events, String listenType) {
      if (events != null && listenType != null) {
         StringBuilder sb = new StringBuilder();

         for (PostmanCollection.Event ev : events) {
            if (ev != null && ev.script != null && ev.script.exec != null && listenType.equalsIgnoreCase(ev.listen)) {
               for (String line : ev.script.exec) {
                  sb.append(line == null ? "" : line).append('\n');
               }
            }
         }

         return sb.toString();
      } else {
         return "";
      }
   }
}
