package burp.utils;

import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class RequestUrlResolver {
   public static String resolve(PostmanCollection.Request request, VariableResolver resolver) {
      if (request == null) {
         return null;
      } else {
         String rawUrl = extractRawUrl(request.url);
         if (rawUrl == null) {
            return null;
         } else {
            String resolved = resolver.resolve(rawUrl);
            return resolved != null && !resolved.trim().isEmpty() ? resolved : rawUrl;
         }
      }
   }

   public static String extractRawUrl(Object urlData) {
      if (urlData == null) {
         return null;
      } else if (urlData instanceof String) {
         return (String)urlData;
      } else {
         try {
            Gson gson = new Gson();
            JsonElement element = gson.toJsonTree(urlData);
            if (element.isJsonObject()) {
               JsonObject obj = element.getAsJsonObject();
               if (obj.has("raw")) {
                  return obj.get("raw").getAsString();
               }
            }
         } catch (Exception var4) {
         }

         return urlData.toString();
      }
   }
}
