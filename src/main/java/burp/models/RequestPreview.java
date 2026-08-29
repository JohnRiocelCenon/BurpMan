package burp.models;

import java.awt.Color;
import java.util.Collections;
import java.util.Set;

public class RequestPreview {
   private final String name;
   private final String path;
   private final String method;
   private final String url;
   private final String description;
   private final boolean hasAuth;
   private final boolean hasHeaders;
   private final boolean hasBody;
   private final Set<String> unresolvedVariables;
   private final Set<String> allVariables;
   private final boolean missingAuthorizationHeader;
   private boolean selected;
   private boolean addAuthorizationHeader;
   private final String authDisplay;
   private PostmanCollection.Request request;

   public RequestPreview(
      String name,
      String path,
      String method,
      String url,
      String description,
      boolean hasAuth,
      boolean hasHeaders,
      boolean hasBody,
      Set<String> unresolvedVariables,
      Set<String> allVariables,
      boolean missingAuthorizationHeader,
      String authDisplay,
      PostmanCollection.Request request
   ) {
      this.name = name;
      this.path = path;
      this.method = method;
      this.url = url;
      this.description = description;
      this.hasAuth = hasAuth;
      this.hasHeaders = hasHeaders;
      this.hasBody = hasBody;
      this.unresolvedVariables = unresolvedVariables != null ? unresolvedVariables : Collections.emptySet();
      this.allVariables = allVariables != null ? allVariables : Collections.emptySet();
      this.missingAuthorizationHeader = missingAuthorizationHeader;
      this.selected = true;
      this.addAuthorizationHeader = false;
      this.authDisplay = authDisplay;
      this.request = request;
   }

   public RequestPreview(
      String name,
      String path,
      String method,
      String url,
      String description,
      boolean hasAuth,
      boolean hasHeaders,
      boolean hasBody,
      Set<String> unresolvedVariables
   ) {
      this(name, path, method, url, description, hasAuth, hasHeaders, hasBody, unresolvedVariables, unresolvedVariables, false, "X", null);
   }

   public RequestPreview(String name, String path, String method, String url, String description, boolean hasAuth, boolean hasHeaders, boolean hasBody) {
      this(name, path, method, url, description, hasAuth, hasHeaders, hasBody, Collections.emptySet(), Collections.emptySet(), false, "X", null);
   }

   public String getName() {
      return this.name;
   }

   public String getPath() {
      return this.path;
   }

   public String getMethod() {
      return this.method;
   }

   public String getUrl() {
      return this.url;
   }

   public String getDescription() {
      return this.description;
   }

   public boolean hasAuth() {
      return this.hasAuth;
   }

   public boolean hasHeaders() {
      return this.hasHeaders;
   }

   public boolean hasBody() {
      return this.hasBody;
   }

   public boolean isSelected() {
      return this.selected;
   }

   public Set<String> getUnresolvedVariables() {
      return this.unresolvedVariables;
   }

   public Set<String> getAllVariables() {
      return this.allVariables;
   }

   public boolean hasUnresolvedVariables() {
      return !this.unresolvedVariables.isEmpty();
   }

   public boolean isMissingAuthorizationHeader() {
      return this.missingAuthorizationHeader;
   }

   public boolean shouldAddAuthorizationHeader() {
      return this.addAuthorizationHeader;
   }

   public void setSelected(boolean selected) {
      this.selected = selected;
   }

   public void setAddAuthorizationHeader(boolean addAuthorizationHeader) {
      this.addAuthorizationHeader = addAuthorizationHeader;
   }

   public String getAuthDisplay() {
      return this.authDisplay;
   }

   public String getVariableStatus() {
      if (this.unresolvedVariables.isEmpty()) {
         return "✅ All resolved";
      } else {
         return this.unresolvedVariables.size() == 1
            ? "⚠️ " + this.unresolvedVariables.iterator().next()
            : "❌ " + this.unresolvedVariables.size() + " variables";
      }
   }

   public Color getVariableStatusColor() {
      if (this.unresolvedVariables.isEmpty()) {
         return new Color(0, 120, 0);
      } else {
         return this.unresolvedVariables.size() <= 2 ? new Color(255, 140, 0) : Color.RED;
      }
   }

   public PostmanCollection.Request getRequest() {
      return this.request;
   }

   @Override
   public String toString() {
      return String.format("[%s] %s - %s", this.method, this.name, this.url);
   }
}
