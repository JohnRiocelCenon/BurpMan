package burp.auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public class OAuth2Config {
   public String id = UUID.randomUUID().toString();
   public String name;
   public String path;
   public String grantType;
   public String accessTokenUrl;
   public String authUrl;
   public String clientId;
   public String clientSecret;
   public String scope;
   public String username;
   public String password;
   public String audience;
   public String state;
   public String callbackUrl;
   public String clientAuthenticationMethod;
   public Map<String, String> rawAttributes = new LinkedHashMap<>();

   public boolean isUsableForTokenRequest() {
      return this.accessTokenUrl != null && !this.accessTokenUrl.trim().isEmpty() && this.grantType != null && !this.grantType.trim().isEmpty();
   }

   @Override
   public String toString() {
      String displayName = this.name != null && !this.name.trim().isEmpty() ? this.name : "OAuth2";
      String grant = this.grantType != null && !this.grantType.trim().isEmpty() ? this.grantType : "unknown";
      String location = this.path != null && !this.path.trim().isEmpty() ? " - " + this.path : "";
      return displayName + " [" + grant + "]" + location;
   }
}
