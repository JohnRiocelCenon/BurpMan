package burp.models;

import burp.auth.JwtEndpointCandidate;
import burp.auth.OAuth2Config;
import java.util.List;

public class AnalyzedCollection {
   private final List<RequestPreview> requests;
   private final List<JwtEndpointCandidate> jwtEndpoints;
   private final List<OAuth2Config> oauthConfigs;

   public AnalyzedCollection(List<RequestPreview> requests, List<JwtEndpointCandidate> jwtEndpoints, List<OAuth2Config> oauthConfigs) {
      this.requests = requests;
      this.jwtEndpoints = jwtEndpoints;
      this.oauthConfigs = oauthConfigs;
   }

   public List<RequestPreview> getRequests() {
      return this.requests;
   }

   public List<JwtEndpointCandidate> getJwtEndpoints() {
      return this.jwtEndpoints;
   }

   public List<OAuth2Config> getOAuthConfigs() {
      return this.oauthConfigs;
   }
}
