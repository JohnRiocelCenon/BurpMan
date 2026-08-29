package burp.auth;

import burp.models.PostmanCollection;

public class JwtEndpointCandidate {
   public PostmanCollection.Request request;
   public String url;
   public String method;
   public int score;
   public String confidence;
   public String path;
   public String collectionName;
   public boolean fromScriptSendRequest;
   public String scriptSource;

   public JwtEndpointCandidate(PostmanCollection.Request r, String u, String m, int s) {
      this.request = r;
      this.url = u;
      this.method = m;
      this.score = s;
      this.confidence = s >= 80 ? "HIGH" : (s >= 50 ? "MEDIUM" : "LOW");
   }
}
