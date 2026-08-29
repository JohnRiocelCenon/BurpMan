package burp.auth;

import burp.auth.signers.Signer;
import java.util.Collections;
import java.util.Map;

public class AuthDecision {
   public final AuthDecision.Type type;
   public final String bearerToken;
   public final String username;
   public final String password;
   public final String reason;
   public final Map<String, String> params;
   public final Signer signer;

   private AuthDecision(AuthDecision.Type type, String bearerToken, String username, String password, String reason, Map<String, String> params, Signer signer) {
      this.type = type;
      this.bearerToken = bearerToken;
      this.username = username;
      this.password = password;
      this.reason = reason;
      this.params = params == null ? Collections.emptyMap() : params;
      this.signer = signer;
   }

   public static AuthDecision none(String reason) {
      return new AuthDecision(AuthDecision.Type.NONE, null, null, null, reason, null, null);
   }

   public static AuthDecision bearer(String token, String reason) {
      return new AuthDecision(AuthDecision.Type.BEARER, token, null, null, reason, null, null);
   }

   public static AuthDecision basic(String username, String password, String reason) {
      return new AuthDecision(AuthDecision.Type.BASIC, null, username, password, reason, null, null);
   }

   public static AuthDecision bodyOAuth(String reason) {
      return new AuthDecision(AuthDecision.Type.BODY_OAUTH, null, null, null, reason, null, null);
   }

   public static AuthDecision withSigner(AuthDecision.Type type, Signer signer, String reason) {
      return new AuthDecision(type, null, null, null, reason, null, signer);
   }

   public static AuthDecision withSigner(AuthDecision.Type type, Signer signer, Map<String, String> params, String reason) {
      return new AuthDecision(type, null, null, null, reason, params, signer);
   }

   public static enum Type {
      NONE,
      BEARER,
      BASIC,
      BODY_OAUTH,
      DIGEST,
      OAUTH1,
      AWS_SIGV4,
      HAWK,
      EDGEGRID,
      ASAP,
      API_KEY,
      NTLM;
   }
}
