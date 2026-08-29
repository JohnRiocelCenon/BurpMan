package burp.auth.signers;

import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

public final class EdgeGridSigner implements Signer {
   private static final int MAX_BODY_HASH_BYTES = 131072;
   private final String clientToken;
   private final String accessToken;
   private final String clientSecret;
   private final String nonce;
   private final String timestamp;

   public EdgeGridSigner(String clientToken, String accessToken, String clientSecret, String nonce, String timestamp) {
      this.clientToken = nz(clientToken);
      this.accessToken = nz(accessToken);
      this.clientSecret = nz(clientSecret);
      this.nonce = nonce != null && !nonce.isEmpty() ? nonce : UUID.randomUUID().toString();
      this.timestamp = timestamp != null && !timestamp.isEmpty() ? timestamp : defaultTimestamp();
   }

   @Override
   public void sign(String method, String url, List<String> headers, byte[] body) {
      SignerUtils.removeAuthorization(headers);
      URI uri = SignerUtils.uri(url);
      if (uri != null) {
         String authPrefix = "EG1-HMAC-SHA256 client_token="
            + this.clientToken
            + ";access_token="
            + this.accessToken
            + ";timestamp="
            + this.timestamp
            + ";nonce="
            + this.nonce
            + ";";
         String contentHash = "";
         if (("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) && body != null && body.length > 0) {
            int len = Math.min(body.length, 131072);
            byte[] slice = len == body.length ? body : Arrays.copyOf(body, len);
            contentHash = Base64.getEncoder().encodeToString(SignerUtils.sha256(slice));
         }

         String pathWithQuery = SignerUtils.path(uri);
         String q = SignerUtils.query(uri);
         if (!q.isEmpty()) {
            pathWithQuery = pathWithQuery + "?" + q;
         }

         String dataToSign = String.join(
            "\t", method.toUpperCase(Locale.ROOT), uri.getScheme(), SignerUtils.host(uri), pathWithQuery, "", contentHash, authPrefix + "signature="
         );
         String signingKey = Base64.getEncoder().encodeToString(SignerUtils.hmacSha256(SignerUtils.utf8(this.clientSecret), SignerUtils.utf8(this.timestamp)));
         String signature = Base64.getEncoder().encodeToString(SignerUtils.hmacSha256(SignerUtils.utf8(signingKey), SignerUtils.utf8(dataToSign)));
         headers.add("Authorization: " + authPrefix + "signature=" + signature);
      }
   }

   private static String defaultTimestamp() {
      SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMdd'T'HH:mm:ss+0000", Locale.US);
      fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
      return fmt.format(new Date());
   }

   private static String nz(String s) {
      return s == null ? "" : s;
   }
}
