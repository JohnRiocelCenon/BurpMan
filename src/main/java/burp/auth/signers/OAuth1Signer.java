package burp.auth.signers;

import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.TreeMap;
import java.util.Map.Entry;

public final class OAuth1Signer implements Signer {
   private final String consumerKey;
   private final String consumerSecret;
   private final String token;
   private final String tokenSecret;
   private final String realm;
   private final OAuth1Signer.SignatureMethod method;
   private final OAuth1Signer.Placement placement;
   private final boolean includeBodyHash;
   private final SecureRandom rng = new SecureRandom();

   public OAuth1Signer(
      String consumerKey,
      String consumerSecret,
      String token,
      String tokenSecret,
      String realm,
      OAuth1Signer.SignatureMethod method,
      OAuth1Signer.Placement placement,
      boolean includeBodyHash
   ) {
      this.consumerKey = nz(consumerKey);
      this.consumerSecret = nz(consumerSecret);
      this.token = nz(token);
      this.tokenSecret = nz(tokenSecret);
      this.realm = realm;
      this.method = method == null ? OAuth1Signer.SignatureMethod.HMAC_SHA1 : method;
      this.placement = placement == null ? OAuth1Signer.Placement.HEADER : placement;
      this.includeBodyHash = includeBodyHash;
   }

   @Override
   public void sign(String httpMethod, String url, List<String> headers, byte[] body) {
      SignerUtils.removeAuthorization(headers);
      URI uri = SignerUtils.uri(url);
      String baseUrl = uri == null
         ? url
         : uri.getScheme() + "://" + SignerUtils.host(uri) + (uri.getPort() > 0 && !isDefaultPort(uri) ? ":" + uri.getPort() : "") + SignerUtils.path(uri);
      TreeMap<String, String> oauthParams = new TreeMap<>();
      oauthParams.put("oauth_consumer_key", this.consumerKey);
      oauthParams.put("oauth_nonce", this.randomNonce());
      oauthParams.put(
         "oauth_signature_method",
         this.method == OAuth1Signer.SignatureMethod.HMAC_SHA256
            ? "HMAC-SHA256"
            : (this.method == OAuth1Signer.SignatureMethod.PLAINTEXT ? "PLAINTEXT" : "HMAC-SHA1")
      );
      oauthParams.put("oauth_timestamp", Long.toString(System.currentTimeMillis() / 1000L));
      oauthParams.put("oauth_version", "1.0");
      if (!this.token.isEmpty()) {
         oauthParams.put("oauth_token", this.token);
      }

      if (this.includeBodyHash && body != null && body.length > 0) {
         byte[] hash = this.method == OAuth1Signer.SignatureMethod.HMAC_SHA256 ? SignerUtils.sha256(body) : SignerUtils.sha1(body);
         oauthParams.put("oauth_body_hash", Base64.getEncoder().encodeToString(hash));
      }

      String signature;
      if (this.method == OAuth1Signer.SignatureMethod.PLAINTEXT) {
         signature = SignerUtils.pctEncode(this.consumerSecret) + "&" + SignerUtils.pctEncode(this.tokenSecret);
      } else {
         String baseString = this.buildSignatureBaseString(httpMethod, baseUrl, uri, body, oauthParams);
         String signingKey = SignerUtils.pctEncode(this.consumerSecret) + "&" + SignerUtils.pctEncode(this.tokenSecret);
         byte[] mac = this.method == OAuth1Signer.SignatureMethod.HMAC_SHA256
            ? SignerUtils.hmacSha256(SignerUtils.utf8(signingKey), SignerUtils.utf8(baseString))
            : SignerUtils.hmacSha1(SignerUtils.utf8(signingKey), SignerUtils.utf8(baseString));
         signature = Base64.getEncoder().encodeToString(mac);
      }

      oauthParams.put("oauth_signature", signature);
      if (this.placement == OAuth1Signer.Placement.HEADER) {
         StringBuilder sb = new StringBuilder("Authorization: OAuth ");
         if (this.realm != null && !this.realm.isEmpty()) {
            sb.append("realm=\"").append(SignerUtils.pctEncode(this.realm)).append("\", ");
         }

         boolean first = true;

         for (Entry<String, String> e : oauthParams.entrySet()) {
            if (!first) {
               sb.append(", ");
            }

            sb.append(SignerUtils.pctEncode(e.getKey())).append("=\"").append(SignerUtils.pctEncode(e.getValue())).append('"');
            first = false;
         }

         headers.add(sb.toString());
      } else {
         StringBuilder sb = new StringBuilder("X-BurpMan-OAuth1-Query: ");
         boolean first = true;

         for (Entry<String, String> e : oauthParams.entrySet()) {
            if (!first) {
               sb.append('&');
            }

            sb.append(SignerUtils.pctEncode(e.getKey())).append('=').append(SignerUtils.pctEncode(e.getValue()));
            first = false;
         }

         headers.add(sb.toString());
      }
   }

   private String buildSignatureBaseString(String httpMethod, String baseUrl, URI uri, byte[] body, TreeMap<String, String> oauthParams) {
      List<String[]> params = new ArrayList<>();

      for (Entry<String, String> e : oauthParams.entrySet()) {
         params.add(new String[]{SignerUtils.pctEncode(e.getKey()), SignerUtils.pctEncode(e.getValue())});
      }

      if (uri != null && uri.getRawQuery() != null) {
         for (String[] kv : SignerUtils.parseQuery(uri.getRawQuery())) {
            params.add(new String[]{kv[0], kv[1]});
         }
      }

      Collections.sort(params, new Comparator<String[]>() {
         public int compare(String[] a, String[] b) {
            int c = a[0].compareTo(b[0]);
            return c != 0 ? c : a[1].compareTo(b[1]);
         }
      });
      StringBuilder norm = new StringBuilder();
      boolean first = true;

      for (String[] kv : params) {
         if (!first) {
            norm.append('&');
         }

         norm.append(kv[0]).append('=').append(kv[1]);
         first = false;
      }

      return httpMethod.toUpperCase(Locale.ROOT) + "&" + SignerUtils.pctEncode(baseUrl) + "&" + SignerUtils.pctEncode(norm.toString());
   }

   private static boolean isDefaultPort(URI uri) {
      if (uri == null) {
         return true;
      } else {
         String s = uri.getScheme();
         int p = uri.getPort();
         return p < 0 ? true : "http".equals(s) && p == 80 || "https".equals(s) && p == 443;
      }
   }

   private String randomNonce() {
      byte[] b = new byte[16];
      this.rng.nextBytes(b);
      return SignerUtils.hex(b);
   }

   private static String nz(String s) {
      return s == null ? "" : s;
   }

   public static enum Placement {
      HEADER,
      QUERY;
   }

   public static enum SignatureMethod {
      HMAC_SHA1,
      HMAC_SHA256,
      PLAINTEXT;
   }
}
