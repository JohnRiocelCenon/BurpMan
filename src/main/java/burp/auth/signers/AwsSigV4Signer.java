package burp.auth.signers;

import java.net.URI;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.Map.Entry;

public final class AwsSigV4Signer implements Signer {
   private final String accessKey;
   private final String secretKey;
   private final String sessionToken;
   private final String service;
   private final String region;
   private final boolean includeContentSha256Header;

   public AwsSigV4Signer(String accessKey, String secretKey, String sessionToken, String service, String region, boolean includeContentSha256Header) {
      this.accessKey = nz(accessKey);
      this.secretKey = nz(secretKey);
      this.sessionToken = sessionToken;
      this.service = nz(service);
      this.region = nz(region);
      this.includeContentSha256Header = includeContentSha256Header || "s3".equalsIgnoreCase(this.service);
   }

   @Override
   public void sign(String method, String url, List<String> headers, byte[] body) {
      SignerUtils.removeAuthorization(headers);
      removeHeader(headers, "x-amz-date");
      removeHeader(headers, "x-amz-security-token");
      if (this.includeContentSha256Header) {
         removeHeader(headers, "x-amz-content-sha256");
      }

      URI uri = SignerUtils.uri(url);
      if (uri != null) {
         SimpleDateFormat amzFmt = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.US);
         SimpleDateFormat dateFmt = new SimpleDateFormat("yyyyMMdd", Locale.US);
         amzFmt.setTimeZone(TimeZone.getTimeZone("UTC"));
         dateFmt.setTimeZone(TimeZone.getTimeZone("UTC"));
         Date now = new Date();
         String amzDate = amzFmt.format(now);
         String dateStamp = dateFmt.format(now);
         headers.add("X-Amz-Date: " + amzDate);
         if (this.sessionToken != null && !this.sessionToken.isEmpty()) {
            headers.add("X-Amz-Security-Token: " + this.sessionToken);
         }

         if (!hasHeader(headers, "host")) {
            String hostHdr = SignerUtils.host(uri);
            if (uri.getPort() > 0 && !isDefaultPort(uri)) {
               hostHdr = hostHdr + ":" + uri.getPort();
            }

            headers.add("Host: " + hostHdr);
         }

         String payloadHash = SignerUtils.hex(SignerUtils.sha256(body == null ? new byte[0] : body));
         if (this.includeContentSha256Header) {
            headers.add("X-Amz-Content-Sha256: " + payloadHash);
         }

         String canonicalUri = canonicalUri(uri);
         String canonicalQuery = canonicalQueryString(uri);
         TreeMap<String, String> signedHeaderMap = new TreeMap<>();

         for (String line : headers) {
            int colon = line.indexOf(58);
            if (colon >= 0) {
               String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
               String value = line.substring(colon + 1).trim().replaceAll("\\s+", " ");
               signedHeaderMap.put(name, value);
            }
         }

         StringBuilder canonicalHeaders = new StringBuilder();
         StringBuilder signedHeaderList = new StringBuilder();
         boolean first = true;

         for (Entry<String, String> e : signedHeaderMap.entrySet()) {
            canonicalHeaders.append(e.getKey()).append(':').append(e.getValue()).append('\n');
            if (!first) {
               signedHeaderList.append(';');
            }

            signedHeaderList.append(e.getKey());
            first = false;
         }

         String canonicalRequest = String.join(
            "\n", method.toUpperCase(Locale.ROOT), canonicalUri, canonicalQuery, canonicalHeaders.toString(), signedHeaderList.toString(), payloadHash
         );
         String credentialScope = dateStamp + "/" + this.region + "/" + this.service + "/aws4_request";
         String stringToSign = "AWS4-HMAC-SHA256\n"
            + amzDate
            + "\n"
            + credentialScope
            + "\n"
            + SignerUtils.hex(SignerUtils.sha256(SignerUtils.utf8(canonicalRequest)));
         byte[] kSecret = SignerUtils.utf8("AWS4" + this.secretKey);
         byte[] kDate = SignerUtils.hmacSha256(kSecret, SignerUtils.utf8(dateStamp));
         byte[] kRegion = SignerUtils.hmacSha256(kDate, SignerUtils.utf8(this.region));
         byte[] kService = SignerUtils.hmacSha256(kRegion, SignerUtils.utf8(this.service));
         byte[] kSigning = SignerUtils.hmacSha256(kService, SignerUtils.utf8("aws4_request"));
         String signature = SignerUtils.hex(SignerUtils.hmacSha256(kSigning, SignerUtils.utf8(stringToSign)));
         String authHeader = "AWS4-HMAC-SHA256 Credential="
            + this.accessKey
            + "/"
            + credentialScope
            + ", SignedHeaders="
            + signedHeaderList
            + ", Signature="
            + signature;
         headers.add("Authorization: " + authHeader);
      }
   }

   private static String canonicalUri(URI uri) {
      return SignerUtils.path(uri);
   }

   private static String canonicalQueryString(URI uri) {
      String q = SignerUtils.query(uri);
      if (q.isEmpty()) {
         return "";
      } else {
         List<String[]> kv = SignerUtils.parseQuery(q);
         List<String> rebuilt = new ArrayList<>();

         for (String[] pair : kv) {
            String k = SignerUtils.pctEncode(urlDecode(pair[0]));
            String v = SignerUtils.pctEncode(urlDecode(pair[1]));
            rebuilt.add(k + "=" + v);
         }

         Collections.sort(rebuilt);
         return String.join("&", rebuilt);
      }
   }

   private static String urlDecode(String s) {
      try {
         return URLDecoder.decode(s.replace("+", "%2B"), "UTF-8");
      } catch (Exception var2) {
         return s;
      }
   }

   private static boolean hasHeader(List<String> headers, String name) {
      String prefix = name.toLowerCase(Locale.ROOT) + ":";

      for (String h : headers) {
         if (h != null && h.toLowerCase(Locale.ROOT).startsWith(prefix)) {
            return true;
         }
      }

      return false;
   }

   private static void removeHeader(List<String> headers, String name) {
      String prefix = name.toLowerCase(Locale.ROOT) + ":";
      headers.removeIf(h -> h != null && h.toLowerCase(Locale.ROOT).startsWith(prefix));
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

   private static String nz(String s) {
      return s == null ? "" : s;
   }
}
