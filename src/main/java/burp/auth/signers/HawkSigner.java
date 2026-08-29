package burp.auth.signers;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

public final class HawkSigner implements Signer {
   private final String hawkId;
   private final String hawkKey;
   private final String algorithm;
   private final String ext;
   private final String app;
   private final String dlg;
   private final boolean includePayloadHash;
   private final SecureRandom rng = new SecureRandom();

   public HawkSigner(String hawkId, String hawkKey, String algorithm, String ext, String app, String dlg, boolean includePayloadHash) {
      this.hawkId = nz(hawkId);
      this.hawkKey = nz(hawkKey);
      this.algorithm = algorithm != null && !algorithm.isEmpty() ? algorithm.toLowerCase(Locale.ROOT) : "sha256";
      this.ext = ext;
      this.app = app;
      this.dlg = dlg;
      this.includePayloadHash = includePayloadHash;
   }

   @Override
   public void sign(String method, String url, List<String> headers, byte[] body) {
      SignerUtils.removeAuthorization(headers);
      URI uri = SignerUtils.uri(url);
      if (uri != null) {
         long ts = System.currentTimeMillis() / 1000L;
         String nonce = this.randomNonce();
         String host = SignerUtils.host(uri);
         int port = uri.getPort();
         if (port < 0) {
            port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
         }

         String resource = SignerUtils.path(uri);
         String q = SignerUtils.query(uri);
         if (!q.isEmpty()) {
            resource = resource + "?" + q;
         }

         String hashB64 = null;
         if (this.includePayloadHash && body != null) {
            StringBuilder pb = new StringBuilder();
            pb.append("hawk.1.payload\n");
            String ct = this.contentType(headers);
            pb.append(ct == null ? "" : ct).append('\n');
            pb.append(new String(body, StandardCharsets.UTF_8));
            pb.append('\n');
            byte[] hash = "sha1".equals(this.algorithm)
               ? SignerUtils.sha1(SignerUtils.utf8(pb.toString()))
               : SignerUtils.sha256(SignerUtils.utf8(pb.toString()));
            hashB64 = Base64.getEncoder().encodeToString(hash);
         }

         StringBuilder base = new StringBuilder();
         base.append("hawk.1.header\n")
            .append(ts)
            .append('\n')
            .append(nonce)
            .append('\n')
            .append(method.toUpperCase(Locale.ROOT))
            .append('\n')
            .append(resource)
            .append('\n')
            .append(host)
            .append('\n')
            .append(port)
            .append('\n')
            .append(hashB64 == null ? "" : hashB64)
            .append('\n')
            .append(this.ext == null ? "" : this.ext)
            .append('\n');
         if (this.app != null && !this.app.isEmpty()) {
            base.append(this.app).append('\n');
            base.append(this.dlg == null ? "" : this.dlg).append('\n');
         }

         byte[] mac = "sha1".equals(this.algorithm)
            ? SignerUtils.hmacSha1(SignerUtils.utf8(this.hawkKey), SignerUtils.utf8(base.toString()))
            : SignerUtils.hmacSha256(SignerUtils.utf8(this.hawkKey), SignerUtils.utf8(base.toString()));
         String macB64 = Base64.getEncoder().encodeToString(mac);
         StringBuilder hdr = new StringBuilder("Authorization: Hawk ");
         hdr.append("id=\"").append(this.hawkId).append('"');
         hdr.append(", ts=\"").append(ts).append('"');
         hdr.append(", nonce=\"").append(nonce).append('"');
         if (hashB64 != null) {
            hdr.append(", hash=\"").append(hashB64).append('"');
         }

         if (this.ext != null && !this.ext.isEmpty()) {
            hdr.append(", ext=\"").append(this.ext.replace("\"", "\\\"")).append('"');
         }

         if (this.app != null && !this.app.isEmpty()) {
            hdr.append(", app=\"").append(this.app).append('"');
         }

         if (this.dlg != null && !this.dlg.isEmpty()) {
            hdr.append(", dlg=\"").append(this.dlg).append('"');
         }

         hdr.append(", mac=\"").append(macB64).append('"');
         headers.add(hdr.toString());
      }
   }

   private String contentType(List<String> headers) {
      for (String h : headers) {
         if (h != null) {
            int c = h.indexOf(58);
            if (c >= 0) {
               String name = h.substring(0, c).trim();
               if ("content-type".equalsIgnoreCase(name)) {
                  String v = h.substring(c + 1).trim();
                  int sc = v.indexOf(59);
                  return sc < 0 ? v : v.substring(0, sc).trim();
               }
            }
         }
      }

      return null;
   }

   private String randomNonce() {
      byte[] b = new byte[6];
      this.rng.nextBytes(b);
      return SignerUtils.hex(b);
   }

   private static String nz(String s) {
      return s == null ? "" : s;
   }
}
