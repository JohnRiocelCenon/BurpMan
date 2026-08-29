package burp.auth.signers;

import java.util.List;
import java.util.Locale;

public final class ApiKeySigner implements Signer {
   private final String keyName;
   private final String keyValue;
   private final ApiKeySigner.Placement placement;

   public ApiKeySigner(String keyName, String keyValue, ApiKeySigner.Placement placement) {
      this.keyName = keyName == null ? "" : keyName;
      this.keyValue = keyValue == null ? "" : keyValue;
      this.placement = placement == null ? ApiKeySigner.Placement.HEADER : placement;
   }

   @Override
   public void sign(String method, String url, List<String> headers, byte[] body) {
      if (this.placement != ApiKeySigner.Placement.QUERY && !this.keyName.isEmpty()) {
         String prefix = this.keyName.toLowerCase(Locale.ROOT) + ":";
         headers.removeIf(h -> h != null && h.toLowerCase(Locale.ROOT).startsWith(prefix));
         headers.add(this.keyName + ": " + this.keyValue);
      }
   }

   public static enum Placement {
      HEADER,
      QUERY;
   }
}
