package burp.codegen;

import java.util.Map.Entry;

public final class PowerShellGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "PowerShell — Invoke-RestMethod";
   }

   @Override
   public String fileExtension() {
      return "ps1";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      if (!req.headers.isEmpty()) {
         sb.append("$headers = @{\n");

         for (Entry<String, String> e : req.headers.entrySet()) {
            sb.append("    ").append(psQuote(e.getKey())).append(" = ").append(psQuote(e.getValue())).append("\n");
         }

         sb.append("}\n\n");
      }

      if (req.body != null && !req.body.isEmpty()) {
         sb.append("$body = @'\n").append(req.body).append("\n'@\n\n");
      }

      sb.append("$response = Invoke-RestMethod ");
      sb.append("-Uri ").append(psQuote(req.url));
      sb.append(" -Method ").append(req.method);
      if (!req.headers.isEmpty()) {
         sb.append(" -Headers $headers");
      }

      if (req.body != null && !req.body.isEmpty()) {
         sb.append(" -Body $body");
      }

      sb.append("\n$response | ConvertTo-Json -Depth 10\n");
      return sb.toString();
   }

   private static String psQuote(String s) {
      return s == null ? "''" : "'" + s.replace("'", "''") + "'";
   }
}
