package burp.codegen;

import java.util.Map.Entry;

public final class CurlGenerator implements CodeGenerator {
   private final boolean bash;

   public CurlGenerator(boolean bash) {
      this.bash = bash;
   }

   @Override
   public String label() {
      return this.bash ? "curl (bash)" : "curl (cmd.exe)";
   }

   @Override
   public String fileExtension() {
      return this.bash ? "sh" : "cmd";
   }

   @Override
   public String generate(GenRequest req) {
      String cont = this.bash ? " \\\n  " : " ^\n  ";
      StringBuilder sb = new StringBuilder();
      sb.append("curl");
      sb.append(cont).append("--request ").append(req.method);
      sb.append(cont).append("--url ").append(this.quote(req.url));

      for (Entry<String, String> e : req.headers.entrySet()) {
         sb.append(cont).append("--header ").append(this.quote(e.getKey() + ": " + e.getValue()));
      }

      if (req.hasBody()) {
         if ("urlencoded".equals(req.bodyMode)) {
            for (String[] kv : req.formFields) {
               sb.append(cont).append("--data-urlencode ").append(this.quote(kv[0] + "=" + kv[1]));
            }
         } else if ("formdata".equals(req.bodyMode)) {
            for (String[] kv : req.formFields) {
               sb.append(cont).append("--form ").append(this.quote(kv[0] + "=" + kv[1]));
            }
         } else if (req.body != null && !req.body.isEmpty()) {
            sb.append(cont).append("--data ").append(this.quote(req.body));
         }
      }

      return sb.toString();
   }

   private String quote(String s) {
      if (this.bash) {
         return GenRequest.shellSingleQuote(s);
      } else {
         StringBuilder out = new StringBuilder("\"");

         for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') {
               out.append("\\\"");
            } else if (c == '%') {
               out.append("%%");
            } else if (c == '^') {
               out.append("^^");
            } else if (c == '\n') {
               out.append(" ");
            } else {
               out.append(c);
            }
         }

         out.append("\"");
         return out.toString();
      }
   }
}
