package burp.codegen;

import java.util.Map.Entry;

public final class JavaScriptFetchGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "JavaScript — fetch";
   }

   @Override
   public String fileExtension() {
      return "js";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("const url = ").append(GenRequest.jsonQuote(req.url)).append(";\n");
      sb.append("const options = {\n");
      sb.append("  method: ").append(GenRequest.jsonQuote(req.method)).append(",\n");
      if (!req.headers.isEmpty()) {
         sb.append("  headers: {\n");

         for (Entry<String, String> e : req.headers.entrySet()) {
            sb.append("    ").append(GenRequest.jsonQuote(e.getKey())).append(": ").append(GenRequest.jsonQuote(e.getValue())).append(",\n");
         }

         sb.append("  },\n");
      }

      if ("urlencoded".equals(req.bodyMode)) {
         sb.append("  body: new URLSearchParams({\n");

         for (String[] kv : req.formFields) {
            sb.append("    ").append(GenRequest.jsonQuote(kv[0])).append(": ").append(GenRequest.jsonQuote(kv[1])).append(",\n");
         }

         sb.append("  }),\n");
      } else if ("formdata".equals(req.bodyMode)) {
         sb.append("  body: (() => { const fd = new FormData();\n");

         for (String[] kv : req.formFields) {
            sb.append("    fd.append(").append(GenRequest.jsonQuote(kv[0])).append(", ").append(GenRequest.jsonQuote(kv[1])).append(");\n");
         }

         sb.append("    return fd; })(),\n");
      } else if (req.body != null && !req.body.isEmpty()) {
         sb.append("  body: ").append(GenRequest.jsonQuote(req.body)).append(",\n");
      }

      sb.append("};\n\n");
      sb.append("const response = await fetch(url, options);\n");
      sb.append("const data = await response.text();\n");
      sb.append("console.log(response.status, data);\n");
      return sb.toString();
   }
}
