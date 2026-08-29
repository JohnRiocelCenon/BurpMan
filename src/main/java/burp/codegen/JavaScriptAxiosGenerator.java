package burp.codegen;

import java.util.Map.Entry;

public final class JavaScriptAxiosGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "JavaScript — axios";
   }

   @Override
   public String fileExtension() {
      return "js";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("const axios = require('axios');\n\n");
      sb.append("const config = {\n");
      sb.append("  method: ").append(GenRequest.jsonQuote(req.method.toLowerCase())).append(",\n");
      sb.append("  url: ").append(GenRequest.jsonQuote(req.url)).append(",\n");
      if (!req.headers.isEmpty()) {
         sb.append("  headers: {\n");

         for (Entry<String, String> e : req.headers.entrySet()) {
            sb.append("    ").append(GenRequest.jsonQuote(e.getKey())).append(": ").append(GenRequest.jsonQuote(e.getValue())).append(",\n");
         }

         sb.append("  },\n");
      }

      if ("urlencoded".equals(req.bodyMode)) {
         sb.append("  data: new URLSearchParams({\n");

         for (String[] kv : req.formFields) {
            sb.append("    ").append(GenRequest.jsonQuote(kv[0])).append(": ").append(GenRequest.jsonQuote(kv[1])).append(",\n");
         }

         sb.append("  }).toString(),\n");
      } else if ("formdata".equals(req.bodyMode)) {
         sb.append("  // formdata: use form-data package and FormData object\n");
         sb.append("  data: (() => { const FormData = require('form-data'); const fd = new FormData();\n");

         for (String[] kv : req.formFields) {
            sb.append("    fd.append(").append(GenRequest.jsonQuote(kv[0])).append(", ").append(GenRequest.jsonQuote(kv[1])).append(");\n");
         }

         sb.append("    return fd; })(),\n");
      } else if (req.body != null && !req.body.isEmpty()) {
         sb.append("  data: ").append(GenRequest.jsonQuote(req.body)).append(",\n");
      }

      sb.append("};\n\n");
      sb.append("axios.request(config)\n");
      sb.append("  .then(res => { console.log(res.status, res.data); })\n");
      sb.append("  .catch(err => { console.error(err); });\n");
      return sb.toString();
   }
}
