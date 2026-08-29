package burp.codegen;

import java.util.Map.Entry;

public final class PythonRequestsGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "Python — requests";
   }

   @Override
   public String fileExtension() {
      return "py";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("import requests\n\n");
      sb.append("url = ").append(repr(req.url)).append('\n');
      if (!req.headers.isEmpty()) {
         sb.append("headers = {\n");

         for (Entry<String, String> e : req.headers.entrySet()) {
            sb.append("    ").append(repr(e.getKey())).append(": ").append(repr(e.getValue())).append(",\n");
         }

         sb.append("}\n");
      } else {
         sb.append("headers = {}\n");
      }

      String dataArg = null;
      if ("urlencoded".equals(req.bodyMode) || "formdata".equals(req.bodyMode)) {
         sb.append("data = {\n");

         for (String[] kv : req.formFields) {
            sb.append("    ").append(repr(kv[0])).append(": ").append(repr(kv[1])).append(",\n");
         }

         sb.append("}\n");
         dataArg = "formdata".equals(req.bodyMode) ? "files=data" : "data=data";
      } else if (req.body != null && !req.body.isEmpty()) {
         sb.append("data = ").append(repr(req.body)).append('\n');
         dataArg = "data=data";
      }

      sb.append("\n");
      sb.append("response = requests.request(\n");
      sb.append("    method=").append(repr(req.method)).append(",\n");
      sb.append("    url=url,\n");
      sb.append("    headers=headers,\n");
      if (dataArg != null) {
         sb.append("    ").append(dataArg).append(",\n");
      }

      sb.append(")\n");
      sb.append("print(response.status_code)\n");
      sb.append("print(response.text)\n");
      return sb.toString();
   }

   static String repr(String s) {
      if (s == null) {
         return "None";
      } else {
         StringBuilder sb = new StringBuilder("\"");

         for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
               case '\t':
                  sb.append("\\t");
                  break;
               case '\n':
                  sb.append("\\n");
                  break;
               case '\r':
                  sb.append("\\r");
                  break;
               case '"':
                  sb.append("\\\"");
                  break;
               case '\\':
                  sb.append("\\\\");
                  break;
               default:
                  if (c < ' ') {
                     sb.append(String.format("\\x%02x", Integer.valueOf(c)));
                  } else {
                     sb.append(c);
                  }
            }
         }

         sb.append("\"");
         return sb.toString();
      }
   }
}
