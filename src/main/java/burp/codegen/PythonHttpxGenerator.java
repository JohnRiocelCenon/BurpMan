package burp.codegen;

import java.util.Map.Entry;

public final class PythonHttpxGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "Python — httpx";
   }

   @Override
   public String fileExtension() {
      return "py";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("import httpx\n\n");
      if (!req.headers.isEmpty()) {
         sb.append("headers = {\n");

         for (Entry<String, String> e : req.headers.entrySet()) {
            sb.append("    ").append(PythonRequestsGenerator.repr(e.getKey())).append(": ").append(PythonRequestsGenerator.repr(e.getValue())).append(",\n");
         }

         sb.append("}\n\n");
      }

      sb.append("with httpx.Client() as client:\n");
      sb.append("    response = client.request(\n");
      sb.append("        method=").append(PythonRequestsGenerator.repr(req.method)).append(",\n");
      sb.append("        url=").append(PythonRequestsGenerator.repr(req.url)).append(",\n");
      if (!req.headers.isEmpty()) {
         sb.append("        headers=headers,\n");
      }

      if ("urlencoded".equals(req.bodyMode) || "formdata".equals(req.bodyMode)) {
         sb.append("        data={\n");

         for (String[] kv : req.formFields) {
            sb.append("            ").append(PythonRequestsGenerator.repr(kv[0])).append(": ").append(PythonRequestsGenerator.repr(kv[1])).append(",\n");
         }

         sb.append("        },\n");
      } else if (req.body != null && !req.body.isEmpty()) {
         sb.append("        content=").append(PythonRequestsGenerator.repr(req.body)).append(",\n");
      }

      sb.append("    )\n");
      sb.append("    print(response.status_code)\n");
      sb.append("    print(response.text)\n");
      return sb.toString();
   }
}
