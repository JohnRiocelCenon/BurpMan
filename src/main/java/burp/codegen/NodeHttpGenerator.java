package burp.codegen;

import java.util.Map.Entry;

public final class NodeHttpGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "Node.js — http/https";
   }

   @Override
   public String fileExtension() {
      return "js";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      boolean https = req.url.startsWith("https:");
      sb.append("const ").append(https ? "https" : "http").append(" = require('").append(https ? "https" : "http").append("');\n");
      sb.append("const { URL } = require('url');\n\n");
      sb.append("const u = new URL(").append(GenRequest.jsonQuote(req.url)).append(");\n\n");
      sb.append("const options = {\n");
      sb.append("  method: ").append(GenRequest.jsonQuote(req.method)).append(",\n");
      sb.append("  hostname: u.hostname,\n");
      sb.append("  port: u.port || ").append(https ? "443" : "80").append(",\n");
      sb.append("  path: u.pathname + u.search,\n");
      sb.append("  headers: {\n");

      for (Entry<String, String> e : req.headers.entrySet()) {
         sb.append("    ").append(GenRequest.jsonQuote(e.getKey())).append(": ").append(GenRequest.jsonQuote(e.getValue())).append(",\n");
      }

      sb.append("  },\n");
      sb.append("};\n\n");
      sb.append("const req = ").append(https ? "https" : "http").append(".request(options, res => {\n");
      sb.append("  let body = '';\n");
      sb.append("  res.on('data', chunk => body += chunk);\n");
      sb.append("  res.on('end', () => console.log(res.statusCode, body));\n");
      sb.append("});\n");
      sb.append("req.on('error', console.error);\n");
      if (req.body != null && !req.body.isEmpty()) {
         sb.append("req.write(").append(GenRequest.jsonQuote(req.body)).append(");\n");
      }

      sb.append("req.end();\n");
      return sb.toString();
   }
}
