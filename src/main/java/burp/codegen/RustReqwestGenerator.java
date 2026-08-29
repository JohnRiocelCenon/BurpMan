package burp.codegen;

import java.util.Map.Entry;

public final class RustReqwestGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "Rust — reqwest";
   }

   @Override
   public String fileExtension() {
      return "rs";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("use reqwest::blocking::Client;\n");
      sb.append("use reqwest::header::{HeaderMap, HeaderValue, HeaderName};\n\n");
      sb.append("fn main() -> Result<(), Box<dyn std::error::Error>> {\n");
      sb.append("    let client = Client::new();\n");
      sb.append("    let mut headers = HeaderMap::new();\n");

      for (Entry<String, String> e : req.headers.entrySet()) {
         sb.append("    headers.insert(HeaderName::from_static(")
            .append(rustStr(e.getKey().toLowerCase()))
            .append("), HeaderValue::from_static(")
            .append(rustStr(e.getValue()))
            .append("));\n");
      }

      sb.append("\n    let response = client\n");
      sb.append("        .request(reqwest::Method::from_bytes(").append(rustStr(req.method)).append(".as_bytes())?, ").append(rustStr(req.url)).append(")\n");
      sb.append("        .headers(headers)\n");
      if (req.body != null && !req.body.isEmpty()) {
         sb.append("        .body(").append(rustStr(req.body)).append(".to_string())\n");
      }

      sb.append("        .send()?;\n\n");
      sb.append("    println!(\"{}\", response.status());\n");
      sb.append("    println!(\"{}\", response.text()?);\n");
      sb.append("    Ok(())\n");
      sb.append("}\n");
      return sb.toString();
   }

   private static String rustStr(String s) {
      return s == null ? "\"\"" : "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
   }
}
