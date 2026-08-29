package burp.codegen;

import java.util.Map.Entry;

public final class GoNetHttpGenerator implements CodeGenerator {
   @Override
   public String label() {
      return "Go — net/http";
   }

   @Override
   public String fileExtension() {
      return "go";
   }

   @Override
   public String generate(GenRequest req) {
      StringBuilder sb = new StringBuilder();
      sb.append("package main\n\n");
      sb.append("import (\n");
      sb.append("    \"fmt\"\n");
      sb.append("    \"io\"\n");
      sb.append("    \"net/http\"\n");
      if (req.body != null && !req.body.isEmpty()) {
         sb.append("    \"strings\"\n");
      }

      sb.append(")\n\n");
      sb.append("func main() {\n");
      if (req.body != null && !req.body.isEmpty()) {
         sb.append("    payload := strings.NewReader(`").append(req.body.replace("`", "` + \"`\" + `")).append("`)\n");
         sb.append("    req, _ := http.NewRequest(")
            .append(GenRequest.jsonQuote(req.method))
            .append(", ")
            .append(GenRequest.jsonQuote(req.url))
            .append(", payload)\n");
      } else {
         sb.append("    req, _ := http.NewRequest(")
            .append(GenRequest.jsonQuote(req.method))
            .append(", ")
            .append(GenRequest.jsonQuote(req.url))
            .append(", nil)\n");
      }

      for (Entry<String, String> e : req.headers.entrySet()) {
         sb.append("    req.Header.Add(").append(GenRequest.jsonQuote(e.getKey())).append(", ").append(GenRequest.jsonQuote(e.getValue())).append(")\n");
      }

      sb.append("\n    res, err := http.DefaultClient.Do(req)\n");
      sb.append("    if err != nil { panic(err) }\n");
      sb.append("    defer res.Body.Close()\n");
      sb.append("    body, _ := io.ReadAll(res.Body)\n");
      sb.append("    fmt.Println(res.StatusCode)\n");
      sb.append("    fmt.Println(string(body))\n");
      sb.append("}\n");
      return sb.toString();
   }
}
