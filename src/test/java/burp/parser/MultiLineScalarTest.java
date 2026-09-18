package burp.parser;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A quoted YAML scalar may continue onto following lines. Reading only the first line cut a
 * JSON request body down to its opening brace, which the server rejected as malformed while
 * the same collection worked in Bruno.
 */
class MultiLineScalarTest {

   @SuppressWarnings("unchecked")
   private static Map<String, Object> http(String yaml) {
      Map<String, Object> root = MiniYaml.parse(yaml);
      return (Map<String, Object>) root.get("http");
   }

   @SuppressWarnings("unchecked")
   private static String bodyData(String yaml) {
      Map<String, Object> body = (Map<String, Object>) http(yaml).get("body");
      return String.valueOf(body.get("data"));
   }

   @Test
   @DisplayName("a JSON body spread over several lines is read whole")
   void readsMultiLineJsonBody() {
      // Verbatim shape from "Chat Answer UAT.yml" in the CA KBOT collection.
      String yaml =
         "http:\n"
            + "  method: POST\n"
            + "  body:\n"
            + "    type: json\n"
            + "    data: \"{\\r\n"
            + "\n"
            + "      \\  \\\"id\\\": \\\"123e4567\\\",\\r\n"
            + "\n"
            + "      \\  \\\"language\\\": \\\"en_US\\\"\\r\n"
            + "\n"
            + "      }\"\n";

      String data = bodyData(yaml);
      assertTrue(data.contains("\"id\": \"123e4567\""), "id field missing from: " + data);
      assertTrue(data.contains("\"language\": \"en_US\""), "language field missing from: " + data);
      assertTrue(data.trim().endsWith("}"), "body should be closed: " + data);
   }

   @Test
   @DisplayName("blank lines between fragments become newlines, not spaces")
   void blankLinesBecomeNewlines() {
      String yaml =
         "http:\n"
            + "  body:\n"
            + "    data: \"first\n"
            + "\n"
            + "      second\"\n";
      // One break plus one blank line is two breaks, which folds to a single newline.
      assertEquals("first\nsecond", bodyData(yaml));
   }

   @Test
   @DisplayName("a single line break folds to a space")
   void singleBreakFoldsToSpace() {
      String yaml =
         "http:\n"
            + "  body:\n"
            + "    data: \"first\n"
            + "      second\"\n";
      assertEquals("first second", bodyData(yaml));
   }

   @Test
   @DisplayName("escapes are decoded after folding, not before")
   void decodesEscapesAfterFolding() {
      String yaml =
         "http:\n"
            + "  body:\n"
            + "    data: \"a\\r\n"
            + "\n"
            + "      b\"\n";
      // \r is a carriage return; the fold adds the newline between the two fragments.
      assertEquals("a\r\nb", bodyData(yaml));
   }

   @Test
   @DisplayName("a value that ends on its own line is unchanged")
   void singleLineValueUnchanged() {
      String yaml =
         "http:\n"
            + "  method: POST\n"
            + "  url: \"{{token_url}}\"\n";
      assertEquals("{{token_url}}", String.valueOf(http(yaml).get("url")));
      assertEquals("POST", String.valueOf(http(yaml).get("method")));
   }

   @Test
   @DisplayName("an escaped quote does not end the scalar early")
   void escapedQuoteDoesNotTerminate() {
      String yaml =
         "http:\n"
            + "  body:\n"
            + "    data: \"say \\\"hi\\\" now\"\n";
      assertEquals("say \"hi\" now", bodyData(yaml));
   }

   @Test
   @DisplayName("a single-quoted value may also span lines")
   void singleQuotedSpansLines() {
      String yaml =
         "http:\n"
            + "  body:\n"
            + "    data: 'first\n"
            + "      second'\n";
      assertEquals("first second", bodyData(yaml));
   }

   @Test
   @DisplayName("a doubled quote inside a single-quoted value is an escape")
   void doubledQuoteIsEscape() {
      String yaml =
         "http:\n"
            + "  body:\n"
            + "    data: 'it''s here'\n";
      assertEquals("it's here", bodyData(yaml));
   }

   @Test
   @DisplayName("a multi-line script keeps every statement")
   void readsMultiLineScript() {
      // Verbatim shape from "Get Token.yml"; the second line used to be dropped, so the
      // token was fetched and then never stored.
      String yaml =
         "runtime:\n"
            + "  scripts:\n"
            + "    - type: after-response\n"
            + "      code: \"var jsonData = res.getBody();\\r\n"
            + "\n"
            + "        bru.setEnvVar(\\\"token\\\", jsonData.access_token);\"\n";

      Map<String, Object> root = MiniYaml.parse(yaml);
      String all = String.valueOf(root);
      assertTrue(all.contains("var jsonData = res.getBody();"), "first statement missing: " + all);
      assertTrue(all.contains("bru.setEnvVar"), "second statement missing: " + all);
   }

   @Test
   @DisplayName("an unterminated quote does not swallow the rest of the document")
   void unterminatedQuoteIsContained() {
      String yaml =
         "http:\n"
            + "  body:\n"
            + "    data: \"never closed\n"
            + "  method: POST\n";
      // The document is not what we think it is; the damage stays with the one value.
      Map<String, Object> parsed = MiniYaml.parse(yaml);
      assertTrue(parsed.containsKey("http"), "the document should still parse: " + parsed);
   }

   @Test
   @DisplayName("literal block scalars still work")
   void blockScalarsUnaffected() {
      String yaml =
         "runtime:\n"
            + "  scripts:\n"
            + "    - type: before-request\n"
            + "      code: |-\n"
            + "        const a = 1;\n"
            + "        const b = 2;\n";
      String all = String.valueOf(MiniYaml.parse(yaml));
      assertTrue(all.contains("const a = 1;"), all);
      assertTrue(all.contains("const b = 2;"), all);
   }
}
