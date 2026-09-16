package burp.parser;

import burp.models.PostmanEnvironment;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bruno withholds a secret's value when exporting, writing the entry with a name but no
 * {@code value}. Skipping those left the variable absent from Edit Variables, so the tester had
 * nothing telling them the collection expects it to be supplied.
 */
class DeclaredEmptyVariableTest {

   private static final String ENVIRONMENT =
      "name: Sample Service Environment - UAT\n"
         + "variables:\n"
         + "  - name: api_client_id\n"
         + "    value: 33333333-3333-4333-8333-333333333333\n"
         + "  - secret: true\n"
         + "    name: api_client_secret\n"
         + "  - name: callback_URL\n"
         + "    value: https://uat.example.ca/app\n"
         + "  - name: disabled_one\n"
         + "    value: nope\n"
         + "    enabled: false\n";

   private static PostmanEnvironment parse() throws Exception {
      Path file = Files.createTempFile("env-", ".yml");
      Files.write(file, ENVIRONMENT.getBytes(StandardCharsets.UTF_8));
      try {
         return BrunoYamlParser.parseEnvironment(new File(file.toString()));
      } finally {
         try {
            Files.deleteIfExists(file);
         } catch (Exception ignore) {
         }
      }
   }

   @Test
   @DisplayName("a secret with its value withheld is still parsed")
   void parsesValuelessSecret() throws Exception {
      PostmanEnvironment env = parse();
      boolean found = false;
      for (PostmanEnvironment.Value v : env.values) {
         if ("api_client_secret".equals(v.key)) {
            found = true;
            assertEquals("secret", v.type);
         }
      }
      assertTrue(found, "the secret entry should survive parsing");
   }

   @Test
   @DisplayName("a declared variable with no value reaches the resolver so it is visible")
   void declaredEmptyVariableIsVisible() throws Exception {
      VariableResolver resolver = new VariableResolver();
      resolver.addEnvironmentVariables(parse());

      Map<String, String> vars = resolver.getVariables();
      // This is what Edit Variables lists; without the key the tester cannot fill it in.
      assertTrue(vars.containsKey("api_client_secret"),
         "a declared secret must be listed even with no value: " + vars.keySet());
      assertEquals("", vars.get("api_client_secret"));
   }

   @Test
   @DisplayName("variables that do have values are unaffected")
   void keepsPopulatedVariables() throws Exception {
      VariableResolver resolver = new VariableResolver();
      resolver.addEnvironmentVariables(parse());

      Map<String, String> vars = resolver.getVariables();
      assertEquals("33333333-3333-4333-8333-333333333333", vars.get("api_client_id"));
      assertEquals("https://uat.example.ca/app", vars.get("callback_URL"));
   }

   @Test
   @DisplayName("a disabled variable is still excluded")
   void stillSkipsDisabled() throws Exception {
      VariableResolver resolver = new VariableResolver();
      resolver.addEnvironmentVariables(parse());

      // Being switched off is a deliberate choice, unlike a value that was withheld.
      assertFalse(resolver.getVariables().containsKey("disabled_one"),
         "a disabled variable should not be added");
   }

   @Test
   @DisplayName("an empty declared variable substitutes as empty rather than leaking its template")
   void emptyVariableResolvesToEmpty() throws Exception {
      VariableResolver resolver = new VariableResolver();
      resolver.addEnvironmentVariables(parse());

      // Sending the literal text "{{api_client_secret}}" to a token endpoint helps nobody;
      // an empty value produces a clear invalid_client response instead.
      assertEquals("client_secret=", resolver.resolve("client_secret={{api_client_secret}}"));
   }

   @Test
   @DisplayName("a variable that was never declared keeps its template")
   void undeclaredVariableKeepsTemplate() throws Exception {
      VariableResolver resolver = new VariableResolver();
      resolver.addEnvironmentVariables(parse());

      // Nothing claims this name, so leaving it visible is the honest outcome.
      assertEquals("{{never_declared}}", resolver.resolve("{{never_declared}}"));
   }
}
