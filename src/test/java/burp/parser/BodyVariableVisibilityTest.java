package burp.parser;

import burp.models.PostmanCollection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Form fields must keep their {{var}} templates all the way to the editor. Resolving them on
 * load hides which variable feeds a field, and a variable that resolves to empty erases the
 * reference altogether — which is how an unset client secret became a blank cell.
 */
class BodyVariableVisibilityTest {

   private static final String COLLECTION =
      "{\n"
         + "  \"name\": \"Body Vars\",\n"
         + "  \"version\": \"1\",\n"
         + "  \"items\": [\n"
         + "    {\n"
         + "      \"type\": \"http\",\n"
         + "      \"name\": \"Token\",\n"
         + "      \"request\": {\n"
         + "        \"url\": \"{{token_url}}\",\n"
         + "        \"method\": \"POST\",\n"
         + "        \"body\": {\n"
         + "          \"mode\": \"multipartForm\",\n"
         + "          \"multipartForm\": [\n"
         + "            {\"name\": \"grant_type\", \"value\": \"client_credentials\", \"enabled\": true},\n"
         + "            {\"name\": \"client_id\", \"value\": \"{{api_client_id}}\", \"enabled\": true},\n"
         + "            {\"name\": \"client_secret\", \"value\": \"{{api_client_secret}}\", \"enabled\": true}\n"
         + "          ]\n"
         + "        }\n"
         + "      }\n"
         + "    }\n"
         + "  ],\n"
         + "  \"environments\": [\n"
         + "    {\n"
         + "      \"name\": \"UAT\",\n"
         + "      \"variables\": [\n"
         + "        {\"name\": \"api_client_id\", \"value\": \"33333333\", \"enabled\": true},\n"
         + "        {\"name\": \"api_client_secret\", \"value\": \"\", \"secret\": true, \"enabled\": true}\n"
         + "      ]\n"
         + "    }\n"
         + "  ]\n"
         + "}\n";

   private static PostmanCollection parse() throws Exception {
      Path file = Files.createTempFile("body-vars-", ".json");
      Files.write(file, COLLECTION.getBytes(StandardCharsets.UTF_8));
      try {
         return new BrunoParser().parseCollection(new File(file.toString()));
      } finally {
         try {
            Files.deleteIfExists(file);
         } catch (Exception ignore) {
         }
      }
   }

   private static PostmanCollection.FormData field(PostmanCollection collection, String key) {
      for (PostmanCollection.Item item : collection.item) {
         if (item.request == null || item.request.body == null) continue;
         if (item.request.body.formdata == null) continue;
         for (PostmanCollection.FormData fd : item.request.body.formdata) {
            if (key.equals(fd.key)) return fd;
         }
      }
      return null;
   }

   @Test
   @DisplayName("a populated variable stays a template rather than being substituted on load")
   void keepsPopulatedTemplate() throws Exception {
      PostmanCollection collection = parse();
      PostmanCollection.FormData clientId = field(collection, "client_id");
      assertNotNull(clientId, "client_id row should survive parsing");
      assertEquals("{{api_client_id}}", clientId.value);
   }

   @Test
   @DisplayName("an empty variable still shows its name instead of a blank cell")
   void keepsEmptyVariableVisible() throws Exception {
      PostmanCollection collection = parse();
      PostmanCollection.FormData secret = field(collection, "client_secret");
      assertNotNull(secret, "client_secret row should survive parsing");
      // Resolving here would leave "", and the tester could not tell which variable to fill.
      assertEquals("{{api_client_secret}}", secret.value);
   }

   @Test
   @DisplayName("literal values are untouched")
   void keepsLiteralValues() throws Exception {
      PostmanCollection collection = parse();
      PostmanCollection.FormData grant = field(collection, "grant_type");
      assertNotNull(grant);
      assertEquals("client_credentials", grant.value);
   }
}
