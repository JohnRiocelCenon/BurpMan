package burp.parser;

import burp.models.PostmanCollection;
import burp.models.PostmanEnvironment;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exporting to Bruno is only worth anything if Bruno can read the result, so every case here
 * writes a collection out and parses it back with {@link BrunoYamlParser}.
 */
class BrunoCollectionExporterTest {

   private static File exportDir() throws Exception {
      File dir = Files.createTempDirectory("bruno-export-test-").toFile();
      dir.deleteOnExit();
      return dir;
   }

   private static PostmanCollection collectionOf(PostmanCollection.Item... items) {
      PostmanCollection c = new PostmanCollection();
      c.info = new PostmanCollection.Info();
      c.info.name = "Test Collection";
      c.item = new ArrayList<>();
      Collections.addAll(c.item, items);
      return c;
   }

   private static PostmanCollection.Item request(String name, String method, String url) {
      PostmanCollection.Item item = new PostmanCollection.Item();
      item.name = name;
      item.request = new PostmanCollection.Request();
      item.request.method = method;
      item.request.url = url;
      return item;
   }

   /** Writes the collection, then reads every request file back. */
   private static List<PostmanCollection.Item> roundTrip(PostmanCollection c) throws Exception {
      File dir = exportDir();
      new BrunoCollectionExporter().exportTo(c, dir);
      return readAll(dir);
   }

   private static List<PostmanCollection.Item> readAll(File dir) throws Exception {
      List<PostmanCollection.Item> out = new ArrayList<>();
      File[] files = dir.listFiles();
      if (files == null) return out;
      java.util.Arrays.sort(files);
      for (File f : files) {
         if (f.isDirectory()) {
            if (!"environments".equals(f.getName())) out.addAll(readAll(f));
            continue;
         }
         if (!f.getName().endsWith(".yml") || f.getName().equals("opencollection.yml")
            || f.getName().equals("folder.yml")) continue;
         PostmanCollection.Item it = BrunoYamlParser.parseRequestFile(f);
         if (it != null) out.add(it);
      }
      return out;
   }

   @Test
   @DisplayName("the collection root declares the OpenCollection version Bruno expects")
   void writesCollectionRoot() throws Exception {
      File dir = exportDir();
      new BrunoCollectionExporter().exportTo(collectionOf(request("A", "GET", "http://x/a")), dir);

      File root = new File(dir, "opencollection.yml");
      assertTrue(root.isFile(), "opencollection.yml should exist");
      String text = new String(Files.readAllBytes(root.toPath()), StandardCharsets.UTF_8);
      assertTrue(text.startsWith("opencollection: 1.0.0"), text);
      assertTrue(text.contains("name: Test Collection"), text);
   }

   @Test
   @DisplayName("a JSON body survives the round trip byte for byte")
   void preservesJsonBody() throws Exception {
      String json = "{\n  \"question\": \"Can I withdraw?\",\n  \"plan_number\": \"10000042\"\n}";
      PostmanCollection.Item item = request("Ask", "POST", "{{url}}");
      item.request.body = new PostmanCollection.Body();
      item.request.body.mode = "raw";
      item.request.body.raw = json;

      List<PostmanCollection.Item> back = roundTrip(collectionOf(item));
      assertEquals(1, back.size());
      assertEquals(json, back.get(0).request.body.raw);
   }

   @Test
   @DisplayName("a body containing carriage returns is not mangled")
   void preservesCarriageReturns() throws Exception {
      // A literal block cannot hold a CR, so this has to fall back to a quoted scalar.
      String body = "{\r\n  \"a\": 1\r\n}";
      PostmanCollection.Item item = request("CRLF", "POST", "http://x");
      item.request.body = new PostmanCollection.Body();
      item.request.body.mode = "raw";
      item.request.body.raw = body;

      List<PostmanCollection.Item> back = roundTrip(collectionOf(item));
      assertEquals(body, back.get(0).request.body.raw);
   }

   @Test
   @DisplayName("headers keep their order, values and disabled flag")
   void preservesHeaders() throws Exception {
      PostmanCollection.Item item = request("H", "GET", "http://x");
      item.request.header = new ArrayList<>();
      PostmanCollection.Header a = new PostmanCollection.Header();
      a.key = "Ocp-Apim-Subscription-Key";
      a.value = "00000000000000000000000000000000";
      PostmanCollection.Header b = new PostmanCollection.Header();
      b.key = "X-Off";
      b.value = "no";
      b.disabled = true;
      item.request.header.add(a);
      item.request.header.add(b);

      PostmanCollection.Request r = roundTrip(collectionOf(item)).get(0).request;
      assertEquals(2, r.header.size());
      assertEquals("Ocp-Apim-Subscription-Key", r.header.get(0).key);
      assertEquals("00000000000000000000000000000000", r.header.get(0).value);
      assertTrue(r.header.get(1).disabled, "the disabled flag should survive");
   }

   @Test
   @DisplayName("form fields keep their {{var}} templates")
   void preservesFormBody() throws Exception {
      PostmanCollection.Item item = request("Token", "POST", "{{token_url}}");
      item.request.body = new PostmanCollection.Body();
      item.request.body.mode = "urlencoded";
      item.request.body.urlencoded = new ArrayList<>();
      PostmanCollection.UrlEncoded u = new PostmanCollection.UrlEncoded();
      u.key = "client_secret";
      u.value = "{{api_client_secret}}";
      item.request.body.urlencoded.add(u);

      PostmanCollection.Body body = roundTrip(collectionOf(item)).get(0).request.body;
      assertEquals("urlencoded", body.mode);
      assertEquals("{{api_client_secret}}", body.urlencoded.get(0).value);
   }

   @Test
   @DisplayName("a multi-line script keeps every statement")
   void preservesScripts() throws Exception {
      String code = "const token = bru.getOauth2CredentialVar(\"$oauth2.credentials.access_token\");\n"
         + "bru.setEnvVar(\"entra_access_token\", token);";
      PostmanCollection.Item item = request("S", "GET", "http://x");
      item.event = new ArrayList<>();
      PostmanCollection.Event e = new PostmanCollection.Event();
      e.listen = "prerequest";
      e.script = new PostmanCollection.Script();
      e.script.exec = java.util.Arrays.asList(code.split("\n"));
      item.event.add(e);

      PostmanCollection.Item back = roundTrip(collectionOf(item)).get(0);
      assertNotNull(back.event, "the script should survive");
      String got = String.join("\n", back.event.get(0).script.exec);
      assertTrue(got.contains("getOauth2CredentialVar"), got);
      assertTrue(got.contains("setEnvVar"), got);
   }

   @Test
   @DisplayName("OAuth2 is written back in the nested shape OpenCollection uses")
   void writesNestedOAuth2() throws Exception {
      PostmanCollection.Item item = request("Auth", "GET", "localhost");
      PostmanCollection.Auth auth = new PostmanCollection.Auth();
      auth.type = "oauth2";
      java.util.Map<String, Object> o = new java.util.LinkedHashMap<>();
      o.put("grant_type", "authorization_code");
      o.put("authorizationUrl", "https://login.example/authorize");
      o.put("accessTokenUrl", "https://login.example/token");
      o.put("callbackUrl", "{{callback_URL}}");
      o.put("clientId", "{{app_client_id}}");
      o.put("client_authentication", "body");
      o.put("scope", "{{api_scope}}");
      o.put("pkce", "true");
      o.put("credentialsId", "credentials");
      auth.oauth2 = o;
      item.request.auth = auth;

      File dir = exportDir();
      new BrunoCollectionExporter().exportTo(collectionOf(item), dir);
      String text = new String(
         Files.readAllBytes(new File(dir, "Auth.yml").toPath()), StandardCharsets.UTF_8);

      // The nesting is the whole point; a flat clientId is what Bruno would not read.
      assertTrue(text.contains("credentials:"), text);
      assertTrue(text.contains("clientId: \"{{app_client_id}}\""), text);
      assertTrue(text.contains("pkce: {}"), text);

      PostmanCollection.Item back = readAll(dir).get(0);
      assertEquals("oauth2", back.request.auth.type);
      burp.auth.OAuth2Config config =
         new burp.auth.OAuth2Detector(new VariableResolver()).detect(collectionOf(back)).get(0);
      assertEquals("{{app_client_id}}", config.clientId);
      assertEquals("authorization_code", config.grantType);
      assertEquals("credentials", config.rawAttributes.get("credentialsId"));
   }

   @Test
   @DisplayName("bearer auth survives")
   void preservesBearerAuth() throws Exception {
      PostmanCollection.Item item = request("B", "GET", "http://x");
      PostmanCollection.Auth auth = new PostmanCollection.Auth();
      auth.type = "bearer";
      java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
      m.put("token", "{{UAT_TOKEN}}");
      auth.bearer = m;
      item.request.auth = auth;

      PostmanCollection.Item back = roundTrip(collectionOf(item)).get(0);
      assertEquals("bearer", back.request.auth.type);
   }

   @Test
   @DisplayName("folders become directories and their requests come back")
   void writesNestedFolders() throws Exception {
      PostmanCollection.Item folder = new PostmanCollection.Item();
      folder.name = "Tokens";
      folder.item = new ArrayList<>();
      folder.item.add(request("Get Token", "POST", "{{token_url}}"));

      File dir = exportDir();
      new BrunoCollectionExporter().exportTo(collectionOf(folder), dir);

      File sub = new File(dir, "Tokens");
      assertTrue(sub.isDirectory(), "the folder should become a directory");
      assertTrue(new File(sub, "Get Token.yml").isFile(), "the request should be inside it");

      List<PostmanCollection.Item> back = readAll(dir);
      assertEquals(1, back.size());
      assertEquals("Get Token", back.get(0).name);
   }

   @Test
   @DisplayName("a name with path characters cannot escape the export folder")
   void sanitisesFileNames() throws Exception {
      File dir = exportDir();
      new BrunoCollectionExporter().exportTo(
         collectionOf(request("../../evil: name?", "GET", "http://x")), dir);

      File[] files = dir.listFiles((d, n) -> n.endsWith(".yml") && !n.equals("opencollection.yml"));
      assertNotNull(files);
      assertEquals(1, files.length);
      String name = files[0].getName();
      assertFalse(name.contains(".."), "path traversal must not survive: " + name);
      assertFalse(name.contains("/") || name.contains("\\"), name);
      // The request itself keeps its real name inside the file.
      assertEquals("../../evil: name?", readAll(dir).get(0).name);
   }

   @Test
   @DisplayName("two requests sharing a name both survive")
   void handlesDuplicateNames() throws Exception {
      List<PostmanCollection.Item> back = roundTrip(collectionOf(
         request("Same", "GET", "http://x/1"),
         request("Same", "POST", "http://x/2")));
      assertEquals(2, back.size(), "neither request should overwrite the other");
   }

   @Test
   @DisplayName("environments are written where Bruno looks for them")
   void writesEnvironments() throws Exception {
      PostmanEnvironment env = new PostmanEnvironment();
      env.name = "UAT";
      env.values = new ArrayList<>();
      PostmanEnvironment.Value v = new PostmanEnvironment.Value();
      v.key = "token_url";
      v.value = "https://login.example/token";
      v.enabled = true;
      env.values.add(v);

      File dir = exportDir();
      BrunoCollectionExporter.Result r = new BrunoCollectionExporter().exportTo(
         collectionOf(request("A", "GET", "http://x")), dir, Collections.singletonList(env));

      assertEquals(1, r.environments);
      File envFile = new File(new File(dir, "environments"), "UAT.yml");
      assertTrue(envFile.isFile(), "environments/UAT.yml should exist");

      PostmanEnvironment back = BrunoYamlParser.parseEnvironment(envFile);
      assertEquals("UAT", back.name);
      assertEquals("https://login.example/token", back.values.get(0).value);
   }

   @Test
   @DisplayName("a value that looks like a number stays text")
   void keepsNumericLookingValuesAsText() throws Exception {
      PostmanCollection.Item item = request("N", "GET", "http://x");
      item.request.header = new ArrayList<>();
      PostmanCollection.Header h = new PostmanCollection.Header();
      h.key = "X-Plan";
      // Unquoted this would come back as a number and lose its leading zero.
      h.value = "0010000042";
      item.request.header.add(h);

      PostmanCollection.Item back = roundTrip(collectionOf(item)).get(0);
      assertEquals("0010000042", back.request.header.get(0).value);
   }

   @Test
   @DisplayName("a value that looks like a boolean stays text")
   void keepsBooleanLookingValuesAsText() throws Exception {
      PostmanCollection.Item item = request("Bool", "GET", "http://x");
      item.request.header = new ArrayList<>();
      PostmanCollection.Header h = new PostmanCollection.Header();
      h.key = "X-Flag";
      h.value = "yes";
      item.request.header.add(h);

      PostmanCollection.Item back = roundTrip(collectionOf(item)).get(0);
      assertEquals("yes", back.request.header.get(0).value);
   }

   @Test
   @DisplayName("the url template is preserved rather than the resolved form")
   void prefersUrlTemplate() throws Exception {
      PostmanCollection.Item item = request("U", "GET", "https://resolved.example/api");
      item.request.rawUrlTemplate = "{{base_url}}/api";

      PostmanCollection.Item back = roundTrip(collectionOf(item)).get(0);
      assertEquals("{{base_url}}/api", String.valueOf(back.request.url));
   }
}
