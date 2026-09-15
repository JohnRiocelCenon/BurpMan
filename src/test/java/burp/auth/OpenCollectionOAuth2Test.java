package burp.auth;

import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import com.google.gson.Gson;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bruno's OpenCollection YAML nests what Postman and Bruno's JSON export keep flat, e.g.
 * {@code credentials.clientId}. Nested objects used to be skipped outright, so the OAuth dialog
 * opened with an empty Client ID and the sign-in could never be completed.
 */
class OpenCollectionOAuth2Test {

   /** Mirrors "01 - Entra Generate Token.yml" from the Sample Service collection. */
   private static final String OAUTH2_YAML_SHAPE =
      "{"
         + "\"flow\":\"authorization_code\","
         + "\"authorizationUrl\":\"https://login.microsoftonline.com/{{tenant_id}}/oauth2/v2.0/authorize\","
         + "\"accessTokenUrl\":\"https://login.microsoftonline.com/{{tenant_id}}/oauth2/v2.0/token\","
         + "\"callbackUrl\":\"{{callback_URL}}\","
         + "\"credentials\":{\"clientId\":\"{{app_client_id}}\",\"placement\":\"body\"},"
         + "\"additionalParameters\":{\"accessTokenRequest\":["
         + "  {\"name\":\"Origin\",\"placement\":\"header\",\"value\":\"https://uat.example.ca/app\"}]},"
         + "\"scope\":\"{{api_scope}}\","
         + "\"pkce\":{},"
         + "\"tokenConfig\":{\"id\":\"credentials\",\"placement\":{\"header\":\"\"},\"source\":\"access_token\"},"
         + "\"settings\":{\"autoFetchToken\":true,\"autoRefreshToken\":false}"
         + "}";

   private static OAuth2Config detect() {
      PostmanCollection.Auth auth = new PostmanCollection.Auth();
      auth.type = "oauth2";
      auth.oauth2 = new Gson().fromJson(OAUTH2_YAML_SHAPE, Map.class);

      PostmanCollection.Request request = new PostmanCollection.Request();
      request.method = "GET";
      request.url = "localhost";
      request.auth = auth;

      PostmanCollection.Item item = new PostmanCollection.Item();
      item.name = "01 - Entra Generate Token";
      item.request = request;

      PostmanCollection collection = new PostmanCollection();
      collection.info = new PostmanCollection.Info();
      collection.info.name = "Sample Service";
      collection.item = new java.util.ArrayList<>();
      collection.item.add(item);

      List<OAuth2Config> configs = new OAuth2Detector(new VariableResolver()).detect(collection);
      assertFalse(configs.isEmpty(), "an oauth2 request should yield a config");
      return configs.get(0);
   }

   @Test
   @DisplayName("the client id nested under credentials is found")
   void findsNestedClientId() {
      // Previously empty, which is exactly what the user saw in the dialog.
      assertEquals("{{app_client_id}}", detect().clientId);
   }

   @Test
   @DisplayName("credentials.placement becomes the client authentication method")
   void mapsCredentialsPlacement() {
      assertEquals("body", detect().clientAuthenticationMethod);
   }

   @Test
   @DisplayName("flow is understood as the grant type")
   void mapsFlowToGrantType() {
      assertEquals("authorization_code", detect().grantType);
   }

   @Test
   @DisplayName("the flat urls and scope still come through")
   void keepsFlatFields() {
      OAuth2Config config = detect();
      assertEquals("https://login.microsoftonline.com/{{tenant_id}}/oauth2/v2.0/authorize", config.authUrl);
      assertEquals("https://login.microsoftonline.com/{{tenant_id}}/oauth2/v2.0/token", config.accessTokenUrl);
      assertEquals("{{callback_URL}}", config.callbackUrl);
      assertEquals("{{api_scope}}", config.scope);
   }

   @Test
   @DisplayName("tokenConfig supplies the credentials id used by scripts")
   void mapsTokenConfigId() {
      // Scripts read $oauth2.<id>.access_token, so this name has to survive.
      assertEquals("credentials", detect().rawAttributes.get("credentialsId"));
   }

   @Test
   @DisplayName("a header placement means the token is sent as a header")
   void mapsTokenPlacement() {
      assertEquals("header", detect().rawAttributes.get("addTokenTo"));
   }

   @Test
   @DisplayName("an empty pkce object means PKCE is enabled")
   void normalisesEmptyPkce() {
      assertEquals("true", detect().rawAttributes.get("pkce"));
   }

   @Test
   @DisplayName("settings are flattened rather than dropped")
   void flattensSettings() {
      OAuth2Config config = detect();
      assertEquals("true", config.rawAttributes.get("autoFetchToken"));
      assertEquals("false", config.rawAttributes.get("autoRefreshToken"));
   }

   @Test
   @DisplayName("a header declared for the token request is sent")
   void sendsDeclaredTokenRequestHeader() {
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new VariableResolver());
      Map<String, String> headers = factory.declaredTokenRequestHeaders(detect());
      assertEquals("https://uat.example.ca/app", headers.get("Origin"));
   }

   @Test
   @DisplayName("a declared Origin is not duplicated by the derived one")
   void doesNotDuplicateOrigin() throws Exception {
      OAuth2Config config = detect();
      config.callbackUrl = "https://uat.example.ca/app";
      config.clientId = "abc";
      config.scope = "api://abc/Some.Scope";
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new VariableResolver());
      String raw = factory.buildAuthorizationCodeTokenRequestText(config, "CODE", "VERIFIER");
      int count = raw.split("(?m)^Origin:", -1).length - 1;
      assertEquals(1, count, "exactly one Origin header expected:\n" + raw);
      assertTrue(raw.contains("Origin: https://uat.example.ca/app"));
   }

   @Test
   @DisplayName("a header value cannot smuggle extra headers")
   void sanitisesDeclaredHeaders() throws Exception {
      PostmanCollection.Auth auth = new PostmanCollection.Auth();
      auth.type = "oauth2";
      auth.oauth2 = new Gson().fromJson(
         "{\"flow\":\"authorization_code\","
            + "\"accessTokenUrl\":\"https://example.com/token\","
            + "\"callbackUrl\":\"https://example.com/cb\","
            + "\"credentials\":{\"clientId\":\"abc\"},"
            + "\"additionalParameters\":{\"accessTokenRequest\":["
            + "  {\"name\":\"X-Test\",\"placement\":\"header\",\"value\":\"a\\r\\nX-Evil: b\"}]}}",
         Map.class);

      PostmanCollection.Request request = new PostmanCollection.Request();
      request.method = "GET";
      request.url = "localhost";
      request.auth = auth;
      PostmanCollection.Item item = new PostmanCollection.Item();
      item.name = "hdr";
      item.request = request;
      PostmanCollection collection = new PostmanCollection();
      collection.info = new PostmanCollection.Info();
      collection.info.name = "c";
      collection.item = new java.util.ArrayList<>();
      collection.item.add(item);

      OAuth2Config config = new OAuth2Detector(new VariableResolver()).detect(collection).get(0);
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new VariableResolver());
      String raw = factory.buildAuthorizationCodeTokenRequestText(config, "CODE", "VERIFIER");
      // The CR/LF is stripped, so the value stays on one line; what matters is that no new
      // header line was created.
      assertFalse(raw.matches("(?s).*[\\r\\n]X-Evil:.*"),
         "CR/LF must not create a second header:\n" + raw);
      assertTrue(raw.contains("X-Test: aX-Evil: b"), "the value should be flattened onto one line:\n" + raw);
   }

   @Test
   @DisplayName("a non-header parameter is not turned into a header")
   void ignoresNonHeaderPlacements() {
      PostmanCollection.Auth auth = new PostmanCollection.Auth();
      auth.type = "oauth2";
      auth.oauth2 = new Gson().fromJson(
         "{\"flow\":\"authorization_code\",\"accessTokenUrl\":\"https://example.com/token\","
            + "\"credentials\":{\"clientId\":\"abc\"},"
            + "\"additionalParameters\":{\"accessTokenRequest\":["
            + "  {\"name\":\"resource\",\"placement\":\"body\",\"value\":\"xyz\"}]}}",
         Map.class);
      PostmanCollection.Request request = new PostmanCollection.Request();
      request.method = "GET";
      request.url = "localhost";
      request.auth = auth;
      PostmanCollection.Item item = new PostmanCollection.Item();
      item.name = "np";
      item.request = request;
      PostmanCollection collection = new PostmanCollection();
      collection.info = new PostmanCollection.Info();
      collection.info.name = "c";
      collection.item = new java.util.ArrayList<>();
      collection.item.add(item);

      OAuth2Config config = new OAuth2Detector(new VariableResolver()).detect(collection).get(0);
      Map<String, String> headers =
         new OAuth2RequestFactory(new VariableResolver()).declaredTokenRequestHeaders(config);
      assertFalse(headers.containsKey("resource"), "body placement must not become a header");
   }

   @Test
   @DisplayName("an explicitly flat field still wins over the nested one")
   void flatFieldWins() {
      PostmanCollection.Auth auth = new PostmanCollection.Auth();
      auth.type = "oauth2";
      auth.oauth2 = new Gson().fromJson(
         "{\"flow\":\"authorization_code\",\"clientId\":\"FLAT\","
            + "\"accessTokenUrl\":\"https://example.com/token\","
            + "\"credentials\":{\"clientId\":\"NESTED\"}}",
         Map.class);
      PostmanCollection.Request request = new PostmanCollection.Request();
      request.method = "GET";
      request.url = "localhost";
      request.auth = auth;
      PostmanCollection.Item item = new PostmanCollection.Item();
      item.name = "fw";
      item.request = request;
      PostmanCollection collection = new PostmanCollection();
      collection.info = new PostmanCollection.Info();
      collection.info.name = "c";
      collection.item = new java.util.ArrayList<>();
      collection.item.add(item);

      OAuth2Config config = new OAuth2Detector(new VariableResolver()).detect(collection).get(0);
      assertNotNull(config.clientId);
      assertTrue(config.clientId.contains("FLAT"), "an explicit flat value must not be overwritten");
   }
}
