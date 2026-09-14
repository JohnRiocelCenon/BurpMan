package burp.auth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChromiumOAuthBrowserTest {

   private static final String AUTH_URL =
      "https://login.microsoftonline.com/22222222-2222-4222-8222-222222222222/oauth2/v2.0/authorize?response_type=code";

   @Test
   @DisplayName("blocks the callback host so its query string stays readable")
   void blocksCallbackHost() {
      String rule = ChromiumOAuthBrowser.callbackBlockingRule(
         AUTH_URL, "https://uat.example.com/example-ui");
      assertEquals("--host-resolver-rules=MAP uat.example.com ~NOTFOUND", rule);
   }

   @Test
   @DisplayName("never blocks the authorization server itself")
   void doesNotBlockAuthorizationServer() {
      assertNull(ChromiumOAuthBrowser.callbackBlockingRule(
         AUTH_URL, "https://login.microsoftonline.com/common/oauth2/nativeclient"));
   }

   @Test
   @DisplayName("leaves loopback callbacks reachable for the local listener")
   void doesNotBlockLoopback() {
      assertNull(ChromiumOAuthBrowser.callbackBlockingRule(AUTH_URL, "http://localhost:8080/callback"));
      assertNull(ChromiumOAuthBrowser.callbackBlockingRule(AUTH_URL, "http://127.0.0.1:8080/callback"));
   }

   @Test
   @DisplayName("tolerates a missing or unparseable callback")
   void toleratesBadInput() {
      assertNull(ChromiumOAuthBrowser.callbackBlockingRule(AUTH_URL, null));
      assertNull(ChromiumOAuthBrowser.callbackBlockingRule(AUTH_URL, ""));
      assertNull(ChromiumOAuthBrowser.callbackBlockingRule(AUTH_URL, "not a url"));
   }

   @Test
   @DisplayName("a Chromium build is discoverable on this machine")
   void findsAChromiumBuild() {
      // Guards the discovery paths; every supported desktop ships at least one Chromium browser.
      java.io.File exe = ChromiumOAuthBrowser.findChromiumExecutable();
      if (exe != null) {
         assertTrue(exe.isFile());
         assertTrue(ChromiumOAuthBrowser.isAvailable());
      } else {
         assertFalse(ChromiumOAuthBrowser.isAvailable());
      }
   }

   @Test
   @DisplayName("generated state is random and hex")
   void generatesRandomState() {
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new burp.parser.VariableResolver());
      OAuth2Config config = new OAuth2Config();
      String first = factory.resolveOrGenerateState(config);
      String second = factory.resolveOrGenerateState(config);
      assertEquals(32, first.length());
      assertTrue(first.matches("[0-9a-f]{32}"));
      assertNotEquals(first, second);
   }

   @Test
   @DisplayName("a configured state is used unchanged")
   void keepsConfiguredState() {
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new burp.parser.VariableResolver());
      OAuth2Config config = new OAuth2Config();
      config.state = "my-fixed-state";
      assertEquals("my-fixed-state", factory.resolveOrGenerateState(config));
   }

   @Test
   @DisplayName("an unresolved state template is replaced rather than sent literally")
   void replacesUnresolvedStateTemplate() {
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new burp.parser.VariableResolver());
      OAuth2Config config = new OAuth2Config();
      config.state = "{{missing_var}}";
      String state = factory.resolveOrGenerateState(config);
      assertFalse(state.contains("{{"));
      assertEquals(32, state.length());
   }

   @Test
   @DisplayName("an account prompt is requested by default so silent SSO cannot pick the identity")
   void asksForAccountPromptByDefault() {
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new burp.parser.VariableResolver());
      OAuth2Config config = new OAuth2Config();
      assertEquals("select_account", factory.resolvePromptParameter(config));
   }

   @Test
   @DisplayName("the account prompt can be turned off")
   void accountPromptCanBeDisabled() {
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new burp.parser.VariableResolver());
      OAuth2Config config = new OAuth2Config();
      config.rawAttributes.put("forceAccountPrompt", "false");
      assertNull(factory.resolvePromptParameter(config));
   }

   @Test
   @DisplayName("an explicit prompt from the collection wins")
   void explicitPromptWins() {
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new burp.parser.VariableResolver());
      OAuth2Config config = new OAuth2Config();
      config.rawAttributes.put("prompt", "consent");
      assertEquals("consent", factory.resolvePromptParameter(config));
   }

   @Test
   @DisplayName("the authorization URL carries state, PKCE and the account prompt")
   void authorizationUrlIsComplete() throws Exception {
      OAuth2RequestFactory factory = new OAuth2RequestFactory(new burp.parser.VariableResolver());
      OAuth2Config config = new OAuth2Config();
      config.authUrl = "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize";
      config.clientId = "11111111-1111-4111-8111-111111111111";
      config.scope = "api://11111111-1111-4111-8111-111111111111/Reports.Read";
      config.callbackUrl = "https://uat.example.com/example-ui";

      String url = factory.buildAuthorizationRequestUrl(config, "CHALLENGE123", "STATE456");

      assertTrue(url.contains("response_type=code"));
      assertTrue(url.contains("state=STATE456"));
      assertTrue(url.contains("code_challenge=CHALLENGE123"));
      assertTrue(url.contains("code_challenge_method=S256"));
      assertTrue(url.contains("prompt=select_account"));
      assertTrue(url.contains("redirect_uri=https%3A%2F%2Fuat.example.com%2Fexample-ui"));
   }
}
