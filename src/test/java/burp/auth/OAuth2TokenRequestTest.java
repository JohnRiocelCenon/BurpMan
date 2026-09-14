package burp.auth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the authorization-code redemption, in particular the cross-origin shape Entra
 * demands for redirect URIs registered as a single-page application (AADSTS9002327).
 */
class OAuth2TokenRequestTest {

   private static OAuth2Config spaConfig() {
      OAuth2Config config = new OAuth2Config();
      config.grantType = "authorization_code";
      config.accessTokenUrl = "https://login.microsoftonline.com/22222222/oauth2/v2.0/token";
      config.authUrl = "https://login.microsoftonline.com/22222222/oauth2/v2.0/authorize";
      config.clientId = "11111111-1111-4111-8111-111111111111";
      config.scope = "api://11111111-1111-4111-8111-111111111111/Reports.Read";
      config.callbackUrl = "https://uat.example.com/app-callback";
      return config;
   }

   private static OAuth2RequestFactory factory() {
      return new OAuth2RequestFactory(new burp.parser.VariableResolver());
   }

   @Test
   @DisplayName("derives the origin of a redirect URI")
   void derivesOrigin() {
      assertEquals("https://uat.example.com",
         OAuth2RequestFactory.originOf("https://uat.example.com/app-callback"));
      assertEquals("http://localhost:8080", OAuth2RequestFactory.originOf("http://localhost:8080/callback"));
      assertEquals("https://example.com", OAuth2RequestFactory.originOf("https://example.com:443/cb?x=1"));
      assertEquals("http://example.com", OAuth2RequestFactory.originOf("http://example.com:80/cb"));
   }

   @Test
   @DisplayName("no origin is produced for custom schemes or junk")
   void skipsNonWebRedirects() {
      assertNull(OAuth2RequestFactory.originOf("myapp://callback"));
      assertNull(OAuth2RequestFactory.originOf("urn:ietf:wg:oauth:2.0:oob"));
      assertNull(OAuth2RequestFactory.originOf("not a url"));
      assertNull(OAuth2RequestFactory.originOf(""));
      assertNull(OAuth2RequestFactory.originOf(null));
   }

   @Test
   @DisplayName("the code exchange is sent as a cross-origin request")
   void sendsOriginHeader() throws Exception {
      String raw = factory().buildAuthorizationCodeTokenRequestText(spaConfig(), "THECODE", "THEVERIFIER");
      assertTrue(raw.contains("Origin: https://uat.example.com"),
         "token request must carry an Origin header, otherwise Entra rejects SPA codes with"
            + " AADSTS9002327:\n" + raw);
   }

   @Test
   @DisplayName("the code exchange carries the PKCE verifier and no blank client secret")
   void sendsVerifierWithoutBlankSecret() throws Exception {
      String raw = factory().buildAuthorizationCodeTokenRequestText(spaConfig(), "THECODE", "THEVERIFIER");
      assertTrue(raw.contains("grant_type=authorization_code"));
      assertTrue(raw.contains("code=THECODE"));
      assertTrue(raw.contains("code_verifier=THEVERIFIER"));
      assertTrue(raw.contains("client_id=11111111-1111-4111-8111-111111111111"));
      // A single-page application is a public client; an empty secret must not be sent at all.
      assertFalse(raw.contains("client_secret"), "blank client_secret must be omitted:\n" + raw);
   }

   @Test
   @DisplayName("the redirect URI is echoed back unchanged on redemption")
   void echoesRedirectUri() throws Exception {
      String raw = factory().buildAuthorizationCodeTokenRequestText(spaConfig(), "THECODE", "THEVERIFIER");
      assertTrue(raw.contains("redirect_uri=https%3A%2F%2Fuat.example.com%2Fapp-callback"),
         "redirect_uri must match the one used for authorization:\n" + raw);
   }

   @Test
   @DisplayName("a confidential client still sends its secret")
   void confidentialClientKeepsSecret() throws Exception {
      OAuth2Config config = spaConfig();
      config.clientSecret = "s3cr3t";
      String raw = factory().buildAuthorizationCodeTokenRequestText(config, "THECODE", "THEVERIFIER");
      assertTrue(raw.contains("client_secret=s3cr3t"));
   }

   @Test
   @DisplayName("a non-web redirect produces no Origin header")
   void customSchemeRedirectHasNoOrigin() throws Exception {
      OAuth2Config config = spaConfig();
      config.callbackUrl = "myapp://callback";
      String raw = factory().buildAuthorizationCodeTokenRequestText(config, "THECODE", "THEVERIFIER");
      assertFalse(raw.contains("Origin:"), "no origin can be formed from a custom scheme:\n" + raw);
   }

   @Test
   @DisplayName("the sign-in page is forced rather than offering the desktop account")
   void forcesCredentialPage() {
      // select_account would still let a browser tied to the Windows session offer that
      // account for one-click sign-in, which is what made BurpMan skip the login page.
      assertEquals("login", factory().resolvePromptParameter(new OAuth2Config()));
   }
}
