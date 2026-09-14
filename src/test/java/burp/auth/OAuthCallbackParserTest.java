package burp.auth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuthCallbackParserTest {

   @Test
   @DisplayName("reads code and state out of a normal redirect URL")
   void parsesQueryRedirect() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse(
         "https://uat.example.com/example-ui?code=0.AR8Aabc-def_123&state=xyz789");
      assertEquals("0.AR8Aabc-def_123", r.code);
      assertEquals("xyz789", r.state);
      assertFalse(r.hasError());
   }

   @Test
   @DisplayName("percent-encoded values are decoded")
   void decodesPercentEncoding() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse(
         "https://host/cb?code=abc%2Fdef%3Dghi&state=a%20b");
      assertEquals("abc/def=ghi", r.code);
      assertEquals("a b", r.state);
   }

   @Test
   @DisplayName("a literal plus in a code is preserved rather than turned into a space")
   void keepsPlusInCode() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse("https://host/cb?code=ab+cd");
      assertEquals("ab+cd", r.code);
   }

   @Test
   @DisplayName("reads a fragment response")
   void parsesFragmentResponse() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse(
         "https://host/cb#access_token=TOKEN123&token_type=Bearer&state=s1");
      assertEquals("TOKEN123", r.accessToken);
      assertEquals("s1", r.state);
      assertTrue(r.hasToken());
      assertFalse(r.hasCode());
   }

   @Test
   @DisplayName("handles hash-router callbacks that put the query after the fragment")
   void parsesHashRouterCallback() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse("https://host/app#/callback?code=HASHCODE&state=s2");
      assertEquals("HASHCODE", r.code);
      assertEquals("s2", r.state);
   }

   @Test
   @DisplayName("the query wins when a code appears in both query and fragment")
   void queryBeatsFragment() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse("https://host/cb?code=FROMQUERY#code=FROMFRAGMENT");
      assertEquals("FROMQUERY", r.code);
   }

   @Test
   @DisplayName("surfaces an error response")
   void parsesErrorResponse() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse(
         "https://host/cb?error=access_denied&error_description=User%20cancelled");
      assertTrue(r.hasError());
      assertEquals("access_denied", r.error);
      assertEquals("access_denied: User cancelled", r.errorMessage());
      assertFalse(r.hasCode());
   }

   @Test
   @DisplayName("accepts a bare code pasted on its own")
   void acceptsBareCode() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse("0.AR8Aabcdefghijklmnop-_123");
      assertEquals("0.AR8Aabcdefghijklmnop-_123", r.code);
   }

   @Test
   @DisplayName("accepts a bare query string without the URL")
   void acceptsBareQueryString() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse("?code=QS_CODE&state=QS_STATE");
      assertEquals("QS_CODE", r.code);
      assertEquals("QS_STATE", r.state);
   }

   @Test
   @DisplayName("strips wrapping that mail clients and terminals add")
   void stripsWrapping() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse("  <https://host/cb?code=WRAPPED>\n");
      assertEquals("WRAPPED", r.code);
   }

   @Test
   @DisplayName("ignores text with nothing OAuth-shaped in it")
   void ignoresNoise() {
      assertTrue(OAuthCallbackParser.parse("hello there, this is not a url").isEmpty());
      assertTrue(OAuthCallbackParser.parse("").isEmpty());
      assertTrue(OAuthCallbackParser.parse(null).isEmpty());
      assertTrue(OAuthCallbackParser.parse("https://host/page?foo=bar").isEmpty());
   }

   @Test
   @DisplayName("the authorize URL itself is not mistaken for a response")
   void authorizeUrlIsNotAResponse() {
      String authorize = "https://login.microsoftonline.com/22222222-2222-4222-8222-222222222222/oauth2/v2.0/authorize"
         + "?response_type=code&client_id=11111111-1111-4111-8111-111111111111"
         + "&scope=api%3A%2F%2F11111111%2FReports.Read"
         + "&redirect_uri=https%3A%2F%2Fuat.example.com%2Fexample-ui"
         + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";
      assertFalse(OAuthCallbackParser.isAuthorizationResponse(authorize));
      assertNull(OAuthCallbackParser.parse(authorize).code);
   }

   @Test
   @DisplayName("matches a callback endpoint regardless of query or trailing slash")
   void matchesCallbackEndpoint() {
      String configured = "https://uat.example.com/example-ui";
      assertTrue(OAuthCallbackParser.matchesCallback(
         "https://uat.example.com/example-ui?code=abc&state=x", configured));
      assertTrue(OAuthCallbackParser.matchesCallback(
         "https://uat.example.com/example-ui/", configured));
      assertFalse(OAuthCallbackParser.matchesCallback("https://evil.example/example-ui?code=abc", configured));
      assertFalse(OAuthCallbackParser.matchesCallback(null, configured));
   }

   @Test
   @DisplayName("a callback on an unreachable host still yields its code")
   void unreachableCallbackHostStillParses() {
      OAuthCallbackParser.Result r = OAuthCallbackParser.parse(
         "https://callback.invalid-host-for-test.example/example-ui?code=TEST_CODE_123&state=xyz789");
      assertEquals("TEST_CODE_123", r.code);
      assertEquals("xyz789", r.state);
   }
}
