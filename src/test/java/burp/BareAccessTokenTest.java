package burp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * OAuth 2.0 keeps the credential and the scheme apart: {@code access_token} is the token,
 * {@code token_type} says how to present it. A collection that puts the token in a header of
 * its own choosing — the sample collection uses {@code x-authorization} — needs it bare, because
 * the gateway does not expect a scheme there.
 */
class BareAccessTokenTest {

   private static final String JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2ln";

   @Test
   @DisplayName("a Bearer prefix is removed")
   void stripsBearer() {
      assertEquals(JWT, PostmanImporter.bareAccessToken("Bearer " + JWT));
   }

   @Test
   @DisplayName("the scheme is matched regardless of case or spacing")
   void stripsBearerCaseInsensitively() {
      assertEquals(JWT, PostmanImporter.bareAccessToken("bearer " + JWT));
      assertEquals(JWT, PostmanImporter.bareAccessToken("BEARER " + JWT));
      assertEquals(JWT, PostmanImporter.bareAccessToken("  Bearer   " + JWT + "  "));
   }

   @Test
   @DisplayName("other schemes some providers use are removed too")
   void stripsOtherSchemes() {
      assertEquals(JWT, PostmanImporter.bareAccessToken("Token " + JWT));
      assertEquals(JWT, PostmanImporter.bareAccessToken("JWT " + JWT));
   }

   @Test
   @DisplayName("a bare token is passed through untouched")
   void leavesBareTokenAlone() {
      assertEquals(JWT, PostmanImporter.bareAccessToken(JWT));
   }

   @Test
   @DisplayName("a token that merely starts with the letters of a scheme is not truncated")
   void doesNotTruncateLookalikes() {
      // No space, so this is one opaque token rather than a scheme and a value.
      assertEquals("bearerish-token", PostmanImporter.bareAccessToken("bearerish-token"));
      assertEquals("tokenvalue", PostmanImporter.bareAccessToken("tokenvalue"));
   }

   @Test
   @DisplayName("empty and null inputs are handled")
   void handlesEmptyInput() {
      assertNull(PostmanImporter.bareAccessToken(null));
      assertEquals("", PostmanImporter.bareAccessToken("   "));
      // A scheme with nothing after it is not a token, so it is left as-is rather than
      // silently becoming an empty string.
      assertEquals("Bearer", PostmanImporter.bareAccessToken("Bearer"));
   }
}
