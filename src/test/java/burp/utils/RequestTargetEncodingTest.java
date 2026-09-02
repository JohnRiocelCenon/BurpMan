package burp.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Whitespace handling in the request target.
 *
 * <p>A raw space would split the request line and break HTTP framing, so it
 * cannot be sent as-is. Deleting it keeps the request well-formed but silently
 * changes what was asked for: an OAuth {@code scope=openid ciam} went out as
 * {@code scope=openidciam}, and the server's {@code invalid_scope} rejection
 * then looked like a server or credentials fault rather than a client-side
 * edit. Encoding preserves the value and keeps the request line unambiguous.
 */
@DisplayName("Illegal request-target characters are encoded, not deleted")
class RequestTargetEncodingTest {

    @Test
    @DisplayName("a space in a query value becomes %20 instead of vanishing")
    void spaceInAQueryValueIsEncodedNotDeleted() {
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars(
                "/am/oauth2/realms/mobile/authorize?scope=openid ciam&state=x");

        assertEquals("/am/oauth2/realms/mobile/authorize?scope=openid%20ciam&state=x", path);
        assertFalse(path.contains("openidciam"), "the space must not be swallowed");
    }

    @Test
    @DisplayName("no raw space or tab survives into the request line")
    void requestLineCannotContainRawWhitespace() {
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars(
                "/a?x=one two\tthree");

        assertFalse(path.contains(" "), "a raw space would split the request line");
        assertFalse(path.contains("\t"));
        assertEquals("/a?x=one%20two%09three", path);
    }

    @Test
    @DisplayName("CR and LF are encoded rather than dropped")
    void carriageReturnAndNewlineAreEncoded() {
        // CR/LF must never survive literally, that is header injection; but
        // dropping them also hides the input, so encode to %0D%0A instead.
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars(
                "/a?x=1\r\nX-Injected:%20yes");

        assertFalse(path.contains("\r"));
        assertFalse(path.contains("\n"));
        assertTrue(path.contains("%0D%0A"));
    }

    @Test
    @DisplayName("non-ASCII separators encode as their UTF-8 bytes")
    void unicodeLineSeparatorsEncodeAsUtf8() {
        // U+2028 must not degrade to a lossy '?'; its UTF-8 bytes are E2 80 A8.
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars("/a?x=1\u2028");

        assertEquals("/a?x=1%E2%80%A8", path);
    }

    @Test
    @DisplayName("a clean path is returned as the same instance")
    void pathWithoutIllegalCharactersIsUnchanged() {
        // No illegal character means no allocation; the input is handed back
        // untouched, including values that already carry percent-escapes.
        String clean = "/v1/benefits/identity/authorize?scope=openid%20ciam&a=b%2Bc";

        assertSame(clean, RequestBuilder.percentEncodeIllegalRequestTargetChars(clean));
    }

    @Test
    @DisplayName("null and empty inputs are tolerated")
    void nullAndEmptyAreTolerated() {
        assertEquals(null, RequestBuilder.percentEncodeIllegalRequestTargetChars(null));
        assertEquals("", RequestBuilder.percentEncodeIllegalRequestTargetChars(""));
    }

    @Test
    @DisplayName("an existing percent-escape is not double-encoded")
    void existingPercentEscapesAreNotReEncoded() {
        // Only whitespace is illegal, so the '%' of an existing escape is left
        // alone; re-encoding it to %25 would corrupt the redirect URI.
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars(
                "/a?redirect_uri=exampleapp%3A%2F%2Foauth2redirect&scope=openid ciam");

        assertEquals("/a?redirect_uri=exampleapp%3A%2F%2Foauth2redirect&scope=openid%20ciam",
                path);
    }
}
