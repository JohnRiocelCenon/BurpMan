package burp.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
class RequestTargetEncodingTest {

    @Test
    void spaceInAQueryValueIsEncodedNotDeleted() {
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars(
                "/am/oauth2/realms/mobile/authorize?scope=openid ciam&state=x");

        assertEquals("/am/oauth2/realms/mobile/authorize?scope=openid%20ciam&state=x", path);
        assertFalse(path.contains("openidciam"), "the space must not be swallowed");
    }

    @Test
    void requestLineCannotContainRawWhitespace() {
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars(
                "/a?x=one two\tthree");

        assertFalse(path.contains(" "), "a raw space would split the request line");
        assertFalse(path.contains("\t"));
        assertEquals("/a?x=one%20two%09three", path);
    }

    /** CR/LF must never survive literally — that is header injection. */
    @Test
    void carriageReturnAndNewlineAreEncoded() {
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars(
                "/a?x=1\r\nX-Injected:%20yes");

        assertFalse(path.contains("\r"));
        assertFalse(path.contains("\n"));
        assertTrue(path.contains("%0D%0A"));
    }

    /** Non-ASCII separators encode as their UTF-8 bytes, not a lossy '?'. */
    @Test
    void unicodeLineSeparatorsEncodeAsUtf8() {
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars("/a?x=1\u2028");

        assertEquals("/a?x=1%E2%80%A8", path);
    }

    /** A clean path is returned untouched, including already-encoded values. */
    @Test
    void pathWithoutIllegalCharactersIsUnchanged() {
        String clean = "/v1/benefits/identity/authorize?scope=openid%20ciam&a=b%2Bc";

        assertSame(clean, RequestBuilder.percentEncodeIllegalRequestTargetChars(clean));
    }

    @Test
    void nullAndEmptyAreTolerated() {
        assertEquals(null, RequestBuilder.percentEncodeIllegalRequestTargetChars(null));
        assertEquals("", RequestBuilder.percentEncodeIllegalRequestTargetChars(""));
    }

    /** A percent sign already in the path is not double-encoded. */
    @Test
    void existingPercentEscapesAreNotReEncoded() {
        String path = RequestBuilder.percentEncodeIllegalRequestTargetChars(
                "/a?redirect_uri=manulifemobile%3A%2F%2Foauth2redirect&scope=openid ciam");

        assertEquals("/a?redirect_uri=manulifemobile%3A%2F%2Foauth2redirect&scope=openid%20ciam",
                path);
    }
}
