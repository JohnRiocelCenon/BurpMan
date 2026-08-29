package burp.script;

import burp.service.RhinoScriptEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static burp.script.ScriptFixture.lastLog;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression coverage for base64 handling.
 *
 * <p>A production collection carried a 41-character secret in its environment
 * ({@code length % 4 == 1}, so not strictly valid base64). Java's strict
 * decoder rejected it, the shim swallowed the exception and returned
 * {@code ""}, and sixty lines later {@code HmacSHA256} failed with
 * "Empty key" — surfacing to the user as an unexplained 401. Browsers and
 * Node are lenient here, so BurpMan must be too.
 */
@DisplayName("Base64 decoding is browser-lenient")
class Base64ToleranceTest {

    /** The exact shape of the value that triggered the original failure. */
    private static final String UNPADDED_41 = "Mnc2eiRDJkYpWll1eCFBdTc2TS1KQE1jUWhUajQ0=";

    @Test
    @DisplayName("atob decodes a value whose length is not a multiple of 4")
    void atobToleratesBadPadding() {
        String decoded = RhinoScriptEngine.atobImpl(UNPADDED_41);
        assertEquals(30, decoded.length(),
            "expected the 30-char secret, got [" + decoded + "]");
        assertEquals("2w6z$C&F)ZYux!Au76M-J@McQhTj44", decoded);
    }

    @Test
    @DisplayName("atob accepts base64url alphabet and whitespace")
    void atobAcceptsUrlSafeAndWhitespace() {
        assertEquals("Hello", RhinoScriptEngine.atobImpl("SGVs bG8="));
        assertEquals("Hello", RhinoScriptEngine.atobImpl("SGVsbG8"));
    }

    @Test
    @DisplayName("btoa/atob round-trip")
    void roundTrip() {
        String original = "the quick brown fox";
        assertEquals(original,
            RhinoScriptEngine.atobImpl(RhinoScriptEngine.btoaImpl(original)));
    }

    @Test
    @DisplayName("atob is reachable from script code")
    void atobFromScript() throws Exception {
        assertEquals("30", lastLog(
            "var atob = require('atob');"
          + "console.log(String(atob('" + UNPADDED_41 + "').length));"));
    }

    @Test
    @DisplayName("HmacSHA256 with the decoded key produces a signature")
    void hmacWithDecodedKeySigns() throws Exception {
        // End-to-end shape of the JWT-signing collection that regressed.
        String sig = lastLog(
            "var CryptoJS=require('crypto-js');"
          + "var atob=require('atob');"
          + "var key=atob('" + UNPADDED_41 + "');"
          + "console.log(CryptoJS.HmacSHA256('payload', key).toString());");
        assertEquals(64, sig.length(), "expected a 64-char hex digest, got [" + sig + "]");
        assertTrue(sig.matches("[0-9a-f]{64}"), "digest must be lowercase hex");
    }

    @Test
    @DisplayName("HmacSHA256 with an empty key does not throw")
    void hmacToleratesEmptyKey() throws Exception {
        // crypto-js accepts an empty key; SecretKeySpec does not. Users hit
        // this whenever an env var is missing, and an exception here aborts
        // the whole pre-request script.
        String sig = lastLog(
            "var CryptoJS=require('crypto-js');"
          + "console.log(CryptoJS.HmacSHA256('payload','').toString());");
        assertEquals(64, sig.length(), "expected a digest, got [" + sig + "]");
    }
}
