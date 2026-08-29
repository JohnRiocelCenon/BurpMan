package burp.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the diagnostic logger's privacy and growth properties.
 *
 * <p>The predecessor wrote unredacted script previews to {@code $HOME} on every
 * execution with no cap, which meant client signing keys accumulated on the
 * tester's disk. These tests pin the behaviour that must not regress.
 */
@DisplayName("Diagnostic logging is private and bounded")
class DiagTest {

    @AfterEach
    void reset() {
        Diag.setEnabled(false);
        Diag.setSink(null);
    }

    @Test
    @DisplayName("file logging is off unless explicitly enabled")
    void offByDefault(@TempDir Path dir) {
        Path log = dir.resolve("burpman.log");
        Diag.setLogFile(log);
        Diag.setEnabled(false);

        Diag.log("this must not be written");

        assertFalse(Files.exists(log), "no file should be created while disabled");
    }

    @Test
    @DisplayName("enabling logging writes to the configured file")
    void writesWhenEnabled(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("burpman.log");
        Diag.setLogFile(log);
        Diag.setEnabled(true);

        Diag.log("collection analysis finished");

        assertTrue(Files.exists(log));
        assertTrue(String.join("\n", Files.readAllLines(log))
            .contains("collection analysis finished"));
    }

    @Test
    @DisplayName("the base64 secret from the original incident is redacted")
    void redactsBase64Secret() {
        // The exact line shape that was being written in full by the old logger.
        String redacted = Diag.redact(
            "runAndApply: let jwtSecret = atob('Mnc2eiRDJkYpWll1eCFBdTc2TS1KQE1jUWhUajQ0=');");

        assertFalse(redacted.contains("Mnc2eiRDJkYpWll1eCFBdTc2TS1KQE1jUWhUajQ0"),
            "the key must not survive: " + redacted);
        assertTrue(redacted.contains("<redacted"), "expected a marker: " + redacted);
    }

    @Test
    @DisplayName("JWTs are redacted")
    void redactsJwt() {
        String redacted = Diag.redact("Authorization header: "
            + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        assertFalse(redacted.contains("eyJhbGciOiJIUzI1NiIs"), redacted);
        assertTrue(redacted.contains("<redacted"), redacted);
    }

    @Test
    @DisplayName("named secret assignments are redacted")
    void redactsNamedSecrets() {
        assertTrue(Diag.redact("client_secret=hunter2").contains("<redacted>"));
        assertTrue(Diag.redact("password: \"correct horse\"").contains("<redacted>"));
        assertFalse(Diag.redact("api_key = abc123def").contains("abc123def"));
    }

    @Test
    @DisplayName("ordinary identifiers stay readable")
    void keepsProseReadable() {
        // A log nobody can read is a log nobody keeps enabled.
        String out = Diag.redact("entering getCascadedTestScriptsForFolder for collection root");
        assertTrue(out.contains("getCascadedTestScriptsForFolder"), out);
    }

    @Test
    @DisplayName("the UI sink receives redacted text, never raw")
    void sinkAlsoRedacted() {
        List<String> seen = new ArrayList<>();
        Diag.setSink(seen::add);
        Diag.setEnabled(false); // sink must work even with file logging off

        Diag.log("token=eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.c2lnbmF0dXJlSGVyZQ");

        assertEquals(1, seen.size(), "sink should be notified once");
        assertFalse(seen.get(0).contains("eyJhbGciOiJIUzI1NiJ9"), seen.get(0));
    }

    @Test
    @DisplayName("a failing sink does not propagate to the caller")
    void sinkFailureIsContained() {
        Diag.setSink(s -> { throw new IllegalStateException("UI is gone"); });
        Diag.log("should not throw"); // must not blow up the calling request
    }
}
