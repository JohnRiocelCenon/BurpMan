package burp.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.models.PostmanCollection;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;

/**
 * Property access on {@code res.headers}.
 *
 * <p>Rhino resolves a property on a plain Java object to a public field or bean
 * getter. Header names are not known at compile time, so
 * {@code res.headers.location} matched neither and evaluated to
 * {@code undefined} — on a 302 that plainly carried a Location header. The
 * script reading the OAuth redirect then reported "Location header not found"
 * and the auth chain stalled with no indication of why.
 */
class ResponseHeadersHostTest {

    private static List<PostmanCollection.Header> headers(String... pairs) {
        List<PostmanCollection.Header> out = new ArrayList<>();
        for (int i = 0; i < pairs.length; i += 2) {
            PostmanCollection.Header h = new PostmanCollection.Header();
            h.key = pairs[i];
            h.value = pairs[i + 1];
            out.add(h);
        }
        return out;
    }

    /**
     * Evaluates {@code expr} with {@code res.headers} bound to the given
     * headers, returning the result as a Java string. The conversion happens
     * inside the Context: a JS string is only convertible while its Context is
     * on the thread.
     */
    private String eval(String expr, List<PostmanCollection.Header> hs) {
        Context cx = Context.enter();
        try {
            // Burp's classloader forbids bytecode generation, so the extension
            // always runs interpreted; test under the same conditions.
            cx.setOptimizationLevel(-1);
            Scriptable scope = cx.initStandardObjects();
            Scriptable host = new RhinoScriptEngine.ResponseHeadersHost(hs, scope);
            scope.put("headers", scope, host);
            Object v = cx.evaluateString(scope, expr, "<test>", 1, null);
            if (v == null || v == Context.getUndefinedValue()) return null;
            return Context.toString(v);
        } finally {
            Context.exit();
        }
    }

    private boolean evalBoolean(String expr, List<PostmanCollection.Header> hs) {
        return Boolean.parseBoolean(eval("String(" + expr + ")", hs));
    }

    @Test
    void headerIsReadableAsAPlainProperty() {
        String v = eval("headers.location",
                headers("Location", "manulifemobile://oauth2redirect?code=abc123"));

        assertNotNull(v, "res.headers.location must not be undefined");
        assertEquals("manulifemobile://oauth2redirect?code=abc123", v);
    }

    /** HTTP header names are case-insensitive; the script's casing may differ. */
    @Test
    void lookupIgnoresCase() {
        List<PostmanCollection.Header> hs = headers("Location", "/next");

        assertEquals("/next", eval("headers.location", hs));
        assertEquals("/next", eval("headers.Location", hs));
        assertEquals("/next", eval("headers['LOCATION']", hs));
    }

    /** The value must behave as a JS string so .split()/.indexOf() work. */
    @Test
    void valueSupportsStringOperations() {
        String v = eval(
                "headers.location.indexOf('?') !== -1 ?"
                        + " headers.location.substring(headers.location.indexOf('?') + 1).split('&')[0]"
                        + " : 'no-query'",
                headers("Location", "manulifemobile://oauth2redirect?code=abc123&state=x"));

        assertEquals("code=abc123", v);
    }

    /** Reproduces the collection's own redirect-parsing script end to end. */
    @Test
    void extractsTheOauthCodeFromARedirect() {
        String script =
                "var loc = headers.location;"
                        + "var out = 'not found';"
                        + "if (loc) {"
                        + "  var q = loc.indexOf('?');"
                        + "  if (q !== -1) {"
                        + "    var parts = loc.substring(q + 1).split('&');"
                        + "    for (var i = 0; i < parts.length; i++) {"
                        + "      var kv = parts[i].split('=');"
                        + "      if (kv[0] === 'code') { out = kv[1]; break; }"
                        + "    }"
                        + "  }"
                        + "} out;";

        String v = eval(script,
                headers("Location", "manulifemobile://oauth2redirect?state=s&code=xyz789"));

        assertEquals("xyz789", v);
    }

    /** A missing header stays falsy, so `if (loc)` still guards correctly. */
    @Test
    void missingHeaderIsFalsy() {
        String v = eval("headers.location ? 'present' : 'absent'",
                headers("Content-Type", "application/json"));

        assertEquals("absent", v);
    }

    /** The older explicit call style must keep working. */
    @Test
    void explicitGetAndHasStillWork() {
        List<PostmanCollection.Header> hs = headers("Location", "/next");

        assertEquals("/next", eval("headers.get('location')", hs));
        assertTrue(evalBoolean("headers.has('Location')", hs));
    }

    @Test
    void headerNamesAreEnumerable() {
        String names = eval("var n = []; for (var k in headers) { n.push(k); } n.join(',');",
                headers("Location", "/a", "Content-Type", "application/json"));

        assertTrue(names.contains("location"), names);
        assertTrue(names.contains("content-type"), names);
    }
}
