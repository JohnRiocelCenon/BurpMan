package burp.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import burp.models.ScriptContext;
import java.lang.reflect.Constructor;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;

/**
 * How a stored variable is handed to a script.
 *
 * <p>Variables are held as text, but an OpenCollection {@code type: object}
 * variable is an object to its author: {@code bru.getEnvVar("test-user").gb.cert}
 * is the documented way to read one. Returning the raw JSON turned that into
 * {@code TypeError: cannot read property "gb" from undefined}, which points at
 * the script rather than at the value it was handed.
 */
class BruHostObjectVariableTest {

    private static final String TEST_USER =
            "{\n"
                    + "  \"am\": { \"user\": { \"username\": \"mobilegr02\" }, \"mfa\": { \"mode\": \"disabled\" } },\n"
                    + "  \"gb\": {\n"
                    + "    \"user\": { \"relationship\": { \"index\": 1 } },\n"
                    + "    \"group\": { \"search\": { \"specific\": true } },\n"
                    + "    \"cert\": \"114652:257461\"\n"
                    + "  }\n"
                    + "}";

    /** Minimal ScriptContext exposing one environment variable. */
    private static ScriptContext contextWith(String key, String value) {
        Map<String, String> env = new LinkedHashMap<>();
        env.put(key, value);
        ScriptContext ctx = new ScriptContext();
        ctx.setEnvironmentVariables(env);
        return ctx;
    }

    private String eval(String expr, ScriptContext sc) throws Exception {
        Context cx = Context.enter();
        try {
            cx.setOptimizationLevel(-1);
            Scriptable scope = cx.initStandardObjects();
            Constructor<?> ctor = RhinoScriptEngine.BruHost.class
                    .getDeclaredConstructor(ScriptContext.class, Scriptable.class);
            ctor.setAccessible(true);
            Object bru = ctor.newInstance(sc, scope);
            ScriptableObject.putProperty(scope, "bru", Context.javaToJS(bru, scope));
            Object v = cx.evaluateString(scope, expr, "<test>", 1, null);
            if (v == null || v == Context.getUndefinedValue()) return null;
            return Context.toString(v);
        } finally {
            Context.exit();
        }
    }

    @Test
    void objectVariableIsNavigable() throws Exception {
        ScriptContext sc = contextWith("test-user", TEST_USER);

        assertEquals("114652:257461", eval("bru.getEnvVar('test-user').gb.cert", sc));
        assertEquals("mobilegr02", eval("bru.getEnvVar('test-user').am.user.username", sc));
    }

    /** Reproduces the branch the collection's Get Identity script takes. */
    @Test
    void reproducesTheGetIdentityScriptNavigation() throws Exception {
        ScriptContext sc = contextWith("test-user", TEST_USER);

        String script =
                "var testUser = bru.getEnvVar('test-user');"
                        + "var specific = testUser.gb.group.search.specific;"
                        + "var cert = testUser.gb.cert;"
                        + "var idx = testUser.gb.user.relationship.index || 0;"
                        + "specific + '|' + cert + '|' + idx;";

        assertEquals("true|114652:257461|1", eval(script, sc));
    }

    /** A number stays a number, so `|| 0` and arithmetic behave. */
    @Test
    void numbersAndBooleansKeepTheirType() throws Exception {
        ScriptContext sc = contextWith("test-user", TEST_USER);

        assertEquals("number", eval("typeof bru.getEnvVar('test-user').gb.user.relationship.index", sc));
        assertEquals("boolean", eval("typeof bru.getEnvVar('test-user').gb.group.search.specific", sc));
    }

    /** A script that instead parses the text must keep working. */
    @Test
    void stillStringifiesToTheOriginalJson() throws Exception {
        ScriptContext sc = contextWith("test-user", TEST_USER);

        assertEquals("114652:257461",
                eval("JSON.parse(String(bru.getEnvVar('test-user'))).gb.cert", sc));
    }

    /**
     * A plain scalar is returned untouched.
     *
     * <p>Asserted through behaviour rather than {@code typeof}: {@code bru} is
     * a host object, so Rhino reports a Java string as {@code "object"} here
     * regardless of this code path.
     */
    @Test
    void scalarVariablesAreUnchanged() throws Exception {
        ScriptContext sc = contextWith("host", "https://api.example.com");

        assertEquals("https://api.example.com", eval("bru.getEnvVar('host')", sc));
        assertEquals("https://api.example.com/v1",
                eval("bru.getEnvVar('host') + '/v1'", sc));
        assertEquals("true", eval("String(String(bru.getEnvVar('host')).indexOf('api') > 0)", sc));
    }

    /** Text that merely starts like JSON but is malformed stays text. */
    @Test
    void malformedJsonStaysAString() throws Exception {
        ScriptContext sc = contextWith("broken", "{not json");

        assertEquals("{not json", eval("bru.getEnvVar('broken')", sc));
        assertEquals("undefined", eval("typeof bru.getEnvVar('broken').gb", sc));
    }

    @Test
    void jsonArraysAreNavigableToo() throws Exception {
        ScriptContext sc = contextWith("ids", "[\"a\",\"b\",\"c\"]");

        assertEquals("b", eval("bru.getEnvVar('ids')[1]", sc));
        assertEquals("3", eval("String(bru.getEnvVar('ids').length)", sc));
    }

    @Test
    void unknownVariableIsNotAnError() throws Exception {
        ScriptContext sc = contextWith("host", "x");

        assertNotNull(eval("typeof bru.getEnvVar('nope')", sc));
    }
}
