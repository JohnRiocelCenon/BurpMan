package burp.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.models.ScriptContext;
import org.junit.jupiter.api.Test;

/**
 * Script syntax that Postman and Bruno accept but bare Rhino does not.
 *
 * <p>Both products execute a script as a function body, so a top-level
 * {@code return} is the ordinary way to say "nothing to do". Rhino evaluates at
 * global level, where that is {@code EvaluatorException: invalid return} — the
 * script dies before its first statement. A folder that meant to bootstrap its
 * auth then does nothing at all, and the only visible symptom is a 401 several
 * requests later.
 */
class ScriptCompatibilityTest {

    /** Runs {@code script} and returns everything it logged. */
    private String run(String script) {
        ScriptContext ctx = new ScriptContext();
        try {
            new RhinoScriptEngine(ctx, null).run(script);
        } catch (Exception expected) {
            // A broken script still logs; the assertions read the output.
        }
        return ctx.getConsoleOutput();
    }

    private boolean logged(String log, String needle) {
        return log != null && log.contains(needle);
    }

    @Test
    void topLevelReturnStopsTheScriptInsteadOfFailing() {
        String log = run(
                "console.log('before');\n"
                        + "if (true) { return; }\n"
                        + "console.log('after');\n");

        assertTrue(logged(log, "before"), "statements before the return must run: " + log);
        assertTrue(!logged(log, "after"), "return must stop the script: " + log);
    }

    /** Guard-clause shape used by real bootstrap scripts. */
    @Test
    void earlyReturnGuardSkipsTheRest() {
        String log = run(
                "var haveToken = true;\n"
                        + "if (haveToken) {\n"
                        + "  console.log('token still valid');\n"
                        + "  return;\n"
                        + "}\n"
                        + "console.log('bootstrapping');\n");

        assertTrue(logged(log, "token still valid"), log);
        assertTrue(!logged(log, "bootstrapping"), "the guard must skip the bootstrap: " + log);
    }

    /** A script without a top-level return must not be wrapped. */
    @Test
    void ordinaryScriptIsUnaffected() {
        String log = run("console.log('one'); console.log('two');");

        assertTrue(logged(log, "one"), log);
        assertTrue(logged(log, "two"), log);
        assertTrue(!logged(log, "top-level return"),
                "no wrapper should be reported for a script that doesn't need one: " + log);
    }

    /** A return inside a function was always legal and must stay untouched. */
    @Test
    void returnInsideAFunctionIsNotTreatedAsTopLevel() {
        String log = run(
                "function pick() { return 'chosen'; }\n"
                        + "console.log(pick());\n");

        assertTrue(logged(log, "chosen"), log);
        assertTrue(!logged(log, "top-level return"), log);
    }

    /**
     * Bruno scripts await their helpers. Our host calls are synchronous, so the
     * keywords are stripped — but the calls must still happen, in order.
     */
    @Test
    void awaitedCallsStillRunInOrder() {
        String log = run(
                "console.log('first');\n"
                        + "await console.log('second');\n"
                        + "console.log('third');\n");

        assertTrue(logged(log, "first"), log);
        assertTrue(logged(log, "second"), log);
        assertTrue(logged(log, "third"), log);
    }

    /** The combination a real folder-bootstrap script uses. */
    @Test
    void awaitAndTopLevelReturnTogether() {
        String log = run(
                "var mode = 'disabled';\n"
                        + "if (mode === 'enabled') {\n"
                        + "  console.log('manual mode');\n"
                        + "  return;\n"
                        + "}\n"
                        + "await console.log('step one');\n"
                        + "await console.log('step two');\n");

        assertTrue(!logged(log, "manual mode"), log);
        assertTrue(logged(log, "step one"), log);
        assertTrue(logged(log, "step two"), log);
    }

    /** bru.runRequest without a runner warns rather than pretending it ran. */
    @Test
    void runRequestWithoutARunnerSaysSo() {
        String log = run("bru.runRequest('Auth/CIAM/initialize');");

        assertTrue(logged(log, "runRequest"),
                "the script must be told the request did not run: " + log);
    }

    /** Variables set before an early return must persist. */
    @Test
    void variablesWrittenBeforeAReturnArePersisted() throws Exception {
        ScriptContext ctx = new ScriptContext();
        new RhinoScriptEngine(ctx, null).run(
                "bru.setVar('marker', 'kept');\n"
                        + "if (true) { return; }\n"
                        + "bru.setVar('marker', 'overwritten');\n");

        assertEquals("kept", ctx.getCollectionVariables().get("marker"));
    }
}
