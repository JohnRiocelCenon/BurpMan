package burp.script;

import burp.models.ScriptContext;
import burp.service.RhinoScriptEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Guards the script sandbox.
 *
 * <p>Scripts come from imported collection files, which a penetration tester
 * routinely receives from a client. Treating them as untrusted input is the
 * whole point: without a {@code ClassShutter}, Rhino exposes the full JVM
 * (arbitrary file read/write, process spawn, and the live {@code MontoyaApi}
 * handle with the tester's proxy history and session state) to anyone who
 * can get a {@code .json} file opened.
 *
 * <p>BurpMan 1.0.0 failed every assertion in this class.
 */
@DisplayName("Script sandbox blocks JVM access")
class SandboxTest {

    /** Runs a snippet and fails the test if the JVM was reachable. */
    private static void assertBlocked(String label, String js) {
        ScriptContext ctx = new ScriptContext();
        try {
            new RhinoScriptEngine(ctx, null).run(js);
        } catch (Throwable expected) {
            return; // Denied at the ClassShutter — this is the pass condition.
        }
        String logged = String.valueOf(ctx.getConsoleOutput());
        if (logged.contains("[script log] ")) {
            fail("Sandbox escape (" + label + ") — script reached the JVM and logged: "
                + logged.substring(logged.lastIndexOf("[script log] ")).trim());
        }
    }

    @Test
    @DisplayName("the 'java' package root is not exposed")
    void javaPackageRootBlocked() {
        assertBlocked("typeof java",
            "if (typeof java !== 'undefined') { console.log('reachable:' + typeof java); }");
    }

    @Test
    @DisplayName("the 'Packages' root is not exposed")
    void packagesRootBlocked() {
        assertBlocked("typeof Packages",
            "if (typeof Packages !== 'undefined') { console.log('reachable:' + typeof Packages); }");
    }

    @Test
    @DisplayName("system properties cannot be read")
    void systemPropertiesBlocked() {
        assertBlocked("System.getProperty",
            "console.log(java.lang.System.getProperty('user.name'));");
    }

    @Test
    @DisplayName("the filesystem cannot be read")
    void fileSystemBlocked() {
        assertBlocked("java.io.File",
            "console.log('entries=' + new java.io.File('.').list().length);");
    }

    @Test
    @DisplayName("Runtime (process spawn) is not reachable")
    void runtimeBlocked() {
        assertBlocked("Runtime.getRuntime",
            "console.log(String(java.lang.Runtime.getRuntime().getClass().getName()));");
    }

    @Test
    @DisplayName("reflection cannot reach the MontoyaApi handle")
    void reflectionBlocked() {
        assertBlocked("Class.forName -> RhinoScriptEngine.api",
            "console.log(String(java.lang.Class.forName('burp.service.RhinoScriptEngine')"
          + ".getField('api').getName()));");
    }

    @Test
    @DisplayName("JavaAdapter cannot be used to synthesise classes")
    void javaAdapterBlocked() {
        assertBlocked("JavaAdapter",
            "if (typeof JavaAdapter !== 'undefined') { console.log('reachable:JavaAdapter'); }");
    }

    @Test
    @DisplayName("an infinite loop is interrupted instead of hanging")
    void infiniteLoopIsInterrupted() {
        // assertTimeoutPreemptively runs on a separate thread and abandons it
        // on expiry, so an unfixed engine fails the build instead of hanging it.
        assertTimeoutPreemptively(Duration.ofSeconds(45), () -> {
            ScriptContext ctx = new ScriptContext();
            assertThrows(Exception.class,
                () -> new RhinoScriptEngine(ctx, null).run("while(true){}"),
                "an unbounded loop must abort, not pin a thread forever");
        }, "script watchdog did not fire — the loop ran unbounded");
    }

    @Test
    @DisplayName("require() still resolves the supported shims")
    void supportedModulesStillResolve() throws Exception {
        // The sandbox must not break legitimate collection scripts.
        ScriptContext ctx = new ScriptContext();
        new RhinoScriptEngine(ctx, null).run(
            "var C=require('crypto-js');"
          + "var h=C.HmacSHA256('msg','key').toString();"
          + "console.log(h.length > 0 ? 'ok' : 'empty');");
        assertTrue(String.valueOf(ctx.getConsoleOutput()).contains("ok"),
            "crypto-js must still work inside the sandbox");
    }

    @Test
    @DisplayName("require() of an unsupported module throws")
    void unsupportedModuleThrows() {
        ScriptContext ctx = new ScriptContext();
        assertThrows(Exception.class,
            () -> new RhinoScriptEngine(ctx, null).run("require('fs');"),
            "'fs' must not resolve");
    }
}
