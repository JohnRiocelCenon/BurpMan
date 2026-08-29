package burp.script;

import burp.service.RhinoScriptEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static burp.script.ScriptFixture.lastLog;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the script engine's classloading contract.
 *
 * <h2>The failure this prevents</h2>
 * {@code RhinoScriptEngine} publishes {@code atob}/{@code btoa} into the script
 * scope using {@code Class.getDeclaredMethod}. The JVM resolves the parameter
 * and return types of <em>every</em> declared method on the class when that is
 * called. The Montoya API is {@code provided} scope — present inside Burp,
 * absent from the packaged jar — so adding a single method with a Montoya-typed
 * parameter to this class was enough to make the entire registration throw
 * {@link NoClassDefFoundError}. The global then never appeared, and the user saw
 * "atob is not a function" on line 1 of their own script.
 *
 * <p>It passed the rest of the suite because tests run against
 * {@code target/classes} with Montoya on the classpath. Only the assembled jar
 * broke — which is what users actually install.
 */
@DisplayName("Script engine loads without provided-scope dependencies")
class EngineClassLoadingTest {

    @Test
    @DisplayName("no method signature on RhinoScriptEngine references a provided-scope type")
    void noProvidedScopeTypesInMethodSignatures() {
        List<String> offenders = new ArrayList<>();

        for (Method m : RhinoScriptEngine.class.getDeclaredMethods()) {
            for (Class<?> p : m.getParameterTypes()) {
                if (isProvidedScope(p)) offenders.add(m.getName() + " parameter " + p.getName());
            }
            if (isProvidedScope(m.getReturnType())) {
                offenders.add(m.getName() + " returns " + m.getReturnType().getName());
            }
        }

        assertTrue(offenders.isEmpty(),
            "These signatures drag a provided-scope type into RhinoScriptEngine, which breaks "
          + "global registration in the packaged jar. Move them to a helper class "
          + "(see WatchdogHttp):\n  " + String.join("\n  ", offenders));
    }

    /**
     * Montoya is compiled against but never shipped — Burp supplies it. Any
     * such type in a signature on this class is a packaging hazard.
     */
    private static boolean isProvidedScope(Class<?> type) {
        Class<?> t = type;
        while (t.isArray()) t = t.getComponentType();
        return t.getName().startsWith("burp.api.montoya.");
    }

    @Test
    @DisplayName("the globals collection scripts depend on are actually registered")
    void requiredGlobalsAreRegistered() throws Exception {
        // Directly asserts the symptom the packaging bug produced.
        assertEquals("function,function,function,function", lastLog(
            "console.log([typeof atob, typeof btoa, typeof test, typeof expect].join(','));"));
    }

    @Test
    @DisplayName("the host objects collection scripts depend on are present")
    void requiredHostObjectsArePresent() throws Exception {
        assertEquals("object,object,object,object", lastLog(
            "console.log([typeof pm, typeof bru, typeof console, typeof postman].join(','));"));
    }
}
