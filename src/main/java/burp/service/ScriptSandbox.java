package burp.service;

import org.mozilla.javascript.ClassShutter;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.ContextFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Confines collection-supplied scripts to a JavaScript-only world.
 *
 * <h2>Why this exists</h2>
 * Pre-request and test scripts arrive inside {@code .postman_collection.json}
 * and {@code .bru} files — routinely handed to a tester by a client, or pulled
 * from a shared drive. They are untrusted input.
 *
 * <p>Rhino's default {@code initStandardObjects()} scope exposes the entire
 * JVM to script code: {@code java.*}, {@code Packages.*}, {@code JavaAdapter},
 * and reflection. In a Burp extension that means an imported collection could
 * read and write arbitrary files, spawn processes, and reach the live
 * {@code MontoyaApi} handle — with it, the tester's proxy history, session
 * state, and every credential in the project.
 *
 * <p>Two independent controls close that off:
 * <ol>
 *   <li>{@link Context#initSafeStandardObjects} builds a scope with no Java
 *       bridge at all — no {@code Packages}, {@code java}, {@code JavaAdapter},
 *       {@code importClass}, or {@code getClass}.</li>
 *   <li>A {@link ClassShutter} allowlist blocks the residual route: every host
 *       object we inject ({@code pm}, {@code bru}, {@code console}) is a
 *       {@code NativeJavaObject}, and {@code someHost.getClass().forName(...)}
 *       would otherwise walk straight back out.</li>
 * </ol>
 *
 * <p>A watchdog runs alongside them. Rhino calls
 * {@link #observeInstructionCount} every few thousand bytecodes, which is the
 * only safe way to interrupt a runaway script — {@code Thread.stop()} is
 * unsafe and {@code while(true){}} never checks an interrupt flag. Without it
 * a single malformed loop pins a core inside Burp until the user restarts.
 */
public final class ScriptSandbox extends ContextFactory {

    /** Bytecodes between watchdog checks. Low enough to interrupt a tight loop promptly. */
    private static final int OBSERVER_THRESHOLD = 10_000;

    /** Default wall-clock budget for a single script. */
    public static final long DEFAULT_TIMEOUT_MS = 15_000L;

    private static final ScriptSandbox INSTANCE = new ScriptSandbox();

    /** Deadline for the script running on the current thread; null when unarmed. */
    private static final ThreadLocal<long[]> DEADLINE = new ThreadLocal<>();

    private ScriptSandbox() {}

    public static ScriptSandbox factory() {
        return INSTANCE;
    }

    /**
     * Classes a script may legitimately touch.
     *
     * <p>The allowlist is deliberately broad for our own {@code burp.*} host
     * facades and narrow for the JDK. That asymmetry is the point: with
     * {@link Context#initSafeStandardObjects} there is no {@code Packages} or
     * {@code java} root, so a script cannot <em>name</em> a Java class at all.
     * The only remaining route out is {@code someHostObject.getClass()}, and
     * that is useless unless {@code java.lang.Class},
     * {@code java.lang.ClassLoader}, or {@code java.lang.Runtime} are visible
     * — none of which are.
     *
     * <p>Enumerating every host class individually was tried first and is too
     * brittle: adding a new {@code *Host} facade would silently break every
     * script that touches it.
     */
    private static final Set<String> ALLOWED_JDK = new HashSet<>(Arrays.asList(
        "java.lang.String",
        "java.lang.Boolean",
        "java.lang.Integer",
        "java.lang.Long",
        "java.lang.Double",
        "java.lang.Number",
        "java.lang.Object",
        "java.lang.CharSequence"
    ));

    private static final String[] ALLOWED_PREFIXES = {
        // Our own host facades (pm, bru, console, req, res, crypto-js, ...)
        // and the data models they hand back.
        "burp.service.",
        "burp.models.",
        // Collections surface through pm.response.headers and friends. These
        // are inert containers with no route back to the classloader.
        "java.util.List",
        "java.util.Map",
        "java.util.Collection",
        "java.util.ArrayList",
        "java.util.HashMap",
        "java.util.LinkedHashMap",
        "java.util.Arrays$"
    };

    private static final ClassShutter SHUTTER = className -> {
        if (className == null) return false;
        if (ALLOWED_JDK.contains(className)) return true;
        for (String p : ALLOWED_PREFIXES) {
            if (className.startsWith(p)) return true;
        }
        return false;
    };

    @Override
    protected Context makeContext() {
        Context cx = super.makeContext();
        // Interpreted mode: Burp's extension classloader disallows the runtime
        // bytecode generation the optimising compiler needs. It is also the
        // only mode in which the instruction observer fires reliably.
        cx.setOptimizationLevel(-1);
        cx.setInstructionObserverThreshold(OBSERVER_THRESHOLD);
        cx.setLanguageVersion(Context.VERSION_ES6);
        // Unwrap Java String/Number/Boolean returns to JS primitives so that
        //   CryptoJS.enc.Base64.stringify(x).replace(/=+$/, '')
        // dispatches to String.prototype.replace rather than Java's
        // overloaded String.replace(char,char), which Rhino otherwise reports
        // as an ambiguous method choice.
        cx.getWrapFactory().setJavaPrimitiveWrap(false);
        cx.setClassShutter(SHUTTER);
        return cx;
    }

    @Override
    protected void observeInstructionCount(Context cx, int instructionCount) {
        long[] deadline = DEADLINE.get();
        if (deadline == null) return;
        if (System.currentTimeMillis() > deadline[0]) {
            DEADLINE.remove();
            throw new ScriptTimeoutException(
                "Script exceeded its " + deadline[1] + " ms time budget and was stopped. "
              + "Check for an unbounded loop, or raise the budget if the script is "
              + "legitimately long-running.");
        }
    }

    /** Starts the watchdog for the calling thread. */
    public static void arm(long budgetMs) {
        long budget = budgetMs > 0 ? budgetMs : DEFAULT_TIMEOUT_MS;
        DEADLINE.set(new long[]{ System.currentTimeMillis() + budget, budget });
    }

    /** Stops the watchdog for the calling thread. */
    public static void disarm() {
        DEADLINE.remove();
    }

    /**
     * Credits {@code blockedMs} back to the current deadline.
     *
     * <p>{@code pm.sendRequest} performs real, synchronous HTTP from inside a
     * script. That wall-clock time is not the script's fault, so charging it
     * against the budget would kill legitimate auth chains that call three or
     * four token endpoints in sequence.
     */
    public static void creditBlockedTime(long blockedMs) {
        if (blockedMs <= 0) return;
        long[] deadline = DEADLINE.get();
        if (deadline != null) deadline[0] += blockedMs;
    }

    /** Thrown when a script outlives its budget. Not an error in the user's code. */
    public static final class ScriptTimeoutException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ScriptTimeoutException(String message) {
            super(message);
        }
    }
}
