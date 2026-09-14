package burp.service;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.models.ScriptContext;
import burp.parser.VariableResolver;
import com.google.gson.JsonParser;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.util.HashMap;
import java.util.Map;

/**
 * Runs Postman-style pre-request / post-response scripts. Exposes a {@code pm.*}
 * proxy object so collection scripts like {@code pm.variables.set('x', y)}
 * just work. Any variables written by the script are mirrored back into the
 * shared {@link VariableResolver} so subsequent {{var}} substitution sees them.
 */
public class ScriptExecutor {

    /**
     * Rhino is bundled in every build flavour, so this is always true. Kept as
     * a method rather than inlined because the UI reports engine status.
     */
    private static boolean rhinoAvailable() {
        return true;
    }

    public static boolean isRhinoRuntimeAvailable() {
        return rhinoAvailable();
    }

    /** Optional UI sink so diagnostics surface in the in-app log panel. */
    public static volatile java.util.function.Consumer<String> UI_LOG = null;

    private static synchronized void diag(String msg) {
        // Delegates to the central logger: off by default, redacted, and size
        // bounded. The previous implementation appended an unredacted script
        // preview to ~/BurpMan-scripts.log on every single execution.
        burp.util.Diag.log(msg);
    }

    public ScriptExecutor() {
        // Nothing to initialise. Script execution goes through
        // RhinoScriptEngine, which is constructed per run so each script gets
        // a fresh scope. This constructor is retained because callers still
        // create an instance before calling the static runAndApply helpers.
    }

    // ============================================================
    // Static high-level entry points
    // ============================================================

    /**
     * Supplies the OAuth 2.0 values a script can read back after a token fetch. Installed by the
     * importer, which owns the auth manager holding the fetched tokens.
     */
    private static volatile java.util.function.Supplier<java.util.Map<String, String>> OAUTH_CREDENTIALS;

    public static void setOAuth2CredentialSupplier(
            java.util.function.Supplier<java.util.Map<String, String>> supplier) {
        OAUTH_CREDENTIALS = supplier;
    }

    public static void runAndApply(String script, VariableResolver resolver) {
        runAndApply(script, resolver, null, null);
    }
    public static void runAndApply(String script, VariableResolver resolver, ExecutedRequest response) {
        runAndApply(script, resolver, response, null);
    }

    public static void runAndApply(String script, VariableResolver resolver, ExecutedRequest response,
                                   burp.models.PostmanCollection.Request currentRequest) {
        if (script == null || script.trim().isEmpty()) return;
        ScriptContext ctx = new ScriptContext();
        // Snapshot of seeded collection vars so we can tell later which entries
        // the script actually wrote vs which were just pre-populated from the
        // resolver (so we don't clobber freshly-written env values like {{token}}
        // with the pre-script collection seed during the merge-back).
        java.util.Map<String, String> seedCollection = new HashMap<>();
        if (resolver != null) {
            seedCollection.putAll(resolver.getVariables());
            ctx.setCollectionVariables(new HashMap<>(seedCollection));
            // Note: do NOT seed env from the resolver. The resolver is a flat
            // merged view (globals < collection < env < runtime); copying it
            // into the env map and then merging back would let globals values
            // win over real env values for keys the script never touched.
        }
        if (response != null) ctx.setExecutedRequest(response);
        if (currentRequest != null) ctx.setRequest(currentRequest);
        java.util.function.Supplier<java.util.Map<String, String>> credentials = OAUTH_CREDENTIALS;
        if (credentials != null) {
            try {
                ctx.setOauth2CredentialVariables(credentials.get());
            } catch (Exception ignore) {
                // A missing credential map must not stop the script from running.
            }
        }
        boolean engineRan = false;
        // The script body is deliberately NOT logged. It routinely contains
        // client signing keys on the first line, and the previous preview
        // (first 80 chars) was long enough to capture a full base64 secret.
        // Diag.redact() is a safety net, not a licence to log source.
        diag("runAndApply (len=" + script.length()
            + ", resolver=" + (resolver != null) + ")");

        // Surface that the script is being dispatched, so a stale cached
        // classloader is obvious in the in-app console.
        java.util.function.Consumer<String> uiSink = UI_LOG;
        if (uiSink != null) {
            uiSink.accept("⚙ runAndApply engineAvailable="
                + rhinoAvailable() + " script=" + script.length() + "ch");
        }

        // Rhino is the only engine. It is bundled in every flavour, so there
        // is no availability probe and no fallback: a script either runs with
        // full ECMAScript semantics or reports a real error. The previous
        // build carried three engines (Rhino, Nashorn, and a hand-written
        // mini-interpreter) whose behaviour had to be kept in sync by hand —
        // a base64 bug once had to be fixed in three separate files to
        // actually take effect.
        try {
            new RhinoScriptEngine(ctx, currentRequest).run(script);
            engineRan = true;
            diag("  -> Script OK. globals=" + ctx.getGlobalVariables().size()
                + " env=" + ctx.getEnvironmentVariables().size()
                + " coll=" + ctx.getCollectionVariables().size());
            if (UI_LOG != null) UI_LOG.accept("✓ Script ran ("
                + script.length() + " chars) — "
                + ctx.getEnvironmentVariables().size() + " env writes, "
                + ctx.getCollectionVariables().size() + " coll writes");
        } catch (Throwable t) {
            diag("  -> Script FAILED: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            if (UI_LOG != null) UI_LOG.accept("⚠ Script error: "
                + t.getClass().getSimpleName() + ": " + t.getMessage());
        }

        // Compact summary of what the script produced. Used to dump every
        // var=value in the log; that pinned the EDT painting hundreds of
        // lines per script run on collections with 50+ env vars. The Edit
        // Variables dialog already shows the full set.
        try {
            int globals = ctx.getGlobalVariables().size();
            int env     = ctx.getEnvironmentVariables().size();
            int coll    = ctx.getCollectionVariables().size();
            int totalWrites = globals + env + coll;
            StringBuilder sb = new StringBuilder("🧪 Script wrote ");
            sb.append(totalWrites).append(" var(s)");
            if (totalWrites > 0) {
                sb.append(" (").append(globals).append(" global, ")
                  .append(env).append(" env, ")
                  .append(coll).append(" coll)");
            }
            if (response != null) {
                String rb = response.getResponseBody();
                sb.append(" | responseBody.len=").append(rb == null ? 0 : rb.length());
            }
            System.out.println("[BurpMan] " + sb);
            if (UI_LOG != null) UI_LOG.accept(sb.toString());
        } catch (Throwable ignore) {
            burp.util.Diag.warn("ScriptExecutor:144", ignore);
        }

        // The regex scraper is a last-resort recovery path, not a companion
        // pass. Running it after a successful execution used to let a literal
        // `pm.environment.set('token','PLACEHOLDER')` string in a dead branch
        // overwrite the real value the engine had just computed.
        if (!engineRan) {
            applyRegexFallback(script, ctx);
        }
        if (resolver != null) {
            String beforeToken = resolver.getVariables().get("token");
            // Apply in order: collection (only changed entries), globals, env.
            // We skip seeded collection vars that the script DIDN'T modify so
            // they can't clobber a freshly-written env value with the same key.
            for (Map.Entry<String, String> en : ctx.getCollectionVariables().entrySet()) {
                String k = en.getKey();
                String v = en.getValue();
                String seed = seedCollection.get(k);
                if (java.util.Objects.equals(seed, v)) continue; // unchanged seed, skip
                resolver.addCustomVariable(k, v);
            }
            for (Map.Entry<String, String> en : ctx.getGlobalVariables().entrySet()) {
                resolver.addCustomVariable(en.getKey(), en.getValue());
            }
            for (Map.Entry<String, String> en : ctx.getEnvironmentVariables().entrySet()) {
                resolver.addCustomVariable(en.getKey(), en.getValue());
            }
            try {
                String afterToken = resolver.getVariables().get("token");
                boolean changed = !java.util.Objects.equals(beforeToken, afterToken);
                // Report only whether the token moved and how long it is. The
                // previous version echoed the first 30 characters, which is
                // most of a signing key and all of a short bearer token.
                String summary = "🔧 Resolver merge: token "
                        + (changed ? "CHANGED" : "unchanged")
                        + " (len " + (beforeToken == null ? "null" : beforeToken.length())
                        + " -> " + (afterToken == null ? "null" : afterToken.length()) + ")";
                diag(summary);
                if (UI_LOG != null) UI_LOG.accept(summary);
            } catch (Throwable t) {
                burp.util.Diag.warn("resolver merge diagnostics", t);
            }
        }
        if (!engineRan) {
            System.err.println("[BurpMan] Applied " + ctx.getGlobalVariables().size()
                + " global + " + ctx.getEnvironmentVariables().size() + " env vars via regex fallback.");
        }
    }

    /**
     * Best-effort regex extractor for {@code pm.*.set('k','v')} and
     * {@code postman.setEnvironmentVariable('k','v')} calls with literal string
     * values. Used as a safety net when the JS engine isn't available or when
     * host-access prevented our proxy from being invoked.
     *
     * <p>JS comments are stripped first so that commented-out set() calls
     * (e.g. {@code //postman.setEnvironmentVariable("grsPlusAccessCode","MULTIPLAN3")})
     * are NOT scraped — otherwise the last such literal in the script would
     * overwrite the value that the interpreter correctly set from live code.
     *
     * <p><b>Fill-in-missing semantics.</b> The regex is control-flow blind: it
     * matches literal-string calls inside unreachable branches too (for
     * example, a {@code default:} case that assigns an "invalid" placeholder
     * when the switch actually took a different case). To avoid clobbering
     * values the interpreter correctly computed, we only write a key here if
     * it isn't already present in the context. This preserves the safety-net
     * behaviour (fills in values when the interpreter ran but couldn't write
     * back) while stopping unreachable literals from overwriting good values.
     */
    private static void applyRegexFallback(String script, ScriptContext ctx) {
        if (script == null) return;
        String cleaned = stripJsComments(script);
        // pm.{variables|environment|collectionVariables|globals}.set('K', 'V')
        java.util.regex.Pattern p1 = java.util.regex.Pattern.compile(
            "pm\\.(variables|environment|collectionVariables|globals)\\.set\\(\\s*[\"'`]([^\"'`]+)[\"'`]\\s*,\\s*[\"'`]([^\"'`]*)[\"'`]\\s*\\)");
        java.util.regex.Matcher m = p1.matcher(cleaned);
        while (m.find()) {
            String scope = m.group(1);
            String k = m.group(2);
            String v = m.group(3);
            if ("environment".equals(scope)) ctx.getEnvironmentVariables().putIfAbsent(k, v);
            else if ("collectionVariables".equals(scope)) ctx.getCollectionVariables().putIfAbsent(k, v);
            else ctx.getGlobalVariables().putIfAbsent(k, v);
        }
        // postman.setEnvironmentVariable('K','V') / postman.setGlobalVariable('K','V')
        java.util.regex.Pattern p2 = java.util.regex.Pattern.compile(
            "postman\\.set(Environment|Global)Variable\\(\\s*[\"'`]([^\"'`]+)[\"'`]\\s*,\\s*[\"'`]([^\"'`]*)[\"'`]\\s*\\)");
        m = p2.matcher(cleaned);
        while (m.find()) {
            String scope = m.group(1);
            String k = m.group(2);
            String v = m.group(3);
            if ("Environment".equals(scope)) ctx.getEnvironmentVariables().putIfAbsent(k, v);
            else ctx.getGlobalVariables().putIfAbsent(k, v);
        }
    }

    /**
     * Strip JavaScript {@code //...} line comments and {@code /* ... *&#47;}
     * block comments, while preserving comment-like sequences that appear
     * inside string literals (single/double quotes and template literals).
     * Newlines inside block comments are preserved so line numbers in any
     * subsequent error message still line up with the original source.
     */
    static String stripJsComments(String src) {
        if (src == null || src.isEmpty()) return src;
        StringBuilder out = new StringBuilder(src.length());
        int i = 0, n = src.length();
        char strDelim = 0;
        boolean escape = false;
        while (i < n) {
            char c = src.charAt(i);
            if (strDelim != 0) {
                out.append(c);
                if (escape) escape = false;
                else if (c == '\\') escape = true;
                else if (c == strDelim) strDelim = 0;
                i++;
                continue;
            }
            if (c == '"' || c == '\'' || c == '`') {
                strDelim = c;
                out.append(c);
                i++;
                continue;
            }
            if (c == '/' && i + 1 < n && src.charAt(i + 1) == '/') {
                int end = src.indexOf('\n', i);
                if (end < 0) end = n;
                i = end;
                continue;
            }
            if (c == '/' && i + 1 < n && src.charAt(i + 1) == '*') {
                int end = src.indexOf("*/", i + 2);
                if (end < 0) end = n; else end += 2;
                for (int j = i; j < end; j++) {
                    if (src.charAt(j) == '\n') out.append('\n');
                }
                i = end;
                continue;
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

}
