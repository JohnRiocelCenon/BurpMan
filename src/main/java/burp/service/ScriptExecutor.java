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
    public enum EngineMode { AUTO, RHINO, NASHORN }
    private final ScriptEngine engine;
    private static volatile boolean bannerPrinted = false;
    private static volatile boolean liteWarningPrinted = false;
    private static volatile EngineMode preferredEngineMode = EngineMode.AUTO;
    private static final java.io.File DIAG_LOG = new java.io.File(
        System.getProperty("user.home"), "BurpMan-scripts.log");

    /** Cached probe: true iff Mozilla Rhino classes are on the classpath.
     *  Lets the lite build (which doesn't bundle Rhino) skip the Rhino path
     *  without throwing NoClassDefFoundError when RhinoScriptEngine loads. */
    private static volatile Boolean rhinoAvailableCache = null;
    private static boolean rhinoAvailable() {
        Boolean c = rhinoAvailableCache;
        if (c != null) return c;
        try {
            Class.forName("org.mozilla.javascript.Context");
            rhinoAvailableCache = Boolean.TRUE;
        } catch (Throwable t) {
            rhinoAvailableCache = Boolean.FALSE;
        }
        return rhinoAvailableCache;
    }

    private static volatile Boolean nashornAvailableCache = null;
    private static boolean nashornAvailable() {
        Boolean c = nashornAvailableCache;
        if (c != null) return c;
        try {
            Class.forName("jdk.nashorn.api.scripting.NashornScriptEngineFactory");
            nashornAvailableCache = Boolean.TRUE;
        } catch (Throwable t) {
            try {
                ScriptEngine e = new ScriptEngineManager().getEngineByName("nashorn");
                nashornAvailableCache = (e != null);
            } catch (Throwable ignore) {
                nashornAvailableCache = Boolean.FALSE;
            }
        }
        return nashornAvailableCache;
    }

    public static EngineMode getPreferredEngineMode() {
        return preferredEngineMode;
    }

    public static void setPreferredEngineMode(EngineMode mode) {
        preferredEngineMode = mode == null ? EngineMode.AUTO : mode;
    }

    public static boolean isRhinoRuntimeAvailable() {
        return rhinoAvailable();
    }

    public static boolean isNashornRuntimeAvailable() {
        return nashornAvailable();
    }

    /** Optional UI sink so diagnostics surface in the in-app log panel. */
    public static volatile java.util.function.Consumer<String> UI_LOG = null;

    private static synchronized void diag(String msg) {
        String line = "[" + new java.util.Date() + "] " + msg;
        System.out.println(line);
        try (java.io.FileWriter fw = new java.io.FileWriter(DIAG_LOG, true)) {
            fw.write(line);
            fw.write(System.lineSeparator());
        } catch (Throwable ignore) { }
    }

    public ScriptExecutor() {
        // Silence GraalJS' "interpreter only" startup warning on non-GraalVM JDKs.
        // Must be set before the engine is created. Idempotent.
        try { System.setProperty("polyglot.engine.WarnInterpreterOnly", "false"); } catch (Throwable ignore) {}

        ScriptEngineManager manager = new ScriptEngineManager();
        // Prefer Graal.js explicitly so Nashorn-style "JavaScript" alias doesn't pick
        // a stub. Fall back to the generic name and finally to Nashorn for old JDKs.
        ScriptEngine e = manager.getEngineByName("graal.js");
        String picked = "graal.js";
        if (e == null) { e = manager.getEngineByName("JavaScript"); picked = "JavaScript"; }
        if (e == null) { e = manager.getEngineByName("nashorn"); picked = "nashorn"; }
        // Burp's extension classloader does NOT honor META-INF/services from
        // shaded jars, so ScriptEngineManager returns nothing even when GraalJS
        // is on the classpath. Fall back to instantiating the factory directly.
        if (e == null) {
            try {
                Class<?> facCls = Class.forName(
                    "com.oracle.truffle.js.scriptengine.GraalJSEngineFactory");
                Object fac = facCls.getDeclaredConstructor().newInstance();
                e = (ScriptEngine) facCls.getMethod("getScriptEngine").invoke(fac);
                picked = "graal.js (direct)";
            } catch (Throwable t) {
                System.err.println("[BurpMan] Direct script engine factory load failed: "
                    + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        if (e == null) { picked = "<none>"; }
        if (e != null) {
            // Allow host access so pm.variables.set(...) can call our Java proxies.
            try {
                javax.script.Bindings b = e.getBindings(javax.script.ScriptContext.ENGINE_SCOPE);
                b.put("polyglot.js.allowHostAccess", true);
                b.put("polyglot.js.allowAllAccess", true);
                b.put("polyglot.js.allowHostClassLookup", (java.util.function.Predicate<String>) s -> true);
                b.put("polyglot.js.nashorn-compat", true);
            } catch (Throwable ignore) { /* Nashorn ignores these */ }
        }
        if (!bannerPrinted) {
            bannerPrinted = true;
            diag("JS engine selected: " + picked
                + " (factories: " + listFactories(manager) + ")");
        }
        this.engine = e; // null on JDK 15+ without GraalJS — callers no-op.
    }

    private static String listFactories(ScriptEngineManager m) {
        StringBuilder sb = new StringBuilder();
        try {
            for (javax.script.ScriptEngineFactory f : m.getEngineFactories()) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(f.getEngineName()).append('/').append(f.getLanguageName());
            }
        } catch (Throwable t) { sb.append("error: ").append(t.getMessage()); }
        return sb.toString();
    }

    public boolean isAvailable() { return engine != null; }

    // ============================================================
    // Static high-level entry points
    // ============================================================

    public static void runAndApply(String script, VariableResolver resolver) {
        runAndApply(script, resolver, null, null);
    }

    public static void runAndApply(String script, VariableResolver resolver, ExecutedRequest response) {
        runAndApply(script, resolver, response, null);
    }

    public static void runAndApply(String script, VariableResolver resolver, ExecutedRequest response,
                                   burp.models.PostmanCollection.Request currentRequest) {
        if (script == null || script.trim().isEmpty()) return;
        ScriptExecutor exec = new ScriptExecutor();
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
        boolean engineRan = false;
        String preview = script.length() > 80 ? script.substring(0, 80).replace('\n',' ') + "…" : script.replace('\n',' ');
        diag("runAndApply (engine=" + exec.isAvailable() + ", len=" + script.length()
            + ", resolver=" + (resolver != null) + "): " + preview);

        // Always show in UI: which engine path runAndApply takes for this script.
        // Bypasses the UI_LOG hook to confirm runAndApply itself is on the
        // expected build, not an old cached classloader.
        java.util.function.Consumer<String> uiSink = UI_LOG;
        if (uiSink != null) {
            uiSink.accept("⚙ runAndApply build=2026-08-10-release-1.0.0 engineAvailable="
                + rhinoAvailable() + " script=" + script.length() + "ch");
        }

        // Primary path: Rhino — full ECMAScript-2015 runtime, handles
        // closures, destructuring, template literals, and pm.sendRequest
        // callback chains used by real-world Postman collections.
        // Probed at runtime so the lite build (without Rhino bundled) skips
        // gracefully to the mini-interpreter instead of crashing with NCDFE.
        boolean rhinoRan = false;
        boolean rhinoTried = false;
        if (rhinoAvailable()) {
            rhinoTried = true;
            try {
                new RhinoScriptEngine(ctx, currentRequest).run(script);
                rhinoRan = true;
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
        } else if (!liteWarningPrinted) {
            liteWarningPrinted = true;
            String msg = "ℹ BurpMan-lite: the full script engine is not bundled. Simple pm.* "
                + "scripts will still run via the mini-interpreter, but real-world "
                + "scripts using closures, destructuring, or pm.sendRequest may not "
                + "execute fully. Install the BurpMan-full build for full script support.";
            diag(msg);
            if (UI_LOG != null) UI_LOG.accept(msg);
        }

        // Fallback path: pure-Java mini-interpreter. ONLY runs if Rhino is
        // unavailable entirely (lite build, NCDFE, etc.) — NOT if Rhino was
        // tried and partially executed before throwing. Re-running the whole
        // script through mini after a Rhino mid-script crash would overwrite
        // freshly-written env values (e.g. `test.auth.id` set by the Rhino
        // pass before the substring crash) with whatever default the mini
        // pass computes (often undefined), poisoning the chain for the next
        // request.
        if (!rhinoTried && !rhinoRan) {
            try {
                new ScriptInterpreter(ctx).run(script);
                engineRan = true;
                diag("  -> JS-lite OK. globals=" + ctx.getGlobalVariables().size()
                    + " env=" + ctx.getEnvironmentVariables().size()
                    + " coll=" + ctx.getCollectionVariables().size());
            } catch (Throwable t) {
                diag("  -> JS-lite FAILED: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
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
        } catch (Throwable ignore) { }

        // Optional: if GraalJS is available, also let it run (additive — its
        // writes go through the same proxy).
        if (exec.isAvailable()) {
            try {
                exec.execute(script, ctx);
            } catch (Throwable ignore) { /* the interpreter has already covered us */ }
        }
        // Safety net: even if the JS engine ran fine, also scrape literal-string
        // set() calls so we never lose those values. This covers cases where the
        // engine ran but host-access prevented our proxy from being invoked.
        applyRegexFallback(script, ctx);
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
                String pb = beforeToken == null ? "null" : (beforeToken.length() > 30 ? beforeToken.substring(0, 30) + "…(" + beforeToken.length() + ")" : beforeToken);
                String pa = afterToken == null ? "null" : (afterToken.length() > 30 ? afterToken.substring(0, 30) + "…(" + afterToken.length() + ")" : afterToken);
                boolean changed = !java.util.Objects.equals(beforeToken, afterToken);
                String diag = "🔧 Resolver merge: token " + (changed ? "CHANGED" : "unchanged")
                        + "  before=" + pb + "  after=" + pa
                        + "  resolver@" + System.identityHashCode(resolver);
                System.out.println("[BurpMan] " + diag);
                if (UI_LOG != null) UI_LOG.accept(diag);
            } catch (Throwable ignore) {}
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

    public void execute(String script, ScriptContext context) throws ScriptException {
        if (script == null || script.trim().isEmpty() || engine == null) return;
        engine.put("pm", new PostmanApiProxy(context));
        engine.put("postman", new PostmanApiProxy(context));
        engine.put("console", new ConsoleProxy(context));
        ExecutedRequest response = context == null ? null : context.getExecutedRequest();
        engine.put("responseBody",
            response == null || response.getResponseBody() == null ? "" : response.getResponseBody());
        java.util.Map<String, Object> responseCode = new java.util.HashMap<>();
        responseCode.put("code", response == null ? 0 : response.getStatusCode());
        responseCode.put("name", "");
        engine.put("responseCode", responseCode);
        engine.put("responseHeaders",
            response == null || response.getResponseHeaders() == null
                ? java.util.Collections.emptyList()
                : response.getResponseHeaders());
        try {
            engine.eval(script);
        } catch (Exception e) {
            String msg = e.getMessage();
            context.log("Script error: " + msg);
            System.err.println("[BurpMan] Script eval error: " + msg);
            throw new ScriptException(e);
        }
    }

    // Backwards-compat aliases (PreRequestScriptExecutor uses these names)
    public void executePreRequest(String script, ScriptContext context) throws ScriptException {
        execute(script, context);
    }
    public void executePostResponse(String script, ScriptContext context) throws ScriptException {
        execute(script, context);
    }

    // ============================================================
    // pm.* proxy
    // ============================================================
    public static class PostmanApiProxy {
        private final ScriptContext context;
        public final VariablesProxy variables;
        public final EnvironmentProxy environment;
        public final VariablesProxy collectionVariables;
        public final VariablesProxy globals;
        public final RequestProxy request;
        public final ResponseProxy response;

        public PostmanApiProxy(ScriptContext context) {
            this.context = context;
            this.variables = new VariablesProxy(context, VariablesProxy.Scope.GLOBAL);
            this.environment = new EnvironmentProxy(context);
            this.collectionVariables = new VariablesProxy(context, VariablesProxy.Scope.COLLECTION);
            this.globals = new VariablesProxy(context, VariablesProxy.Scope.GLOBAL);
            this.request = new RequestProxy(context.getRequest());
            this.response = new ResponseProxy(context.getExecutedRequest());
        }

        public void setVariable(String key, Object value) { variables.set(key, value); }
        public String getVariable(String key) { return variables.get(key); }
        public RequestProxy getRequest() { return request; }
        public ResponseProxy getResponse() { return response; }
        public Map<String, String> getEnvironment() { return context.getEnvironmentVariables(); }
        public void setEnvironmentVariable(String key, Object value) { environment.set(key, value); }
        public String getEnvironmentVariable(String key) { return environment.get(key); }
        public void setGlobalVariable(String key, Object value) { globals.set(key, value); }
        public String getGlobalVariable(String key) { return globals.get(key); }
        public void clearEnvironmentVariable(String key) {
            if (key == null) return;
            context.getEnvironmentVariables().remove(key);
        }
        public void clearEnvironmentVariables() { context.getEnvironmentVariables().clear(); }
        public void clearGlobalVariable(String key) {
            if (key == null) return;
            context.getGlobalVariables().remove(key);
        }
        public void clearGlobalVariables() { context.getGlobalVariables().clear(); }
        public void unsetEnvironmentVariable(String key) { clearEnvironmentVariable(key); }
        public void unsetGlobalVariable(String key) { clearGlobalVariable(key); }
    }

    public static class VariablesProxy {
        public enum Scope { GLOBAL, COLLECTION }
        private final ScriptContext context;
        private final Scope scope;
        public VariablesProxy(ScriptContext c, Scope s) { this.context = c; this.scope = s; }
        public void set(String key, Object value) {
            if (key == null) return;
            String v = value == null ? "" : value.toString();
            if (scope == Scope.COLLECTION) context.getCollectionVariables().put(key, v);
            context.setVariable(key, v);
        }
        public String get(String key) { return context.getVariable(key); }
        public boolean has(String key) { return context.getVariable(key) != null; }
        public void unset(String key) {
            context.getGlobalVariables().remove(key);
            context.getCollectionVariables().remove(key);
            context.getEnvironmentVariables().remove(key);
        }
    }

    public static class EnvironmentProxy {
        private final ScriptContext context;
        public EnvironmentProxy(ScriptContext c) { this.context = c; }
        public void set(String key, Object value) {
            if (key == null) return;
            String v = value == null ? "" : value.toString();
            context.getEnvironmentVariables().put(key, v);
            context.setVariable(key, v);
        }
        public String get(String key) {
            String v = context.getEnvironmentVariables().get(key);
            if (v == null) v = context.getVariable(key);
            return v;
        }
        public boolean has(String key) { return get(key) != null; }
        public void unset(String key) { context.getEnvironmentVariables().remove(key); }
    }

    public static class RequestProxy {
        private final PostmanCollection.Request request;
        public final RequestBodyProxy body;
        public RequestProxy(PostmanCollection.Request request) {
            this.request = request;
            this.body = new RequestBodyProxy(request);
        }
        public String getUrl() { return request != null && request.url != null ? request.url.toString() : ""; }
        public String getMethod() { return request != null ? request.method : ""; }
        public Map<String, String> getHeaders() {
            Map<String, String> headers = new HashMap<>();
            if (request != null && request.header != null) {
                for (PostmanCollection.Header h : request.header) headers.put(h.key, h.value);
            }
            return headers;
        }
        public Object getBody() {
            return body;
        }
    }

    public static class RequestBodyProxy {
        private final PostmanCollection.Request request;
        public RequestBodyProxy(PostmanCollection.Request request) { this.request = request; }
        public String getMode() {
            if (request == null || request.body == null) return "";
            if (request.body.mode != null && !request.body.mode.trim().isEmpty()) return request.body.mode;
            if (request.body.raw != null) return "raw";
            if (request.body.formdata != null && !request.body.formdata.isEmpty()) return "formdata";
            if (request.body.urlencoded != null && !request.body.urlencoded.isEmpty()) return "urlencoded";
            return "";
        }
        public String getRaw() {
            if (request == null || request.body == null || request.body.raw == null) return "";
            return request.body.raw;
        }
        public Object getFormdata() {
            if (request == null || request.body == null || request.body.formdata == null) {
                return java.util.Collections.emptyList();
            }
            return request.body.formdata;
        }
        public Object getUrlencoded() {
            if (request == null || request.body == null || request.body.urlencoded == null) {
                return java.util.Collections.emptyList();
            }
            return request.body.urlencoded;
        }
    }

    public static class ResponseProxy {
        private final ExecutedRequest response;
        public ResponseProxy(ExecutedRequest response) { this.response = response; }
        public int getStatus() { return response != null ? response.getStatusCode() : 0; }
        public int code() { return getStatus(); }
        public String text() { return getBody(); }
        public String getBody() { return response != null ? response.getResponseBody() : ""; }
        public Map<String, String> getHeaders() {
            Map<String, String> headers = new HashMap<>();
            if (response != null && response.getResponseHeaders() != null) {
                for (PostmanCollection.Header h : response.getResponseHeaders()) {
                    headers.put(h.key, h.value);
                }
            }
            return headers;
        }
        public Object json() { return getJson(); }
        public Object getJson() {
            String body = getBody();
            if (body == null || body.isEmpty()) return null;
            try { return JsonParser.parseString(body); } catch (Exception e) { return null; }
        }
    }

    public static class ConsoleProxy {
        private final ScriptContext context;
        public ConsoleProxy(ScriptContext context) { this.context = context; }
        public void log(Object obj)   { context.log(obj != null ? obj.toString() : "null"); }
        public void error(Object obj) { context.log("[ERROR] " + (obj != null ? obj.toString() : "null")); }
        public void warn(Object obj)  { context.log("[WARN] "  + (obj != null ? obj.toString() : "null")); }
        public void info(Object obj)  { log(obj); }
        public void debug(Object obj) { log(obj); }
    }
}
