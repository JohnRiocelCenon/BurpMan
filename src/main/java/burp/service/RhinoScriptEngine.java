package burp.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.models.ScriptContext;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.mozilla.javascript.Callable;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.ContextFactory;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.NativeArray;
import org.mozilla.javascript.NativeObject;
import org.mozilla.javascript.ScriptRuntime;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.Undefined;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Mozilla Rhino-backed script engine for Postman pre-/post-request scripts.
 * <p>
 * Real-world Postman collections frequently use closures, destructuring,
 * template literals, and synchronous-looking callback chains powered by
 * {@code pm.sendRequest(...)}. The mini-interpreter in {@link ScriptInterpreter}
 * cannot run those without becoming a full JS engine — so we embed Rhino,
 * which is small (~1.5 MB), pure-Java, and works inside Burp's extension
 * classloader without the {@code META-INF/services} issues that prevent
 * GraalJS from loading.
 * <p>
 * This engine is wired as the primary path. The mini-interpreter and the
 * regex fallback in {@link ScriptExecutor} stay in place as safety nets if
 * Rhino itself fails to load (e.g. when the user runs an old fat-jar that
 * doesn't include Rhino classes).
 */
public final class RhinoScriptEngine {

    /** Set by {@link burp.BurpExtender} so {@code pm.sendRequest} can fire HTTP. */
    public static volatile MontoyaApi api;

    private final ScriptContext ctx;
    private final PostmanCollection.Request currentRequest;

    public RhinoScriptEngine(ScriptContext ctx, PostmanCollection.Request currentRequest) {
        this.ctx = ctx;
        this.currentRequest = currentRequest;
    }

    /**
     * Evaluate a script. Throws on parse/runtime errors so the caller can
     * decide whether to fall back to the mini-interpreter.
     */
    public void run(String script) throws Exception {
        if (script == null || script.trim().isEmpty()) return;
        ctx.log("[Script] starting (" + script.length() + " chars)");
        // Rhino 1.7.15 still has gaps in ES2018-2020 syntax: object spread,
        // optional chaining, and nullish coalescing all parse incompletely.
        // Rewrite them to equivalent ES5 expressions before evaluation.
        String preprocessed = rewriteObjectSpread(script);
        preprocessed = rewriteOptionalChaining(preprocessed);
        preprocessed = rewriteNullishCoalescing(preprocessed);
        // Real-world Postman / Bruno scripts frequently redeclare the same
        // `let` or `const` inside one block (e.g. two `let callback = ...`).
        // Node.js's V8 in Postman/Bruno tolerates this when the declarations
        // are in different sub-blocks, but Rhino's parser is strict. Convert
        // ES6 block-scoped declarations to `var` so hoisting absorbs the
        // duplicates without changing semantics for the patterns we see.
        preprocessed = downgradeLetConstToVar(preprocessed);
        // Rhino routes {@code .split("X")} on a Java-wrapped String through
        // {@code java.lang.String.split(regex)}, which throws when X is a
        // regex meta-character. Real Postman/Bruno scripts assume V8 literal
        // semantics, so authorize chains using
        // {@code Location.split("?")[1].split("&")} crash with
        // PatternSyntaxException. Rewrite {@code .split("metachar")} to
        // {@code .split(/escaped/)} so Rhino's RegExp engine handles it
        // literally regardless of whether the receiver is a JS or Java
        // string.
        preprocessed = rewriteSplitWithRegexMetachars(preprocessed);
        // Rhino 1.7.15.1 rejects `await` as a reserved word at top-level and
        // `async function` in some positions. Postman/Bruno users write scripts
        // like `await bru.sendRequest(cfg, async function(err,res){...})`,
        // relying on Node.js top-level await + async callback wrapping. Our
        // `bru.sendRequest` / `pm.sendRequest` implementations are synchronous
        // — the callback is invoked before the call returns and no Promise is
        // produced — so stripping the keywords is safe and preserves order:
        //   * top-level `await expr;` → `expr;`
        //   * `async function` / `async (args) =>` → `function` / `(args) =>`
        preprocessed = stripAsyncAwait(preprocessed);
        Context cx = ContextFactory.getGlobal().enterContext();
        try {
            // Interpreted mode — works under restrictive classloaders (Burp's
            // extension loader) where bytecode generation isn't allowed.
            cx.setOptimizationLevel(-1);
            // ES_6 in Rhino 1.7.15+ enables optional chaining (?.), nullish
            // coalescing (??), object spread, async/await, etc.
            cx.setLanguageVersion(Context.VERSION_ES6);
            // Unwrap Java Strings/Numbers/Booleans returned from host methods
            // back to JS primitives so scripts can call
            //   CryptoJS.enc.Base64.stringify(...).replace(/=+$/, '')
            // and dispatch to String.prototype.replace(regex, str) instead of
            // Java's overloaded String.replace(char,char) — which Rhino picks
            // when the receiver is a NativeJavaObject wrapping java.lang.String,
            // throwing "The choice of Java method ... is ambiguous".
            cx.getWrapFactory().setJavaPrimitiveWrap(false);

            Scriptable scope = cx.initStandardObjects();

            PmHost pm = new PmHost(ctx, currentRequest, scope);
            ScriptableObject.putProperty(scope, "pm", Context.javaToJS(pm, scope));
            ScriptableObject.putProperty(scope, "postman", Context.javaToJS(pm, scope));
            ScriptableObject.putProperty(scope, "bru", Context.javaToJS(new BruHost(ctx, scope), scope));
            ScriptableObject.putProperty(scope, "console", Context.javaToJS(new ConsoleHost(ctx), scope));

            // Bruno-native bindings: scripts use bare `req` / `res` (no
            // pm.* prefix), `test(name, fn)` to register test cases, and
            // `expect(value).to.equal(...)` Chai-style assertions.
            ScriptableObject.putProperty(scope, "req",
                Context.javaToJS(new BrunoReqHost(currentRequest, ctx), scope));
            ExecutedRequest bResp = ctx.getExecutedRequest();
            BrunoResHost resHost = new BrunoResHost(bResp, scope);
            ScriptableObject.putProperty(scope, "res",
                Context.javaToJS(resHost, scope));
            // Legacy Postman globals still used by older collections.
            String legacyResponseBody = (bResp == null || bResp.getResponseBody() == null)
                ? "" : bResp.getResponseBody();
            ScriptableObject.putProperty(scope, "responseBody", legacyResponseBody);

            NativeObject legacyResponseCode = new NativeObject();
            ScriptRuntime.setObjectProtoAndParent(legacyResponseCode, scope);
            legacyResponseCode.put("code", legacyResponseCode, bResp == null ? 0 : bResp.getStatusCode());
            legacyResponseCode.put("name", legacyResponseCode, "");
            ScriptableObject.putProperty(scope, "responseCode", legacyResponseCode);

            Object legacyResponseHeaders = Context.javaToJS(
                (bResp == null || bResp.getResponseHeaders() == null)
                    ? new ArrayList<>()
                    : bResp.getResponseHeaders(),
                scope
            );
            ScriptableObject.putProperty(scope, "responseHeaders", legacyResponseHeaders);
            registerGlobalFn(scope, "test",   "testImpl",   String.class, Object.class);
            registerGlobalFn(scope, "expect", "expectImpl", Object.class);

            // Global helpers used by real-world auth scripts.
            registerGlobalFn(scope, "btoa", "btoaImpl", String.class);
            registerGlobalFn(scope, "atob", "atobImpl", String.class);

            // crypto-js facade for scripts that do
            //   let CryptoJS = require("crypto-js");
            //   CryptoJS.HmacSHA256(msg, key)
            //   CryptoJS.enc.Utf8.parse(...)
            //   CryptoJS.enc.Base64.stringify(...)
            // Rhino has no Node.js require(); without this, real-world JWT-signing
            // pre-request scripts abort on line 1 with ReferenceError and the
            // request goes out with a literal {{token}} placeholder → 400/401.
            ScriptableObject.putProperty(scope, "__burpManCryptoJs",
                Context.javaToJS(new CryptoJsHost(), scope));

            // Wire the per-script log sink so test()/expect() can surface
            // pass/fail messages through the same log pipe pm.* uses.
            SCRIPT_LOG_THREADLOCAL.set(s -> ctx.log(s));

            // Rhino 1.7.x has a long-standing quirk where
            // {@code "foo?bar".split("?")} treats the argument as a Java
            // regex Pattern, so a raw '?' / '*' / '+' / '(' / '[' / etc.
            // throws PatternSyntaxException ("Dangling meta character '?'").
            // Real Postman/Bruno scripts assume the V8/Node behaviour where
            // a string argument is matched literally. We monkey-patch
            // String.prototype.split here so the user's own script reads
            // as if it ran on V8.
            try {
                cx.evaluateString(scope,
                    "if (typeof require === 'undefined') {\n" +
                    "  var require = function(name) {\n" +
                    "    if (name === 'crypto-js') return __burpManCryptoJs;\n" +
                    "    if (name === 'atob') return atob;\n" +
                    "    if (name === 'btoa') return btoa;\n" +
                    "    if (name === 'moment') return __burpManMoment;\n" +
                    "    throw new Error('Module not available in BurpMan script sandbox: ' + name);\n" +
                    "  };\n" +
                    "}\n" +
                    // Minimal moment.js shim — covers the format tokens Bruno collections
                    // typically use for JWT payload date/time fields (moment().format('YYYY-MM-DD'),
                    // moment().format('HH:mm:ss'), moment().add(15, 'minutes').unix(), etc.). Not
                    // a full moment implementation — just enough that JWT-signing pre-request
                    // scripts don't abort on ReferenceError before setting the token variable.
                    "var __burpManMoment = (function(){\n" +
                    "  function pad(n,w){ n=String(n); w=w||2; while(n.length<w) n='0'+n; return n; }\n" +
                    "  function fmtDate(d, s){\n" +
                    "    if (!s) return d.toISOString();\n" +
                    "    var Y=d.getFullYear(), M=d.getMonth()+1, D=d.getDate(), H=d.getHours(), m=d.getMinutes(), sec=d.getSeconds(), ms=d.getMilliseconds();\n" +
                    "    return String(s)\n" +
                    "      .replace(/YYYY/g, pad(Y,4)).replace(/YY/g, pad(Y%100,2))\n" +
                    "      .replace(/MM/g, pad(M,2)).replace(/M/g, String(M))\n" +
                    "      .replace(/DD/g, pad(D,2)).replace(/D/g, String(D))\n" +
                    "      .replace(/HH/g, pad(H,2)).replace(/H/g, String(H))\n" +
                    "      .replace(/mm/g, pad(m,2)).replace(/ss/g, pad(sec,2))\n" +
                    "      .replace(/SSS/g, pad(ms,3));\n" +
                    "  }\n" +
                    "  function make(d){\n" +
                    "    d = d || new Date();\n" +
                    "    return {\n" +
                    "      format: function(s){ return fmtDate(d, s); },\n" +
                    "      unix: function(){ return Math.floor(d.getTime()/1000); },\n" +
                    "      valueOf: function(){ return d.getTime(); },\n" +
                    "      toISOString: function(){ return d.toISOString(); },\n" +
                    "      toDate: function(){ return d; },\n" +
                    "      add: function(n, unit){\n" +
                    "        var ms = 0; n = Number(n); unit = String(unit||'').toLowerCase();\n" +
                    "        if (unit==='ms'||unit==='milliseconds') ms = n;\n" +
                    "        else if (unit==='s'||unit==='second'||unit==='seconds') ms = n*1000;\n" +
                    "        else if (unit==='m'||unit==='minute'||unit==='minutes') ms = n*60*1000;\n" +
                    "        else if (unit==='h'||unit==='hour'||unit==='hours') ms = n*3600*1000;\n" +
                    "        else if (unit==='d'||unit==='day'||unit==='days') ms = n*86400*1000;\n" +
                    "        return make(new Date(d.getTime()+ms));\n" +
                    "      },\n" +
                    "      subtract: function(n, unit){ return this.add(-n, unit); }\n" +
                    "    };\n" +
                    "  }\n" +
                    "  var m = function(v){ return make(v ? new Date(v) : new Date()); };\n" +
                    "  m.utc = function(v){ return make(v ? new Date(v) : new Date()); };\n" +
                    "  m.unix = function(t){ return make(new Date(Number(t)*1000)); };\n" +
                    "  return m;\n" +
                    "})();\n",
                    "<burpman-require>", 1, null);
            } catch (Throwable ignore) { /* polyfill best-effort */ }

            // Expose process.env.* so Bruno collections that read secrets from
            // the OS environment (e.g. `{{process.env.US_QQ_CLIENT_SECRET}}` in
            // a URL, or `process.env.API_KEY` in a script) work without users
            // having to manually re-declare each secret as a collection var.
            // Backed by System.getenv() at access time via ProcessEnvHost.
            ScriptableObject.putProperty(scope, "__burpManProcessEnv",
                Context.javaToJS(new ProcessEnvHost(), scope));
            try {
                cx.evaluateString(scope,
                    "if (typeof process === 'undefined') {\n" +
                    "  var process = { env: new Proxy({}, {\n" +
                    "    get: function(_, k){ return __burpManProcessEnv.get(String(k)); },\n" +
                    "    has: function(_, k){ return __burpManProcessEnv.get(String(k)) !== null; }\n" +
                    "  }) };\n" +
                    "}\n",
                    "<burpman-process-env>", 1, null);
            } catch (Throwable ignore) {
                // Rhino <1.7.14 has no Proxy. Fallback: eagerly copy all
                // OS env vars into a plain object. Still gives users
                // process.env.NAME lookups, just without live re-reads.
                try {
                    NativeObject envObj = new NativeObject();
                    ScriptRuntime.setObjectProtoAndParent(envObj, scope);
                    for (Map.Entry<String,String> e : System.getenv().entrySet()) {
                        envObj.put(e.getKey(), envObj, e.getValue());
                    }
                    NativeObject procObj = new NativeObject();
                    ScriptRuntime.setObjectProtoAndParent(procObj, scope);
                    procObj.put("env", procObj, envObj);
                    ScriptableObject.putProperty(scope, "process", procObj);
                } catch (Throwable ignore2) { /* best-effort */ }
            }

            try {
                cx.evaluateString(scope,
                    "(function(){\n" +
                    "  var nativeSplit = String.prototype.split;\n" +
                    "  String.prototype.split = function(sep, limit) {\n" +
                    "    if (typeof sep === 'string') {\n" +
                    "      var s = String(this);\n" +
                    "      if (sep === '') { return nativeSplit.call(s, ''); }\n" +
                    "      var out = [];\n" +
                    "      var i = 0, n = s.length, slen = sep.length;\n" +
                    "      while (i <= n) {\n" +
                    "        var idx = s.indexOf(sep, i);\n" +
                    "        if (idx < 0) { out.push(s.substring(i)); break; }\n" +
                    "        out.push(s.substring(i, idx));\n" +
                    "        i = idx + slen;\n" +
                    "        if (typeof limit === 'number' && out.length >= limit) break;\n" +
                    "      }\n" +
                    "      if (typeof limit === 'number') return out.slice(0, limit);\n" +
                    "      return out;\n" +
                    "    }\n" +
                    "    return nativeSplit.apply(this, arguments);\n" +
                    "  };\n" +
                    "})();\n",
                    "<burpman-polyfills>", 1, null);
            } catch (Throwable ignore) { /* polyfill best-effort */ }

            try {
                cx.evaluateString(scope, preprocessed, "<pm-script>", 1, null);
            } catch (org.mozilla.javascript.RhinoException re) {
                // Surface the line/column so users can see exactly which
                // unsupported syntax tripped the engine instead of silently
                // failing back to the mini-interpreter.
                String where = "line " + re.lineNumber()
                        + (re.columnNumber() > 0 ? ":col " + re.columnNumber() : "");
                ctx.log("[script error] " + re.details() + " (" + where + ")");
                throw re;
            }
        } finally {
            SCRIPT_LOG_THREADLOCAL.remove();
            Context.exit();
        }
    }

    /**
     * Rewrite ES2018 object spread {@code {...x}} into Rhino-compatible
     * {@code Object.assign({}, x)} expressions. Rhino 1.7.15 supports spread
     * in arrays and function calls but not in object literals.
     * <p>
     * Patterns handled:
     * <pre>
     *   { ...props }                 -> Object.assign({}, props)
     *   { foo: 1, ...rest, bar: 2 }  -> Object.assign({foo:1}, rest, {bar:2})
     * </pre>
     * Naive but string-safe: skips literals/comments and only fires inside
     * top-level braces of object literals (heuristically detected via depth
     * + previous-token rules). When in doubt we leave the source alone, so
     * the worst case is "Rhino still can't parse" rather than corruption.
     */
    private static String rewriteObjectSpread(String src) {
        if (src == null || src.indexOf("...") < 0) return src;
        // For our use case the simple pattern is enough: whenever we see a
        // ',' or '{' followed by '...identifier' (possibly preceded by ws
        // or a newline) inside what looks like an object literal, wrap the
        // whole literal in Object.assign(...).
        // Implement as a token-aware scanner; if we can't safely rewrite
        // a particular brace, we leave it alone.
        StringBuilder out = new StringBuilder(src.length() + 64);
        int i = 0;
        int n = src.length();
        boolean inLine = false, inBlock = false;
        char strQ = 0;
        while (i < n) {
            char c = src.charAt(i);
            if (inLine) {
                out.append(c); i++;
                if (c == '\n') inLine = false;
                continue;
            }
            if (inBlock) {
                out.append(c); i++;
                if (c == '*' && i < n && src.charAt(i) == '/') { out.append('/'); i++; inBlock = false; }
                continue;
            }
            if (strQ != 0) {
                out.append(c); i++;
                if (c == '\\' && i < n) { out.append(src.charAt(i)); i++; continue; }
                if (c == strQ) strQ = 0;
                continue;
            }
            // start of comment
            if (c == '/' && i + 1 < n) {
                char nxt = src.charAt(i + 1);
                if (nxt == '/') { out.append("//"); i += 2; inLine = true; continue; }
                if (nxt == '*') { out.append("/*"); i += 2; inBlock = true; continue; }
            }
            if (c == '\'' || c == '"' || c == '`') { strQ = c; out.append(c); i++; continue; }

            // detect object spread: '{' (or after an opening brace inside an
            // object literal) followed by ...ident
            if (c == '{') {
                // Try to parse a balanced block and see if it's an object literal
                // containing a spread.
                int end = findMatchingBrace(src, i);
                if (end > i) {
                    String inner = src.substring(i + 1, end);
                    if (containsTopLevelSpread(inner) && looksLikeObjectLiteral(src, i, inner)) {
                        String rewritten = rewriteSingleObjectLiteral(inner);
                        out.append(rewritten);
                        i = end + 1;
                        continue;
                    }
                }
            }
            out.append(c); i++;
        }
        return out.toString();
    }

    private static int findMatchingBrace(String s, int openIdx) {
        int depth = 0;
        boolean inLine = false, inBlock = false;
        char strQ = 0;
        for (int i = openIdx; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inLine) { if (c == '\n') inLine = false; continue; }
            if (inBlock) { if (c == '*' && i + 1 < s.length() && s.charAt(i + 1) == '/') { i++; inBlock = false; } continue; }
            if (strQ != 0) {
                if (c == '\\') { i++; continue; }
                if (c == strQ) strQ = 0;
                continue;
            }
            if (c == '/' && i + 1 < s.length()) {
                char nxt = s.charAt(i + 1);
                if (nxt == '/') { i++; inLine = true; continue; }
                if (nxt == '*') { i++; inBlock = true; continue; }
            }
            if (c == '\'' || c == '"' || c == '`') { strQ = c; continue; }
            if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    private static boolean containsTopLevelSpread(String inner) {
        int depth = 0;
        boolean inLine = false, inBlock = false;
        char strQ = 0;
        for (int i = 0; i < inner.length() - 2; i++) {
            char c = inner.charAt(i);
            if (inLine) { if (c == '\n') inLine = false; continue; }
            if (inBlock) { if (c == '*' && i + 1 < inner.length() && inner.charAt(i + 1) == '/') { i++; inBlock = false; } continue; }
            if (strQ != 0) {
                if (c == '\\') { i++; continue; }
                if (c == strQ) strQ = 0;
                continue;
            }
            if (c == '/' && i + 1 < inner.length()) {
                char nxt = inner.charAt(i + 1);
                if (nxt == '/') { i++; inLine = true; continue; }
                if (nxt == '*') { i++; inBlock = true; continue; }
            }
            if (c == '\'' || c == '"' || c == '`') { strQ = c; continue; }
            if (c == '(' || c == '[' || c == '{') depth++;
            else if (c == ')' || c == ']' || c == '}') depth--;
            if (depth != 0) continue;
            if (c == '.' && i + 2 < inner.length()
                    && inner.charAt(i + 1) == '.' && inner.charAt(i + 2) == '.') {
                // Make sure prev non-ws is '{' or ',' (or start)
                int p = i - 1;
                while (p >= 0 && Character.isWhitespace(inner.charAt(p))) p--;
                if (p < 0) return true;
                char pc = inner.charAt(p);
                if (pc == ',' || pc == '{') return true;
            }
        }
        return false;
    }

    private static boolean looksLikeObjectLiteral(String src, int braceIdx, String inner) {
        // Heuristic: an object literal appears in expression position. Look at
        // the previous non-ws character. If it's '(' ',' '=' ':' 'return' '?'
        // '||' '&&' or start of file, treat as object literal. If it's a
        // statement starter (';' '{' '}' newline-then-keyword), treat as block.
        int p = braceIdx - 1;
        while (p >= 0 && Character.isWhitespace(src.charAt(p))) p--;
        if (p < 0) return false;
        char pc = src.charAt(p);
        if (pc == '(' || pc == ',' || pc == '=' || pc == ':' || pc == '?'
                || pc == '|' || pc == '&' || pc == '!' || pc == '+'
                || pc == '-' || pc == '*' || pc == '/' || pc == '%'
                || pc == '<' || pc == '>' || pc == '~') {
            return true;
        }
        // `return {` is also an object literal
        if (pc == 'n' && p >= 5 && src.regionMatches(p - 5, "return", 0, 6)) {
            return true;
        }
        // `=> {` could be either; if it has a top-level spread it's almost
        // certainly an object literal arrow body would use parens around obj.
        if (pc == '>' && p > 0 && src.charAt(p - 1) == '=') return false; // arrow block body
        return false;
    }

    /** Rewrite the inner content of an object literal that contains spreads. */
    private static String rewriteSingleObjectLiteral(String inner) {
        // Split inner on top-level commas.
        java.util.List<String> parts = splitTopLevelCommas(inner);
        StringBuilder out = new StringBuilder("Object.assign({}");
        StringBuilder current = new StringBuilder();
        boolean openLiteral = false;
        for (String p : parts) {
            String t = p.trim();
            if (t.isEmpty()) continue;
            if (t.startsWith("...")) {
                if (openLiteral) {
                    out.append(", {").append(current).append("}");
                    current.setLength(0);
                    openLiteral = false;
                }
                out.append(", ").append(t.substring(3).trim());
            } else {
                if (openLiteral) current.append(", ");
                current.append(t);
                openLiteral = true;
            }
        }
        if (openLiteral) {
            out.append(", {").append(current).append("}");
        }
        out.append(")");
        return out.toString();
    }

    private static java.util.List<String> splitTopLevelCommas(String s) {
        java.util.List<String> out = new java.util.ArrayList<>();
        int depth = 0;
        boolean inLine = false, inBlock = false;
        char strQ = 0;
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inLine) { cur.append(c); if (c == '\n') inLine = false; continue; }
            if (inBlock) { cur.append(c); if (c == '*' && i + 1 < s.length() && s.charAt(i + 1) == '/') { cur.append('/'); i++; inBlock = false; } continue; }
            if (strQ != 0) {
                cur.append(c);
                if (c == '\\' && i + 1 < s.length()) { cur.append(s.charAt(i + 1)); i++; continue; }
                if (c == strQ) strQ = 0;
                continue;
            }
            if (c == '/' && i + 1 < s.length()) {
                char nxt = s.charAt(i + 1);
                if (nxt == '/') { cur.append("//"); i++; inLine = true; continue; }
                if (nxt == '*') { cur.append("/*"); i++; inBlock = true; continue; }
            }
            if (c == '\'' || c == '"' || c == '`') { strQ = c; cur.append(c); continue; }
            if (c == '(' || c == '[' || c == '{') { depth++; cur.append(c); continue; }
            if (c == ')' || c == ']' || c == '}') { depth--; cur.append(c); continue; }
            if (c == ',' && depth == 0) { out.add(cur.toString()); cur.setLength(0); continue; }
            cur.append(c);
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }

    /**
     * Rewrite ES2020 optional chaining {@code a?.b}, {@code a?.b()} and
     * {@code a?.[k]} into ES5 ternary expressions. Pure regex pass; only
     * touches text outside of string literals and comments.
     * <pre>
     *   res?.json()       -> (res==null?void 0:res.json())
     *   foo?.bar          -> (foo==null?void 0:foo.bar)
     *   arr?.[0]          -> (arr==null?void 0:arr[0])
     * </pre>
     */
    private static String rewriteOptionalChaining(String src) {
        if (src == null || src.indexOf("?.") < 0) return src;
        StringBuilder out = new StringBuilder(src.length() + 64);
        int i = 0;
        int n = src.length();
        boolean inLine = false, inBlock = false;
        char strQ = 0;
        while (i < n) {
            char c = src.charAt(i);
            if (inLine) { out.append(c); if (c == '\n') inLine = false; i++; continue; }
            if (inBlock) { out.append(c); if (c == '*' && i + 1 < n && src.charAt(i + 1) == '/') { out.append('/'); i += 2; inBlock = false; continue; } i++; continue; }
            if (strQ != 0) {
                out.append(c); i++;
                if (c == '\\' && i < n) { out.append(src.charAt(i)); i++; continue; }
                if (c == strQ) strQ = 0;
                continue;
            }
            if (c == '/' && i + 1 < n) {
                char nxt = src.charAt(i + 1);
                if (nxt == '/') { out.append("//"); i += 2; inLine = true; continue; }
                if (nxt == '*') { out.append("/*"); i += 2; inBlock = true; continue; }
            }
            if (c == '\'' || c == '"' || c == '`') { strQ = c; out.append(c); i++; continue; }
            // Match a?.b / a?.() / a?.[
            if (c == '?' && i + 1 < n && src.charAt(i + 1) == '.') {
                // Walk back to find the receiver expression.
                int recvEnd = out.length();
                int recvStart = findReceiverStart(out, recvEnd);
                if (recvStart >= 0) {
                    String recv = out.substring(recvStart, recvEnd);
                    out.delete(recvStart, recvEnd);
                    String wrapped = "(" + recv + "==null?void 0:" + recv;
                    out.append(wrapped);
                    // After ?. comes . or ( or [ — emit accordingly:
                    int j = i + 2;
                    if (j < n && src.charAt(j) == '(') {
                        // ?.( method call: emit the parens as a call on recv
                        // Pattern: a?.(args)  =>  (recv==null?void 0:recv(args))
                        // We've already emitted recv. Now skip the '(' below and
                        // emit it as the call.
                        i = j;
                        out.append('(');
                        i++; // consume '('
                        out.append(')');  // placeholder, will be wrong; abort
                        // Actually this branch is rare; bail and just keep original
                        // — restore state and copy ?. literally
                        out.setLength(recvStart);
                        out.append(recv);
                        out.append("?.");
                        i = i; // continue normally
                        continue;
                    } else if (j < n && src.charAt(j) == '[') {
                        out.append('[');
                        i = j + 1;
                        // Append until matching ']'
                        int depth = 1;
                        while (i < n && depth > 0) {
                            char cc = src.charAt(i);
                            out.append(cc);
                            if (cc == '[') depth++;
                            else if (cc == ']') depth--;
                            i++;
                        }
                        out.append(')');
                        continue;
                    } else {
                        // ?.identifier  (possibly followed by '(' for method call)
                        out.append('.');
                        i = j;
                        // Emit identifier
                        while (i < n) {
                            char cc = src.charAt(i);
                            if (Character.isLetterOrDigit(cc) || cc == '_' || cc == '$') { out.append(cc); i++; }
                            else break;
                        }
                        // If followed by '(' include the call too so the ?. wraps the result
                        if (i < n && src.charAt(i) == '(') {
                            int depth = 0;
                            while (i < n) {
                                char cc = src.charAt(i);
                                out.append(cc);
                                i++;
                                if (cc == '(') depth++;
                                else if (cc == ')') { depth--; if (depth == 0) break; }
                            }
                        }
                        out.append(')');
                        continue;
                    }
                }
            }
            out.append(c); i++;
        }
        return out.toString();
    }

    /** Walk back from {@code end} in {@code sb} to find the start of the
     *  receiver expression (identifier, member access, or balanced call). */
    private static int findReceiverStart(StringBuilder sb, int end) {
        int i = end - 1;
        // Skip trailing whitespace
        while (i >= 0 && Character.isWhitespace(sb.charAt(i))) i--;
        if (i < 0) return -1;
        // If ends with ')' or ']', walk back through balanced parens
        while (i >= 0) {
            char c = sb.charAt(i);
            if (c == ')' || c == ']') {
                char open = (c == ')') ? '(' : '[';
                int depth = 1;
                i--;
                while (i >= 0 && depth > 0) {
                    char cc = sb.charAt(i);
                    if (cc == c) depth++;
                    else if (cc == open) depth--;
                    i--;
                }
                continue;
            }
            if (c == '.' || Character.isLetterOrDigit(c) || c == '_' || c == '$') { i--; continue; }
            break;
        }
        return i + 1;
    }

    /**
     * Downgrade {@code let} / {@code const} declarations at statement boundaries
     * to {@code var}. Postman/Bruno scripts in the wild routinely redeclare the
     * same {@code let} (typically because two if/else branches each declare a
     * temp), which is fine in Node/V8 thanks to its block-scope analysis but
     * Rhino's ES6 parser treats as a SyntaxError. {@code var} hoisting absorbs
     * the duplicate without breaking the patterns we see.
     *
     * Conservative: only matches at start-of-line (with optional indent) and
     * after common statement separators. Skips matches inside strings / comments.
     */
    /** Rewrite {@code .split("X")} where X is a single character that's a
     *  regex metachar to {@code .split(/&#92;X/)}. Rhino routes Java-wrapped
     *  strings through {@code java.lang.String.split(regex)} which crashes
     *  on bare meta chars; rewriting to a literal regex bypasses the crash
     *  while staying semantically identical. */
    private static String rewriteSplitWithRegexMetachars(String src) {
        if (src == null || src.indexOf(".split(") < 0) return src;
        // .split("X") or .split('X') where X is one of: ? * + ( ) [ ] { } | ^ $ . \
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\\.split\\(\\s*([\"'])([?*+()\\[\\]{}|^$.\\\\])\\1\\s*\\)");
        java.util.regex.Matcher m = p.matcher(src);
        StringBuffer out = new StringBuffer(src.length() + 16);
        while (m.find()) {
            String ch = m.group(2);
            // Build the replacement string: ".split(/\X/)" where \X is a
            // regex literal matching X. We assemble plain-text first, then
            // hand it to quoteReplacement so any $/\ chars in ch don't get
            // re-interpreted by appendReplacement.
            String regexBody;
            if ("\\".equals(ch)) {
                regexBody = "\\\\\\\\"; // /\\\\/ in source = /\\/ in JS = matches single \
            } else {
                regexBody = "\\" + ch;
            }
            String repl = ".split(/" + regexBody + "/)";
            m.appendReplacement(out, java.util.regex.Matcher.quoteReplacement(repl));
        }
        m.appendTail(out);
        return out.toString();
    }

    /**
     * Strip {@code async} and {@code await} keywords that Rhino 1.7.15.1
     * treats as reserved-word errors at top-level or in some positions.
     *
     * <p>Postman/Bruno scripts commonly use:
     * <pre>
     *   await bru.sendRequest(cfg, async function(err, res) { ... });
     * </pre>
     * The user-visible semantics under Node.js is: dispatch the request,
     * wait for the response, run the callback with the result. Our
     * {@code bru.sendRequest} / {@code pm.sendRequest} host methods are
     * <b>synchronous</b> — they perform the HTTP round-trip and invoke
     * the callback before returning. Consequently, stripping the async
     * plumbing is behavior-preserving: the callback still fires, values
     * still land in the outer scope in the same order, and there is no
     * Promise to await because none was ever produced.
     *
     * <p>The scan is token-aware (skips strings and comments) and only
     * touches full {@code async} / {@code await} identifiers (word
     * boundaries on both sides).
     */
    private static String stripAsyncAwait(String src) {
        if (src == null) return src;
        if (src.indexOf("async") < 0 && src.indexOf("await") < 0) return src;
        StringBuilder out = new StringBuilder(src.length());
        int i = 0;
        int n = src.length();
        boolean inLine = false, inBlock = false;
        char strQ = 0;
        while (i < n) {
            char c = src.charAt(i);
            if (inLine) { out.append(c); if (c == '\n') inLine = false; i++; continue; }
            if (inBlock) {
                out.append(c);
                if (c == '*' && i + 1 < n && src.charAt(i + 1) == '/') {
                    out.append('/'); i += 2; inBlock = false; continue;
                }
                i++; continue;
            }
            if (strQ != 0) {
                out.append(c);
                if (c == '\\' && i + 1 < n) { out.append(src.charAt(i + 1)); i += 2; continue; }
                if (c == strQ) strQ = 0;
                i++; continue;
            }
            if (c == '/' && i + 1 < n) {
                char nxt = src.charAt(i + 1);
                if (nxt == '/') { out.append("//"); i += 2; inLine = true; continue; }
                if (nxt == '*') { out.append("/*"); i += 2; inBlock = true; continue; }
            }
            if (c == '\'' || c == '"' || c == '`') { strQ = c; out.append(c); i++; continue; }

            // Word boundary check on the left
            boolean leftOk = (i == 0) || isNonIdentChar(src.charAt(i - 1));
            if (leftOk && matchesWord(src, i, "async")) {
                // Skip "async" plus a single following space (if any) so
                // "async function" → "function", "async (" → "(".
                i += 5;
                if (i < n && (src.charAt(i) == ' ' || src.charAt(i) == '\t')) i++;
                continue;
            }
            if (leftOk && matchesWord(src, i, "await")) {
                i += 5;
                if (i < n && (src.charAt(i) == ' ' || src.charAt(i) == '\t')) i++;
                continue;
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    private static boolean matchesWord(String src, int off, String word) {
        int wl = word.length();
        if (off + wl > src.length()) return false;
        for (int k = 0; k < wl; k++) {
            if (src.charAt(off + k) != word.charAt(k)) return false;
        }
        int end = off + wl;
        if (end >= src.length()) return true;
        return isNonIdentChar(src.charAt(end));
    }

    private static boolean isNonIdentChar(char c) {
        return !(Character.isLetterOrDigit(c) || c == '_' || c == '$');
    }

    private static String downgradeLetConstToVar(String src) {
        if (src == null) return src;
        if (src.indexOf("let") < 0 && src.indexOf("const") < 0) return src;
        StringBuilder out = new StringBuilder(src.length() + 16);
        int i = 0;
        int n = src.length();
        boolean inLine = false, inBlock = false;
        char strQ = 0;
        boolean atStmtStart = true; // start of file is a statement boundary
        // We always downgrade const/let to var. Rhino 1.7's VERSION_ES6
        // enforces strict re-declaration / TDZ even for separate `if`
        // blocks at the same brace depth, which Postman/Bruno scripts
        // routinely violate (their V8 runtime is more lenient).  `var`
        // hoists, absorbing the duplicates without changing behavior for
        // the patterns we see (each branch only reads its own value).
        while (i < n) {
            char c = src.charAt(i);
            if (inLine) { out.append(c); if (c == '\n') { inLine = false; atStmtStart = true; } i++; continue; }
            if (inBlock) { out.append(c); if (c == '*' && i + 1 < n && src.charAt(i + 1) == '/') { out.append('/'); i += 2; inBlock = false; } else i++; continue; }
            if (strQ != 0) {
                out.append(c); i++;
                if (c == '\\' && i < n) { out.append(src.charAt(i)); i++; continue; }
                if (c == strQ) strQ = 0;
                continue;
            }
            // Detect string / comment starts
            if (c == '"' || c == '\'' || c == '`') { strQ = c; out.append(c); i++; atStmtStart = false; continue; }
            if (c == '/' && i + 1 < n) {
                char nx = src.charAt(i + 1);
                if (nx == '/') { inLine = true; out.append("//"); i += 2; continue; }
                if (nx == '*') { inBlock = true; out.append("/*"); i += 2; continue; }
            }
            // Try to match `let ` or `const ` at a statement boundary
            if (atStmtStart && c == 'l' && i + 3 < n
                    && src.charAt(i + 1) == 'e' && src.charAt(i + 2) == 't'
                    && isIdentBoundary(src.charAt(i + 3))) {
                out.append("var");
                i += 3;
                atStmtStart = false;
                continue;
            }
            if (atStmtStart && c == 'c' && i + 5 < n
                    && src.charAt(i + 1) == 'o' && src.charAt(i + 2) == 'n'
                    && src.charAt(i + 3) == 's' && src.charAt(i + 4) == 't'
                    && isIdentBoundary(src.charAt(i + 5))) {
                out.append("var");
                i += 5;
                atStmtStart = false;
                continue;
            }
            // Track statement boundaries: ; { } and start-of-line whitespace
            if (c == ';' || c == '{' || c == '}') { atStmtStart = true; out.append(c); i++; continue; }
            if (c == '\n') { atStmtStart = true; out.append(c); i++; continue; }
            if (c == ' ' || c == '\t' || c == '\r') { out.append(c); i++; continue; } // keep atStmtStart
            atStmtStart = false;
            out.append(c); i++;
        }
        return out.toString();
    }

    private static boolean isIdentBoundary(char c) {
        // Whitespace, brackets, operators all terminate an identifier.
        return !(Character.isLetterOrDigit(c) || c == '_' || c == '$');
    }

    /**
     * Rewrite {@code a ?? b} (nullish coalescing) into {@code (a==null?b:a)}.
     */
    private static String rewriteNullishCoalescing(String src) {
        if (src == null || src.indexOf("??") < 0) return src;
        // Token-aware scan; only fires outside strings/comments. We keep
        // it simple: when we see `??`, walk back to grab the LHS expression
        // (same algorithm as receiver extraction).
        StringBuilder out = new StringBuilder(src.length() + 32);
        int i = 0;
        int n = src.length();
        boolean inLine = false, inBlock = false;
        char strQ = 0;
        while (i < n) {
            char c = src.charAt(i);
            if (inLine) { out.append(c); if (c == '\n') inLine = false; i++; continue; }
            if (inBlock) { out.append(c); if (c == '*' && i + 1 < n && src.charAt(i + 1) == '/') { out.append('/'); i += 2; inBlock = false; continue; } i++; continue; }
            if (strQ != 0) {
                out.append(c); i++;
                if (c == '\\' && i < n) { out.append(src.charAt(i)); i++; continue; }
                if (c == strQ) strQ = 0;
                continue;
            }
            if (c == '/' && i + 1 < n) {
                char nxt = src.charAt(i + 1);
                if (nxt == '/') { out.append("//"); i += 2; inLine = true; continue; }
                if (nxt == '*') { out.append("/*"); i += 2; inBlock = true; continue; }
            }
            if (c == '\'' || c == '"' || c == '`') { strQ = c; out.append(c); i++; continue; }
            if (c == '?' && i + 1 < n && src.charAt(i + 1) == '?'
                    && (i + 2 >= n || src.charAt(i + 2) != '=')) {
                int recvEnd = out.length();
                int recvStart = findReceiverStart(out, recvEnd);
                if (recvStart >= 0) {
                    String lhs = out.substring(recvStart, recvEnd);
                    // Find RHS up to next top-level operator/comma
                    i += 2; // consume '??'
                    StringBuilder rhs = new StringBuilder();
                    int depth = 0;
                    char rstrQ = 0;
                    while (i < n) {
                        char cc = src.charAt(i);
                        if (rstrQ != 0) {
                            rhs.append(cc);
                            if (cc == '\\' && i + 1 < n) { rhs.append(src.charAt(i + 1)); i += 2; continue; }
                            if (cc == rstrQ) rstrQ = 0;
                            i++; continue;
                        }
                        if (cc == '\'' || cc == '"' || cc == '`') { rstrQ = cc; rhs.append(cc); i++; continue; }
                        if (cc == '(' || cc == '[' || cc == '{') { depth++; rhs.append(cc); i++; continue; }
                        if (cc == ')' || cc == ']' || cc == '}') { if (depth == 0) break; depth--; rhs.append(cc); i++; continue; }
                        if (depth == 0 && (cc == ',' || cc == ';')) break;
                        rhs.append(cc); i++;
                    }
                    out.delete(recvStart, recvEnd);
                    out.append("(").append(lhs).append("==null?").append(rhs.toString().trim()).append(":").append(lhs).append(")");
                    continue;
                }
            }
            out.append(c); i++;
        }
        return out.toString();
    }

    private static void registerGlobalFn(Scriptable scope, String jsName, String javaName, Class<?>... params) {
        try {
            Method m = RhinoScriptEngine.class.getDeclaredMethod(javaName, params);
            org.mozilla.javascript.FunctionObject fn = new org.mozilla.javascript.FunctionObject(jsName, m, scope);
            ScriptableObject.putProperty(scope, jsName, fn);
        } catch (Throwable ignore) { /* best-effort */ }
    }

    @SuppressWarnings("unused") // called from JS via reflection
    public static String btoaImpl(String s) {
        if (s == null) return "";
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unused")
    public static String atobImpl(String s) {
        if (s == null) return "";
        // Real browser/Node atob() is far more forgiving than Java's strict
        // Base64.getDecoder(): it silently accepts URL-safe base64 (- and _),
        // strips whitespace/newlines, and tolerates missing OR excess padding.
        // Java's strict decoder rejects any of these — which caused
        // `atob(bru.getEnvVar('VarArrowJWTKEY'))` to silently return "" for
        // real-world env values with an extra trailing `=` (yielding an
        // empty HMAC key downstream and 401 responses). Mirror browser
        // behaviour: sanitize input, try the MIME decoder first (which
        // ignores non-alphabet chars), then fall back to strict decoder,
        // then to URL-safe decoder — in that order.
        String cleaned = s.replaceAll("\\s+", "")
                          .replace('-', '+')
                          .replace('_', '/');
        // Strip trailing `=` and re-pad to length%4 == 0 so both malformed
        // ("KE1jUWhUajQ0=" — 41 chars) and unpadded ("KE1jUWhUajQ0" — 40
        // chars) inputs land on a valid multiple-of-4 length. Excess `=`
        // beyond one full padding group is dropped.
        String stripped = cleaned.replaceAll("=+$", "");
        int rem = stripped.length() % 4;
        if (rem == 2) stripped = stripped + "==";
        else if (rem == 3) stripped = stripped + "=";
        else if (rem == 1) {
            // Length%4==1 is never valid base64 — best effort: drop 1 char.
            stripped = stripped.substring(0, stripped.length() - 1);
        }
        try {
            return new String(Base64.getDecoder().decode(stripped), StandardCharsets.UTF_8);
        } catch (Exception ignore) {}
        // Last-ditch: MIME decoder is more forgiving of odd characters that
        // slip through — e.g. some collections paste base64 embedded in HTML.
        try {
            return new String(Base64.getMimeDecoder().decode(stripped), StandardCharsets.UTF_8);
        } catch (Exception ignore) {}
        return "";
    }

    /** Bruno-style top-level {@code test(name, fn)}. Runs the function in a
     *  try/catch so an assertion failure inside one test doesn't abort the
     *  whole script — surfaces pass/fail through the script log instead. */
    @SuppressWarnings("unused")
    public static Object testImpl(String name, Object fn) {
        java.util.function.Consumer<String> log = SCRIPT_LOG_THREADLOCAL.get();
        if (log == null) log = s -> {};
        java.util.List<burp.models.ExecutedRequest.TestResult> sink = TEST_RESULTS_THREADLOCAL.get();
        String shownName = name == null ? "(unnamed)" : name;
        if (!(fn instanceof org.mozilla.javascript.Function)) {
            log.accept("[test] ⚠ \"" + shownName + "\" — second argument is not a function");
            if (sink != null) sink.add(new burp.models.ExecutedRequest.TestResult(
                shownName, false, "second argument is not a function"));
            return null;
        }
        org.mozilla.javascript.Function f = (org.mozilla.javascript.Function) fn;
        Context cx = Context.getCurrentContext();
        Scriptable scope = f.getParentScope();
        try {
            f.call(cx, scope, scope, new Object[0]);
            log.accept("[test] ✓ " + shownName);
            if (sink != null) sink.add(new burp.models.ExecutedRequest.TestResult(shownName, true, null));
        } catch (Throwable t) {
            log.accept("[test] ✗ " + shownName + " — " + t.getMessage());
            if (sink != null) sink.add(new burp.models.ExecutedRequest.TestResult(
                shownName, false, t.getMessage()));
        }
        return null;
    }

    /** Bruno-style top-level {@code expect(value)}. Returns a Chai-like
     *  fluent matcher so {@code expect(x).to.equal(y)},
     *  {@code expect(x).to.not.include(y)}, etc. work as scripts expect. */
    @SuppressWarnings("unused")
    public static Object expectImpl(Object actual) {
        return new ExpectChain(actual, false);
    }

    /** Per-script log sink for {@code test()} pass/fail messages.
     *  Set by {@link #run(String)} before evaluation, cleared in finally. */
    static final ThreadLocal<java.util.function.Consumer<String>> SCRIPT_LOG_THREADLOCAL =
        new ThreadLocal<>();
    /** Per-script collector for test() results so the runner can attach
     *  them to the Run Results panel. Caller sets this list before invoking
     *  runAndApply; testImpl appends to it as tests fire. */
    public static final ThreadLocal<java.util.List<burp.models.ExecutedRequest.TestResult>>
        TEST_RESULTS_THREADLOCAL = new ThreadLocal<>();
    /** Process-wide reference to the BurpMan {@link burp.service.CookieJar}.
     *  Used by Bruno's {@code bru.cookies.jar().clear()} to wipe session
     *  cookies before multi-step auth flows. {@link AtomicReference} so
     *  PostmanImporter can publish its single jar instance once at startup
     *  without requiring scripts to know about it. */
    public static final java.util.concurrent.atomic.AtomicReference<burp.service.CookieJar>
        SCRIPT_COOKIE_JAR = new java.util.concurrent.atomic.AtomicReference<>();

    /** Per-script signal from {@code bru.setNextRequest(name)}. The runner
     *  reads + clears this after each post-response script. Empty string
     *  means "stop the run"; a name means "jump forward to that request,
     *  skipping anything in between". {@code null} (default) means "continue
     *  normally". Thread-local so concurrent runs don't cross-talk. */
    public static final ThreadLocal<String> NEXT_REQUEST_THREADLOCAL =
        new ThreadLocal<>();

    // =====================================================================
    // Host objects exposed to JS scripts
    // =====================================================================

    /** Top-level {@code pm} object — mirrors Postman's documented surface. */
    public static final class PmHost {
        private final ScriptContext ctx;
        private final PostmanCollection.Request currentRequest;
        private final Scriptable jsScope;
        public final VariablesHost variables;
        public final VariablesHost environment;
        public final VariablesHost collectionVariables;
        public final VariablesHost globals;
        public final RequestHost request;
        public final ResponseHost response;
        public final InfoHost info;

        PmHost(ScriptContext ctx, PostmanCollection.Request currentRequest, Scriptable jsScope) {
            this.ctx = ctx;
            this.currentRequest = currentRequest;
            this.jsScope = jsScope;
            this.variables = new VariablesHost(ctx, VariablesHost.Scope.GLOBAL);
            this.environment = new VariablesHost(ctx, VariablesHost.Scope.ENV);
            this.collectionVariables = new VariablesHost(ctx, VariablesHost.Scope.COLLECTION);
            this.globals = new VariablesHost(ctx, VariablesHost.Scope.GLOBAL);
            this.request = new RequestHost(currentRequest);
            this.response = new ResponseHost(ctx.getExecutedRequest(), jsScope);
            this.info = new InfoHost();
        }

        // postman.setEnvironmentVariable / setGlobalVariable aliases
        public void setEnvironmentVariable(String k, Object v) { environment.set(k, v); }
        public Object getEnvironmentVariable(String k) { return environment.get(k); }
        public void setGlobalVariable(String k, Object v) { globals.set(k, v); }
        public Object getGlobalVariable(String k) { return globals.get(k); }

        // Legacy postman.clear* / unset* — used by older Postman collections
        // (2018-era) to reset env/globals inside collection-level pre-request
        // scripts. Without these, scripts that start with a wall of
        // postman.clearEnvironmentVariable(...) calls crash on line 1 and the
        // rest of the script (which typically sets baseUrl / auth vars) never
        // runs, leaving every {{var}} unresolved at send time.
        public void clearEnvironmentVariable(String k) {
            if (k == null) return;
            ctx.getEnvironmentVariables().remove(k);
        }
        public void clearEnvironmentVariables() {
            ctx.getEnvironmentVariables().clear();
        }
        public void clearGlobalVariable(String k) {
            if (k == null) return;
            ctx.getGlobalVariables().remove(k);
        }
        public void clearGlobalVariables() {
            ctx.getGlobalVariables().clear();
        }
        public void unsetEnvironmentVariable(String k) { clearEnvironmentVariable(k); }
        public void unsetGlobalVariable(String k) { clearGlobalVariable(k); }

        /** {@code postman.setNextRequest(name)} — Postman's classic flow
         *  control. Empty/null stops the run, a name jumps forward
         *  (skipping intervening requests). Mirrors {@code bru.setNextRequest}
         *  so collections that mix Postman and Bruno conventions both work. */
        public void setNextRequest(String name) {
            String s = (name == null) ? "" : name;
            NEXT_REQUEST_THREADLOCAL.set(s);
        }

        /** {@code pm.test(name, fn)} — registers a Postman test case. Mirrors
         *  the bare {@code test(...)} global so scripts can use either form
         *  (real Postman scripts use {@code pm.test}; real Bruno scripts use
         *  bare {@code test}). Both wire into the same TEST_RESULTS_THREADLOCAL
         *  so the Run Results panel sees pass/fail rows either way. */
        public Object test(String name, Object fn) {
            return testImpl(name, fn);
        }

        /** {@code pm.expect(value)} — Chai-like fluent matcher. Same as
         *  {@code expectImpl} so collections using either {@code pm.expect}
         *  or bare {@code expect} get identical behavior. */
        public Object expect(Object actual) {
            return expectImpl(actual);
        }

        /**
         * Synchronously fire an HTTP request from inside a script and invoke
         * the callback with {@code (err, response)} just like Postman's
         * runtime would. Implements the most-used pieces of the real Postman
         * contract:
         * <pre>
         *   pm.sendRequest('https://example.com/x', function(err, res) {...});
         *   pm.sendRequest({url, method, header, body}, function(err, res) {...});
         * </pre>
         */
        public Object sendRequest(Object configOrUrl, Object cb) {
            // Respect thread interruption — when the user clicks Stop on the
            // Send button, the pre-script worker thread is interrupted, and
            // we abort here instead of firing the next token endpoint.
            if (Thread.currentThread().isInterrupted()) {
                ctx.log("[pm.sendRequest] aborted (thread interrupted)");
                invokeCallback(cb, "Cancelled by user", null);
                return null;
            }
            String url;
            String method = "GET";
            Map<String, String> headers = new HashMap<>();
            String body = null;
            String bodyMode = null;

            if (configOrUrl instanceof CharSequence) {
                url = configOrUrl.toString();
            } else if (configOrUrl instanceof Scriptable) {
                Scriptable cfg = (Scriptable) configOrUrl;
                url = stringProp(cfg, "url");
                String m = stringProp(cfg, "method");
                if (m != null && !m.isEmpty()) method = m.toUpperCase();
                Object hdr = ScriptableObject.getProperty(cfg, "header");
                headers = readHeaders(hdr);
                Object bodyObj = ScriptableObject.getProperty(cfg, "body");
                if (bodyObj instanceof Scriptable && !(bodyObj instanceof CharSequence)) {
                    bodyMode = stringProp((Scriptable) bodyObj, "mode");
                }
                body = readBody(bodyObj);
            } else {
                invokeCallback(cb, "Unsupported sendRequest argument", null);
                return null;
            }

            if (url == null || url.isEmpty()) {
                invokeCallback(cb, "sendRequest: missing URL", null);
                return null;
            }

            // Best-effort {{var}} substitution against the current variable map.
            url = interpolate(url);
            for (Map.Entry<String, String> e : new ArrayList<>(headers.entrySet())) {
                headers.put(e.getKey(), interpolate(e.getValue()));
            }
            if (body != null) body = interpolate(body);

            // Body modes need authoritative Content-Type. Postman overrides
            // whatever the script set when the body has a mode declared, so
            // we do the same — otherwise OAuth endpoints reject the request.
            if (bodyMode != null) {
                String authoritative = null;
                if ("urlencoded".equalsIgnoreCase(bodyMode)
                        || "formdata".equalsIgnoreCase(bodyMode)) {
                    // We serialize formdata as urlencoded (works for OAuth /token
                    // endpoints which accept both multipart and urlencoded). True
                    // multipart needs binary parts which are uncommon in scripts.
                    authoritative = "application/x-www-form-urlencoded";
                } else if ("raw".equalsIgnoreCase(bodyMode) || "application/json".equalsIgnoreCase(bodyMode)) {
                    if (!hasHeaderCi(headers, "Content-Type")) {
                        // Best-effort: leave alone if user already set one.
                        authoritative = "application/json";
                    }
                }
                if (authoritative != null) {
                    putHeaderCi(headers, "Content-Type", authoritative);
                }
            }

            ctx.log("[pm.sendRequest] " + method + " " + url);

            MontoyaApi mApi = api;
            if (mApi == null) {
                invokeCallback(cb, "MontoyaApi not initialized — cannot fire pm.sendRequest", null);
                return null;
            }

            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod(method);
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    req = req.withAddedHeader(e.getKey(), e.getValue());
                }
                if (body != null && !body.isEmpty()) {
                    req = req.withBody(body);
                }
                HttpRequestResponse rr = burp.service.ProxyRouter.sendRequest(mApi, req);
                if (rr == null || rr.response() == null) {
                    invokeCallback(cb, "No response", null);
                    return null;
                }
                final String fbody = rr.response().bodyToString();
                final int status = rr.response().statusCode();
                ctx.log("[pm.sendRequest] -> " + status + " (" + (fbody == null ? 0 : fbody.length()) + " bytes)");

                // Build a Postman-shaped response object directly in the user's
                // script scope so res?.json() optional chaining and res.json()
                // calls hit real Rhino Function objects (not opaque Java
                // Callables that ?. can't unwrap).
                Context cx = Context.getCurrentContext();
                Scriptable scope = (jsScope != null) ? jsScope
                        : (cx != null ? cx.initStandardObjects() : null);
                NativeObject resObj = new NativeObject();
                ScriptRuntime.setObjectProtoAndParent(resObj, scope);
                resObj.put("code", resObj, (double) status);
                resObj.put("status", resObj, "OK");
                resObj.put("responseTime", resObj, 0);

                final Scriptable fScope = scope;
                org.mozilla.javascript.BaseFunction textFn = new org.mozilla.javascript.BaseFunction() {
                    @Override
                    public Object call(Context c, Scriptable s, Scriptable thisObj, Object[] args) {
                        return fbody == null ? "" : fbody;
                    }
                };
                ScriptRuntime.setObjectProtoAndParent(textFn, fScope);
                resObj.put("text", resObj, textFn);

                org.mozilla.javascript.BaseFunction jsonFn = new org.mozilla.javascript.BaseFunction() {
                    @Override
                    public Object call(Context c, Scriptable s, Scriptable thisObj, Object[] args) {
                        if (fbody == null || fbody.isEmpty()) return null;
                        // Prefer the script-scope JSON.parse so the parsed
                        // object's prototype chain matches the rest of the
                        // script. Falls back to NativeJSON.parse on older
                        // Rhino runtimes that lack a scope-bound JSON object.
                        try {
                            Object jsonObj = ScriptableObject.getProperty(fScope, "JSON");
                            if (jsonObj instanceof Scriptable) {
                                Scriptable js = (Scriptable) jsonObj;
                                Object pf = ScriptableObject.getProperty(js, "parse");
                                if (pf instanceof org.mozilla.javascript.Function) {
                                    return ((org.mozilla.javascript.Function) pf)
                                        .call(c, fScope, js, new Object[]{ fbody });
                                }
                            }
                        } catch (Throwable ignore) {}
                        try {
                            return org.mozilla.javascript.NativeJSON.parse(c, fScope, fbody, null);
                        } catch (Throwable t) { return null; }
                    }
                };
                ScriptRuntime.setObjectProtoAndParent(jsonFn, fScope);
                resObj.put("json", resObj, jsonFn);

                invokeCallback(cb, null, resObj);
                return null;
            } catch (Throwable t) {
                ctx.log("[pm.sendRequest] error: " + t.getMessage());
                invokeCallback(cb, t.getMessage(), null);
                return null;
            }
        }

        private static String stringProp(Scriptable cfg, String name) {
            Object v = ScriptableObject.getProperty(cfg, name);
            if (v == null || v == Scriptable.NOT_FOUND || v == Undefined.instance) return null;
            return Context.toString(v);
        }

        @SuppressWarnings("rawtypes")
        private static Map<String, String> readHeaders(Object hdr) {
            Map<String, String> out = new HashMap<>();
            if (hdr == null || hdr == Scriptable.NOT_FOUND) return out;
            // String form: "Header: Value" or "H1: V1\nH2: V2" or comma-separated.
            // Real-world Postman scripts often pass header as a single string for
            // single-header requests (e.g. `header: 'Content-Type: application/json'`).
            if (hdr instanceof CharSequence) {
                String s = hdr.toString();
                for (String line : s.split("[\\r\\n,]+")) {
                    int idx = line.indexOf(':');
                    if (idx > 0) {
                        String k = line.substring(0, idx).trim();
                        String v = line.substring(idx + 1).trim();
                        if (!k.isEmpty()) out.put(k, v);
                    }
                }
                return out;
            }
            // Object literal {Key: 'Val', ...}
            if (hdr instanceof Scriptable && !(hdr instanceof NativeArray)) {
                Scriptable s = (Scriptable) hdr;
                for (Object id : s.getIds()) {
                    String key = id.toString();
                    Object v = ScriptableObject.getProperty(s, key);
                    if (v != null && v != Scriptable.NOT_FOUND) out.put(key, Context.toString(v));
                }
                return out;
            }
            // Array: [{key:'X', value:'Y'}, ...]
            if (hdr instanceof NativeArray) {
                NativeArray arr = (NativeArray) hdr;
                for (long i = 0; i < arr.getLength(); i++) {
                    Object item = arr.get((int) i, arr);
                    if (item instanceof Scriptable) {
                        Scriptable it = (Scriptable) item;
                        String k = stringProp(it, "key");
                        String v = stringProp(it, "value");
                        if (k != null) out.put(k, v == null ? "" : v);
                    }
                }
            }
            return out;
        }

        private static boolean hasHeaderCi(Map<String, String> headers, String name) {
            for (String k : headers.keySet()) {
                if (k != null && k.equalsIgnoreCase(name)) return true;
            }
            return false;
        }

        private static void putHeaderCi(Map<String, String> headers, String name, String value) {
            // Remove any case variant of the header, then put the canonical name.
            headers.entrySet().removeIf(e -> e.getKey() != null && e.getKey().equalsIgnoreCase(name));
            headers.put(name, value);
        }

        private static String readBody(Object body) {
            if (body == null || body == Scriptable.NOT_FOUND) return null;
            if (body instanceof CharSequence) return body.toString();
            if (body instanceof Scriptable) {
                Scriptable s = (Scriptable) body;
                String raw = stringProp(s, "raw");
                if (raw != null) return raw;
                String mode = stringProp(s, "mode");
                // Handle urlencoded / formdata loosely
                if ("urlencoded".equals(mode) || "formdata".equals(mode)) {
                    Object items = ScriptableObject.getProperty(s, "urlencoded");
                    if (items == null || items == Scriptable.NOT_FOUND) {
                        items = ScriptableObject.getProperty(s, "formdata");
                    }
                    if (items instanceof NativeArray) {
                        StringBuilder sb = new StringBuilder();
                        NativeArray arr = (NativeArray) items;
                        for (long i = 0; i < arr.getLength(); i++) {
                            Object it = arr.get((int) i, arr);
                            if (it instanceof Scriptable) {
                                Scriptable ito = (Scriptable) it;
                                if (sb.length() > 0) sb.append('&');
                                sb.append(stringProp(ito, "key")).append('=').append(stringProp(ito, "value"));
                            }
                        }
                        return sb.toString();
                    }
                }
            }
            return null;
        }

        private void invokeCallback(Object cb, Object err, Object res) {
            if (!(cb instanceof Function)) return;
            try {
                Function fn = (Function) cb;
                Context cx = Context.getCurrentContext();
                // Use the user's actual script scope so closures inside the
                // callback can see env/locals from the surrounding script.
                Scriptable scope = (jsScope != null) ? jsScope
                        : (cx != null ? cx.initStandardObjects() : null);
                Object[] args = new Object[]{
                    err == null ? null : err,
                    res == null ? Undefined.instance : res
                };
                fn.call(cx, scope, scope, args);
            } catch (Throwable t) {
                ctx.log("[pm.sendRequest callback error] " + t.getMessage());
            }
        }

        private String interpolate(String s) {
            if (s == null || s.indexOf("{{") < 0) return s;
            StringBuilder out = new StringBuilder(s.length());
            int i = 0;
            while (i < s.length()) {
                int open = s.indexOf("{{", i);
                if (open < 0) { out.append(s, i, s.length()); break; }
                out.append(s, i, open);
                int close = s.indexOf("}}", open + 2);
                if (close < 0) { out.append(s, open, s.length()); break; }
                String key = s.substring(open + 2, close).trim();
                String v = ctx.getVariable(key);
                out.append(v == null ? "{{" + key + "}}" : v);
                i = close + 2;
            }
            return out.toString();
        }

        private static Callable asJsFunction(Scriptable scope, java.util.function.Function<Object[], Object> fn) {
            return (cx, sc, thisObj, args) -> fn.apply(args);
        }

        private static Object jsonParseToJs(Scriptable scope, String json) {
            try {
                JsonElement el = JsonParser.parseString(json);
                return jsonToJs(el, scope);
            } catch (Exception e) { return null; }
        }

        private static Object jsonToJs(JsonElement el, Scriptable scope) {
            if (el == null || el.isJsonNull()) return null;
            if (el.isJsonPrimitive()) {
                if (el.getAsJsonPrimitive().isBoolean()) return el.getAsBoolean();
                if (el.getAsJsonPrimitive().isNumber()) return el.getAsDouble();
                return el.getAsString();
            }
            if (el.isJsonArray()) {
                NativeArray arr = new NativeArray(0);
                int idx = 0;
                for (JsonElement e : el.getAsJsonArray()) {
                    arr.put(idx++, arr, jsonToJs(e, scope));
                }
                return arr;
            }
            if (el.isJsonObject()) {
                NativeObject obj = new NativeObject();
                for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                    obj.put(e.getKey(), obj, jsonToJs(e.getValue(), scope));
                }
                return obj;
            }
            return null;
        }
    }

    /** {@code pm.variables} / {@code pm.environment} / {@code pm.collectionVariables} / {@code pm.globals}. */
    public static final class VariablesHost {
        public enum Scope { GLOBAL, ENV, COLLECTION }
        private final ScriptContext ctx;
        private final Scope scope;
        VariablesHost(ScriptContext ctx, Scope scope) { this.ctx = ctx; this.scope = scope; }

        public void set(String k, Object v) {
            if (k == null) return;
            // Same undefined→no-op coercion as bru.setVar/setEnvVar so a
            // pm.environment.set("k", undefined) doesn't store the literal
            // string "undefined" / "" and poison the next request that
            // uses {{k}}.  Mirrors Postman's actual behavior — its scripts
            // wrap these calls in `if (value)` guards but the authentic
            // runtime also silently drops undefined writes.
            String s;
            if (v == null
                    || v == org.mozilla.javascript.Undefined.instance
                    || v instanceof org.mozilla.javascript.Undefined) {
                return;
            } else if (v instanceof org.mozilla.javascript.Wrapper) {
                Object u = ((org.mozilla.javascript.Wrapper) v).unwrap();
                if (u == null) return;
                s = Context.toString(u);
            } else {
                s = Context.toString(v);
            }
            if ("undefined".equals(s) || "null".equals(s) || s.isEmpty()) return;
            switch (scope) {
                case ENV:        ctx.getEnvironmentVariables().put(k, s); break;
                case COLLECTION: ctx.getCollectionVariables().put(k, s); break;
                default:         /* GLOBAL */ break;
            }
            ctx.setVariable(k, s);
        }
        public Object get(String k) {
            if (scope == Scope.ENV)        return nv(ctx.getEnvironmentVariables().get(k), ctx.getVariable(k));
            if (scope == Scope.COLLECTION) return nv(ctx.getCollectionVariables().get(k), ctx.getVariable(k));
            return ctx.getVariable(k);
        }
        public boolean has(String k) { return get(k) != null; }
        public void unset(String k) {
            ctx.getGlobalVariables().remove(k);
            ctx.getEnvironmentVariables().remove(k);
            ctx.getCollectionVariables().remove(k);
        }
        private static String nv(String a, String b) { return a != null ? a : b; }
    }

    /** {@code pm.request} — read accessors plus {@code headers.add(...)} mutation. */
    public static final class RequestHost {
        private final PostmanCollection.Request request;
        public final HeadersHost headers;
        public final RequestBodyHost body;

        RequestHost(PostmanCollection.Request request) {
            this.request = request;
            this.headers = new HeadersHost(request);
            this.body = new RequestBodyHost(request);
        }
        public String getUrl() { return request != null && request.url != null ? request.url.toString() : ""; }
        public String getMethod() { return request != null ? request.method : ""; }
    }

    /** {@code pm.request.body} — safe body view so scripts can read
     *  {@code pm.request.body.raw} without crashing on bodyless requests. */
    public static final class RequestBodyHost {
        private final PostmanCollection.Request request;
        RequestBodyHost(PostmanCollection.Request request) { this.request = request; }

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

    /** {@code pm.request.headers} — supports {@code add({key, value})} which mutates the outgoing request. */
    public static final class HeadersHost {
        private final PostmanCollection.Request request;
        HeadersHost(PostmanCollection.Request request) { this.request = request; }

        public void add(Object obj) {
            if (request == null) return;
            String keyVal = null, valueVal = null;
            if (obj instanceof Scriptable) {
                Scriptable s = (Scriptable) obj;
                Object k = ScriptableObject.getProperty(s, "key");
                Object v = ScriptableObject.getProperty(s, "value");
                if (k != null && k != Scriptable.NOT_FOUND) keyVal = Context.toString(k);
                if (v != null && v != Scriptable.NOT_FOUND) valueVal = Context.toString(v);
            }
            if (keyVal == null || keyVal.isEmpty()) return;
            if (request.header == null) request.header = new ArrayList<>();
            // Replace existing header with same key (case-insensitive)
            final String fk = keyVal;
            request.header.removeIf(h -> h != null && fk.equalsIgnoreCase(h.key));
            PostmanCollection.Header h = new PostmanCollection.Header();
            h.key = keyVal;
            h.value = valueVal == null ? "" : valueVal;
            request.header.add(h);
        }

        public void remove(String key) {
            if (request == null || request.header == null || key == null) return;
            final String fk = key;
            request.header.removeIf(h -> h != null && fk.equalsIgnoreCase(h.key));
        }

        public Object get(String key) {
            if (request == null || request.header == null || key == null) return null;
            for (PostmanCollection.Header h : request.header) {
                if (h != null && key.equalsIgnoreCase(h.key)) return h.value;
            }
            return null;
        }
    }

    /** {@code pm.response} — read accessors. */
    public static final class ResponseHost {
        private final ExecutedRequest resp;
        private final Scriptable scriptScope;
        private Object cachedJsonBody;
        private boolean cachedJsonComputed;
        ResponseHost(ExecutedRequest resp, Scriptable scope) {
            this.resp = resp;
            this.scriptScope = scope;
        }
        ResponseHost(ExecutedRequest resp) { this(resp, null); }
        // pm.response.code is a NUMBER property in real Postman, not a method.
        // We deliberately omit code()/status() no-arg methods because Rhino's
        // LiveConnect would expose them via the .code / .status property
        // accessor as Function references, breaking expect(res.code).to.equal(200).
        public int getCode() { return resp == null ? 0 : resp.getStatusCode(); }
        public int getStatus() { return getCode(); }
        public int getResponseTime() { return resp == null ? 0 : (int) resp.getDurationMs(); }
        public String getText() { return resp == null ? "" : resp.getResponseBody(); }
        public String text() { return getText(); }
        /** {@code pm.response.json()} returns the parsed body. Uses the
         *  script's own JSON.parse so the result is a NativeObject scripts
         *  can navigate with dot notation (json.args.foo, etc.). */
        public Object json() {
            if (cachedJsonComputed) return cachedJsonBody;
            cachedJsonComputed = true;
            String body = getText();
            if (body == null || body.isEmpty()) return null;
            try {
                Context cx = Context.getCurrentContext();
                if (cx != null && scriptScope != null) {
                    String key = "__pm_resp_json__" + System.nanoTime();
                    ScriptableObject.putProperty(scriptScope, key, body);
                    try {
                        Object parsed = cx.evaluateString(scriptScope,
                            "JSON.parse(" + key + ")",
                            "<pm-response-json>", 1, null);
                        cachedJsonBody = parsed;
                        return parsed;
                    } finally {
                        try { ScriptableObject.deleteProperty(scriptScope, key); }
                        catch (Throwable ignore) {}
                    }
                }
            } catch (Throwable ignore) {}
            try {
                Context cx = Context.getCurrentContext();
                if (cx != null) {
                    Scriptable s = scriptScope != null ? scriptScope : cx.initStandardObjects();
                    return org.mozilla.javascript.NativeJSON.parse(cx, s, body, null);
                }
            } catch (Throwable ignore) {}
            try { return new Gson().fromJson(body, Object.class); }
            catch (Exception e) { return null; }
        }
        /** {@code pm.response.headers} — case-insensitive header lookup. */
        public Object getHeaders() {
            if (resp == null || resp.getResponseHeaders() == null) return null;
            return new ResponseHeadersHost(resp.getResponseHeaders(), scriptScope);
        }
        /** {@code pm.response.to.have.status(n)} chai-style assertion. */
        public Object getTo() { return new PmResponseTo(this); }
    }

    /** Implements {@code pm.response.to.have.status(n)} and similar chains.
     *  Real Postman scripts do {@code pm.response.to.have.status(200)} which
     *  via Rhino's bean introspection means {@code .to} → {@code getTo()},
     *  {@code .have} → {@code getHave()}, then {@code .status(200)} call.
     *  We deliberately omit no-arg {@code to()} / {@code have()} methods so
     *  Rhino exposes them as properties (not Function refs that would
     *  shadow the chain).  */
    public static final class PmResponseTo {
        private final ResponseHost resp;
        PmResponseTo(ResponseHost r) { this.resp = r; }
        public PmResponseHave getHave() { return new PmResponseHave(resp); }
        public PmResponseBe getBe() { return new PmResponseBe(resp); }
        public PmResponseTo getNot() { return this; } // soft alias; real chai negates
    }
    public static final class PmResponseBe {
        private final ResponseHost resp;
        PmResponseBe(ResponseHost r) { this.resp = r; }
        public PmResponseHave getHave() { return new PmResponseHave(resp); }
        public PmResponseBe getNot() { return this; } // soft alias; real chai negates
        public Object getJson() { return json(); }
        public Object json() {
            if (resp == null) throw new RuntimeException("expected response to be json");
            Object parsed = null;
            try { parsed = resp.json(); } catch (Throwable ignore) {}
            if (parsed != null) return null;
            String body = null;
            try { body = resp.text(); } catch (Throwable ignore) {}
            if (body == null || body.trim().isEmpty()) {
                throw new RuntimeException("expected response body to be json but it was empty");
            }
            throw new RuntimeException("expected response body to be json");
        }
    }
    public static final class PmResponseHave {
        private final ResponseHost resp;
        PmResponseHave(ResponseHost r) { this.resp = r; }
        public Object status(int expected) {
            int actual = resp.getCode();
            if (actual != expected) {
                throw new RuntimeException("expected status " + actual + " to equal " + expected);
            }
            return null;
        }
    }

    /** {@code pm.info} — empty stub; real Postman exposes request name etc. */
    public static final class InfoHost {
        public String getRequestName() { return ""; }
        public String getEventName() { return ""; }
    }

    /** {@code bru.*} — Bruno collection scripting API (subset). */
    public static final class BruHost {
        private final ScriptContext ctx;
        private final Scriptable jsScope;
        private boolean runRequestWarningLogged = false;

        /** Returns fixed text, so a parsed object still stringifies to its JSON. */
        private static final class RawTextFunction extends org.mozilla.javascript.BaseFunction {
            private static final long serialVersionUID = 1L;
            private final String text;
            RawTextFunction(Scriptable scope, String text) {
                this.text = text;
                if (scope != null) {
                    setParentScope(scope);
                    setPrototype(ScriptableObject.getFunctionPrototype(scope));
                }
            }
            @Override
            public Object call(Context cx, Scriptable scope, Scriptable thisObj, Object[] args) {
                return text;
            }
        }
        BruHost(ScriptContext ctx, Scriptable jsScope) { this.ctx = ctx; this.jsScope = jsScope; }
        /** Legacy no-scope constructor kept for backwards compatibility with any
         *  callers that construct BruHost directly (e.g. test harnesses).
         *  When used, {@code bru.sendRequest} callbacks fall back to the current
         *  Rhino Context's standard-objects scope, which is fine for most cases
         *  but does mean closures over the outer script's locals may not see
         *  the same live bindings. */
        BruHost(ScriptContext ctx) { this(ctx, null); }

        /** Coerce a Rhino value to a string the way Postman/Bruno would for
         *  variable storage. Critically, treat {@code undefined} and
         *  {@code null} as empty strings instead of letting Rhino's
         *  Context.toString stringify them as the LITERAL strings
         *  "undefined" / "null". Without this, a script that does
         *  {@code bru.setEnvVar("authId", res.getBody().authId)} when
         *  authId is missing stores the literal text "undefined", which
         *  then gets interpolated into the next request's body and the
         *  server rejects it ("not right number of dots"). */
        private static String toStorableString(Object v) {
            if (v == null) return "";
            if (v == org.mozilla.javascript.Undefined.instance) return "";
            if (v instanceof org.mozilla.javascript.Undefined) return "";
            // NativeJavaObject wrapping a null Java reference.
            if (v instanceof org.mozilla.javascript.Wrapper) {
                Object u = ((org.mozilla.javascript.Wrapper) v).unwrap();
                if (u == null) return "";
                String us = Context.toString(u);
                return ("undefined".equals(us) || "null".equals(us)) ? "" : us;
            }
            String s = Context.toString(v);
            // Belt-and-suspenders: even after the type checks above, some
            // Rhino values (e.g. NativeArray of nothing, certain proxied
            // objects) stringify to the literal "undefined" / "null".
            // Treat both as empty so we never serialize them into the URL
            // or body of the next request.
            if ("undefined".equals(s) || "null".equals(s)) return "";
            return s;
        }

        public void setVar(String k, Object v) {
            if (k == null) return;
            // undefined / null is treated as a no-op rather than an empty
            // string overwrite. Real Postman/Bruno auth chains rely on a
            // prior request's value (e.g. {{test.auth.id}} from credentials)
            // surviving when a later request's response is missing the
            // expected field. Without this rule, channel display's
            // post-response script — which unconditionally calls
            // bru.setVar("test.auth.id", res.getBody().authId) — wipes the
            // good value and the next request sends an empty body.
            if (isUndefinedLike(v)) return;
            String s = toStorableString(v);
            // Same empty-string guard as setEnvVar — see comment there.
            if (s.isEmpty()) return;
            ctx.getCollectionVariables().put(k, s);
            ctx.setVariable(k, s);
        }
        public Object getVar(String k) {
            String v = ctx.getCollectionVariables().get(k);
            return asScriptValue(v != null ? v : ctx.getVariable(k));
        }

        /**
         * Presents a stored variable the way a script expects to receive it.
         *
         * <p>Variables are held as text, but an OpenCollection {@code type:
         * object} variable is an object as far as its author is concerned:
         * {@code bru.getEnvVar("test-user").gb.cert} is the documented way to
         * read one. Returning the raw JSON made that a
         * {@code TypeError: cannot read property "gb" from undefined}, pointing
         * at the script rather than at the value it was handed.
         *
         * <p>The parsed object keeps {@code toString}/{@code valueOf} returning
         * the original text, so a script that instead does
         * {@code JSON.parse(bru.getEnvVar(...))} or concatenates the value still
         * behaves as before. Anything that is not a JSON object or array is
         * returned untouched.
         */
        private Object asScriptValue(Object stored) {
            if (!(stored instanceof String)) return stored;
            String raw = (String) stored;
            String t = raw.trim();
            if (t.length() < 2) return raw;
            char c = t.charAt(0);
            if (c != '{' && c != '[') return raw;

            Context cx = Context.getCurrentContext();
            if (cx == null) return raw;
            Scriptable scope = jsScope != null ? jsScope : ScriptRuntime.getTopCallScope(cx);
            if (scope == null) return raw;

            try {
                Object parsed = new org.mozilla.javascript.json.JsonParser(cx, scope).parseValue(t);
                if (!(parsed instanceof Scriptable)) return raw;
                Scriptable obj = (Scriptable) parsed;
                // Keep the text form reachable so existing string uses still work.
                ScriptableObject.putProperty(obj, "toString",
                        new RawTextFunction(scope, raw));
                ScriptableObject.putProperty(obj, "valueOf",
                        new RawTextFunction(scope, raw));
                return obj;
            } catch (Exception notJson) {
                return raw;
            }
        }
        public void setEnvVar(String k, Object v) {
            if (k == null) return;
            if (isUndefinedLike(v)) {
                // Mirrors Postman/Bruno: undefined values don't overwrite a
                // previously-set env var. See setVar comment.
                try {
                    String existing = ctx.getEnvironmentVariables().get(k);
                    String preview = existing == null
                        ? "(unchanged — was unset)"
                        : (existing.length() > 60
                            ? existing.substring(0, 60) + "…(kept len=" + existing.length() + ")"
                            : "(kept '" + existing + "')");
                    ctx.log("[bru.setEnvVar] " + k + " = " + preview
                        + "  ← skipped undefined write");
                } catch (Throwable ignore) {}
                return;
            }
            String s = toStorableString(v);
            // Catch the case where toStorableString returned empty for a
            // value our isUndefinedLike heuristic missed.  Empty-string
            // writes from auth scripts almost always indicate a missing
            // response field; treating them as "keep prior value" matches
            // Postman/Bruno semantics in practice (their scripts wrap
            // these in `if (value)` guards anyway).
            if (s.isEmpty()) {
                try {
                    String existing = ctx.getEnvironmentVariables().get(k);
                    String preview = existing == null
                        ? "(unchanged — was unset)"
                        : (existing.length() > 60
                            ? existing.substring(0, 60) + "…(kept len=" + existing.length() + ")"
                            : "(kept '" + existing + "')");
                    String typeName = v == null ? "null" : v.getClass().getName();
                    ctx.log("[bru.setEnvVar] " + k + " = " + preview
                        + "  ← skipped empty write (was " + typeName + ")");
                } catch (Throwable ignore) {}
                return;
            }
            ctx.getEnvironmentVariables().put(k, s);
            ctx.setVariable(k, s);
            try {
                String preview = s.length() > 60
                    ? s.substring(0, 60) + "…(len=" + s.length() + ")" : s;
                ctx.log("[bru.setEnvVar] " + k + " = " + preview);
            } catch (Throwable ignore) {}
        }

        /** True for JS {@code undefined}, Java {@code null}, and {@code Wrapper}
         *  values whose underlying Java reference is null. Also catches the
         *  literal string {@code "undefined"} that Rhino's coercion path
         *  occasionally produces when a missing property flows through
         *  {@code Context.jsToJava(Object.class)} — that's the bridge case
         *  for {@code bru.setEnvVar("k", missing.field)} on real-world auth
         *  scripts which crashes the chain by overwriting prior good values
         *  with empty.  */
        private static boolean isUndefinedLike(Object v) {
            if (v == null) return true;
            if (v == org.mozilla.javascript.Undefined.instance) return true;
            if (v instanceof org.mozilla.javascript.Undefined) return true;
            if (v instanceof org.mozilla.javascript.Wrapper) {
                Object u = ((org.mozilla.javascript.Wrapper) v).unwrap();
                if (u == null) return true;
                String us = String.valueOf(u);
                return "undefined".equals(us);
            }
            // Belt-and-suspenders: stringify and check.  When Rhino coerces
            // a JS undefined to Java Object via jsToJava, some builds return
            // the String "undefined" instead of null/Undefined.instance.
            // Treat that as undefined too.
            String s = String.valueOf(v);
            return "undefined".equals(s);
        }
        public Object getEnvVar(String k) {
            String v = ctx.getEnvironmentVariables().get(k);
            return asScriptValue(v != null ? v : ctx.getVariable(k));
        }
        public boolean hasEnvVar(String k) { return ctx.getEnvironmentVariables().containsKey(k); }
        public boolean hasVar(String k) { return ctx.getCollectionVariables().containsKey(k) || ctx.getVariable(k) != null; }

        public Object getCollectionVar(String k) {
            if (k == null) return null;
            String v = ctx.getCollectionVariables().get(k);
            return asScriptValue(v != null ? v : ctx.getVariable(k));
        }
        public void setCollectionVar(String k, Object v) {
            if (k == null) return;
            if (isUndefinedLike(v)) return;
            String s = toStorableString(v);
            if (s.isEmpty()) return;
            ctx.getCollectionVariables().put(k, s);
            ctx.setVariable(k, s);
        }
        public boolean hasCollectionVar(String k) {
            return k != null && ctx.getCollectionVariables().containsKey(k);
        }

        /** Bruno's cookie jar accessor — Bruno scripts call {@code bru.cookies.jar().clear()}
         *  before auth flows. We don't manage cookies per-script (CookieJar lives at
         *  the executor level), so return a no-op stub instead of throwing. Without
         *  this, real-world auth scripts abort at line 1 with TypeError and the
         *  whole chain breaks. */
        public final CookiesHost cookies = new CookiesHost();

        public static final class CookiesHost {
            private final CookieJarStub jar = new CookieJarStub();
            public CookieJarStub jar() { return jar; }
            public CookieJarStub getJar() { return jar; }
        }
        public static final class CookieJarStub {
            public void clear() {
                // Bruno auth scripts call this in the FIRST request's pre-
                // request hook to wipe stale OpenAM/CIAM session cookies
                // before starting the multi-step authenticate flow. Without
                // it, the second request sends iPlanetDirectoryPro from a
                // previous session and OpenAM short-circuits to a final
                // tokenId response — which has no `authId`/`callbacks`
                // fields, breaking every downstream `res.getBody().authId`
                // extraction in the chain.
                burp.service.CookieJar j = SCRIPT_COOKIE_JAR.get();
                if (j != null) j.clear();
            }
            public void clear(String url) { clear(); }
            public void clear(String url, Object cb) {
                clear();
                if (cb instanceof org.mozilla.javascript.Function) {
                    try {
                        Context cx = Context.getCurrentContext();
                        Scriptable scope = ((org.mozilla.javascript.Function) cb).getParentScope();
                        ((org.mozilla.javascript.Function) cb).call(cx, scope, scope,
                            new Object[] { null }); // null = no error
                    } catch (Throwable ignore) {}
                }
            }
            // Bruno's documented jar API names. A script that calls
            // jar.deleteCookies(url) threw "Cannot find function deleteCookies",
            // which aborts the whole pre-request hook — so the cookies it was
            // trying to clear stayed, and every later failure in the chain
            // pointed away from the real cause.
            public void deleteCookies() { clear(); }
            public void deleteCookies(String url) { clear(); }
            public void deleteCookies(String url, Object cb) { clear(url, cb); }
            public void deleteAllCookies() { clear(); }
            public void deleteAllCookies(Object cb) { clear(null, cb); }
            public void deleteCookie(String url, String name) { /* no per-cookie removal yet */ }
            public void deleteCookie(String url, String name, Object cb) { clear(url, cb); }
            public void set(String url, String name, String value) { /* no-op */ }
            public void setCookie(String url, String name, String value) { /* no-op */ }
            public void setCookies(String url, Object cookies) { /* no-op */ }
            public Object get(String url, String name) { return null; }
            public Object getCookie(String url, String name) { return null; }
            public Object getCookies(String url) { return null; }
        }

        /** Bruno's request-control helpers. {@code bru.setNextRequest(name)}
         *  asks Bruno to jump to the request named {@code name}, skipping
         *  any intervening requests in the run; {@code null} / empty aborts.
         *  Real .bru collections rely on this to short-circuit MFA branches
         *  when the server returns an early {@code tokenId}. We surface the
         *  request via a thread-local so the runner can read it after the
         *  post-response script finishes. */
        public void setNextRequest(String name) {
            // Bruno docs: pass null/empty to STOP the run after this request.
            String s = (name == null) ? "" : name;
            NEXT_REQUEST_THREADLOCAL.set(s);
        }
        public Object runRequest(String name) {
            if (!runRequestWarningLogged) {
                runRequestWarningLogged = true;
                String target = (name == null || name.trim().isEmpty()) ? "<empty>" : name;
                ctx.log("⚠ bru.runRequest(\"" + target + "\") is not implemented in BurpMan.");
            }
            return null;
        }
        public void sleep(int ms) {
            try { Thread.sleep(Math.max(0, ms)); } catch (InterruptedException ignore) {}
        }

        /** Bruno's bru.getProcessEnv("KEY") — proxy to System.getenv. */
        public String getProcessEnv(String k) {
            try { return k == null ? null : System.getenv(k); }
            catch (Exception e) { return null; }
        }

        /** Active environment name — best-effort; returns "" when not tracked. */
        public String getEnvName() { return ""; }
        public String cwd() { return ""; }

        /** Bruno's bru.interpolate("...{{var}}...") — uses the same single-pass
         *  substitution real scripts expect. Also honours Postman/Bruno dynamic
         *  variables like {@code {{$guid}}}, {@code {{$randomUUID}}}, and
         *  {@code {{$timestamp}}} so JWT-signing pre-request scripts that call
         *  {@code bru.interpolate("{{$guid}}").toUpperCase()} get a real UUID
         *  instead of a literal placeholder string. */
        public String interpolate(String s) {
            if (s == null) return "";
            StringBuilder out = new StringBuilder();
            int i = 0;
            while (i < s.length()) {
                int open = s.indexOf("{{", i);
                if (open < 0) { out.append(s, i, s.length()); break; }
                out.append(s, i, open);
                int close = s.indexOf("}}", open + 2);
                if (close < 0) { out.append(s, open, s.length()); break; }
                String key = s.substring(open + 2, close).trim();
                String v = resolveDynamic(key);
                if (v == null) v = ctx.getVariable(key);
                if (v == null) v = ctx.getEnvironmentVariables().get(key);
                if (v == null) v = ctx.getCollectionVariables().get(key);
                out.append(v == null ? "{{" + key + "}}" : v);
                i = close + 2;
            }
            return out.toString();
        }

        /** Resolves Postman/Bruno dynamic variables ($guid, $randomUUID,
         *  $timestamp, $isoTimestamp, $randomInt). Returns {@code null} for
         *  anything else so the caller falls back to normal variable lookup. */
        private String resolveDynamic(String key) {
            if (key == null || key.isEmpty() || key.charAt(0) != '$') return null;
            String lower = key.toLowerCase(java.util.Locale.ROOT);
            if ("$guid".equals(lower) || "$randomuuid".equals(lower)) {
                return java.util.UUID.randomUUID().toString();
            }
            if ("$guid:upper".equals(lower)) {
                return java.util.UUID.randomUUID().toString().toUpperCase(java.util.Locale.ROOT);
            }
            if ("$timestamp".equals(lower)) {
                return String.valueOf(System.currentTimeMillis() / 1000);
            }
            if ("$isotimestamp".equals(lower)) {
                return java.time.Instant.now().toString();
            }
            if ("$randomint".equals(lower)) {
                return String.valueOf((int)(Math.random() * 1000));
            }
            return null;
        }

        /**
         * Bruno's {@code bru.sendRequest(config, callback)} — fires an HTTP
         * request from inside a script and invokes the callback with
         * {@code (err, response)}. Config shape matches Bruno's docs:
         * <pre>
         *   {
         *     method: 'POST',
         *     url: 'https://...',
         *     data: { key: value, ... },   // object; serialized per Content-Type
         *     headers: { 'Content-Type': '...', ... }
         *   }
         * </pre>
         *
         * Body serialization follows Bruno's axios convention:
         * <ul>
         *   <li>{@code multipart/form-data} → multipart body with generated
         *       boundary (Content-Type header rewritten to include boundary)</li>
         *   <li>{@code application/x-www-form-urlencoded} → urlencoded key=value</li>
         *   <li>{@code application/json} (or missing) → {@code JSON.stringify(data)}</li>
         *   <li>Any other C-T → JSON stringify (safe default matching axios)</li>
         * </ul>
         *
         * The callback receives {@code (err, response)} where response has:
         * {@code status} (number), {@code data} (parsed JSON if the response is
         * JSON, else raw text), {@code body} (raw text), {@code headers}
         * (object keyed by lowercased name).
         */
        public Object sendRequest(Object config, Object cb) {
            if (Thread.currentThread().isInterrupted()) {
                ctx.log("[bru.sendRequest] aborted (thread interrupted)");
                bruInvokeCallback(cb, "Cancelled by user", null);
                return null;
            }
            if (!(config instanceof Scriptable)) {
                bruInvokeCallback(cb, "bru.sendRequest: config must be an object", null);
                return null;
            }
            Scriptable cfg = (Scriptable) config;

            String url = bruStringProp(cfg, "url");
            if (url == null || url.isEmpty()) {
                bruInvokeCallback(cb, "bru.sendRequest: missing url", null);
                return null;
            }
            String method = bruStringProp(cfg, "method");
            if (method == null || method.isEmpty()) method = "GET";
            method = method.toUpperCase(java.util.Locale.ROOT);

            Map<String, String> headers = bruReadHeaders(cfg);
            Object dataObj = ScriptableObject.getProperty(cfg, "data");
            if (dataObj == Scriptable.NOT_FOUND) dataObj = null;

            String contentType = bruLookupHeaderCi(headers, "Content-Type");
            String body = null;
            if (dataObj != null && !(dataObj instanceof Undefined)) {
                if (dataObj instanceof CharSequence) {
                    body = dataObj.toString();
                } else if (contentType != null
                        && contentType.toLowerCase(java.util.Locale.ROOT)
                             .contains("multipart/form-data")) {
                    // Bruno auto-generates a multipart boundary and rewrites
                    // the Content-Type header to include it. Real axios does
                    // the same. Without this the server sees a header that
                    // says "multipart" but a body that's just raw text and
                    // fails to parse the parameters.
                    String boundary = "----BurpManBruBoundary"
                        + Long.toHexString(System.nanoTime())
                        + Integer.toHexString(System.identityHashCode(cfg));
                    body = bruBuildMultipartBody(dataObj, boundary);
                    bruPutHeaderCi(headers, "Content-Type",
                        "multipart/form-data; boundary=" + boundary);
                } else if (contentType != null
                        && contentType.toLowerCase(java.util.Locale.ROOT)
                             .contains("x-www-form-urlencoded")) {
                    body = bruBuildUrlEncodedBody(dataObj);
                } else {
                    // Default: JSON stringify (matches axios' default).
                    body = bruStringifyJson(dataObj);
                    if (!bruHasHeaderCi(headers, "Content-Type")) {
                        bruPutHeaderCi(headers, "Content-Type", "application/json");
                    }
                }
            }

            // {{var}} substitution against the current variable map so scripts
            // that pass "{{env.token_url}}" in the config still work.
            url = interpolate(url);
            for (Map.Entry<String, String> e : new java.util.ArrayList<>(headers.entrySet())) {
                headers.put(e.getKey(), interpolate(e.getValue()));
            }
            if (body != null) body = interpolate(body);

            ctx.log("[bru.sendRequest] " + method + " " + url);

            MontoyaApi mApi = api;
            if (mApi == null) {
                bruInvokeCallback(cb,
                    "MontoyaApi not initialized — cannot fire bru.sendRequest", null);
                return null;
            }

            try {
                burp.api.montoya.http.message.requests.HttpRequest req =
                    burp.api.montoya.http.message.requests.HttpRequest
                        .httpRequestFromUrl(url).withMethod(method);
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    req = req.withAddedHeader(e.getKey(), e.getValue());
                }
                if (body != null && !body.isEmpty()) {
                    req = req.withBody(body);
                }
                burp.api.montoya.http.message.HttpRequestResponse rr =
                    burp.service.ProxyRouter.sendRequest(mApi, req);
                if (rr == null || rr.response() == null) {
                    bruInvokeCallback(cb, "No response", null);
                    return null;
                }
                final String fbody = rr.response().bodyToString();
                final int status = rr.response().statusCode();
                ctx.log("[bru.sendRequest] -> " + status + " ("
                    + (fbody == null ? 0 : fbody.length()) + " bytes)");

                // Build a Bruno-shaped response object in the current script
                // scope so callback closures see the outer script's env.
                Context cx = Context.getCurrentContext();
                Scriptable scope = (jsScope != null) ? jsScope
                        : (cx != null ? cx.initStandardObjects() : null);
                NativeObject resObj = new NativeObject();
                ScriptRuntime.setObjectProtoAndParent(resObj, scope);
                resObj.put("status", resObj, (double) status);
                resObj.put("statusCode", resObj, (double) status);
                resObj.put("body", resObj, fbody == null ? "" : fbody);

                // response.headers as a plain JS object keyed by lowercased name
                // (matches axios' response.headers shape).
                NativeObject hdrObj = new NativeObject();
                ScriptRuntime.setObjectProtoAndParent(hdrObj, scope);
                try {
                    for (burp.api.montoya.http.message.HttpHeader h
                            : rr.response().headers()) {
                        String hn = h.name();
                        String hv = h.value();
                        if (hn == null) continue;
                        hdrObj.put(hn.toLowerCase(java.util.Locale.ROOT),
                            hdrObj, hv == null ? "" : hv);
                    }
                } catch (Throwable ignore) {}
                resObj.put("headers", resObj, hdrObj);

                // response.data — parsed JSON if the response is JSON, else
                // the raw text. Bruno scripts almost always access
                // `response.data.access_token` etc. directly.
                String respCt = null;
                try {
                    for (burp.api.montoya.http.message.HttpHeader h
                            : rr.response().headers()) {
                        if (h.name() != null
                                && h.name().equalsIgnoreCase("Content-Type")) {
                            respCt = h.value();
                            break;
                        }
                    }
                } catch (Throwable ignore) {}
                boolean isJson = respCt != null
                    && respCt.toLowerCase(java.util.Locale.ROOT).contains("json");
                if (!isJson && fbody != null) {
                    // Some Azure/OAuth endpoints don't set Content-Type
                    // correctly. Fall back to sniffing the body.
                    String trimmed = fbody.trim();
                    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                        isJson = true;
                    }
                }
                Object dataVal = fbody == null ? "" : fbody;
                if (isJson && fbody != null && !fbody.isEmpty()) {
                    try {
                        Object jsonObj = ScriptableObject.getProperty(scope, "JSON");
                        if (jsonObj instanceof Scriptable) {
                            Scriptable js = (Scriptable) jsonObj;
                            Object pf = ScriptableObject.getProperty(js, "parse");
                            if (pf instanceof org.mozilla.javascript.Function) {
                                dataVal = ((org.mozilla.javascript.Function) pf)
                                    .call(cx, scope, js, new Object[]{ fbody });
                            }
                        }
                        if (dataVal == fbody) {
                            dataVal = org.mozilla.javascript.NativeJSON
                                .parse(cx, scope, fbody, null);
                        }
                    } catch (Throwable ignore) {
                        dataVal = fbody;
                    }
                }
                resObj.put("data", resObj, dataVal);

                bruInvokeCallback(cb, null, resObj);
                return resObj;
            } catch (Throwable t) {
                ctx.log("[bru.sendRequest] error: " + t.getMessage());
                bruInvokeCallback(cb, t.getMessage(), null);
                return null;
            }
        }

        private static String bruStringProp(Scriptable cfg, String name) {
            Object v = ScriptableObject.getProperty(cfg, name);
            if (v == null || v == Scriptable.NOT_FOUND || v == Undefined.instance) return null;
            return Context.toString(v);
        }

        private static Map<String, String> bruReadHeaders(Scriptable cfg) {
            Map<String, String> out = new java.util.LinkedHashMap<>();
            Object hdr = ScriptableObject.getProperty(cfg, "headers");
            if (hdr == null || hdr == Scriptable.NOT_FOUND) {
                hdr = ScriptableObject.getProperty(cfg, "header");
            }
            if (hdr == null || hdr == Scriptable.NOT_FOUND) return out;
            if (hdr instanceof CharSequence) {
                String s = hdr.toString();
                for (String line : s.split("[\\r\\n,]+")) {
                    int idx = line.indexOf(':');
                    if (idx > 0) {
                        String k = line.substring(0, idx).trim();
                        String v = line.substring(idx + 1).trim();
                        if (!k.isEmpty()) out.put(k, v);
                    }
                }
                return out;
            }
            if (hdr instanceof NativeArray) {
                NativeArray arr = (NativeArray) hdr;
                for (long i = 0; i < arr.getLength(); i++) {
                    Object item = arr.get((int) i, arr);
                    if (item instanceof Scriptable) {
                        Scriptable it = (Scriptable) item;
                        String k = bruStringProp(it, "key");
                        String v = bruStringProp(it, "value");
                        if (k != null) out.put(k, v == null ? "" : v);
                    }
                }
                return out;
            }
            if (hdr instanceof Scriptable) {
                Scriptable s = (Scriptable) hdr;
                for (Object id : s.getIds()) {
                    String key = id.toString();
                    Object v = ScriptableObject.getProperty(s, key);
                    if (v != null && v != Scriptable.NOT_FOUND) {
                        out.put(key, Context.toString(v));
                    }
                }
            }
            return out;
        }

        private static String bruLookupHeaderCi(Map<String, String> headers, String name) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)) return e.getValue();
            }
            return null;
        }

        private static boolean bruHasHeaderCi(Map<String, String> headers, String name) {
            return bruLookupHeaderCi(headers, name) != null;
        }

        private static void bruPutHeaderCi(Map<String, String> headers, String name, String value) {
            headers.entrySet().removeIf(e -> e.getKey() != null && e.getKey().equalsIgnoreCase(name));
            headers.put(name, value);
        }

        private static String bruBuildUrlEncodedBody(Object data) {
            if (!(data instanceof Scriptable)) return "";
            StringBuilder sb = new StringBuilder();
            Scriptable s = (Scriptable) data;
            for (Object id : s.getIds()) {
                String k = id.toString();
                Object v = ScriptableObject.getProperty(s, k);
                if (v == null || v == Scriptable.NOT_FOUND || v == Undefined.instance) continue;
                if (sb.length() > 0) sb.append('&');
                try {
                    sb.append(java.net.URLEncoder.encode(k, "UTF-8"));
                    sb.append('=');
                    sb.append(java.net.URLEncoder.encode(Context.toString(v), "UTF-8"));
                } catch (java.io.UnsupportedEncodingException ignore) {
                    sb.append(k).append('=').append(Context.toString(v));
                }
            }
            return sb.toString();
        }

        private static String bruBuildMultipartBody(Object data, String boundary) {
            if (!(data instanceof Scriptable)) return "";
            StringBuilder sb = new StringBuilder();
            Scriptable s = (Scriptable) data;
            for (Object id : s.getIds()) {
                String k = id.toString();
                Object v = ScriptableObject.getProperty(s, k);
                if (v == null || v == Scriptable.NOT_FOUND || v == Undefined.instance) continue;
                sb.append("--").append(boundary).append("\r\n");
                sb.append("Content-Disposition: form-data; name=\"")
                    .append(k).append("\"\r\n\r\n");
                sb.append(Context.toString(v)).append("\r\n");
            }
            sb.append("--").append(boundary).append("--\r\n");
            return sb.toString();
        }

        private String bruStringifyJson(Object data) {
            try {
                Context cx = Context.getCurrentContext();
                Scriptable scope = (jsScope != null) ? jsScope
                        : (cx != null ? cx.initStandardObjects() : null);
                Object jsonObj = ScriptableObject.getProperty(scope, "JSON");
                if (jsonObj instanceof Scriptable) {
                    Scriptable js = (Scriptable) jsonObj;
                    Object sf = ScriptableObject.getProperty(js, "stringify");
                    if (sf instanceof org.mozilla.javascript.Function) {
                        Object r = ((org.mozilla.javascript.Function) sf)
                            .call(cx, scope, js, new Object[]{ data });
                        return r == null ? "" : Context.toString(r);
                    }
                }
            } catch (Throwable ignore) {}
            // Fallback: hand-build a JSON object literal for the common
            // case of a plain object with string/number/boolean values.
            if (!(data instanceof Scriptable)) return "";
            StringBuilder sb = new StringBuilder("{");
            Scriptable s = (Scriptable) data;
            boolean first = true;
            for (Object id : s.getIds()) {
                String k = id.toString();
                Object v = ScriptableObject.getProperty(s, k);
                if (v == null || v == Scriptable.NOT_FOUND || v == Undefined.instance) continue;
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(k.replace("\"", "\\\"")).append("\":");
                if (v instanceof Number || v instanceof Boolean) {
                    sb.append(Context.toString(v));
                } else {
                    sb.append('"').append(Context.toString(v).replace("\"", "\\\"")).append('"');
                }
            }
            sb.append('}');
            return sb.toString();
        }

        private void bruInvokeCallback(Object cb, Object err, Object res) {
            if (!(cb instanceof org.mozilla.javascript.Function)) return;
            try {
                org.mozilla.javascript.Function fn = (org.mozilla.javascript.Function) cb;
                Context cx = Context.getCurrentContext();
                Scriptable scope = (jsScope != null) ? jsScope
                        : (cx != null ? cx.initStandardObjects() : null);
                Object[] args = new Object[]{
                    err == null ? null : err,
                    res == null ? Undefined.instance : res
                };
                fn.call(cx, scope, scope, args);
            } catch (Throwable t) {
                ctx.log("[bru.sendRequest callback error] " + t.getMessage());
            }
        }
    }

    /** {@code console.log/info/warn/error/debug} — surfaces messages into the in-app log. */
    public static final class ConsoleHost {
        private final ScriptContext ctx;
        ConsoleHost(ScriptContext ctx) { this.ctx = ctx; }
        private void out(String level, Object[] args) {
            StringBuilder sb = new StringBuilder("[script ").append(level).append("] ");
            for (int i = 0; i < args.length; i++) {
                if (i > 0) sb.append(' ');
                sb.append(args[i] == null ? "null" : Context.toString(args[i]));
            }
            ctx.log(sb.toString());
        }
        public void log(Object... args)   { out("log",   args); }
        public void info(Object... args)  { out("info",  args); }
        public void warn(Object... args)  { out("warn",  args); }
        public void error(Object... args) { out("error", args); }
        public void debug(Object... args) { out("debug", args); }
    }

    /** Bruno top-level {@code req} — read accessors and header mutation.
     *  Mirrors https://docs.usebruno.com/scripting/script-reference#req */
    public static final class BrunoReqHost {
        private final PostmanCollection.Request request;
        private final ScriptContext ctx;
        public final HeadersHost headers;
        private int maxRedirects = 5;
        private int timeout = 0;
        private boolean requestControlWarningLogged = false;
        private boolean disableParsingWarningLogged = false;
        BrunoReqHost(PostmanCollection.Request r, ScriptContext c) {
            this.request = r; this.ctx = c;
            this.headers = new HeadersHost(r);
        }
        public String getName() {
            try { return ctx.getRequest() != null ? "" : ""; } catch (Throwable ignore) { return ""; }
        }
        public String getUrl()    { return request != null && request.url != null ? request.url.toString() : ""; }
        public String getMethod() { return request != null ? request.method : ""; }
        public Object getHeaders(){ return headers; }
        public Object getBody() {
            if (request == null || request.body == null) return null;
            return request.body.raw;
        }
        public void setUrl(String u) {
            if (request != null) request.url = u;
        }
        public void setMethod(String m) {
            if (request != null) request.method = m;
        }
        public void setBody(Object b) {
            if (request != null) {
                if (request.body == null) request.body = new PostmanCollection.Body();
                request.body.raw = b == null ? null : Context.toString(b);
            }
        }
        // Bruno's request-control surface — accepted so scripts don't crash;
        // we don't actually follow redirects or enforce timeouts because
        // Burp's HTTP API handles those at a different layer.
        private void logRequestControlWarningOnce(String call) {
            if (requestControlWarningLogged) return;
            requestControlWarningLogged = true;
            if (ctx != null) {
                ctx.log("⚠ " + call + " is recorded, but BurpMan currently does not enforce req timeout/redirect controls.");
            }
        }
        public void setMaxRedirects(int n) {
            this.maxRedirects = n;
            logRequestControlWarningOnce("req.setMaxRedirects(" + n + ")");
        }
        public int  getMaxRedirects()      { return this.maxRedirects; }
        public void setTimeout(int ms) {
            this.timeout = ms;
            logRequestControlWarningOnce("req.setTimeout(" + ms + ")");
        }
        public int  getTimeout()           { return this.timeout; }
        public void disableParsingResponseJson() {
            if (disableParsingWarningLogged) return;
            disableParsingWarningLogged = true;
            if (ctx != null) {
                ctx.log("⚠ req.disableParsingResponseJson() is not implemented; BurpMan still uses best-effort response JSON parsing.");
            }
        }
    }

    /** Bruno top-level {@code res} — read accessors. Bruno scripts read
     *  {@code res.status}, {@code res.body}, {@code res.headers},
     *  {@code res.getBody()}, etc. */
    public static final class BrunoResHost {
        private final ExecutedRequest resp;
        /** Script-side scope captured at engine boot — needed to call the
         *  same JSON.parse the rest of the script uses. Without it, parsing
         *  with a fresh detached scope (cx.initStandardObjects()) silently
         *  fails on some Rhino builds and getBody() leaks the raw string,
         *  which then makes every `.authId.substring(...)` crash. */
        private final Scriptable scriptScope;
        private Object cachedJsonBody;
        private boolean cachedJsonComputed;
        BrunoResHost(ExecutedRequest r, Scriptable scope) {
            this.resp = r;
            this.scriptScope = scope;
        }
        // Backward-compat: older call sites that don't have a scope.
        BrunoResHost(ExecutedRequest r) { this(r, null); }
        public int getStatus()       { return resp == null ? 0 : resp.getStatusCode(); }
        public int getStatusCode()   { return getStatus(); }
        public int getCode()         { return getStatus(); }
        public Object getHeaders() {
            int hc = (resp == null || resp.getResponseHeaders() == null)
                ? -1 : resp.getResponseHeaders().size();
            java.util.function.Consumer<String> sink =
                RhinoScriptEngine.SCRIPT_LOG_THREADLOCAL.get();
            if (sink != null) sink.accept("[debug] BrunoResHost.getHeaders() hc=" + hc);
            if (resp == null || resp.getResponseHeaders() == null) return null;
            // Bruno scripts read res.headers.<name> AND res.headers["x"] —
            // return a thin wrapper that supports both, plus case-insensitive
            // header lookup since HTTP header names are case-insensitive.
            // Pass the script scope so values returned by .get() are real
            // JS strings (so subsequent .split("?") goes through our JS
            // polyfill, not Java's regex split).
            return new ResponseHeadersHost(resp.getResponseHeaders(), scriptScope);
        }
        /** Bruno's {@code res.getHeader(name)} convenience — case-insensitive
         *  single-header lookup used by scripts that parse Location/Set-Cookie
         *  out of the response (CIAM authorize → access_token chains rely on
         *  this to extract the OAuth code from the 302 redirect). */
        public Object getHeader(String name) {
            if (resp == null || name == null) return null;
            java.util.List<burp.models.PostmanCollection.Header> hs =
                resp.getResponseHeaders();
            if (hs == null) return null;
            String want = name.toLowerCase().trim();
            for (burp.models.PostmanCollection.Header h : hs) {
                if (h != null && h.key != null
                        && want.equals(h.key.toLowerCase().trim())) {
                    String val = h.value == null ? "" : h.value;
                    return toJsString(val, scriptScope);
                }
            }
            return null;
        }
        /**
         * Bruno's res.getBody() must return a JS-navigable object so that
         * scripts can do {@code res.getBody().authId.substring(...)}. We
         * delegate to the SCRIPT'S JSON.parse so the resulting NativeObject
         * lives in the same scope as the rest of the script — using a fresh
         * cx.initStandardObjects() scope leads to silent failures on some
         * Rhino builds, which would make this method return the raw body
         * string and break every property lookup downstream.
         * Cached per-instance so repeated calls in the same test block don't
         * re-parse.
         */
        public Object getBody() {
            if (cachedJsonComputed) return cachedJsonBody;
            cachedJsonComputed = true;
            if (resp == null) { cachedJsonBody = null; return null; }
            String body = resp.getResponseBody();
            if (body == null || body.isEmpty()) { cachedJsonBody = null; return null; }
            // Strategy 1: stuff the raw body into the scope as a global
            // string and call the script-side JSON.parse on it. This is the
            // most reliable parse path because it executes in the same
            // scope/Context the script itself uses, so the resulting
            // NativeObject's prototype chain matches everything else and
            // property access (`.authId`) doesn't accidentally hit the
            // wrong prototype and return undefined.
            try {
                Context cx = Context.getCurrentContext();
                Scriptable scope = scriptScope;
                if (cx != null && scope != null) {
                    String key = "__burpman_resBody__" + System.identityHashCode(this);
                    ScriptableObject.putProperty(scope, key, body);
                    try {
                        Object parsed = cx.evaluateString(scope,
                            "JSON.parse(" + key + ")",
                            "<burpman-getBody>", 1, null);
                        if (parsed != null
                                && parsed != org.mozilla.javascript.Undefined.instance) {
                            cachedJsonBody = parsed;
                            return parsed;
                        }
                    } finally {
                        try { ScriptableObject.deleteProperty(scope, key); }
                        catch (Throwable ignore) {}
                    }
                }
            } catch (Throwable ignore) {}
            // Strategy 2: NativeJSON.parse directly (works even when no
            // current context is active, e.g. some test paths).
            try {
                Context cx = Context.getCurrentContext();
                if (cx != null) {
                    Scriptable scope = scriptScope != null
                        ? scriptScope : cx.initStandardObjects();
                    Object parsed = org.mozilla.javascript.NativeJSON.parse(
                        cx, scope, body, null);
                    if (parsed != null
                            && parsed != org.mozilla.javascript.Undefined.instance) {
                        cachedJsonBody = parsed;
                        return parsed;
                    }
                }
            } catch (Throwable ignore) {}
            // Strategy 3: Gson → Scriptable. Last resort for non-standard
            // JSON edge cases (trailing commas, comments) Rhino rejects.
            try {
                com.google.gson.JsonElement el =
                    com.google.gson.JsonParser.parseString(body);
                Object converted = jsonElementToScriptable(el, scriptScope);
                if (converted != null) {
                    cachedJsonBody = converted;
                    return converted;
                }
            } catch (Throwable ignore) {}
            // Body isn't valid JSON — return the raw string so scripts can
            // still call .indexOf(...) / .length on it.
            cachedJsonBody = body;
            return body;
        }

        /** Convert a Gson element tree into Rhino-navigable Scriptable
         *  objects so {@code body.authId.substring(...)} works on the
         *  fallback parse path. Handles nested objects and arrays. */
        private static Object jsonElementToScriptable(com.google.gson.JsonElement el,
                                                      Scriptable scope) {
            if (el == null || el.isJsonNull()) return null;
            if (el.isJsonPrimitive()) {
                com.google.gson.JsonPrimitive p = el.getAsJsonPrimitive();
                if (p.isBoolean()) return p.getAsBoolean();
                if (p.isNumber())  return p.getAsDouble();
                return p.getAsString();
            }
            Context cx = Context.getCurrentContext();
            Scriptable s = scope != null ? scope
                : (cx != null ? cx.initStandardObjects() : null);
            if (el.isJsonArray()) {
                com.google.gson.JsonArray arr = el.getAsJsonArray();
                Object[] items = new Object[arr.size()];
                for (int i = 0; i < arr.size(); i++) {
                    items[i] = jsonElementToScriptable(arr.get(i), s);
                }
                if (cx != null && s != null) {
                    return cx.newArray(s, items);
                }
                return items;
            }
            if (el.isJsonObject()) {
                org.mozilla.javascript.NativeObject obj =
                    new org.mozilla.javascript.NativeObject();
                if (s != null) {
                    org.mozilla.javascript.ScriptRuntime.setObjectProtoAndParent(obj, s);
                }
                for (java.util.Map.Entry<String, com.google.gson.JsonElement> e
                        : el.getAsJsonObject().entrySet()) {
                    obj.put(e.getKey(), obj,
                        jsonElementToScriptable(e.getValue(), s));
                }
                return obj;
            }
            return null;
        }
        // NOTE: Do NOT add a `public Object body()` method. Rhino's bean
        // introspection treats `res.body` (property access without parens)
        // ambiguously when both a `getBody()` getter AND a `body()` method
        // exist — some Rhino builds return the Function reference instead
        // of calling the getter, which makes `res.body?.access_token`
        // evaluate to undefined and breaks every real-world post-script
        // that does `bru.setEnvVar("Authorization", res.body.access_token)`.
        /** Bruno's `res.body` (no parens) and explicit getter — both
         *  return the parsed JSON object. */
        public Object getBody_property() { return getBody(); }
        public String text() { return resp == null ? "" : resp.getResponseBody(); }
        public String getText() { return text(); }
        public Object json() { return getBody(); }
        public Object getJson() { return getBody(); }
        public long getResponseTime() { return resp == null ? 0L : resp.getDurationMs(); }
        public long getDuration() { return getResponseTime(); }
    }

    /**
     * Case-insensitive response-headers view.
     *
     * <p>Extends {@link ScriptableObject} rather than being exposed as a plain
     * Java object, because Rhino resolves a property on a Java object to a
     * public field or bean getter. {@code res.headers.location} matched neither,
     * so it evaluated to {@code undefined} — and a script reading the OAuth
     * {@code Location} redirect saw no header at all on a response that plainly
     * had one. Header names are not known at compile time, so they have to be
     * resolved dynamically.
     *
     * <p>{@code get}/{@code has}/{@code getNames} stay callable so scripts
     * written against the older shape keep working.
     */
    public static final class ResponseHeadersHost extends ScriptableObject {
        private static final long serialVersionUID = 1L;
        private final java.util.Map<String, String> byLower = new java.util.LinkedHashMap<>();
        private final transient Scriptable scriptScope;

        ResponseHeadersHost(java.util.List<burp.models.PostmanCollection.Header> headers,
                            Scriptable scope) {
            this.scriptScope = scope;
            if (headers != null) {
                for (burp.models.PostmanCollection.Header h : headers) {
                    if (h != null && h.key != null) {
                        byLower.put(h.key.toLowerCase().trim(), h.value == null ? "" : h.value);
                    }
                }
            }
            if (scope != null) {
                try {
                    setParentScope(scope);
                    setPrototype(ScriptableObject.getObjectPrototype(scope));
                } catch (RuntimeException ignore) {
                    // A missing prototype only costs Object.prototype helpers;
                    // header lookup below still works.
                }
                defineHostFunction("get", String.class);
                defineHostFunction("has", String.class);
                defineHostFunction("getNames");
            }
        }

        ResponseHeadersHost(java.util.List<burp.models.PostmanCollection.Header> headers) {
            this(headers, null);
        }

        private void defineHostFunction(String name, Class<?>... args) {
            try {
                java.lang.reflect.Method m = ResponseHeadersHost.class.getMethod(name, args);
                defineProperty(name,
                        new org.mozilla.javascript.FunctionObject(name, m, this),
                        ScriptableObject.DONTENUM);
            } catch (RuntimeException | NoSuchMethodException ignore) {
                // Property access still resolves headers; only the explicit
                // .get()/.has() call style would be unavailable.
            }
        }

        @Override public String getClassName() { return "ResponseHeaders"; }

        /** Resolves {@code res.headers.location} and {@code res.headers["Location"]}. */
        @Override
        public Object get(String name, Scriptable start) {
            Object defined = super.get(name, start);
            if (defined != NOT_FOUND) return defined;
            if (name == null) return NOT_FOUND;
            String v = byLower.get(name.toLowerCase().trim());
            if (v == null) return NOT_FOUND;
            return toJsString(v, scriptScope != null ? scriptScope : start);
        }

        @Override
        public boolean has(String name, Scriptable start) {
            if (super.has(name, start)) return true;
            return name != null && byLower.containsKey(name.toLowerCase().trim());
        }

        @Override
        public Object[] getIds() {
            return byLower.keySet().toArray(new Object[0]);
        }

        /** Return value MUST be a real JS string (not a Java {@code String})
         *  so subsequent {@code .split("?")} / {@code .replace("?", ...)}
         *  calls hit Rhino's polyfilled methods rather than Java's regex
         *  engine (which throws on bare meta chars).  We force the
         *  conversion by stuffing the value into the script scope and
         *  reading it back via {@code String(x)}. */
        public Object get(String name) {
            java.util.function.Consumer<String> sink =
                RhinoScriptEngine.SCRIPT_LOG_THREADLOCAL.get();
            if (name == null) {
                if (sink != null) sink.accept("[debug] ResponseHeadersHost.get(null) → null");
                return null;
            }
            String v = byLower.get(name.toLowerCase().trim());
            if (sink != null) {
                String preview = (v == null) ? "<null>"
                    : (v.length() > 80 ? v.substring(0, 80) + "…" : v);
                sink.accept("[debug] ResponseHeadersHost.get(\"" + name + "\") keys="
                    + byLower.keySet() + " → " + preview);
            }
            if (v == null) return null;
            return toJsString(v, scriptScope);
        }
        public boolean has(String name) {
            if (name == null) return false;
            return byLower.containsKey(name.toLowerCase().trim());
        }
        public Object getNames() { return byLower.keySet().toArray(new String[0]); }
        @Override public String toString() { return byLower.toString(); }
    }

    /** Convert a Java {@code String} into a true JS string within the given
     *  scope so prototype methods like {@code .split("?")} go through our
     *  polyfilled JS implementation, not Java's regex engine. Falls back to
     *  the raw Java string if no scope/context is available.
     *
     *  <p>Why a JS {@code String} wrapper object: Rhino's LiveConnect maps a
     *  Java {@code java.lang.String} to a Java-backed object whose {@code
     *  .split} dispatches to {@code java.lang.String.split(regex)} — which
     *  treats {@code "?"} as a regex meta-char and crashes. Wrapping with
     *  {@code new String(s)} via {@code cx.newObject} produces a real JS
     *  {@code String} object whose proto chain includes our polyfilled
     *  {@code String.prototype.split}. */
    static Object toJsString(String s, Scriptable scope) {
        if (s == null) return null;
        java.util.function.Consumer<String> sink =
            RhinoScriptEngine.SCRIPT_LOG_THREADLOCAL.get();
        Context cx = Context.getCurrentContext();
        if (cx == null || scope == null) {
            if (sink != null) sink.accept("[debug] toJsString: no Context/scope — returning Java String");
            return s;
        }
        try {
            // cx.newObject(scope, "String", [s]) constructs a JS String
            // object whose [[Prototype]] is String.prototype — so .split,
            // .substring, .indexOf etc. all resolve to the JS implementations
            // (including our polyfill). Behaves like `new String(s)` in JS.
            Object jsStr = cx.newObject(scope, "String", new Object[]{s});
            if (sink != null) sink.accept("[debug] toJsString: wrapped as JS String, type="
                + jsStr.getClass().getName());
            return jsStr;
        } catch (Throwable t) {
            if (sink != null) sink.accept("[debug] toJsString FAILED: "
                + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
        return s;
    }

    /**
     * Chai-like fluent assertion chain. Supports the shapes seen in real
     * Bruno collections: {@code expect(x).to.equal(y)},
     * {@code expect(x).to.not.include(y)}, {@code .to.be.true}, {@code .to.exist},
     * {@code .to.have.length(n)}, etc. Mismatches throw to abort the
     * surrounding {@code test(name, fn)} block, which catches and surfaces
     * a "✗ name — message" line in the script log.
     */
    public static final class ExpectChain {
        private final Object actual;
        private final boolean negated;
        public final ExpectChain to;
        public final ExpectChain be;
        public final ExpectChain have;
        public final ExpectChain that;
        public final ExpectChain which;

        public ExpectChain(Object actual, boolean negated) {
            this.actual = actual;
            this.negated = negated;
            // Self-referential chain so .to.be / .to.have all return the same
            // matcher instance — Chai compatibility. We deliberately do NOT
            // expose .a/.an as properties — they're METHODS so scripts can
            // write expect(x).to.be.a("string") for type checks.
            this.to = this; this.be = this; this.have = this;
            this.that = this; this.which = this;
        }

        /** {@code .not} flips the assertion. */
        public ExpectChain getNot() { return new ExpectChain(actual, !negated); }

        // ---- Property-style assertions (no parens needed in JS) ----
        public Object getTrue()   { check(boolEq(actual, true),   "to be true",  "true",  String.valueOf(actual)); return null; }
        public Object getFalse()  { check(boolEq(actual, false),  "to be false", "false", String.valueOf(actual)); return null; }
        public Object getNull()   { check(actual == null,         "to be null",  "null",  String.valueOf(actual)); return null; }
        public Object getUndefined() { check(actual == null || actual == org.mozilla.javascript.Undefined.instance,
                                              "to be undefined", "undefined", String.valueOf(actual)); return null; }
        public Object getOk()     { check(truthy(actual),         "to be truthy", "truthy", String.valueOf(actual)); return null; }
        public Object getExist()  { check(actual != null && actual != org.mozilla.javascript.Undefined.instance,
                                              "to exist", "non-null/undefined", String.valueOf(actual)); return null; }
        public Object getEmpty() {
            int len = lenOf(actual);
            check(len == 0, "to be empty", "length 0", "length " + len); return null;
        }

        // ---- Method-style assertions ----
        public Object equal(Object expected)        { check(eq(actual, expected),      "equal",     str(expected), str(actual)); return null; }
        public Object eq(Object expected)           { return equal(expected); }
        public Object eql(Object expected)          { return equal(expected); }
        /** Chai's {@code expect(x).to.be.a("string")} / .a("number") / .a("array") type check. */
        public Object a(String type)                { return aOrAn(type); }
        public Object an(String type)               { return aOrAn(type); }
        private Object aOrAn(String type) {
            String t = type == null ? "" : type.toLowerCase().trim();
            boolean ok;
            switch (t) {
                case "string":   ok = actual instanceof CharSequence; break;
                case "number":   ok = actual instanceof Number; break;
                case "boolean":  ok = actual instanceof Boolean; break;
                case "array":    ok = actual instanceof org.mozilla.javascript.NativeArray
                                       || actual instanceof java.util.List
                                       || (actual != null && actual.getClass().isArray()); break;
                case "object":   ok = actual instanceof org.mozilla.javascript.Scriptable
                                       || actual instanceof java.util.Map; break;
                case "function": ok = actual instanceof org.mozilla.javascript.Function; break;
                case "null":     ok = actual == null; break;
                case "undefined":ok = actual == null || actual == org.mozilla.javascript.Undefined.instance; break;
                default: ok = actual != null && actual.getClass().getSimpleName().equalsIgnoreCase(t);
            }
            check(ok, "be a " + type, type, actual == null ? "null" : actual.getClass().getSimpleName());
            return null;
        }
        public Object include(Object expected)      { check(contains(actual, expected),"include",   str(expected), str(actual)); return null; }
        public Object includes(Object expected)     { return include(expected); }
        public Object contain(Object expected)      { return include(expected); }
        public Object match(Object pattern)         { check(matches(actual, pattern),  "match",     str(pattern),  str(actual)); return null; }
        public Object length(int expected)          { int len = lenOf(actual); check(len == expected, "have length " + expected, String.valueOf(expected), String.valueOf(len)); return null; }
        public Object lengthOf(int expected)        { return length(expected); }
        public Object above(Number expected)        { check(cmp(actual, expected) > 0, "be above",     str(expected), str(actual)); return null; }
        public Object below(Number expected)        { check(cmp(actual, expected) < 0, "be below",     str(expected), str(actual)); return null; }
        public Object atLeast(Number expected)      { check(cmp(actual, expected) >= 0, "be at least",  str(expected), str(actual)); return null; }
        public Object atMost(Number expected)       { check(cmp(actual, expected) <= 0, "be at most",   str(expected), str(actual)); return null; }
        public Object property(String name)         { check(hasProp(actual, name),     "have property", name, str(actual)); return null; }
        public Object property(String name, Object expected) {
            Object propValue = getProp(actual, name);
            check(hasProp(actual, name) && eq(propValue, expected),
                "have property " + name, str(expected), str(propValue));
            return null;
        }

        // Property accessors that look like assertions (Chai style: .to.be.true)
        public ExpectChain getDeep() { return this; }
        public ExpectChain getNested() { return this; }

        private void check(boolean ok, String verb, String expectedStr, String actualStr) {
            boolean pass = negated ? !ok : ok;
            if (!pass) {
                throw new RuntimeException("expected " + actualStr
                    + (negated ? " to not " : " to ") + verb
                    + (expectedStr == null ? "" : " " + expectedStr));
            }
        }

        private static String str(Object o) {
            if (o == null) return "null";
            String s = Context.toString(o);
            return s.length() > 200 ? s.substring(0, 200) + "…" : s;
        }
        private static boolean truthy(Object o) {
            if (o == null) return false;
            if (o instanceof Boolean) return (Boolean) o;
            if (o instanceof Number) return ((Number) o).doubleValue() != 0;
            if (o instanceof CharSequence) return ((CharSequence) o).length() > 0;
            return true;
        }
        private static boolean boolEq(Object a, boolean b) {
            return a instanceof Boolean && ((Boolean) a) == b;
        }
        private static boolean eq(Object a, Object e) {
            if (a == null) return e == null;
            if (e == null) return false;
            // Loose equality: number-vs-string, Rhino doubles vs JS ints.
            if (a instanceof Number && e instanceof Number) {
                return ((Number) a).doubleValue() == ((Number) e).doubleValue();
            }
            if (a instanceof Number || e instanceof Number) {
                try { return Double.parseDouble(Context.toString(a))
                                == Double.parseDouble(Context.toString(e)); }
                catch (Exception ignore) {}
            }
            return Context.toString(a).equals(Context.toString(e));
        }
        private static int cmp(Object a, Object e) {
            try {
                double ad = a instanceof Number ? ((Number) a).doubleValue() : Double.parseDouble(Context.toString(a));
                double ed = e instanceof Number ? ((Number) e).doubleValue() : Double.parseDouble(Context.toString(e));
                return Double.compare(ad, ed);
            } catch (Exception ex) { return 0; }
        }
        private static boolean contains(Object haystack, Object needle) {
            if (haystack == null || haystack == Undefined.instance
                    || needle == null || needle == Undefined.instance) {
                return false;
            }
            return containsDeep(
                haystack,
                needle,
                new java.util.IdentityHashMap<>(),
                0
            );
        }
        private static boolean containsDeep(
                Object haystack,
                Object needle,
                java.util.IdentityHashMap<Object, Boolean> seen,
                int depth) {
            if (haystack == null || haystack == Undefined.instance || depth > 12) {
                return false;
            }
            if (haystack instanceof org.mozilla.javascript.Wrapper) {
                try {
                    Object unwrapped = ((org.mozilla.javascript.Wrapper) haystack).unwrap();
                    if (unwrapped != null) haystack = unwrapped;
                } catch (Throwable ignore) {}
            }
            if (needle instanceof org.mozilla.javascript.Wrapper) {
                try {
                    Object unwrapped = ((org.mozilla.javascript.Wrapper) needle).unwrap();
                    if (unwrapped != null) needle = unwrapped;
                } catch (Throwable ignore) {}
            }

            if (eq(haystack, needle)) return true;
            String needleStr = Context.toString(needle);
            if (haystack instanceof CharSequence) {
                return haystack.toString().contains(needleStr);
            }
            Class<?> haystackClass = haystack.getClass();
            if (haystackClass.isArray()) {
                int len = java.lang.reflect.Array.getLength(haystack);
                for (int i = 0; i < len; i++) {
                    Object v = java.lang.reflect.Array.get(haystack, i);
                    if (containsDeep(v, needle, seen, depth + 1)) return true;
                }
                return false;
            }
            if (haystack instanceof Iterable<?>) {
                if (seen.put(haystack, Boolean.TRUE) != null) return false;
                for (Object v : (Iterable<?>) haystack) {
                    if (containsDeep(v, needle, seen, depth + 1)) return true;
                }
                return false;
            }
            if (haystack instanceof java.util.Map<?, ?>) {
                if (seen.put(haystack, Boolean.TRUE) != null) return false;
                for (java.util.Map.Entry<?, ?> en : ((java.util.Map<?, ?>) haystack).entrySet()) {
                    if (en.getKey() != null && Context.toString(en.getKey()).contains(needleStr)) {
                        return true;
                    }
                    if (containsDeep(en.getValue(), needle, seen, depth + 1)) return true;
                }
                return false;
            }
            if (haystack instanceof org.mozilla.javascript.Scriptable) {
                if (seen.put(haystack, Boolean.TRUE) != null) return false;
                org.mozilla.javascript.Scriptable s = (org.mozilla.javascript.Scriptable) haystack;
                Object[] ids = s.getIds();
                for (Object id : ids) {
                    if (id != null && Context.toString(id).contains(needleStr)) return true;
                    Object v = id instanceof Integer
                        ? s.get((Integer) id, s)
                        : s.get(String.valueOf(id), s);
                    if (v == org.mozilla.javascript.Scriptable.NOT_FOUND) continue;
                    if (containsDeep(v, needle, seen, depth + 1)) return true;
                }
                return Context.toString(haystack).contains(needleStr);
            }
            return Context.toString(haystack).contains(needleStr);
        }
        private static boolean matches(Object actual, Object pattern) {
            if (actual == null || pattern == null) return false;
            try {
                String pat = Context.toString(pattern);
                if (pat.startsWith("/") && pat.lastIndexOf('/') > 0) {
                    int last = pat.lastIndexOf('/');
                    pat = pat.substring(1, last);
                }
                return Context.toString(actual).matches(".*" + pat + ".*");
            } catch (Exception e) { return false; }
        }
        private static int lenOf(Object o) {
            if (o == null) return 0;
            if (o instanceof CharSequence) return ((CharSequence) o).length();
            if (o instanceof org.mozilla.javascript.Scriptable) {
                Object len = ((org.mozilla.javascript.Scriptable) o).get("length",
                    (org.mozilla.javascript.Scriptable) o);
                if (len instanceof Number) return ((Number) len).intValue();
            }
            return 0;
        }
        private static boolean hasProp(Object o, String name) {
            return getPropInternal(o, name) != PROP_MISSING;
        }
        private static Object getProp(Object o, String name) {
            Object v = getPropInternal(o, name);
            return v == PROP_MISSING ? null : v;
        }
        private static final Object PROP_MISSING = new Object();
        private static Object getPropInternal(Object o, String name) {
            if (o == null || name == null || name.isEmpty()) return PROP_MISSING;
            if (o instanceof org.mozilla.javascript.Wrapper) {
                try {
                    Object unwrapped = ((org.mozilla.javascript.Wrapper) o).unwrap();
                    if (unwrapped != null) o = unwrapped;
                } catch (Throwable ignore) {}
            }
            if (o instanceof org.mozilla.javascript.Scriptable) {
                org.mozilla.javascript.Scriptable s = (org.mozilla.javascript.Scriptable) o;
                Object v = s.get(name, s);
                if (v != org.mozilla.javascript.Scriptable.NOT_FOUND) return v;
            }
            if (o instanceof java.util.Map) {
                java.util.Map<?, ?> m = (java.util.Map<?, ?>) o;
                if (m.containsKey(name)) return m.get(name);
            }
            try {
                java.lang.reflect.Method exact = o.getClass().getMethod(name);
                if (exact.getParameterCount() == 0) return exact.invoke(o);
            } catch (Throwable ignore) {}
            try {
                String cap = Character.toUpperCase(name.charAt(0)) + name.substring(1);
                java.lang.reflect.Method getter = o.getClass().getMethod("get" + cap);
                if (getter.getParameterCount() == 0) return getter.invoke(o);
            } catch (Throwable ignore) {}
            try {
                String cap = Character.toUpperCase(name.charAt(0)) + name.substring(1);
                java.lang.reflect.Method isser = o.getClass().getMethod("is" + cap);
                if (isser.getParameterCount() == 0) return isser.invoke(o);
            } catch (Throwable ignore) {}
            try {
                java.lang.reflect.Field f = o.getClass().getField(name);
                return f.get(o);
            } catch (Throwable ignore) {}
            return PROP_MISSING;
        }
    }
}
