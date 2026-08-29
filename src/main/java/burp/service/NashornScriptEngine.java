package burp.service;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.models.ScriptContext;
import com.google.gson.Gson;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Pattern;
import javax.script.Bindings;
import javax.script.ScriptEngine;
import javax.script.SimpleBindings;

public final class NashornScriptEngine {
   private static volatile Boolean availableCache = null;
   private final ScriptContext ctx;
   private final PostmanCollection.Request currentRequest;

   public static boolean isAvailable() {
      Boolean c = availableCache;
      if (c != null) {
         return c;
      } else {
         try {
            Class<?> facCls = Class.forName("org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory");
            Object fac = facCls.getDeclaredConstructor().newInstance();
            Method getter = facCls.getMethod("getScriptEngine", String[].class);
            ScriptEngine probe = (ScriptEngine)getter.invoke(fac, new String[]{"--language=es6"});
            probe.eval("1+1");
            availableCache = Boolean.TRUE;
         } catch (Throwable var5) {
            availableCache = Boolean.FALSE;
         }

         return availableCache;
      }
   }

   private static ScriptEngine newEngine() throws Exception {
      Class<?> facCls = Class.forName("org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory");
      Object fac = facCls.getDeclaredConstructor().newInstance();
      Method getter = facCls.getMethod("getScriptEngine", String[].class);
      return (ScriptEngine)getter.invoke(fac, new String[]{"--language=es6"});
   }

   public NashornScriptEngine(ScriptContext ctx, PostmanCollection.Request currentRequest) {
      this.ctx = ctx;
      this.currentRequest = currentRequest;
   }

   public void run(String script) throws Exception {
      if (script != null && !script.trim().isEmpty()) {
         ScriptEngine engine = newEngine();
         Bindings b = new SimpleBindings();
         NashornScriptEngine.PmHost pm = new NashornScriptEngine.PmHost(this.ctx, this.currentRequest);
         b.put("pm", pm);
         b.put("postman", new NashornScriptEngine.PostmanHost());
         b.put("bru", new NashornScriptEngine.BruHost(this.ctx));
         b.put("console", new NashornScriptEngine.ConsoleHost(this.ctx));
         b.put("btoa", (Function<String, String>)s -> Base64.getEncoder().encodeToString(s == null ? new byte[0] : s.getBytes(StandardCharsets.ISO_8859_1)));
         b.put("atob", (Function<String, String>)s -> burp.service.RhinoScriptEngine.atobImpl(s));
         b.put("__burpManProcessEnv", new ProcessEnvHost());
         engine.eval("if (typeof globalThis === 'undefined') { this.globalThis = this; }\n", b);
         // process.env.NAME → System.getenv(NAME) so Bruno scripts that
         // read secrets from the OS environment work under Nashorn too.
         engine.eval(
            "if (typeof process === 'undefined') {\n" +
            "  var process = { env: new Proxy({}, {\n" +
            "    get: function(_, k){ return __burpManProcessEnv.get(String(k)); },\n" +
            "    has: function(_, k){ return __burpManProcessEnv.get(String(k)) !== null; }\n" +
            "  }) };\n" +
            "}\n", b);
         engine.eval(script, b);
      }
   }

   private static Class<?> tryLoad(String name) {
      try {
         return Class.forName(name);
      } catch (Throwable var2) {
         return null;
      }
   }

   public static final class BruHost {
      public final NashornScriptEngine.VariablesHost env;
      public final NashornScriptEngine.VariablesHost vars;
      public final NashornScriptEngine.CookiesHost cookies;

      BruHost(ScriptContext ctx) {
         this.env = new NashornScriptEngine.VariablesHost(ctx, NashornScriptEngine.VariablesHost.Scope.ENV);
         this.vars = new NashornScriptEngine.VariablesHost(ctx, NashornScriptEngine.VariablesHost.Scope.COLLECTION);
         this.cookies = new NashornScriptEngine.CookiesHost();
      }

      public Object getEnvVar(String k) {
         return this.env.get(k);
      }

      public void setEnvVar(String k, Object v) {
         this.env.set(k, v);
      }

      public Object getVar(String k) {
         return this.vars.get(k);
      }

      public void setVar(String k, Object v) {
         this.vars.set(k, v);
      }

      public void setNextRequest(String name) {
         RhinoScriptEngine.NEXT_REQUEST_THREADLOCAL.set(name == null ? "" : name);
      }
   }

   public static final class ConsoleHost {
      private final ScriptContext ctx;

      ConsoleHost(ScriptContext ctx) {
         this.ctx = ctx;
      }

      public void log(Object... args) {
         this.ctx.log("[console.log] " + join(args));
      }

      public void info(Object... args) {
         this.ctx.log("[console.info] " + join(args));
      }

      public void warn(Object... args) {
         this.ctx.log("[console.warn] " + join(args));
      }

      public void error(Object... args) {
         this.ctx.log("[console.error] " + join(args));
      }

      public void debug(Object... args) {
         this.ctx.log("[console.debug] " + join(args));
      }

      private static String join(Object[] args) {
         if (args != null && args.length != 0) {
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < args.length; i++) {
               if (i > 0) {
                  sb.append(' ');
               }

               sb.append(args[i] == null ? "null" : args[i].toString());
            }

            return sb.toString();
         } else {
            return "";
         }
      }
   }

   public static final class CookieJarStub {
      public void clear() {
         CookieJar jar = RhinoScriptEngine.SCRIPT_COOKIE_JAR.get();
         if (jar != null) {
            jar.clear();
         }
      }
   }

   public static final class CookiesHost {
      public NashornScriptEngine.CookieJarStub jar() {
         return new NashornScriptEngine.CookieJarStub();
      }
   }

   public static final class ExpectChain {
      private final Object actual;
      private final boolean negate;
      public final NashornScriptEngine.ExpectChain to;
      public final NashornScriptEngine.ExpectChain not;
      public final NashornScriptEngine.ExpectChain be;
      public final NashornScriptEngine.ExpectChain have;
      public final boolean exist;

      ExpectChain(Object actual, boolean negate) {
         this.actual = actual;
         this.negate = negate;
         this.to = this;
         this.not = new NashornScriptEngine.ExpectChain(actual, !negate, this);
         this.be = this;
         this.have = this;
         this.exist = actual != null;
         if (!this.exist && !negate) {
            this.shouldEnforceExist();
         }
      }

      private ExpectChain(Object actual, boolean negate, NashornScriptEngine.ExpectChain parent) {
         this.actual = actual;
         this.negate = negate;
         this.to = this;
         this.not = parent;
         this.be = this;
         this.have = this;
         this.exist = actual != null;
      }

      private boolean shouldEnforceExist() {
         return false;
      }

      public boolean equal(Object expected) {
         boolean eq = this.actual == null && expected == null
            || this.actual != null && this.actual.toString().equals(expected == null ? null : expected.toString());
         if (eq == this.negate) {
            throw new RuntimeException("expected " + this.actual + (this.negate ? " not " : " ") + "to equal " + expected);
         } else {
            return true;
         }
      }

      public boolean eql(Object expected) {
         return this.equal(expected);
      }

      public boolean include(Object expected) {
         String a = this.actual == null ? "" : this.actual.toString();
         String bv = expected == null ? "" : expected.toString();
         boolean has = containsDeep(this.actual, bv, new java.util.IdentityHashMap<>(), 0);
         if (has == this.negate) {
            throw new RuntimeException("expected " + a + (this.negate ? " not " : " ") + "to include " + bv);
         } else {
            return true;
         }
      }

      private static boolean containsDeep(Object haystack, String needle,
                                          java.util.IdentityHashMap<Object, Boolean> seen,
                                          int depth) {
         if (haystack == null || needle == null || depth > 12) {
            return false;
         }

         String hay = haystack.toString();
         if (hay.contains(needle)) {
            return true;
         }

         Class<?> hc = haystack.getClass();
         if (hc.isArray()) {
            int len = java.lang.reflect.Array.getLength(haystack);
            for(int i = 0; i < len; ++i) {
               Object v = java.lang.reflect.Array.get(haystack, i);
               if (containsDeep(v, needle, seen, depth + 1)) return true;
            }
            return false;
         }

         if (haystack instanceof Iterable) {
            if (seen.put(haystack, Boolean.TRUE) != null) return false;
            for(Object v : (Iterable)haystack) {
               if (containsDeep(v, needle, seen, depth + 1)) return true;
            }
            return false;
         }

         if (haystack instanceof Map) {
            if (seen.put(haystack, Boolean.TRUE) != null) return false;
            for(Object eObj : ((Map)haystack).entrySet()) {
               Map.Entry en = (Map.Entry)eObj;
               Object key = en.getKey();
               if (key != null && key.toString().contains(needle)) return true;
               if (containsDeep(en.getValue(), needle, seen, depth + 1)) return true;
            }
            return false;
         }

         return false;
      }

      public boolean a(String type) {
         return this.is(type);
      }

      public boolean an(String type) {
         return this.is(type);
      }

      private boolean is(String type) {
         String actualType = typeOf(this.actual);
         boolean match = actualType.equalsIgnoreCase(type);
         if (match == this.negate) {
            throw new RuntimeException("expected " + this.actual + (this.negate ? " not " : " ") + "to be a " + type + ", got " + actualType);
         } else {
            return true;
         }
      }

      private static String typeOf(Object o) {
         if (o == null) {
            return "null";
         } else if (o instanceof String) {
            return "string";
         } else if (o instanceof Boolean) {
            return "boolean";
         } else if (o instanceof Number) {
            return "number";
         } else if (o instanceof List) {
            return "array";
         } else {
            return o instanceof Map ? "object" : "object";
         }
      }

      public boolean length(int expected) {
         int len;
         if (this.actual instanceof String) {
            len = ((String)this.actual).length();
         } else if (this.actual instanceof List) {
            len = ((List)this.actual).size();
         } else {
            if (!(this.actual instanceof Map)) {
               throw new RuntimeException("length: actual has no .length: " + this.actual);
            }

            len = ((Map)this.actual).size();
         }

         boolean match = len == expected;
         if (match == this.negate) {
            throw new RuntimeException("expected length " + expected + " but got " + len);
         } else {
            return true;
         }
      }

      public boolean match(Object regex) {
         String a = this.actual == null ? "" : this.actual.toString();
         String pattern = regex == null ? "" : regex.toString();
         if (pattern.startsWith("/") && pattern.lastIndexOf(47) > 0) {
            pattern = pattern.substring(1, pattern.lastIndexOf(47));
         }

         boolean matched = Pattern.compile(pattern).matcher(a).find();
         if (matched == this.negate) {
            throw new RuntimeException("expected " + a + (this.negate ? " not " : " ") + "to match " + regex);
         } else {
            return true;
         }
      }
   }

   public static final class HeadersHost {
      private final Map<String, String> map = new HashMap<>();

      HeadersHost(List<PostmanCollection.Header> headers) {
         if (headers != null) {
            for (PostmanCollection.Header h : headers) {
               if (h != null && h.key != null) {
                  this.map.put(h.key.toLowerCase(), h.value == null ? "" : h.value);
               }
            }
         }
      }

      public String get(String name) {
         return name == null ? null : this.map.get(name.toLowerCase());
      }

      public boolean has(String name) {
         return name != null && this.map.containsKey(name.toLowerCase());
      }
   }

   public static final class InfoHost {
      public String requestName = "";
      public String requestId = "";
      public String iteration = "0";
   }

   public static final class PmHost {
      private final ScriptContext ctx;
      private final PostmanCollection.Request currentRequest;
      public final NashornScriptEngine.VariablesHost variables;
      public final NashornScriptEngine.VariablesHost environment;
      public final NashornScriptEngine.VariablesHost collectionVariables;
      public final NashornScriptEngine.VariablesHost globals;
      public final NashornScriptEngine.RequestHost request;
      public final NashornScriptEngine.ResponseHost response;
      public final NashornScriptEngine.InfoHost info;

      PmHost(ScriptContext ctx, PostmanCollection.Request currentRequest) {
         this.ctx = ctx;
         this.currentRequest = currentRequest;
         this.variables = new NashornScriptEngine.VariablesHost(ctx, NashornScriptEngine.VariablesHost.Scope.GLOBAL);
         this.environment = new NashornScriptEngine.VariablesHost(ctx, NashornScriptEngine.VariablesHost.Scope.ENV);
         this.collectionVariables = new NashornScriptEngine.VariablesHost(ctx, NashornScriptEngine.VariablesHost.Scope.COLLECTION);
         this.globals = new NashornScriptEngine.VariablesHost(ctx, NashornScriptEngine.VariablesHost.Scope.GLOBAL);
         this.request = new NashornScriptEngine.RequestHost(currentRequest);
         this.response = new NashornScriptEngine.ResponseHost(ctx.getExecutedRequest());
         this.info = new NashornScriptEngine.InfoHost();
      }

      public Object test(String name, Object fn) {
         boolean passed = true;
         String error = null;

         try {
            if (fn != null) {
               Class<?> jsObjCls = NashornScriptEngine.tryLoad("org.openjdk.nashorn.api.scripting.JSObject");
               if (jsObjCls != null && jsObjCls.isInstance(fn)) {
                  Method call = jsObjCls.getMethod("call", Object.class, Object[].class);
                  call.invoke(fn, null, new Object[0]);
               }
            }
         } catch (Throwable var9) {
            Throwable cause = var9.getCause() != null ? var9.getCause() : var9;
            passed = false;
            error = cause.getClass().getSimpleName() + ": " + cause.getMessage();
         }

         ExecutedRequest.TestResult result = new ExecutedRequest.TestResult(name, passed, error);
         List<ExecutedRequest.TestResult> sink = RhinoScriptEngine.TEST_RESULTS_THREADLOCAL.get();
         if (sink != null) {
            sink.add(result);
         }

         try {
            Consumer<String> uiLog = ScriptExecutor.UI_LOG;
            if (uiLog != null) {
               uiLog.accept(passed ? "✓ " + name : "✗ " + name + (error == null ? "" : " — " + error));
            }
         } catch (Throwable var8) {
         }

         return null;
      }

      public NashornScriptEngine.ExpectChain expect(Object actual) {
         return new NashornScriptEngine.ExpectChain(actual, false);
      }

      public void setEnvironmentVariable(String k, Object v) {
         this.environment.set(k, v);
      }

      public Object getEnvironmentVariable(String k) {
         return this.environment.get(k);
      }

      public void setGlobalVariable(String k, Object v) {
         this.globals.set(k, v);
      }

      public Object getGlobalVariable(String k) {
         return this.globals.get(k);
      }

      public Object sendRequest(Object urlOrReq, Object callback) {
         String url = urlOrReq == null ? "" : urlOrReq.toString();

         try {
            HttpURLConnection conn = (HttpURLConnection)new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(15000);
            int code = conn.getResponseCode();
            InputStream in = code < 400 ? conn.getInputStream() : conn.getErrorStream();
            String body = in == null ? "" : new String(in.readAllBytes(), StandardCharsets.UTF_8);
            invokeJsCallback(callback, null, new NashornScriptEngine.SimpleResponse(code, body));
         } catch (Throwable var8) {
            invokeJsCallback(callback, var8.getMessage(), null);
         }

         return null;
      }

      private static void invokeJsCallback(Object callback, Object errArg, Object resArg) {
         if (callback != null) {
            try {
               Class<?> jsObjCls = NashornScriptEngine.tryLoad("org.openjdk.nashorn.api.scripting.JSObject");
               if (jsObjCls != null && jsObjCls.isInstance(callback)) {
                  Method call = jsObjCls.getMethod("call", Object.class, Object[].class);
                  call.invoke(callback, null, new Object[]{errArg, resArg});
               }
            } catch (Throwable var5) {
            }
         }
      }
   }

   public static final class PostmanHost {
      public void setNextRequest(String name) {
         RhinoScriptEngine.NEXT_REQUEST_THREADLOCAL.set(name == null ? "" : name);
      }
   }

   public static final class RequestHost {
      private final PostmanCollection.Request req;
      public final NashornScriptEngine.RequestBodyHost body;

      RequestHost(PostmanCollection.Request req) {
         this.req = req;
         this.body = new NashornScriptEngine.RequestBodyHost(req);
      }

      public String getUrl() {
         return this.req != null && this.req.url != null ? this.req.url.toString() : "";
      }

      public String getMethod() {
         return this.req != null && this.req.method != null ? this.req.method : "GET";
      }

      public Object getHeaders() {
         Map<String, String> h = new HashMap<>();
         if (this.req != null && this.req.header != null) {
            for (PostmanCollection.Header header : this.req.header) {
               if (header != null && header.key != null && !header.disabled) {
                  h.put(header.key, header.value == null ? "" : header.value);
               }
            }
         }

         return h;
      }

      public Object getBody() {
         return this.body;
      }
   }

   public static final class RequestBodyHost {
      private final PostmanCollection.Request req;

      RequestBodyHost(PostmanCollection.Request req) {
         this.req = req;
      }

      public String getMode() {
         if (this.req == null || this.req.body == null) return "";
         if (this.req.body.mode != null && !this.req.body.mode.trim().isEmpty()) return this.req.body.mode;
         if (this.req.body.raw != null) return "raw";
         if (this.req.body.formdata != null && !this.req.body.formdata.isEmpty()) return "formdata";
         if (this.req.body.urlencoded != null && !this.req.body.urlencoded.isEmpty()) return "urlencoded";
         return "";
      }

      public String getRaw() {
         if (this.req == null || this.req.body == null || this.req.body.raw == null) return "";
         return this.req.body.raw;
      }

      public Object getFormdata() {
         if (this.req == null || this.req.body == null || this.req.body.formdata == null) {
            return java.util.Collections.emptyList();
         }
         return this.req.body.formdata;
      }

      public Object getUrlencoded() {
         if (this.req == null || this.req.body == null || this.req.body.urlencoded == null) {
            return java.util.Collections.emptyList();
         }
         return this.req.body.urlencoded;
      }
   }

   public static final class ResponseHaveChain {
      private final NashornScriptEngine.ResponseHost r;

      ResponseHaveChain(NashornScriptEngine.ResponseHost r) {
         this.r = r;
      }

      public void status(int expected) {
         if (this.r.code != expected) {
            throw new RuntimeException("expected status " + expected + " but got " + this.r.code);
         }
      }
   }

   public static final class ResponseHost {
      private final ExecutedRequest execResp;
      public final int code;
      public final String status;
      public final long responseTime;
      public final NashornScriptEngine.HeadersHost headers;
      public final NashornScriptEngine.ResponseToChain to;

      ResponseHost(ExecutedRequest execResp) {
         this.execResp = execResp;
         this.code = execResp == null ? 0 : execResp.getStatusCode();
         this.status = execResp == null ? "" : (execResp.getStatusText() == null ? this.code + "" : execResp.getStatusText());
         this.responseTime = execResp == null ? 0L : execResp.getDurationMs();
         this.headers = new NashornScriptEngine.HeadersHost(execResp == null ? null : execResp.getResponseHeaders());
         this.to = new NashornScriptEngine.ResponseToChain(this);
      }

      public String text() {
         return this.execResp != null && this.execResp.getResponseBody() != null ? this.execResp.getResponseBody() : "";
      }

      public Object json() {
         try {
            return new Gson().fromJson(this.text(), Object.class);
         } catch (Throwable var2) {
            return null;
         }
      }
   }

   public static final class ResponseToChain {
      public final NashornScriptEngine.ResponseHaveChain have;
      public final NashornScriptEngine.ResponseBeChain be;

      ResponseToChain(NashornScriptEngine.ResponseHost r) {
         this.have = new NashornScriptEngine.ResponseHaveChain(r);
         this.be = new NashornScriptEngine.ResponseBeChain(r);
      }
   }

   public static final class ResponseBeChain {
      private final NashornScriptEngine.ResponseHost r;

      ResponseBeChain(NashornScriptEngine.ResponseHost r) {
         this.r = r;
      }

      public Object getJson() {
         return this.json();
      }

      public Object json() {
         if (this.r == null) {
            throw new RuntimeException("expected response to be json");
         }
         Object parsed = null;
         try {
            parsed = this.r.json();
         } catch (Throwable ignore) {
         }
         if (parsed != null) return null;
         String body = null;
         try {
            body = this.r.text();
         } catch (Throwable ignore) {
         }
         if (body == null || body.trim().isEmpty()) {
            throw new RuntimeException("expected response body to be json but it was empty");
         }
         throw new RuntimeException("expected response body to be json");
      }
   }

   public static final class SimpleResponse {
      public final int code;
      public final String text;

      SimpleResponse(int code, String text) {
         this.code = code;
         this.text = text;
      }

      public String json() {
         return this.text;
      }
   }

   public static final class VariablesHost {
      private final ScriptContext ctx;
      private final NashornScriptEngine.VariablesHost.Scope scope;

      VariablesHost(ScriptContext ctx, NashornScriptEngine.VariablesHost.Scope scope) {
         this.ctx = ctx;
         this.scope = scope;
      }

      public Object get(String key) {
         if (key == null) {
            return null;
         } else {
            switch (this.scope) {
               case ENV:
                  return this.ctx.getEnvironmentVariables().get(key);
               case GLOBAL:
               default:
                  String v = this.ctx.getGlobalVariables().get(key);
                  if (v != null) {
                     return v;
                  } else {
                     v = this.ctx.getEnvironmentVariables().get(key);
                     if (v != null) {
                        return v;
                     }

                     return this.ctx.getCollectionVariables().get(key);
                  }
               case COLLECTION:
                  return this.ctx.getCollectionVariables().get(key);
            }
         }
      }

      public void set(String key, Object value) {
         if (key != null && value != null) {
            String v = value.toString();
            switch (this.scope) {
               case ENV:
                  this.ctx.getEnvironmentVariables().put(key, v);
                  break;
               case GLOBAL:
               default:
                  this.ctx.setVariable(key, v);
                  break;
               case COLLECTION:
                  this.ctx.getCollectionVariables().put(key, v);
            }
         }
      }

      public void unset(String key) {
         if (key != null) {
            this.ctx.getEnvironmentVariables().remove(key);
            this.ctx.getCollectionVariables().remove(key);
            this.ctx.getGlobalVariables().remove(key);
         }
      }

      public boolean has(String key) {
         return this.get(key) != null;
      }

      public void clear() {
         switch (this.scope) {
            case ENV:
               this.ctx.getEnvironmentVariables().clear();
               break;
            case GLOBAL:
            default:
               this.ctx.getGlobalVariables().clear();
               break;
            case COLLECTION:
               this.ctx.getCollectionVariables().clear();
         }
      }

      public Object toObject() {
         switch (this.scope) {
            case ENV:
               return new HashMap<>(this.ctx.getEnvironmentVariables());
            case GLOBAL:
            default:
               return new HashMap<>(this.ctx.getGlobalVariables());
            case COLLECTION:
               return new HashMap<>(this.ctx.getCollectionVariables());
         }
      }

      public static enum Scope {
         ENV,
         GLOBAL,
         COLLECTION;
      }
   }
}
