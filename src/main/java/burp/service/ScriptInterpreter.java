package burp.service;

import burp.models.ExecutedRequest;
import burp.models.PostmanCollection;
import burp.models.ScriptContext;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

final class ScriptInterpreter {
   private final ScriptContext ctx;
   private final Map<String, Object> locals = new HashMap<>();

   ScriptInterpreter(ScriptContext ctx) {
      this.ctx = ctx;
   }

   void run(String script) {
      if (script != null) {
         String stripped = stripComments(script);

         for (String stmt : splitStatements(stripped)) {
            String s = stmt.trim();
            if (!s.isEmpty()) {
               try {
                  this.executeStatement(s);
               } catch (Throwable var7) {
               }
            }
         }
      }
   }

   private static String stripComments(String src) {
      StringBuilder out = new StringBuilder(src.length());
      int i = 0;
      boolean inStr = false;
      char strCh = 0;

      while (i < src.length()) {
         char c = src.charAt(i);
         if (inStr) {
            out.append(c);
            if (c == '\\' && i + 1 < src.length()) {
               out.append(src.charAt(i + 1));
               i += 2;
            } else {
               if (c == strCh) {
                  inStr = false;
               }

               i++;
            }
         } else if (c != '\'' && c != '"' && c != '`') {
            if (c == '/' && i + 1 < src.length() && src.charAt(i + 1) == '/') {
               while (i < src.length() && src.charAt(i) != '\n') {
                  i++;
               }
            } else if (c == '/' && i + 1 < src.length() && src.charAt(i + 1) == '*') {
               i += 2;

               while (i + 1 < src.length() && (src.charAt(i) != '*' || src.charAt(i + 1) != '/')) {
                  i++;
               }

               i = Math.min(i + 2, src.length());
            } else {
               out.append(c);
               i++;
            }
         } else {
            inStr = true;
            strCh = c;
            out.append(c);
            i++;
         }
      }

      return out.toString();
   }

   private static List<String> splitStatements(String src) {
      List<String> out = new ArrayList<>();
      int depth = 0;
      boolean inStr = false;
      char strCh = 0;
      StringBuilder cur = new StringBuilder();

      for (int i = 0; i < src.length(); i++) {
         char c = src.charAt(i);
         if (inStr) {
            cur.append(c);
            if (c == '\\' && i + 1 < src.length()) {
               cur.append(src.charAt(++i));
            } else if (c == strCh) {
               inStr = false;
            }
         } else if (c != '\'' && c != '"' && c != '`') {
            if (c == '(' || c == '[' || c == '{') {
               depth++;
            } else if (c == ')' || c == ']' || c == '}') {
               depth--;
            }

            if (c == ';' && depth == 0) {
               out.add(cur.toString());
               cur.setLength(0);
            } else if (c != '\n' || depth != 0) {
               cur.append(c);
            } else if (cur.length() > 0) {
               out.add(cur.toString());
               cur.setLength(0);
            }
         } else {
            inStr = true;
            strCh = c;
            cur.append(c);
         }
      }

      if (cur.length() > 0) {
         out.add(cur.toString());
      }

      return out;
   }

   private void executeStatement(String stmt) {
      String low = stmt.replaceAll("^\\s+", "");
      if (!low.startsWith("if ")
         && !low.startsWith("if(")
         && !low.startsWith("for ")
         && !low.startsWith("for(")
         && !low.startsWith("while ")
         && !low.startsWith("while(")
         && !low.startsWith("function ")
         && !low.startsWith("function(")
         && !low.startsWith("return")
         && !low.startsWith("try")
         && !low.startsWith("catch")) {
         String[] var6;
         for (String kw : var6 = new String[]{"var ", "let ", "const "}) {
            if (low.startsWith(kw)) {
               String rest = low.substring(kw.length());
               int eq = rest.indexOf(61);
               if (eq < 0) {
                  return;
               }

               String name = rest.substring(0, eq).trim();
               Object val = this.evalExpr(rest.substring(eq + 1).trim());
               this.locals.put(name, val);
               return;
            }
         }

         int eq = topLevelChar(low, '=');
         if (eq > 0
            && (eq + 1 >= low.length() || low.charAt(eq + 1) != '=')
            && (eq <= 0 || low.charAt(eq - 1) != '!' && low.charAt(eq - 1) != '<' && low.charAt(eq - 1) != '>' && low.charAt(eq - 1) != '=')) {
            String lhs = low.substring(0, eq).trim();
            if (lhs.matches("[A-Za-z_][A-Za-z_0-9]*")) {
               Object val = this.evalExpr(low.substring(eq + 1).trim());
               this.locals.put(lhs, val);
               return;
            }
         }

         this.evalExpr(low);
      }
   }

   private static int topLevelChar(String s, char c) {
      int depth = 0;
      boolean inStr = false;
      char strCh = 0;

      for (int i = 0; i < s.length(); i++) {
         char ch = s.charAt(i);
         if (inStr) {
            if (ch == '\\' && i + 1 < s.length()) {
               i++;
            } else if (ch == strCh) {
               inStr = false;
            }
         } else if (ch == '\'' || ch == '"' || ch == '`') {
            inStr = true;
            strCh = ch;
         } else if (ch == '(' || ch == '[' || ch == '{') {
            depth++;
         } else if (ch != ')' && ch != ']' && ch != '}') {
            if (depth == 0 && ch == c) {
               return i;
            }
         } else {
            depth--;
         }
      }

      return -1;
   }

   private Object evalExpr(String expr) {
      if (expr == null) {
         return null;
      } else {
         ScriptInterpreter.Parser p = new ScriptInterpreter.Parser(expr);
         return p.parseExpr();
      }
   }

   private Object resolveIdent(String name) {
      if (this.locals.containsKey(name)) {
         return this.locals.get(name);
      } else {
         switch (name.hashCode()) {
            case -1950496919:
               if (name.equals("Number")) {
                  return "fn:Number";
               }
               break;
            case -1808118735:
               if (name.equals("String")) {
                  return "fn:String";
               }
               break;
            case -1003958423:
               if (name.equals("parseFloat")) {
                  return "fn:parseFloat";
               }
               break;
            case -391198534:
               if (name.equals("postman")) {
                  return new ScriptInterpreter.PmRoot();
               }
               break;
            case 3581:
               if (name.equals("pm")) {
                  return new ScriptInterpreter.PmRoot();
               }
               break;
            case 97829:
               if (name.equals("bru")) {
                  return new ScriptInterpreter.BruRoot();
               }
               break;
            case 112798:
               if (name.equals("req")) {
                  return this.ctx.getRequest();
               }
               break;
            case 112800:
               if (name.equals("res")) {
                  return new ScriptInterpreter.PmResponse(this.ctx.getExecutedRequest());
               }
               break;
            case 2122702:
               if (name.equals("Date")) {
                  return new ScriptInterpreter.DateObj();
               }
               break;
            case 2286824:
               if (name.equals("JSON")) {
                  return new ScriptInterpreter.JsonObj();
               }
               break;
            case 2390824:
               if (name.equals("Math")) {
                  return new ScriptInterpreter.MathObj();
               }
               break;
            case 951510359:
               if (name.equals("console")) {
                  return new ScriptInterpreter.ConsoleObj();
               }
               break;
            case 1095692943:
               if (name.equals("request")) {
                  return this.ctx.getRequest();
               }
               break;
            case 1187783740:
               if (name.equals("parseInt")) {
                  return "fn:parseInt";
               }
               break;
            case 1387714565:
               if (name.equals("responseHeaders")) {
                  ExecutedRequest r = this.ctx.getExecutedRequest();
                  return r == null ? new ArrayList() : r.getResponseHeaders();
               }
               break;
            case 1438693763:
               if (name.equals("responseBody")) {
                  ExecutedRequest r = this.ctx.getExecutedRequest();
                  return r == null ? "" : (r.getResponseBody() == null ? "" : r.getResponseBody());
               }
               break;
            case 1438723534:
               if (name.equals("responseCode")) {
                  ExecutedRequest r = this.ctx.getExecutedRequest();
                  Map<String, Object> m = new HashMap<>();
                  m.put("code", r == null ? 0.0 : r.getStatusCode());
                  m.put("name", "");
                  return m;
               }
               break;
            case 1729365000:
               if (name.equals("Boolean")) {
                  return "fn:Boolean";
               }
         }

         return null;
      }
   }

   private Object getProp(Object obj, String name) {
      if (obj == null) {
         return null;
      } else if (obj instanceof Map) {
         return ((Map)obj).get(name);
      } else if (obj instanceof List) {
         List<Object> list = (List<Object>)obj;
         if ("length".equals(name)) {
            return (double)list.size();
         } else {
            try {
               return list.get(Integer.parseInt(name));
            } catch (Exception var5) {
               return null;
            }
         }
      } else if (obj instanceof ScriptInterpreter.PmRoot) {
         return ((ScriptInterpreter.PmRoot)obj).get(name);
      } else if (obj instanceof ScriptInterpreter.BruRoot) {
         return ((ScriptInterpreter.BruRoot)obj).get(name);
      } else if (obj instanceof ScriptInterpreter.ExpectChain) {
         return ((ScriptInterpreter.ExpectChain)obj).bound(name);
      } else if (obj instanceof ScriptInterpreter.PmScope) {
         return ((ScriptInterpreter.PmScope)obj).bound(name);
      } else if (obj instanceof ScriptInterpreter.PmResponse) {
         return ((ScriptInterpreter.PmResponse)obj).get(name);
      } else if (obj instanceof ScriptInterpreter.PmHeaders) {
         return ((ScriptInterpreter.PmHeaders)obj).bound(name);
      } else if (obj instanceof ScriptInterpreter.MathObj) {
         return ((ScriptInterpreter.MathObj)obj).bound(name);
      } else if (obj instanceof ScriptInterpreter.DateObj) {
         return ((ScriptInterpreter.DateObj)obj).bound(name);
      } else if (obj instanceof ScriptInterpreter.JsonObj) {
         return ((ScriptInterpreter.JsonObj)obj).bound(name);
      } else {
         return obj instanceof ScriptInterpreter.ConsoleObj ? ((ScriptInterpreter.ConsoleObj)obj).bound(name) : null;
      }
   }

   private Object invoke(Object self, String method, List<Object> args) {
      if (self instanceof ScriptInterpreter.PmScope) {
         return ((ScriptInterpreter.PmScope)self).call(method, args);
      } else if (self instanceof ScriptInterpreter.PmResponse) {
         return ((ScriptInterpreter.PmResponse)self).call(method, args);
      } else if (self instanceof ScriptInterpreter.PmHeaders) {
         return ((ScriptInterpreter.PmHeaders)self).call(method, args);
      } else if (self instanceof ScriptInterpreter.MathObj) {
         return ((ScriptInterpreter.MathObj)self).call(method, args);
      } else if (self instanceof ScriptInterpreter.DateObj) {
         return ((ScriptInterpreter.DateObj)self).call(method, args);
      } else if (self instanceof ScriptInterpreter.JsonObj) {
         return ((ScriptInterpreter.JsonObj)self).call(method, args);
      } else if (self instanceof ScriptInterpreter.ConsoleObj) {
         return ((ScriptInterpreter.ConsoleObj)self).call(method, args);
      } else {
         if (self instanceof ScriptInterpreter.PmRoot) {
            if ("setEnvironmentVariable".equals(method) && args.size() >= 2) {
               this.ctx.getEnvironmentVariables().put(stringify(args.get(0)), stringify(args.get(1)));
               this.ctx.setVariable(stringify(args.get(0)), stringify(args.get(1)));
               return null;
            }

            if ("setGlobalVariable".equals(method) && args.size() >= 2) {
               this.ctx.setVariable(stringify(args.get(0)), stringify(args.get(1)));
               return null;
            }

            if ("getEnvironmentVariable".equals(method) && args.size() >= 1) {
               return this.ctx.getEnvironmentVariables().get(stringify(args.get(0)));
            }

            if ("getGlobalVariable".equals(method) && args.size() >= 1) {
               return this.ctx.getGlobalVariables().get(stringify(args.get(0)));
            }
         }

         if (self instanceof ScriptInterpreter.BruRoot) {
            return ((ScriptInterpreter.BruRoot)self).call(method, args);
         } else if (self instanceof ScriptInterpreter.ExpectChain) {
            return ((ScriptInterpreter.ExpectChain)self).call(method, args);
         } else {
            if (self instanceof Map) {
               Object v = ((Map)self).get(method);
               if ("fn:get".equals(v) && !args.isEmpty()) {
                  return ((Map)self).get(stringify(args.get(0)));
               }
            }

            return null;
         }
      }
   }

   private Object invoke(Object self, String name, List<Object> args, Object receiver) {
      if (self == null && receiver == null) {
         switch (name.hashCode()) {
            case -1950496919:
               if (name.equals("Number")) {
                  return args.isEmpty() ? 0.0 : num(args.get(0));
               }
               break;
            case -1808118735:
               if (name.equals("String")) {
                  return args.isEmpty() ? "" : stringify(args.get(0));
               }
               break;
            case -1289163687:
               if (name.equals("expect")) {
                  return new ScriptInterpreter.ExpectChain(args.isEmpty() ? null : args.get(0));
               }
               break;
            case -1003958423:
               if (name.equals("parseFloat")) {
                  if (args.isEmpty()) {
                     return null;
                  }

                  try {
                     return Double.parseDouble(stringify(args.get(0)).trim());
                  } catch (Exception var8) {
                     return Double.NaN;
                  }
               }
               break;
            case 3556498:
               if (name.equals("test")) {
                  String label = args.isEmpty() ? "" : stringify(args.get(0));
                  if (label != null && !label.isEmpty()) {
                     this.ctx.log("[test] " + label);
                  }

                  return null;
               }
               break;
            case 1187783740:
               if (name.equals("parseInt")) {
                  if (args.isEmpty()) {
                     return null;
                  }

                  try {
                     return (double)Integer.parseInt(stringify(args.get(0)).trim());
                  } catch (Exception var7) {
                     return Double.NaN;
                  }
               }
               break;
            case 1729365000:
               if (name.equals("Boolean")) {
                  return args.isEmpty() ? false : truthy(args.get(0));
               }
         }

         return null;
      } else {
         return this.invoke(receiver, name, args);
      }
   }

   private static String nv(String a, String b) {
      return a != null ? a : b;
   }

   static double num(Object v) {
      if (v == null) {
         return 0.0;
      } else if (v instanceof Boolean) {
         return (Boolean)v ? 1 : 0;
      } else if (v instanceof Number) {
         return ((Number)v).doubleValue();
      } else {
         try {
            return Double.parseDouble(v.toString());
         } catch (Exception var2) {
            return Double.NaN;
         }
      }
   }

   static boolean truthy(Object v) {
      if (v == null) {
         return false;
      } else if (v instanceof Boolean) {
         return (Boolean)v;
      } else if (v instanceof Number) {
         double d = ((Number)v).doubleValue();
         return d != 0.0 && !Double.isNaN(d);
      } else {
         return v instanceof String ? !((String)v).isEmpty() : true;
      }
   }

   static String stringify(Object v) {
      if (v == null) {
         return "";
      } else if (v instanceof Double) {
         double d = (Double)v;
         return d == Math.floor(d) && !Double.isInfinite(d) ? Long.toString((long)d) : Double.toString(d);
      } else {
         return v.toString();
      }
   }

   static boolean looseEq(Object a, Object b) {
      if (a == null && b == null) {
         return true;
      } else if (a == null || b == null) {
         return false;
      } else {
         return !(a instanceof Number) && !(b instanceof Number) ? stringify(a).equals(stringify(b)) : Math.abs(num(a) - num(b)) < 1.0E-9;
      }
   }

   private static Object parseJson(String s) {
      if (s != null && !s.isEmpty()) {
         JsonElement el = JsonParser.parseString(s);
         return jsonToJava(el);
      } else {
         return null;
      }
   }

   private static Object jsonToJava(JsonElement el) {
      if (el == null || el.isJsonNull()) {
         return null;
      } else if (el.isJsonPrimitive()) {
         JsonPrimitive p = el.getAsJsonPrimitive();
         if (p.isBoolean()) {
            return p.getAsBoolean();
         } else {
            return p.isNumber() ? p.getAsDouble() : p.getAsString();
         }
      } else if (el.isJsonArray()) {
         List<Object> list = new ArrayList<>();

         for (JsonElement e : el.getAsJsonArray()) {
            list.add(jsonToJava(e));
         }

         return list;
      } else if (!el.isJsonObject()) {
         return null;
      } else {
         Map<String, Object> map = new HashMap<>();

         for (Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
            map.put(e.getKey(), jsonToJava(e.getValue()));
         }

         return map;
      }
   }

   private final class BruRoot {
      private boolean warnedSleepNoop = false;
      private boolean warnedSetNextRequestNoop = false;
      private boolean warnedRunRequestNoop = false;

      Object get(String name) {
         return null;
      }

      Object call(String method, List<Object> args) {
         label185: {
            switch (method.hashCode()) {
               case -2010588927:
                  if (method.equals("interpolate")) {
                     if (args.isEmpty()) {
                        return "";
                     }

                     String s = ScriptInterpreter.stringify(args.get(0));
                     if (s == null) {
                        return "";
                     }

                     StringBuilder out = new StringBuilder();
                     int i = 0;

                     while (i < s.length()) {
                        int open = s.indexOf("{{", i);
                        if (open < 0) {
                           out.append(s, i, s.length());
                           break;
                        }

                        out.append(s, i, open);
                        int close = s.indexOf("}}", open + 2);
                        if (close < 0) {
                           out.append(s, open, s.length());
                           break;
                        }

                        String key = s.substring(open + 2, close).trim();
                        String v = ScriptInterpreter.this.ctx.getVariable(key);
                        out.append(v == null ? "{{" + key + "}}" : v);
                        i = close + 2;
                     }

                     return out.toString();
                  }

                  return null;
               case -1939050509:
                  if (!method.equals("getCollectionVar")) {
                     return null;
                  }
                  break;
               case -1249347599:
                  if (!method.equals("getVar")) {
                     return null;
                  }
                  break;
               case -1224442323:
                  if (method.equals("hasVar")) {
                     if (!args.isEmpty()) {
                        String k = ScriptInterpreter.stringify(args.get(0));
                        if (!ScriptInterpreter.this.ctx.getCollectionVariables().containsKey(k) && ScriptInterpreter.this.ctx.getVariable(k) == null) {
                           return false;
                        }

                        return true;
                     }

                     return false;
                  }

                  return null;
               case -1166292859:
                  if (method.equals("deleteEnvVar")) {
                     if (!args.isEmpty()) {
                        ScriptInterpreter.this.ctx.getEnvironmentVariables().remove(ScriptInterpreter.stringify(args.get(0)));
                     }

                     return null;
                  }

                  return null;
               case -905797787:
                  if (!method.equals("setVar")) {
                     return null;
                  }
                  break label185;
               case -750523004:
                  if (method.equals("runRequest")) {
                     if (!this.warnedRunRequestNoop) {
                        this.warnedRunRequestNoop = true;
                        ScriptInterpreter.this.ctx.log("⚠ JS-lite: bru.runRequest(...) is not supported.");
                     }

                     return null;
                  }

                  return null;
               case -678484428:
                  if (method.equals("hasEnvVar")) {
                     if (!args.isEmpty()) {
                        return ScriptInterpreter.this.ctx.getEnvironmentVariables().containsKey(ScriptInterpreter.stringify(args.get(0)));
                     }

                     return false;
                  }

                  return null;
               case -553945886:
                  if (method.equals("getEnvName")) {
                     return "";
                  }

                  return null;
               case -358718084:
                  if (method.equals("deleteVar")) {
                     if (!args.isEmpty()) {
                        String k = ScriptInterpreter.stringify(args.get(0));
                        ScriptInterpreter.this.ctx.getCollectionVariables().remove(k);
                        ScriptInterpreter.this.ctx.getGlobalVariables().remove(k);
                     }

                     return null;
                  }

                  return null;
               case -260647410:
                  if (method.equals("getRequestVar")) {
                     if (!args.isEmpty()) {
                        return ScriptInterpreter.this.ctx.getVariable(ScriptInterpreter.stringify(args.get(0)));
                     }

                     return null;
                  }

                  return null;
               case 98928:
                  if (method.equals("cwd")) {
                     return "";
                  }

                  return null;
               case 35525210:
                  if (method.equals("setNextRequest")) {
                     if (!this.warnedSetNextRequestNoop) {
                        this.warnedSetNextRequestNoop = true;
                        ScriptInterpreter.this.ctx.log("⚠ JS-lite: bru.setNextRequest(...) is not supported; use full build for request flow control.");
                     }

                     return null;
                  }

                  return null;
               case 109522647:
                  if (method.equals("sleep")) {
                     if (!this.warnedSleepNoop) {
                        this.warnedSleepNoop = true;
                        ScriptInterpreter.this.ctx.log("⚠ JS-lite: bru.sleep(...) is ignored.");
                     }

                     return null;
                  }

                  return null;
               case 124411892:
                  if (method.equals("getProcessEnv")) {
                     if (!args.isEmpty()) {
                        try {
                           return System.getenv(ScriptInterpreter.stringify(args.get(0)));
                        } catch (Exception var11) {
                           return null;
                        }
                     }

                     return null;
                  }

                  return null;
               case 183163388:
                  if (method.equals("setEnvVar")) {
                     if (args.size() >= 2) {
                        String k = ScriptInterpreter.stringify(args.get(0));
                        String v = ScriptInterpreter.stringify(args.get(1));
                        ScriptInterpreter.this.ctx.getEnvironmentVariables().put(k, v);
                        ScriptInterpreter.this.ctx.setVariable(k, v);
                     }

                     return null;
                  }

                  return null;
               case 397780464:
                  if (method.equals("getEnvVar")) {
                     if (!args.isEmpty()) {
                        String k = ScriptInterpreter.stringify(args.get(0));
                        return ScriptInterpreter.nv(ScriptInterpreter.this.ctx.getEnvironmentVariables().get(k), ScriptInterpreter.this.ctx.getVariable(k));
                     }

                     return null;
                  }

                  return null;
               case 513483802:
                  if (method.equals("setRequestVar")) {
                     if (args.size() >= 2) {
                        ScriptInterpreter.this.ctx.setVariable(ScriptInterpreter.stringify(args.get(0)), ScriptInterpreter.stringify(args.get(1)));
                     }

                     return null;
                  }

                  return null;
               case 524473959:
                  if (!method.equals("setCollectionVar")) {
                     return null;
                  }
                  break label185;
               default:
                  return null;
            }

            if (!args.isEmpty()) {
               String k = ScriptInterpreter.stringify(args.get(0));
               return ScriptInterpreter.nv(ScriptInterpreter.this.ctx.getCollectionVariables().get(k), ScriptInterpreter.this.ctx.getVariable(k));
            }

            return null;
         }

         if (args.size() >= 2) {
            String k = ScriptInterpreter.stringify(args.get(0));
            String v = ScriptInterpreter.stringify(args.get(1));
            ScriptInterpreter.this.ctx.getCollectionVariables().put(k, v);
            ScriptInterpreter.this.ctx.setVariable(k, v);
         }

         return null;
      }
   }

   private final class ConsoleObj {
      Object bound(String name) {
         return null;
      }

      Object call(String method, List<Object> args) {
         StringBuilder sb = new StringBuilder("[script ").append(method).append("] ");

         for (int i = 0; i < args.size(); i++) {
            if (i > 0) {
               sb.append(' ');
            }

            sb.append(ScriptInterpreter.stringify(args.get(i)));
         }

         try {
            System.out.println(sb.toString());
         } catch (Throwable var5) {
         }

         ScriptInterpreter.this.ctx.log(sb.toString());
         return null;
      }
   }

   private final class DateObj {
      Object bound(String name) {
         return null;
      }

      Object call(String method, List<Object> args) {
         switch (method.hashCode()) {
            case 109270:
               if (method.equals("now")) {
                  return (double)System.currentTimeMillis();
               }
            default:
               return null;
         }
      }
   }

   private final class ExpectChain {
      final Object value;

      ExpectChain(Object value) {
         this.value = value;
      }

      Object bound(String name) {
         return this;
      }

      Object call(String method, List<Object> args) {
         return this;
      }
   }

   private final class JsonObj {
      Object bound(String name) {
         return null;
      }

      Object call(String method, List<Object> args) {
         if ("parse".equals(method) && !args.isEmpty()) {
            try {
               return ScriptInterpreter.parseJson(ScriptInterpreter.stringify(args.get(0)));
            } catch (Exception var4) {
               return null;
            }
         } else {
            return "stringify".equals(method) && !args.isEmpty() ? new Gson().toJson(args.get(0)) : null;
         }
      }
   }

   private static final class Kind {
      static final int GLOBAL = 0;
      static final int ENV = 1;
      static final int COLLECTION = 2;
   }

   private static final class Lambda {
   }

   private final class MathObj {
      Object bound(String name) {
         switch (name.hashCode()) {
            case 69:
               if (name.equals("E")) {
                  return Math.E;
               }
               break;
            case 2553:
               if (name.equals("PI")) {
                  return Math.PI;
               }
         }

         return null;
      }

      Object call(String method, List<Object> args) {
         switch (method.hashCode()) {
            case -938285885:
               if (method.equals("random")) {
                  return Math.random();
               }
               break;
            case 96370:
               if (method.equals("abs")) {
                  return Math.abs(ScriptInterpreter.num(args.get(0)));
               }
               break;
            case 107332:
               if (method.equals("log")) {
                  return Math.log(ScriptInterpreter.num(args.get(0)));
               }
               break;
            case 107876:
               if (method.equals("max")) {
                  return args.size() >= 2
                     ? Math.max(ScriptInterpreter.num(args.get(0)), ScriptInterpreter.num(args.get(1)))
                     : ScriptInterpreter.num(args.get(0));
               }
               break;
            case 108114:
               if (method.equals("min")) {
                  return args.size() >= 2
                     ? Math.min(ScriptInterpreter.num(args.get(0)), ScriptInterpreter.num(args.get(1)))
                     : ScriptInterpreter.num(args.get(0));
               }
               break;
            case 111192:
               if (method.equals("pow")) {
                  return Math.pow(ScriptInterpreter.num(args.get(0)), ScriptInterpreter.num(args.get(1)));
               }
               break;
            case 3049733:
               if (method.equals("ceil")) {
                  return Math.ceil(ScriptInterpreter.num(args.get(0)));
               }
               break;
            case 3538208:
               if (method.equals("sqrt")) {
                  return Math.sqrt(ScriptInterpreter.num(args.get(0)));
               }
               break;
            case 97526796:
               if (method.equals("floor")) {
                  return Math.floor(ScriptInterpreter.num(args.get(0)));
               }
               break;
            case 108704142:
               if (method.equals("round")) {
                  return (double)Math.round(ScriptInterpreter.num(args.get(0)));
               }
         }

         return null;
      }
   }

   private final class Parser {
      private final String src;
      private int pos;

      Parser(String src) {
         this.src = src;
         this.pos = 0;
      }

      Object parseExpr() {
         return this.parseTernary();
      }

      Object parseTernary() {
         Object cond = this.parseLogicalOr();
         this.skipWs();
         if (this.peek() == '?') {
            this.pos++;
            Object a = this.parseTernary();
            this.skipWs();
            if (this.peek() == ':') {
               this.pos++;
            }

            Object b = this.parseTernary();
            return ScriptInterpreter.truthy(cond) ? a : b;
         } else {
            return cond;
         }
      }

      Object parseLogicalOr() {
         Object l = this.parseLogicalAnd();

         while (this.matchOp("||")) {
            Object r = this.parseLogicalAnd();
            l = ScriptInterpreter.truthy(l) ? l : r;
         }

         return l;
      }

      Object parseLogicalAnd() {
         Object l = this.parseEquality();

         while (this.matchOp("&&")) {
            Object r = this.parseEquality();
            l = ScriptInterpreter.truthy(l) ? r : l;
         }

         return l;
      }

      Object parseEquality() {
         Object l = this.parseRel();

         while (true) {
            while (this.matchOp("===") || this.matchOp("==")) {
               Object r = this.parseRel();
               l = ScriptInterpreter.looseEq(l, r);
            }

            if (!this.matchOp("!==") && !this.matchOp("!=")) {
               return l;
            }

            Object r = this.parseRel();
            l = !ScriptInterpreter.looseEq(l, r);
         }
      }

      Object parseRel() {
         Object l = this.parseAdd();

         while (true) {
            while (!this.matchOp("<=")) {
               if (this.matchOp(">=")) {
                  Object r = this.parseAdd();
                  l = ScriptInterpreter.num(l) >= ScriptInterpreter.num(r);
               } else if (this.matchOp("<")) {
                  Object r = this.parseAdd();
                  l = ScriptInterpreter.num(l) < ScriptInterpreter.num(r);
               } else {
                  if (!this.matchOp(">")) {
                     return l;
                  }

                  Object r = this.parseAdd();
                  l = ScriptInterpreter.num(l) > ScriptInterpreter.num(r);
               }
            }

            Object r = this.parseAdd();
            l = ScriptInterpreter.num(l) <= ScriptInterpreter.num(r);
         }
      }

      Object parseAdd() {
         Object l = this.parseMul();

         while (true) {
            this.skipWs();
            char c = this.peek();
            if (c == '+') {
               this.pos++;
               Object r = this.parseMul();
               if (!(l instanceof String) && !(r instanceof String)) {
                  l = ScriptInterpreter.num(l) + ScriptInterpreter.num(r);
               } else {
                  l = ScriptInterpreter.stringify(l) + ScriptInterpreter.stringify(r);
               }
            } else {
               if (c != '-') {
                  return l;
               }

               this.pos++;
               Object r = this.parseMul();
               l = ScriptInterpreter.num(l) - ScriptInterpreter.num(r);
            }
         }
      }

      Object parseMul() {
         Object l = this.parseUnary();

         while (true) {
            this.skipWs();
            char c = this.peek();
            if (c == '*') {
               this.pos++;
               Object r = this.parseUnary();
               l = ScriptInterpreter.num(l) * ScriptInterpreter.num(r);
            } else if (c == '/') {
               this.pos++;
               Object r = this.parseUnary();
               l = ScriptInterpreter.num(l) / ScriptInterpreter.num(r);
            } else {
               if (c != '%') {
                  return l;
               }

               this.pos++;
               Object r = this.parseUnary();
               l = ScriptInterpreter.num(l) % ScriptInterpreter.num(r);
            }
         }
      }

      Object parseUnary() {
         this.skipWs();
         char c = this.peek();
         if (c == '!') {
            this.pos++;
            return !ScriptInterpreter.truthy(this.parseUnary());
         } else if (c == '-') {
            this.pos++;
            return -ScriptInterpreter.num(this.parseUnary());
         } else if (c == '+') {
            this.pos++;
            return ScriptInterpreter.num(this.parseUnary());
         } else {
            return this.parsePostfix();
         }
      }

      Object parsePostfix() {
         Object v = this.parsePrimary();

         while (true) {
            this.skipWs();
            char c = this.peek();
            if (c == '.') {
               this.pos++;
               String name = this.readIdent();
               this.skipWs();
               if (this.peek() == '(') {
                  this.pos++;
                  List<Object> args = this.parseArgs();
                  v = ScriptInterpreter.this.invoke(v, name, args);
               } else {
                  v = ScriptInterpreter.this.getProp(v, name);
               }
            } else if (c == '[') {
               this.pos++;
               Object key = this.parseExpr();
               this.skipWs();
               if (this.peek() == ']') {
                  this.pos++;
               }

               v = ScriptInterpreter.this.getProp(v, ScriptInterpreter.stringify(key));
            } else {
               if (c != '(') {
                  return v;
               }

               this.pos++;
               List<Object> args = this.parseArgs();
               v = ScriptInterpreter.this.invoke(null, ScriptInterpreter.stringify(v), args, v);
            }
         }
      }

      List<Object> parseArgs() {
         List<Object> args = new ArrayList<>();
         this.skipWs();
         if (this.peek() == ')') {
            this.pos++;
            return args;
         } else {
            while (this.pos < this.src.length()) {
               args.add(this.parseExpr());
               this.skipWs();
               if (this.peek() == ',') {
                  this.pos++;
               } else {
                  if (this.peek() == ')') {
                     this.pos++;
                     break;
                  }

                  this.pos++;
               }
            }

            return args;
         }
      }

      Object parsePrimary() {
         this.skipWs();
         if (this.pos >= this.src.length()) {
            return null;
         } else {
            char c = this.src.charAt(this.pos);
            if (c == '(') {
               int save = this.pos++;
               Object v = this.parseExpr();
               this.skipWs();
               if (this.peek() == ')') {
                  this.pos++;
                  this.skipWs();
                  if (this.pos + 1 < this.src.length() && this.src.charAt(this.pos) == '=' && this.src.charAt(this.pos + 1) == '>') {
                     this.pos += 2;
                     this.skipArrowBody();
                     return new ScriptInterpreter.Lambda();
                  } else {
                     return v;
                  }
               } else {
                  this.pos = save + 1;

                  while (this.pos < this.src.length() && this.src.charAt(this.pos) != ')') {
                     this.pos++;
                  }

                  if (this.pos < this.src.length()) {
                     this.pos++;
                  }

                  this.skipWs();
                  if (this.pos + 1 < this.src.length() && this.src.charAt(this.pos) == '=' && this.src.charAt(this.pos + 1) == '>') {
                     this.pos += 2;
                     this.skipArrowBody();
                     return new ScriptInterpreter.Lambda();
                  } else {
                     return null;
                  }
               }
            } else if (c == '\'' || c == '"' || c == '`') {
               return this.readString();
            } else if (!Character.isDigit(c) && (c != '.' || this.pos + 1 >= this.src.length() || !Character.isDigit(this.src.charAt(this.pos + 1)))) {
               if (!Character.isLetter(c) && c != '_' && c != '$') {
                  this.pos++;
                  return null;
               } else {
                  String name = this.readIdent();
                  if (name.equals("true")) {
                     return Boolean.TRUE;
                  } else if (name.equals("false")) {
                     return Boolean.FALSE;
                  } else if (name.equals("null") || name.equals("undefined")) {
                     return null;
                  } else if (name.equals("function")) {
                     this.skipFunctionLiteral();
                     return new ScriptInterpreter.Lambda();
                  } else {
                     this.skipWs();
                     if (this.pos + 1 < this.src.length() && this.src.charAt(this.pos) == '=' && this.src.charAt(this.pos + 1) == '>') {
                        this.pos += 2;
                        this.skipArrowBody();
                        return new ScriptInterpreter.Lambda();
                     } else if (this.peek() == '(') {
                        this.pos++;
                        List<Object> args = this.parseArgs();
                        return ScriptInterpreter.this.invoke(null, name, args, null);
                     } else {
                        return ScriptInterpreter.this.resolveIdent(name);
                     }
                  }
               }
            } else {
               return this.readNumber();
            }
         }
      }

      char peek() {
         return this.pos < this.src.length() ? this.src.charAt(this.pos) : '\u0000';
      }

      void skipWs() {
         while (this.pos < this.src.length() && Character.isWhitespace(this.src.charAt(this.pos))) {
            this.pos++;
         }
      }

      void skipFunctionLiteral() {
         this.skipWs();
         if (this.pos < this.src.length() && (Character.isLetter(this.peek()) || this.peek() == '_' || this.peek() == '$')) {
            this.readIdent();
            this.skipWs();
         }

         if (this.peek() == '(') {
            this.pos++;
            int depth = 1;

            while (this.pos < this.src.length() && depth > 0) {
               char c = this.src.charAt(this.pos++);
               if (c == '(') {
                  depth++;
               } else if (c == ')') {
                  depth--;
               }
            }
         }

         this.skipArrowBody();
      }

      void skipArrowBody() {
         this.skipWs();
         if (this.peek() == '{') {
            this.pos++;
            int depth = 1;
            boolean inStr = false;
            char q = 0;

            while (this.pos < this.src.length() && depth > 0) {
               char c = this.src.charAt(this.pos++);
               if (inStr) {
                  if (c == '\\' && this.pos < this.src.length()) {
                     this.pos++;
                  } else if (c == q) {
                     inStr = false;
                  }
               } else if (c == '\'' || c == '"' || c == '`') {
                  inStr = true;
                  q = c;
               } else if (c == '{') {
                  depth++;
               } else if (c == '}') {
                  depth--;
               }
            }
         } else {
            int depth = 0;
            boolean inStr = false;
            char q = 0;

            while (this.pos < this.src.length()) {
               char c = this.src.charAt(this.pos);
               if (inStr) {
                  if (c == '\\' && this.pos + 1 < this.src.length()) {
                     this.pos += 2;
                  } else {
                     if (c == q) {
                        inStr = false;
                     }

                     this.pos++;
                  }
               } else if (c != '\'' && c != '"' && c != '`') {
                  if (c == '(' || c == '[' || c == '{') {
                     depth++;
                  } else if (c != ')' && c != ']' && c != '}') {
                     if (c == ',' && depth == 0) {
                        break;
                     }
                  } else {
                     if (depth == 0) {
                        break;
                     }

                     depth--;
                  }

                  this.pos++;
               } else {
                  inStr = true;
                  q = c;
                  this.pos++;
               }
            }
         }
      }

      boolean matchOp(String op) {
         this.skipWs();
         if (this.pos + op.length() > this.src.length()) {
            return false;
         } else if (!this.src.regionMatches(this.pos, op, 0, op.length())) {
            return false;
         } else if (op.equals("==") && this.peekAt(this.pos + 2) == '=') {
            return false;
         } else if (op.equals("!=") && this.peekAt(this.pos + 2) == '=') {
            return false;
         } else if (op.equals("<") && this.peekAt(this.pos + 1) == '=') {
            return false;
         } else if (op.equals(">") && this.peekAt(this.pos + 1) == '=') {
            return false;
         } else {
            this.pos = this.pos + op.length();
            return true;
         }
      }

      char peekAt(int i) {
         return i < this.src.length() ? this.src.charAt(i) : '\u0000';
      }

      String readIdent() {
         int start;
         for (start = this.pos; this.pos < this.src.length(); this.pos++) {
            char c = this.src.charAt(this.pos);
            if (!Character.isLetterOrDigit(c) && c != '_' && c != '$') {
               break;
            }
         }

         return this.src.substring(start, this.pos);
      }

      String readString() {
         char quote = this.src.charAt(this.pos++);
         StringBuilder sb = new StringBuilder();

         while (this.pos < this.src.length()) {
            char c = this.src.charAt(this.pos++);
            if (c == '\\' && this.pos < this.src.length()) {
               char n = this.src.charAt(this.pos++);
               switch (n) {
                  case '"':
                     sb.append('"');
                     break;
                  case '\'':
                     sb.append('\'');
                     break;
                  case '\\':
                     sb.append('\\');
                     break;
                  case '`':
                     sb.append('`');
                     break;
                  case 'n':
                     sb.append('\n');
                     break;
                  case 'r':
                     sb.append('\r');
                     break;
                  case 't':
                     sb.append('\t');
                     break;
                  default:
                     sb.append(n);
               }
            } else {
               if (c == quote) {
                  break;
               }

               sb.append(c);
            }
         }

         return sb.toString();
      }

      Object readNumber() {
         int start;
         for (start = this.pos; this.pos < this.src.length(); this.pos++) {
            char c = this.src.charAt(this.pos);
            if (!Character.isDigit(c) && c != '.' && c != 'e' && c != 'E' && c != '+' && c != '-'
               || (c == '+' || c == '-') && (this.pos <= start || this.src.charAt(this.pos - 1) != 'e' && this.src.charAt(this.pos - 1) != 'E')) {
               break;
            }
         }

         try {
            return Double.parseDouble(this.src.substring(start, this.pos));
         } catch (Exception var3) {
            return 0.0;
         }
      }
   }

   private final class PmHeaders {
      final List<PostmanCollection.Header> headers;

      PmHeaders(List<PostmanCollection.Header> h) {
         this.headers = h;
      }

      Object call(String method, List<Object> args) {
         if ("get".equals(method) && !args.isEmpty()) {
            String k = ScriptInterpreter.stringify(args.get(0));
            if (this.headers != null) {
               for (PostmanCollection.Header h : this.headers) {
                  if (h != null && k.equalsIgnoreCase(h.key)) {
                     return h.value;
                  }
               }
            }
         }

         return null;
      }

      Object bound(String name) {
         if (this.headers != null) {
            for (PostmanCollection.Header h : this.headers) {
               if (h != null && name.equalsIgnoreCase(h.key)) {
                  return h.value;
               }
            }
         }

         return null;
      }
   }

   private final class PmResponse {
      final ExecutedRequest resp;

      PmResponse(ExecutedRequest r) {
         this.resp = r;
      }

      Object get(String name) {
         if (this.resp == null) {
            return null;
         } else {
            switch (name.hashCode()) {
               case -892481550:
                  if (name.equals("status")) {
                     return (double)this.resp.getStatusCode();
                  }
                  break;
               case 3029410:
                  if (name.equals("body")) {
                     try {
                        Object j = ScriptInterpreter.parseJson(this.resp.getResponseBody());
                        if (j != null) {
                           return j;
                        }
                     } catch (Exception var4) {
                     }

                     return this.resp.getResponseBody();
                  }
                  break;
               case 3059181:
                  if (name.equals("code")) {
                     return (double)this.resp.getStatusCode();
                  }
                  break;
               case 247507199:
                  if (name.equals("statusCode")) {
                     return (double)this.resp.getStatusCode();
                  }
                  break;
               case 795307910:
                  if (name.equals("headers")) {
                     return ScriptInterpreter.this.new PmHeaders(this.resp.getResponseHeaders());
                  }
                  break;
               case 1439224494:
                  if (name.equals("responseTime")) {
                     return 0.0;
                  }
            }

            return null;
         }
      }

      Object call(String method, List<Object> args) {
         if (this.resp == null) {
            return null;
         } else {
            switch (method.hashCode()) {
               case -1229232860:
                  if (method.equals("getResponseTime")) {
                     return 0.0;
                  }
                  break;
               case -75652584:
                  if (method.equals("getBody")) {
                     try {
                        Object j = ScriptInterpreter.parseJson(this.resp.getResponseBody());
                        if (j != null) {
                           return j;
                        }
                     } catch (Exception var9) {
                     }

                     return this.resp.getResponseBody();
                  }
                  break;
               case -50241291:
                  if (method.equals("getStatusCode")) {
                     return (double)this.resp.getStatusCode();
                  }
                  break;
               case 3059181:
                  if (method.equals("code")) {
                     return (double)this.resp.getStatusCode();
                  }
                  break;
               case 3271912:
                  if (method.equals("json")) {
                     try {
                        return ScriptInterpreter.parseJson(this.resp.getResponseBody());
                     } catch (Exception var8) {
                        return null;
                     }
                  }
                  break;
               case 3556653:
                  if (method.equals("text")) {
                     return this.resp.getResponseBody();
                  }
                  break;
               case 474744195:
                  if (method.equals("getHeader")) {
                     if (args.isEmpty()) {
                        return null;
                     }

                     String k = ScriptInterpreter.stringify(args.get(0));
                     List<PostmanCollection.Header> hs = this.resp.getResponseHeaders();
                     if (hs != null) {
                        for (PostmanCollection.Header h : hs) {
                           if (h != null && k.equalsIgnoreCase(h.key)) {
                              return h.value;
                           }
                        }
                     }

                     return null;
                  }
                  break;
               case 803533544:
                  if (method.equals("getStatus")) {
                     return (double)this.resp.getStatusCode();
                  }
                  break;
               case 1832168272:
                  if (method.equals("getHeaders")) {
                     return ScriptInterpreter.this.new PmHeaders(this.resp.getResponseHeaders());
                  }
            }

            return null;
         }
      }
   }

   private final class PmRoot {
      Object get(String name) {
         switch (name.hashCode()) {
            case -340323263:
               if (name.equals("response")) {
                  return ScriptInterpreter.this.new PmResponse(ScriptInterpreter.this.ctx.getExecutedRequest());
               }
               break;
            case -165052295:
               if (name.equals("collectionVariables")) {
                  return ScriptInterpreter.this.new PmScope(2);
               }
               break;
            case -85904877:
               if (name.equals("environment")) {
                  return ScriptInterpreter.this.new PmScope(1);
               }
               break;
            case -82477705:
               if (name.equals("variables")) {
                  return ScriptInterpreter.this.new PmScope(0);
               }
               break;
            case 3237038:
               if (name.equals("info")) {
                  return new HashMap();
               }
               break;
            case 121073968:
               if (name.equals("globals")) {
                  return ScriptInterpreter.this.new PmScope(0);
               }
               break;
            case 1095692943:
               if (name.equals("request")) {
                  return ScriptInterpreter.this.ctx.getRequest();
               }
         }

         return null;
      }
   }

   private final class PmScope {
      final int kind;

      PmScope(int k) {
         this.kind = k;
      }

      Object call(String method, List<Object> args) {
         switch (method.hashCode()) {
            case 102230:
               if (method.equals("get")) {
                  if (!args.isEmpty()) {
                     String k = ScriptInterpreter.stringify(args.get(0));
                     if (this.kind == 1) {
                        return ScriptInterpreter.nv(ScriptInterpreter.this.ctx.getEnvironmentVariables().get(k), ScriptInterpreter.this.ctx.getVariable(k));
                     }

                     if (this.kind == 2) {
                        return ScriptInterpreter.nv(ScriptInterpreter.this.ctx.getCollectionVariables().get(k), ScriptInterpreter.this.ctx.getVariable(k));
                     }

                     return ScriptInterpreter.this.ctx.getVariable(k);
                  }

                  return null;
               }
               break;
            case 103066:
               if (method.equals("has")) {
                  if (!args.isEmpty()) {
                     if (ScriptInterpreter.this.ctx.getVariable(ScriptInterpreter.stringify(args.get(0))) != null) {
                        return true;
                     }

                     return false;
                  }

                  return false;
               }
               break;
            case 113762:
               if (method.equals("set")) {
                  if (args.size() >= 2) {
                     String k = ScriptInterpreter.stringify(args.get(0));
                     String v = ScriptInterpreter.stringify(args.get(1));
                     switch (this.kind) {
                        case 1:
                           ScriptInterpreter.this.ctx.getEnvironmentVariables().put(k, v);
                           break;
                        case 2:
                           ScriptInterpreter.this.ctx.getCollectionVariables().put(k, v);
                     }

                     ScriptInterpreter.this.ctx.setVariable(k, v);
                  }

                  return null;
               }
               break;
            case 111442729:
               if (method.equals("unset")) {
                  if (!args.isEmpty()) {
                     String k = ScriptInterpreter.stringify(args.get(0));
                     ScriptInterpreter.this.ctx.getGlobalVariables().remove(k);
                     ScriptInterpreter.this.ctx.getEnvironmentVariables().remove(k);
                     ScriptInterpreter.this.ctx.getCollectionVariables().remove(k);
                  }

                  return null;
               }
         }

         return null;
      }

      Object bound(String name) {
         return null;
      }
   }
}
