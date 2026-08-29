package burp.service;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ScriptAnalyzer {
   public static ScriptAnalyzer.Result analyze(String script) {
      ScriptAnalyzer.Result r = new ScriptAnalyzer.Result();
      if (script != null && !script.isEmpty()) {
         r.charCount = script.length();
         r.lineCount = script.split("\\r?\\n", -1).length;
         String s = stripStrings(script);
         scanScopeCalls(s, r);
         Pattern sendUrl = Pattern.compile("pm\\.sendRequest\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");
         Matcher m = sendUrl.matcher(script);

         while (m.find()) {
            r.sendRequestUrls.add(m.group(1));
         }

         Pattern urlField = Pattern.compile("url\\s*:\\s*[`'\"]([^`'\"]+)[`'\"]");
         m = urlField.matcher(script);

         while (m.find()) {
            String u = m.group(1);
            if (u.contains("/") || u.contains("{{") || u.startsWith("http")) {
               r.sendRequestUrls.add(u);
            }
         }

         Pattern hAdd = Pattern.compile("pm\\.request\\.headers\\.add\\s*\\(\\s*\\{[^}]*?key\\s*:\\s*['\"`]([^'\"`]+)['\"`]", 32);
         m = hAdd.matcher(script);

         while (m.find()) {
            r.headersAdded.add(m.group(1));
         }

         Pattern hRm = Pattern.compile("pm\\.request\\.headers\\.remove\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");
         m = hRm.matcher(script);

         while (m.find()) {
            r.headersRemoved.add(m.group(1));
         }

         Pattern addH = Pattern.compile("addHeader\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");
         m = addH.matcher(script);

         while (m.find()) {
            r.headersAdded.add(m.group(1));
         }

         if (script.contains("btoa(")) {
            r.helpers.add("btoa  (Base64 encode)");
         }

         if (script.contains("atob(")) {
            r.helpers.add("atob  (Base64 decode)");
         }

         if (script.contains("JSON.parse")) {
            r.helpers.add("JSON.parse");
         }

         if (script.contains("JSON.stringify")) {
            r.helpers.add("JSON.stringify");
         }

         if (script.contains("new Date(") || script.contains("Date.now")) {
            r.helpers.add("Date");
         }

         if (script.contains("Math.")) {
            r.helpers.add("Math");
         }

         if (script.contains("console.log") || script.contains("console.warn") || script.contains("console.error") || script.contains("console.info")) {
            r.helpers.add("console.* (logging)");
         }

         if (script.contains("CryptoJS")) {
            r.helpers.add("CryptoJS  (NOT supported — install BurpMan-full)");
         }

         if (s.contains("=>")) {
            r.esFeatures.add("Arrow functions");
         }

         if (s.contains("`")) {
            r.esFeatures.add("Template literals");
         }

         if (Pattern.compile("[a-zA-Z_$\\)\\]]\\s*\\?\\.").matcher(s).find()) {
            r.esFeatures.add("Optional chaining (?.)");
         }

         if (Pattern.compile("\\?\\?[^?=]").matcher(s).find()) {
            r.esFeatures.add("Nullish coalescing (??)");
         }

         if (Pattern.compile("(?:const|let)\\s*\\{").matcher(s).find() || Pattern.compile("(?:const|let)\\s*\\[").matcher(s).find()) {
            r.esFeatures.add("Destructuring");
         }

         if (Pattern.compile("\\.\\.\\.[a-zA-Z_$]").matcher(s).find()) {
            r.esFeatures.add("Spread / rest");
         }

         if (Pattern.compile("\\bclass\\s+[A-Z]").matcher(s).find()) {
            r.esFeatures.add("Class declaration");
         }

         if (Pattern.compile("\\b(?:async|await)\\b").matcher(s).find()) {
            r.esFeatures.add("async / await");
         }

         if (Pattern.compile("\\bfor\\s*\\(\\s*(?:const|let|var)\\s+\\w+\\s+of\\s").matcher(s).find()) {
            r.esFeatures.add("for-of");
         }

         if (Pattern.compile("\\bfunction\\s*[*]\\s*\\w*\\s*\\(").matcher(s).find() || Pattern.compile("\\byield\\b").matcher(s).find()) {
            r.esFeatures.add("Generators");
         }

         if (!r.esFeatures.isEmpty()
            || !r.sendRequestUrls.isEmpty()
            || !r.headersAdded.isEmpty()
            || !r.headersRemoved.isEmpty()
            || r.helpers.contains("CryptoJS")
            || r.helpers.contains("btoa  (Base64 encode)")
            || r.helpers.contains("atob  (Base64 decode)")) {
            r.requiredEngine = "rhino";
         }

         if (script.contains("setTimeout") || script.contains("setInterval")) {
            r.warnings.add("Uses setTimeout/setInterval — async timers won't fire in BurpMan's synchronous runtime.");
         }

         if (script.contains("Promise") || script.contains("fetch(") || script.contains("XMLHttpRequest")) {
            r.warnings.add("Uses Promise/fetch/XHR — only pm.sendRequest is supported for HTTP calls.");
         }

         if (r.helpers.contains("CryptoJS")) {
            r.warnings.add("CryptoJS is not bundled. Add it to the script as a string or use Java's MessageDigest via a custom host.");
         }

         if (r.requiredEngine.equals("rhino") && !rhinoAvailable()) {
            r.warnings.add("This script needs the full script engine. Use the BurpMan-full build.");
         }

         return r;
      } else {
         r.warnings.add("Script is empty.");
         return r;
      }
   }

   private static String stripStrings(String src) {
      StringBuilder out = new StringBuilder(src.length());
      int i = 0;
      boolean inStr = false;
      char q = 0;

      while (i < src.length()) {
         char c = src.charAt(i);
         if (inStr) {
            out.append(' ');
            if (c == '\\' && i + 1 < src.length()) {
               out.append(' ');
               i += 2;
            } else {
               if (c == q) {
                  inStr = false;
                  out.setCharAt(out.length() - 1, c);
               }

               i++;
            }
         } else if (c != '\'' && c != '"' && c != '`') {
            if (c == '/' && i + 1 < src.length() && src.charAt(i + 1) == '/') {
               while (i < src.length() && src.charAt(i) != '\n') {
                  out.append(' ');
                  i++;
               }
            } else if (c == '/' && i + 1 < src.length() && src.charAt(i + 1) == '*') {
               while (i + 1 < src.length() && (src.charAt(i) != '*' || src.charAt(i + 1) != '/')) {
                  out.append(' ');
                  i++;
               }

               if (i + 1 < src.length()) {
                  out.append("  ");
                  i += 2;
               }
            } else {
               out.append(c);
               i++;
            }
         } else {
            inStr = true;
            q = c;
            out.append(c);
            i++;
         }
      }

      return out.toString();
   }

   private static void scanScopeCalls(String s, ScriptAnalyzer.Result r) {
      Pattern p = Pattern.compile("pm\\.(environment|collectionVariables|variables|globals)\\.(get|set|unset)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");
      Matcher m = p.matcher(s);

      while (m.find()) {
         String scope = m.group(1);
         String op = m.group(2);
         String name = m.group(3);
         boolean isWrite = "set".equals(op) || "unset".equals(op);
         switch (scope.hashCode()) {
            case -165052295:
               if (scope.equals("collectionVariables")) {
                  if (isWrite) {
                     r.writesCollection.add(name);
                  } else {
                     r.readsCollection.add(name);
                  }
               }
               break;
            case -85904877:
               if (scope.equals("environment")) {
                  if (isWrite) {
                     r.writesEnv.add(name);
                  } else {
                     r.readsEnv.add(name);
                  }
               }
               break;
            case -82477705:
               if (scope.equals("variables")) {
                  if (isWrite) {
                     r.writesGlobal.add(name);
                  } else {
                     r.readsGlobal.add(name);
                  }
               }
               break;
            case 121073968:
               if (scope.equals("globals")) {
                  if (isWrite) {
                     r.writesGlobal.add(name);
                  } else {
                     r.readsGlobal.add(name);
                  }
               }
         }
      }

      Pattern p2 = Pattern.compile("postman\\.(set|get)(Environment|Global)Variable\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");
      m = p2.matcher(s);

      while (m.find()) {
         String op = m.group(1);
         String scope = m.group(2);
         String name = m.group(3);
         boolean isWrite = "set".equals(op);
         if ("Environment".equals(scope)) {
            if (isWrite) {
               r.writesEnv.add(name);
            } else {
               r.readsEnv.add(name);
            }
         } else if (isWrite) {
            r.writesGlobal.add(name);
         } else {
            r.readsGlobal.add(name);
         }
      }
   }

   private static boolean rhinoAvailable() {
      try {
         Class.forName("org.mozilla.javascript.Context");
         return true;
      } catch (Throwable var1) {
         return false;
      }
   }

   private ScriptAnalyzer() {
   }

   public static final class Result {
      public final LinkedHashSet<String> readsEnv = new LinkedHashSet<>();
      public final LinkedHashSet<String> writesEnv = new LinkedHashSet<>();
      public final LinkedHashSet<String> readsCollection = new LinkedHashSet<>();
      public final LinkedHashSet<String> writesCollection = new LinkedHashSet<>();
      public final LinkedHashSet<String> readsGlobal = new LinkedHashSet<>();
      public final LinkedHashSet<String> writesGlobal = new LinkedHashSet<>();
      public final LinkedHashSet<String> sendRequestUrls = new LinkedHashSet<>();
      public final LinkedHashSet<String> headersAdded = new LinkedHashSet<>();
      public final LinkedHashSet<String> headersRemoved = new LinkedHashSet<>();
      public final LinkedHashSet<String> helpers = new LinkedHashSet<>();
      public final LinkedHashSet<String> esFeatures = new LinkedHashSet<>();
      public final LinkedHashSet<String> warnings = new LinkedHashSet<>();
      public int lineCount;
      public int charCount;
      public String requiredEngine = "mini";

      public String render() {
         StringBuilder sb = new StringBuilder();
         sb.append("===== Script Analysis =====\n");
         sb.append("Length: ").append(this.lineCount).append(" lines, ").append(this.charCount).append(" chars\n");
         sb.append("Required engine: ").append(displayRequiredEngine(this.requiredEngine));
         if ("rhino".equals(this.requiredEngine)) {
            sb.append("  (uses features only the BurpMan-full build supports)");
         }

         sb.append("\n\n");
         section(sb, "Reads (environment)", this.readsEnv);
         section(sb, "Writes (environment)", this.writesEnv);
         section(sb, "Reads (collection)", this.readsCollection);
         section(sb, "Writes (collection)", this.writesCollection);
         section(sb, "Reads (globals)", this.readsGlobal);
         section(sb, "Writes (globals)", this.writesGlobal);
         section(sb, "HTTP calls (pm.sendRequest)", this.sendRequestUrls);
         section(sb, "Headers added", this.headersAdded);
         section(sb, "Headers removed", this.headersRemoved);
         section(sb, "Helpers used", this.helpers);
         section(sb, "ES syntax features", this.esFeatures);
         section(sb, "Warnings", this.warnings);
         return sb.toString();
      }

      private static void section(StringBuilder sb, String title, Set<String> items) {
         if (!items.isEmpty()) {
            sb.append("• ").append(title).append(" (").append(items.size()).append("):\n");

            for (String it : items) {
               sb.append("    - ").append(it).append("\n");
            }
            sb.append("\n");
         }
      }

      private static String displayRequiredEngine(String requiredEngine) {
         if (requiredEngine == null) return "BASIC";
         switch (requiredEngine) {
            case "rhino":
               return "FULL";
            case "mini":
               return "BASIC";
            default:
               return requiredEngine.toUpperCase();
         }
      }
   }
}
