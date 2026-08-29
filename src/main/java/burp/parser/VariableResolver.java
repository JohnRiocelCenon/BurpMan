package burp.parser;

import burp.models.*;
import java.util.*;
import java.util.regex.*;

public class VariableResolver {

    private final Map<String, String> variables = new HashMap<>();

    /** Per-collection-scope user variable overrides. Keyed by collection
     *  wrapper name (the top-level node label users see in the tree). When
     *  an active scope is set, lookups check the scope map FIRST before
     *  falling back to the global {@link #variables} map. */
    private final Map<String, Map<String, String>> scopedVariables = new HashMap<>();
    private String activeScope = null;

    public void setActiveScope(String scope) {
        this.activeScope = (scope == null || scope.isEmpty()) ? null : scope;
    }
    public void clearActiveScope() { this.activeScope = null; }
    public String getActiveScope() { return activeScope; }

    public Map<String, String> getScopedVariables(String scope) {
        if (scope == null || scope.isEmpty()) return new HashMap<>(variables);
        Map<String, String> m = scopedVariables.get(scope);
        return m == null ? new HashMap<>() : new HashMap<>(m);
    }

    public java.util.Set<String> getDefinedScopes() {
        return new java.util.LinkedHashSet<>(scopedVariables.keySet());
    }

    public void putScopedVariable(String scope, String key, String value) {
        if (scope == null || scope.isEmpty() || key == null) return;
        scopedVariables.computeIfAbsent(scope, k -> new HashMap<>()).put(key, value);
    }

    public void removeScopedVariable(String scope, String key) {
        if (scope == null || scope.isEmpty() || key == null) return;
        Map<String, String> m = scopedVariables.get(scope);
        if (m != null) m.remove(key);
    }

    public void clearScope(String scope) {
        if (scope == null) return;
        scopedVariables.remove(scope);
    }

    // ✅ Updated pattern: ignore {{$...}} (handled separately)
    private static final Pattern VARIABLE_PATTERN =
            Pattern.compile("\\{\\{(?!\\$)(.+?)\\}\\}");

    public void addEnvironmentVariables(PostmanEnvironment environment) {
        if (environment.values != null) {
            for (PostmanEnvironment.Value value : environment.values) {
                if (value.enabled && value.value != null) {
                    // Env vars outrank both globals and collection vars in
                    // Postman's precedence (globals < collection < env < runtime).
                    // Force-overwrite so a globals or collection-defined key
                    // loaded earlier doesn't shadow the env's authoritative value.
                    variables.put(value.key, value.value);
                }
            }
        }
    }

    /** Add {@code .env}-style secrets under the Bruno {@code process.env.*}
     *  namespace, e.g. a {@code .env} row {@code uat-api-secret=xyz} becomes
     *  {@code {{process.env.uat-api-secret}}} → {@code xyz}. This makes a
     *  dotenv file behave like Bruno's always-on "process.env" overlay:
     *  it stays active regardless of which flat environment the user has
     *  selected in the dropdown, so environment files can reference
     *  {@code {{process.env.KEY}}} placeholders and they resolve.
     *
     *  <p>Keys are stored under both {@code process.env.<key>} (Bruno
     *  convention) and the raw {@code <key>} (fallback for tools that
     *  don't use the process.env prefix). The process.env variant wins
     *  on conflict since it's the more specific namespace. */
    public void addProcessEnvVariables(PostmanEnvironment dotenv) {
        if (dotenv == null || dotenv.values == null) return;
        for (PostmanEnvironment.Value value : dotenv.values) {
            if (value == null || value.key == null || value.value == null) continue;
            if (!value.enabled) continue;
            variables.put("process.env." + value.key, value.value);
            // Bruno also accepts bare {{KEY}} for .env values, so keep a
            // fallback mapping — but only if no higher-precedence source
            // has already set it.
            variables.putIfAbsent(value.key, value.value);
        }
    }

    /** Drop the {@code process.env.*} overlay. Called when the user
     *  unchecks the .env file in the Overview tab, or when the workspace
     *  is torn down on Restart. Also clears the bare-key fallbacks that
     *  were only present because of the .env overlay. */
    public void clearProcessEnvVariables() {
        java.util.Iterator<java.util.Map.Entry<String, String>> it = variables.entrySet().iterator();
        java.util.Set<String> processKeys = new java.util.HashSet<>();
        while (it.hasNext()) {
            java.util.Map.Entry<String, String> e = it.next();
            if (e.getKey().startsWith("process.env.")) {
                processKeys.add(e.getKey().substring("process.env.".length()));
                it.remove();
            }
        }
        // Drop the bare-key fallbacks that we added for the same keys.
        variables.keySet().removeAll(processKeys);
    }

    /** Add Postman "globals" variables. Same JSON shape as environment
     *  ({@code values[]}) but lower precedence — only fill in keys not already
     *  present so env-set values win. Postman exports globals via
     *  Workspaces → Globals → Export. */
    public void addGlobalsVariables(PostmanEnvironment globals) {
        if (globals != null && globals.values != null) {
            for (PostmanEnvironment.Value value : globals.values) {
                if (value.enabled && value.value != null) {
                    variables.putIfAbsent(value.key, value.value);
                }
            }
        }
    }

    public void addCollectionVariables(PostmanCollection collection) {
        if (collection.variable != null) {
            for (PostmanCollection.Variable var : collection.variable) {
                if (var.value != null) {
                    // Collection vars outrank globals in Postman's precedence
                    // chain (globals < collection < env < runtime). Use put,
                    // not putIfAbsent, so a globals-defined key (auto-loaded
                    // earlier) doesn't shadow the collection's authoritative
                    // value for the same key.
                    variables.put(var.key, var.value);
                }
            }
        }
    }

    public void addCustomVariable(String key, String value) {
        // When a collection scope is active, write to BOTH the scope's
        // private map (so analysis-only writes like host1/host2 detection
        // can stay collection-private) AND the global map (so runtime
        // values written by post-response scripts — Authorization,
        // am.mobile.token, test.client.code, etc. — are visible to manual
        // Send and to other collections in the same workspace).
        // Real Postman/Bruno post-script writes are visible everywhere;
        // hiding them in a per-scope silo broke cross-folder reuse where
        // a user runs the auth folder then clicks any non-auth request
        // below to send manually.
        if (activeScope != null) {
            scopedVariables.computeIfAbsent(activeScope, k -> new HashMap<>()).put(key, value);
        }
        variables.put(key, value);
    }

    /** Force-write a variable to GLOBAL (workspace-wide), bypassing any active scope.
     *  Used for shared things like host1/host2 that should be visible to all collections. */
    public void putGlobalVariable(String key, String value) {
        if (key == null) return;
        variables.put(key, value);
    }

    /** Update a variable everywhere it currently exists: global map AND every
     *  scope that has it. Also writes to the active scope (or global if none).
     *  Used when the user edits a value in a place like the OAuth dialog so
     *  the change propagates to every Edit Variables view. */
    public void updateVariableEverywhere(String key, String value) {
        if (key == null) return;
        variables.put(key, value);
        for (Map<String, String> sv : scopedVariables.values()) {
            if (sv != null && sv.containsKey(key)) {
                sv.put(key, value);
            }
        }
        if (activeScope != null) {
            scopedVariables.computeIfAbsent(activeScope, k -> new HashMap<>()).put(key, value);
        }
    }

    /** Remove a single variable by key. Used by the Edit Variables dialog
     *  so a user-deleted row actually disappears from the resolver. */
    public void removeCustomVariable(String key) {
        if (key == null) return;
        if (activeScope != null) {
            Map<String, String> sv = scopedVariables.get(activeScope);
            if (sv != null) sv.remove(key);
        } else {
            variables.remove(key);
        }
    }

    public String resolve(String value) {
        if (value == null) return null;
        // Fast path: most header values, body fragments, and URL parts do
        // not contain a {{var}} at all. Skip the regex/iteration entirely
        // for those — used to dominate hot-path resolve time when called
        // 30+ times per request (URL + every header + every body field).
        // Also skip dynamic-var probing if no $ present.
        if (value.indexOf("{{") < 0) return value;

        String resolved = value;
        String previous;

        int maxIterations = 10;
        int count = 0;

        do {
            previous = resolved;
            resolved = resolveOnce(previous);

            count++;
            if (count > maxIterations) {
                break;
            }

        } while (!resolved.equals(previous));

        return resolved;
    }

    /**
     * Resolved-text result that also records which substring ranges in the
     * resolved output came from which {{var}} substitutions. Used by the URL
     * bar / Headers tab / body editor to color those segments and show
     * "this part is from {{baseUrl}}" tooltips (Postman parity).
     */
    public static final class Resolution {
        public final String resolved;
        /** Each entry: { start, end (exclusive), varName, originalValue }. */
        public final java.util.List<Span> spans;
        public Resolution(String r, java.util.List<Span> s) {
            this.resolved = r;
            this.spans = s == null ? java.util.Collections.emptyList() : s;
        }
    }

    public static final class Span {
        public final int start;
        public final int end;
        public final String varName;
        public final String value;
        public Span(int start, int end, String varName, String value) {
            this.start = start; this.end = end;
            this.varName = varName; this.value = value;
        }
    }

    /**
     * Like {@link #resolve(String)} but also records which substring ranges
     * in the final, fully-expanded output came from which top-level {{var}}.
     * Recursively expands variable values that themselves contain {{vars}}
     * (matches {@link #resolve} behavior). The spans returned point at
     * ranges in the FULLY EXPANDED output, attributing each range to the
     * outermost {{var}} that ultimately produced it.
     */
    /**
     * Like {@link #resolve(String)} but also records which substring ranges
     * in the final, fully-expanded output came from which top-level {{var}}.
     * Recursively expands variable values that themselves contain {{vars}}
     * (matches {@link #resolve} behavior). The spans returned point at
     * ranges in the FULLY EXPANDED output, attributing each range to the
     * outermost {{var}} that ultimately produced it.
     *
     * <p><b>Defined-but-empty preservation:</b> when a variable is defined
     * but its value is empty (e.g. {@code CASE_ID=""}), this method KEEPS
     * the {@code {{key}}} literal in the output rather than substituting
     * with an empty string. The corresponding span has {@code value=""}
     * (as opposed to {@code null} for undefined vars). This lets UI
     * consumers show the marker in a distinct color so users can see
     * "this variable is set but has no value" instead of the marker
     * silently vanishing. This is a UI-only convenience — sending code
     * paths should call {@link #resolve(String)} which will still expand
     * the empty-string substitution.
     */
    public Resolution resolveTracked(String value) {
        if (value == null) return new Resolution(null, java.util.Collections.emptyList());
        StringBuilder out = new StringBuilder();
        java.util.List<Span> spans = new java.util.ArrayList<>();
        Matcher m = VARIABLE_PATTERN.matcher(value);
        int last = 0;
        while (m.find()) {
            out.append(value, last, m.start());
            String key = m.group(1);
            String replacement = null;
            if (activeScope != null) {
                Map<String, String> sv = scopedVariables.get(activeScope);
                if (sv != null && sv.containsKey(key)) replacement = sv.get(key);
            }
            if (replacement == null) replacement = variables.get(key);
            if (replacement == null) {
                int s = out.length();
                out.append("{{").append(key).append("}}");
                spans.add(new Span(s, out.length(), key, null));
            } else {
                // Fully expand the replacement so nested {{vars}} (e.g.
                // baseUrl={{cpsServerUrl}}/prospecting/v1) resolve completely.
                String expanded = resolve(replacement);
                if (expanded == null || expanded.isEmpty()) {
                    // Preserve {{key}} literal so users can see the marker.
                    // Span value = "" sentinel (distinct from null=undefined).
                    int s = out.length();
                    out.append("{{").append(key).append("}}");
                    spans.add(new Span(s, out.length(), key, ""));
                } else {
                    int s = out.length();
                    out.append(expanded);
                    spans.add(new Span(s, out.length(), key, expanded));
                }
            }
            last = m.end();
        }
        out.append(value, last, value.length());
        return new Resolution(out.toString(), spans);
    }

    private String resolveOnce(String value) {
        if (value == null) return null;
        // Fast path mirrors resolve() — skip both static and dynamic
        // matchers when there's no {{ anywhere in the input.
        if (value.indexOf("{{") < 0) return value;

        String resolved = value;

        // ✅ 1. Resolve normal {{vars}}
        Matcher matcher = VARIABLE_PATTERN.matcher(resolved);
        StringBuffer sb = new StringBuffer();

        while (matcher.find()) {
            String key = matcher.group(1);
            String replacement = null;
            // Per-collection scoped override wins.
            if (activeScope != null) {
                Map<String, String> sv = scopedVariables.get(activeScope);
                if (sv != null && sv.containsKey(key)) replacement = sv.get(key);
            }
            if (replacement == null) replacement = variables.get(key);

            // Bruno-style {{process.env.NAME}} — resolve to OS env vars.
            // Users can also override this per-collection by setting a
            // variable literally named "process.env.NAME" (checked above).
            if (replacement == null && key != null && key.startsWith("process.env.")) {
                String envName = key.substring("process.env.".length());
                if (!envName.isEmpty()) {
                    String osValue = System.getenv(envName);
                    if (osValue != null) replacement = osValue;
                }
            }

            if (replacement == null) {
                replacement = "{{" + key + "}}";
            }

            matcher.appendReplacement(
                    sb,
                    Matcher.quoteReplacement(replacement)
            );
        }

        matcher.appendTail(sb);
        resolved = sb.toString();

        // ✅ 2. Resolve dynamic {{$vars}} (Postman style) — legacy narrow set.
        resolved = resolveDynamicVariables(resolved);

        // ✅ 3. Catch-all faker expander — adds the remaining ~60 Postman
        //       dynamic variables ($randomCity, $randomCompanyName,
        //       $randomMacAddress, $randomLoremParagraph, ...) that the
        //       legacy resolver above doesn't handle. Leaves unknown names
        //       untouched so user-defined {{name}} vars still resolve.
        resolved = burp.vars.PostmanFaker.expand(resolved);

        return resolved;
    }

    // ✅ NEW: Dynamic variable resolver
    private String resolveDynamicVariables(String input) {

        if (input == null) return null;

        String result = input;

        // =====================================================
        // ✅ {{$guid}} / {{$randomUUID}} (Postman aliases) and {{$guid:upper}}
        // =====================================================
        // Replace each occurrence with a *fresh* UUID so two appearances differ.
        result = replacePerOccurrence(result, "\\{\\{\\$guid\\}\\}",
                () -> UUID.randomUUID().toString());
        result = replacePerOccurrence(result, "\\{\\{\\$randomUUID\\}\\}",
                () -> UUID.randomUUID().toString());
        result = replacePerOccurrence(result, "\\{\\{\\$guid:upper\\}\\}",
                () -> UUID.randomUUID().toString().toUpperCase());

        // Postman "random data" dynamic variables (subset most commonly used)
        Random rnd = new Random();
        result = replacePerOccurrence(result, "\\{\\{\\$randomAlphaNumeric\\}\\}",
                () -> randomAlphaNumeric(rnd, 1));
        result = replacePerOccurrence(result, "\\{\\{\\$randomPassword\\}\\}",
                () -> randomAlphaNumeric(rnd, 16));
        result = replacePerOccurrence(result, "\\{\\{\\$randomFirstName\\}\\}",
                () -> randomFromList(rnd, FIRST_NAMES));
        result = replacePerOccurrence(result, "\\{\\{\\$randomLastName\\}\\}",
                () -> randomFromList(rnd, LAST_NAMES));
        result = replacePerOccurrence(result, "\\{\\{\\$randomFullName\\}\\}",
                () -> randomFromList(rnd, FIRST_NAMES) + " " + randomFromList(rnd, LAST_NAMES));
        result = replacePerOccurrence(result, "\\{\\{\\$randomEmail\\}\\}",
                () -> (randomFromList(rnd, FIRST_NAMES) + "." + randomFromList(rnd, LAST_NAMES)
                        + "@example.com").toLowerCase());
        result = replacePerOccurrence(result, "\\{\\{\\$randomIP\\}\\}",
                () -> rnd.nextInt(256) + "." + rnd.nextInt(256) + "." + rnd.nextInt(256) + "." + rnd.nextInt(256));
        result = replacePerOccurrence(result, "\\{\\{\\$randomIPV4\\}\\}",
                () -> rnd.nextInt(256) + "." + rnd.nextInt(256) + "." + rnd.nextInt(256) + "." + rnd.nextInt(256));
        result = replacePerOccurrence(result, "\\{\\{\\$randomBoolean\\}\\}",
                () -> rnd.nextBoolean() ? "true" : "false");

        // =====================================================
        // ✅ {{$timestamp}} and {{$timestamp+N}}
        // =====================================================
        result = result.replaceAll("\\{\\{\\$timestamp\\}\\}", 
                String.valueOf(System.currentTimeMillis() / 1000));

        // {{$timestamp+60}} or {{$timestamp-60}}
        Pattern tsPattern = Pattern.compile("\\{\\{\\$timestamp([+-]\\d+)\\}\\}");
        Matcher tsMatcher = tsPattern.matcher(result);

        StringBuffer tsBuffer = new StringBuffer();
        while (tsMatcher.find()) {
            int offset = Integer.parseInt(tsMatcher.group(1));
            long ts = (System.currentTimeMillis() / 1000) + offset;
            tsMatcher.appendReplacement(tsBuffer, String.valueOf(ts));
        }
        tsMatcher.appendTail(tsBuffer);
        result = tsBuffer.toString();

        // =====================================================
        // ✅ {{$isoTimestamp}}
        // =====================================================
        result = result.replaceAll("\\{\\{\\$isoTimestamp\\}\\}", 
                java.time.Instant.now().toString());

        // =====================================================
        // ✅ {{$randomInt}} and {{$randomInt(min,max)}}
        // =====================================================
        result = result.replaceAll("\\{\\{\\$randomInt\\}\\}", 
                String.valueOf(new Random().nextInt(100000)));

        Pattern randPattern = Pattern.compile("\\{\\{\\$randomInt\\((\\d+),(\\d+)\\)\\}\\}");
        Matcher randMatcher = randPattern.matcher(result);

        StringBuffer randBuffer = new StringBuffer();
        Random r = new Random();

        while (randMatcher.find()) {
            int min = Integer.parseInt(randMatcher.group(1));
            int max = Integer.parseInt(randMatcher.group(2));

            int val = r.nextInt((max - min) + 1) + min;

            randMatcher.appendReplacement(randBuffer, String.valueOf(val));
        }
        randMatcher.appendTail(randBuffer);
        result = randBuffer.toString();

        return result;
    }

    public Map<String, String> getVariables() {
        return new HashMap<>(variables);
    }

    public void clearAllVariables() {
        variables.clear();
        scopedVariables.clear();
        activeScope = null;
    }

    // -------- helpers for dynamic-variable expansion --------

    private static final java.util.List<String> FIRST_NAMES = java.util.Arrays.asList(
        "Alex","Sam","Jordan","Casey","Taylor","Morgan","Drew","Reese","Quinn","Riley",
        "Avery","Jamie","Cameron","Hayden","Logan","Skyler","Kendall","Emerson","Parker","Rowan"
    );
    private static final java.util.List<String> LAST_NAMES = java.util.Arrays.asList(
        "Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Rodriguez",
        "Martinez","Hernandez","Lopez","Wilson","Anderson","Thomas","Taylor","Moore","Jackson"
    );

    private static String randomAlphaNumeric(Random r, int len) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(chars.charAt(r.nextInt(chars.length())));
        return sb.toString();
    }

    private static String randomFromList(Random r, java.util.List<String> list) {
        return list.get(r.nextInt(list.size()));
    }

    /** Replace each occurrence of {@code regex} with a fresh value from {@code supplier}. */
    private static String replacePerOccurrence(String input, String regex,
                                               java.util.function.Supplier<String> supplier) {
        if (input == null) return null;
        Matcher m = Pattern.compile(regex).matcher(input);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(supplier.get()));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}