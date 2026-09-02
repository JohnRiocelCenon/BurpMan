package burp.parser;

import burp.models.PostmanCollection;
import burp.models.PostmanEnvironment;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Maps Bruno's {@code opencollection: 1.0.0} YAML schema (Bruno v3.x)
 * onto BurpMan's internal {@link PostmanCollection} shape.
 *
 * <p>Supports request files with an {@code http:} block, folder
 * descriptors ({@code folder.yml}), the collection root descriptor
 * ({@code opencollection.yml}), and environment files under
 * {@code environments/*.yml}.
 *
 * <p>Body types translated: {@code json}, {@code text}, {@code xml},
 * {@code sparql}, {@code graphql}, {@code form-urlencoded},
 * {@code multipart-form}, {@code file}, {@code none}.
 *
 * <p>Auth types translated: {@code bearer}, {@code basic},
 * {@code apikey}, {@code oauth2}, {@code inherit} (returns null so
 * cascade logic still applies), {@code none} (mapped to {@code noauth}).
 *
 * <p>Runtime scripts translated: {@code pre-request} →
 * {@code prerequest}, {@code after-response} and {@code tests} →
 * {@code test} (they run at the same point in Postman's model).
 * Multiple scripts of the same {@code type} are concatenated with a
 * separator comment so both run at send time.
 *
 * <p>Variables are unwrapped from OpenCollection's
 * {@code {type: object, data: "<json>"}} envelope, and object values are
 * flattened to dotted paths so a reference like {@code {{gb.exp.apim.url}}}
 * resolves. Entries marked {@code disabled: true} are treated as switched off.
 */
final class BrunoYamlParser {

    /** Guards against a self-referential or pathologically nested value. */
    private static final int MAX_VAR_DEPTH = 12;

    private static final Gson COMPACT_JSON = new Gson();

    private BrunoYamlParser() {}

    static PostmanCollection.Item parseRequestFile(File file) throws Exception {
        Map<String, Object> tree = readTree(file);
        return buildRequestItem(tree, stripExtension(file.getName()));
    }

    /** Build a request {@link PostmanCollection.Item} from a Bruno-shaped
     *  {@code {info, http, runtime, settings, docs}} map. Returns
     *  {@code null} when the map doesn't describe an HTTP request (e.g.
     *  wrong {@code info.type} or missing {@code http:} block). */
    private static PostmanCollection.Item buildRequestItem(Map<String, Object> tree, String fallbackName) {
        Map<String, Object> info = asMap(tree.get("info"));
        String type = str(info != null ? info.get("type") : null);
        if (type != null && !type.equalsIgnoreCase("http")) {
            return null;
        }
        Map<String, Object> http = asMap(tree.get("http"));
        if (http == null || http.isEmpty()) {
            return null;
        }

        PostmanCollection.Item item = new PostmanCollection.Item();
        item.name = firstNonBlank(str(info != null ? info.get("name") : null), fallbackName, "Request");
        item.request = new PostmanCollection.Request();
        item.request.method = firstNonBlank(str(http.get("method")), "GET").toUpperCase(Locale.ROOT);
        item.request.url = firstNonBlank(str(http.get("url")), "");
        item.request.header = parseHeaders(asList(http.get("headers")));
        item.request.body = parseBody(asMap(http.get("body")));
        item.request.auth = parseAuth(http.get("auth"));

        String docs = firstNonBlank(str(tree.get("docs")), str(tree.get("description")));
        if (docs != null) {
            item.description = docs;
            item.request.description = docs;
        }

        List<PostmanCollection.Event> events = parseRuntimeScripts(asMap(tree.get("runtime")));
        if (!events.isEmpty()) {
            item.event = events;
        }
        return item;
    }

    /** Parse a single-file bundled OpenCollection export — a YAML file that
     *  starts with {@code opencollection: 1.0.0} and carries the whole
     *  collection (info, config, vars, items) in one document. Items may
     *  be requests ({@code info.type: http}) or folders ({@code info.type:
     *  folder}) with nested {@code items}. */
    static PostmanCollection parseBundledCollection(File file) throws Exception {
        Map<String, Object> tree = readTree(file);
        PostmanCollection collection = new PostmanCollection();
        collection.info = new PostmanCollection.Info();
        Map<String, Object> info = asMap(tree.get("info"));
        String infoName = str(info != null ? info.get("name") : null);
        collection.info.name = firstNonBlank(infoName, stripExtension(file.getName()));
        collection.item = new ArrayList<>();
        collection.variable = new ArrayList<>();

        List<Object> vars = asList(tree.get("vars"));
        if (vars != null) {
            for (Object entry : vars) {
                collection.variable.addAll(toCollectionVariables(asMap(entry)));
            }
        }

        Map<String, Object> request = asMap(tree.get("request"));
        if (request != null) {
            PostmanCollection.Auth auth = parseAuth(request.get("auth"));
            if (auth != null) collection.auth = auth;
        }
        List<PostmanCollection.Event> events = parseRuntimeScripts(asMap(tree.get("runtime")));
        if (!events.isEmpty()) {
            collection.event = events;
        }

        List<Object> items = asList(tree.get("items"));
        if (items != null) {
            for (Object raw : items) {
                Map<String, Object> node = asMap(raw);
                if (node == null) continue;
                PostmanCollection.Item built = buildBundledNode(node);
                if (built != null) collection.item.add(built);
            }
        }
        return collection;
    }

    /** Recursively convert a bundled OCF item map into a Postman {@link
     *  PostmanCollection.Item}. Requests become leaf items with a
     *  {@code request}; folders become items with a nested {@code item}
     *  list. */
    private static PostmanCollection.Item buildBundledNode(Map<String, Object> node) {
        Map<String, Object> info = asMap(node.get("info"));
        String type = str(info != null ? info.get("type") : null);
        String name = firstNonBlank(str(info != null ? info.get("name") : null), "Item");
        String norm = type == null ? "" : type.toLowerCase(Locale.ROOT);

        if (norm.equals("folder")) {
            PostmanCollection.Item folder = new PostmanCollection.Item();
            folder.name = name;
            folder.item = new ArrayList<>();
            Map<String, Object> request = asMap(node.get("request"));
            if (request != null) {
                folder.auth = parseAuth(request.get("auth"));
            }
            List<PostmanCollection.Event> folderEvents = parseRuntimeScripts(asMap(node.get("runtime")));
            if (!folderEvents.isEmpty()) {
                folder.event = folderEvents;
            }
            List<Object> children = asList(node.get("items"));
            if (children != null) {
                for (Object raw : children) {
                    Map<String, Object> child = asMap(raw);
                    if (child == null) continue;
                    PostmanCollection.Item built = buildBundledNode(child);
                    if (built != null) folder.item.add(built);
                }
            }
            return folder;
        }
        // Default to request (type: http, or missing type with http block)
        return buildRequestItem(node, name);
    }

    /** Read a Bruno folder-descriptor and stamp its auth/scripts onto {@code folder}. */
    static void applyFolderMeta(PostmanCollection.Item folder, File file) throws Exception {
        Map<String, Object> tree = readTree(file);
        Map<String, Object> info = asMap(tree.get("info"));
        String infoName = str(info.get("name"));
        if (infoName != null && !infoName.trim().isEmpty()) {
            folder.name = infoName;
        }
        Map<String, Object> request = asMap(tree.get("request"));
        if (request != null) {
            folder.auth = parseAuth(request.get("auth"));
        }
        List<PostmanCollection.Event> events = parseRuntimeScripts(asMap(tree.get("runtime")));
        if (!events.isEmpty()) {
            folder.event = events;
        }
    }

    /** Read {@code opencollection.yml} and stamp collection-level metadata. */
    static void applyCollectionMeta(PostmanCollection collection, File file) throws Exception {
        Map<String, Object> tree = readTree(file);
        Map<String, Object> info = asMap(tree.get("info"));
        String infoName = str(info.get("name"));
        if (infoName != null && !infoName.trim().isEmpty()) {
            if (collection.info == null) collection.info = new PostmanCollection.Info();
            collection.info.name = infoName;
        }
        Map<String, Object> request = asMap(tree.get("request"));
        if (request != null) {
            PostmanCollection.Auth auth = parseAuth(request.get("auth"));
            if (auth != null) collection.auth = auth;
        }
        List<PostmanCollection.Event> events = parseRuntimeScripts(asMap(tree.get("runtime")));
        if (!events.isEmpty()) {
            collection.event = events;
        }
        // Collection-level vars (Bruno v3 puts them under "vars" or in the
        // "extensions" section — vars is what the runtime uses).
        List<Object> vars = asList(tree.get("vars"));
        if (vars != null) {
            for (Object entry : vars) {
                List<PostmanCollection.Variable> expanded = toCollectionVariables(asMap(entry));
                if (expanded.isEmpty()) continue;
                if (collection.variable == null) collection.variable = new ArrayList<>();
                collection.variable.addAll(expanded);
            }
        }
    }

    /**
     * Collection-level {@code vars}, expanded the same way as environment
     * variables. {@link PostmanCollection.Variable} has no enabled flag, so a
     * disabled entry is dropped rather than added as if it were live.
     */
    private static List<PostmanCollection.Variable> toCollectionVariables(Map<String, Object> raw) {
        List<PostmanCollection.Variable> out = new ArrayList<>();
        for (VarEntry e : expandVariable(raw)) {
            if (!e.enabled) continue;
            PostmanCollection.Variable variable = new PostmanCollection.Variable();
            variable.key = e.key;
            variable.value = e.value;
            variable.type = e.type;
            out.add(variable);
        }
        return out;
    }

    static PostmanEnvironment parseEnvironment(File file) throws Exception {
        Map<String, Object> tree = readTree(file);
        PostmanEnvironment env = new PostmanEnvironment();
        env.name = firstNonBlank(str(tree.get("name")), stripExtension(file.getName()));
        env.values = new ArrayList<>();
        List<Object> vars = asList(tree.get("variables"));
        if (vars == null) vars = asList(tree.get("vars"));
        if (vars != null) {
            for (Object entry : vars) {
                for (VarEntry e : expandVariable(asMap(entry))) {
                    PostmanEnvironment.Value value = new PostmanEnvironment.Value();
                    value.key = e.key;
                    value.value = e.value;
                    value.enabled = e.enabled;
                    value.type = e.type;
                    env.values.add(value);
                }
            }
        }
        return env;
    }

    /**
     * Expands one declared variable into the entries a collection can actually
     * reference.
     *
     * <p>OpenCollection does not store a bare scalar. A value arrives wrapped as
     * {@code {type: object, data: "<json>"}}, and collections address the pieces
     * by dotted path — {@code {{gb.exp.apim.url}}}, never {@code {{gb}}}. Keeping
     * only the declared name therefore leaves every reference unresolved while
     * the environment still reports a healthy variable count, which reads as
     * "the environment loaded but the values are wrong". So an object value is
     * also flattened to one entry per leaf.
     *
     * <p>The declared name is kept as well, holding the JSON, so {@code {{gb}}}
     * and scripts that want the whole document still work.
     */
    private static List<VarEntry> expandVariable(Map<String, Object> v) {
        List<VarEntry> out = new ArrayList<>();
        if (v == null) return out;
        String name = str(v.get("name"));
        if (name == null || name.trim().isEmpty()) return out;
        name = name.trim();

        // OpenCollection switches an entry off with `disabled: true`; older
        // Bruno YAML uses `enabled: false`. Reading only one of the two silently
        // activates variables the author turned off — and because a disabled
        // duplicate normally sits *after* the live one, the stale value wins.
        boolean enabled = !isTrue(v.get("disabled"));
        Object enabledFlag = v.get("enabled");
        if (enabledFlag != null && "false".equalsIgnoreCase(String.valueOf(enabledFlag).trim())) {
            enabled = false;
        }

        Object raw = v.get("value");
        String declaredType = str(v.get("type"));
        if (raw instanceof Map) {
            Map<String, Object> holder = asMap(raw);
            declaredType = firstNonBlank(str(holder.get("type")), declaredType);
            raw = holder.get("data");
        }

        String type = isTrue(v.get("secret")) ? "secret" : firstNonBlank(declaredType, "text");
        String text = raw == null ? null : str(raw);

        out.add(new VarEntry(name, text, enabled, type));
        flattenInto(out, name, tryParseJson(text), enabled, type, 0);
        return out;
    }

    /** Adds one entry per child of {@code el}, keyed by dotted path. */
    private static void flattenInto(List<VarEntry> out, String prefix, JsonElement el,
                                    boolean enabled, String type, int depth) {
        if (el == null || depth > MAX_VAR_DEPTH) return;
        if (el.isJsonObject()) {
            for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                addNode(out, prefix + "." + e.getKey(), e.getValue(), enabled, type, depth);
            }
        } else if (el.isJsonArray()) {
            JsonArray arr = el.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                addNode(out, prefix + "." + i, arr.get(i), enabled, type, depth);
            }
        }
    }

    private static void addNode(List<VarEntry> out, String key, JsonElement el,
                                boolean enabled, String type, int depth) {
        if (el == null || el.isJsonNull()) return;
        if (el.isJsonObject() || el.isJsonArray()) {
            // Containers keep their JSON so {{gb.exp}} behaves like {{gb}}.
            out.add(new VarEntry(key, COMPACT_JSON.toJson(el), enabled, type));
            flattenInto(out, key, el, enabled, type, depth + 1);
        } else {
            // getAsString on a primitive yields the unquoted scalar, so a number
            // or boolean substitutes as written rather than as `"1"`.
            out.add(new VarEntry(key, el.getAsJsonPrimitive().getAsString(), enabled, type));
        }
    }

    private static JsonElement tryParseJson(String text) {
        if (text == null) return null;
        String t = text.trim();
        if (t.length() < 2) return null;
        char c = t.charAt(0);
        if (c != '{' && c != '[') return null;
        try {
            JsonElement el = JsonParser.parseString(t);
            return el != null && (el.isJsonObject() || el.isJsonArray()) ? el : null;
        } catch (RuntimeException notJson) {
            return null;
        }
    }

    private static boolean isTrue(Object o) {
        return o != null && "true".equalsIgnoreCase(String.valueOf(o).trim());
    }

    /** A variable after unwrapping and flattening. */
    private static final class VarEntry {
        final String key;
        final String value;
        final boolean enabled;
        final String type;

        VarEntry(String key, String value, boolean enabled, String type) {
            this.key = key;
            this.value = value;
            this.enabled = enabled;
            this.type = type;
        }
    }

    static int readSeq(File file) {
        try {
            Map<String, Object> tree = readTree(file);
            Map<String, Object> info = asMap(tree.get("info"));
            String seq = str(info != null ? info.get("seq") : null);
            if (seq != null && !seq.trim().isEmpty()) {
                return Integer.parseInt(seq.trim());
            }
        } catch (Exception ignored) {
        }
        return Integer.MAX_VALUE;
    }

    // ---------------- helpers ----------------

    private static Map<String, Object> readTree(File file) throws Exception {
        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        return MiniYaml.parse(content);
    }

    private static List<PostmanCollection.Header> parseHeaders(List<Object> raw) {
        List<PostmanCollection.Header> out = new ArrayList<>();
        if (raw == null) return out;
        for (Object entry : raw) {
            Map<String, Object> h = asMap(entry);
            if (h == null) continue;
            String key = str(h.get("name"));
            if (key == null || key.trim().isEmpty()) continue;
            PostmanCollection.Header header = new PostmanCollection.Header();
            header.key = key;
            header.value = str(h.get("value"));
            Object enabled = h.get("enabled");
            header.disabled = enabled != null && "false".equalsIgnoreCase(String.valueOf(enabled));
            header.description = str(h.get("description"));
            out.add(header);
        }
        return out;
    }

    private static PostmanCollection.Body parseBody(Map<String, Object> raw) {
        if (raw == null || raw.isEmpty()) return null;
        String type = str(raw.get("type"));
        if (type == null || type.trim().isEmpty() || "none".equalsIgnoreCase(type)) return null;
        String t = type.toLowerCase(Locale.ROOT);
        Object data = raw.get("data");

        if (t.equals("json") || t.equals("text") || t.equals("xml") || t.equals("sparql")) {
            String rawBody = str(data);
            if (rawBody == null || rawBody.isEmpty()) return null;
            PostmanCollection.Body body = new PostmanCollection.Body();
            body.mode = "raw";
            body.raw = rawBody;
            body.options = new PostmanCollection.Options();
            body.options.raw = new PostmanCollection.Raw();
            body.options.raw.language = t.equals("json") ? "json" : t;
            return body;
        }

        if (t.equals("graphql")) {
            PostmanCollection.Body body = new PostmanCollection.Body();
            body.mode = "graphql";
            body.graphql = new PostmanCollection.GraphQL();
            Map<String, Object> gql = asMap(data);
            if (gql != null) {
                body.graphql.query = str(gql.get("query"));
                Object vars = gql.get("variables");
                body.graphql.variables = vars == null ? null : String.valueOf(vars);
            } else {
                String rawBody = str(data);
                if (rawBody != null) body.graphql.query = rawBody;
            }
            return body;
        }

        if (t.equals("form-urlencoded") || t.equals("formurlencoded")) {
            PostmanCollection.Body body = new PostmanCollection.Body();
            body.mode = "urlencoded";
            body.urlencoded = new ArrayList<>();
            List<Object> entries = asList(data);
            if (entries != null) {
                for (Object entry : entries) {
                    Map<String, Object> e = asMap(entry);
                    if (e == null) continue;
                    String key = str(e.get("name"));
                    if (key == null || key.trim().isEmpty()) continue;
                    PostmanCollection.UrlEncoded form = new PostmanCollection.UrlEncoded();
                    form.key = key;
                    form.value = str(e.get("value"));
                    Object enabled = e.get("enabled");
                    form.disabled = enabled != null && "false".equalsIgnoreCase(String.valueOf(enabled));
                    form.description = str(e.get("description"));
                    form.type = firstNonBlank(str(e.get("type")), "text");
                    body.urlencoded.add(form);
                }
            }
            return body.urlencoded.isEmpty() ? null : body;
        }

        if (t.equals("multipart-form") || t.equals("multipartform") || t.equals("multipart-formdata")) {
            PostmanCollection.Body body = new PostmanCollection.Body();
            body.mode = "formdata";
            body.formdata = new ArrayList<>();
            List<Object> entries = asList(data);
            if (entries != null) {
                for (Object entry : entries) {
                    Map<String, Object> e = asMap(entry);
                    if (e == null) continue;
                    String key = str(e.get("name"));
                    if (key == null || key.trim().isEmpty()) continue;
                    PostmanCollection.FormData form = new PostmanCollection.FormData();
                    form.key = key;
                    Object enabled = e.get("enabled");
                    form.disabled = enabled != null && "false".equalsIgnoreCase(String.valueOf(enabled));
                    form.type = firstNonBlank(str(e.get("type")), "text");
                    form.contentType = str(e.get("contentType"));
                    if ("file".equalsIgnoreCase(form.type)) {
                        form.src = firstNonBlank(str(e.get("src")), str(e.get("value")));
                    } else {
                        form.value = str(e.get("value"));
                    }
                    body.formdata.add(form);
                }
            }
            return body.formdata.isEmpty() ? null : body;
        }

        if (t.equals("file") || t.equals("binary")) {
            PostmanCollection.Body body = new PostmanCollection.Body();
            body.mode = "file";
            body.file = new PostmanCollection.File();
            body.file.src = str(data);
            return body;
        }

        // Fallback: treat unknown type as raw
        String rawBody = str(data);
        if (rawBody == null || rawBody.isEmpty()) return null;
        PostmanCollection.Body body = new PostmanCollection.Body();
        body.mode = "raw";
        body.raw = rawBody;
        return body;
    }

    private static PostmanCollection.Auth parseAuth(Object raw) {
        if (raw == null) return null;
        if (raw instanceof String) {
            String s = ((String) raw).trim().toLowerCase(Locale.ROOT);
            if (s.isEmpty() || s.equals("inherit")) return null;
            if (s.equals("none") || s.equals("noauth")) {
                PostmanCollection.Auth auth = new PostmanCollection.Auth();
                auth.type = "noauth";
                return auth;
            }
            PostmanCollection.Auth auth = new PostmanCollection.Auth();
            auth.type = s;
            return auth;
        }
        Map<String, Object> m = asMap(raw);
        if (m == null) return null;
        String type = str(m.get("type"));
        if (type == null || type.trim().isEmpty()) return null;
        String lower = type.toLowerCase(Locale.ROOT);
        if (lower.equals("inherit")) return null;
        if (lower.equals("none") || lower.equals("noauth")) {
            PostmanCollection.Auth auth = new PostmanCollection.Auth();
            auth.type = "noauth";
            return auth;
        }
        PostmanCollection.Auth auth = new PostmanCollection.Auth();
        auth.type = lower;
        switch (lower) {
            case "bearer":
                auth.bearer = authAttributes(new String[][] { { "token", str(m.get("token")) } });
                break;
            case "basic":
                auth.basic = authAttributes(new String[][] {
                    { "username", str(m.get("username")) },
                    { "password", str(m.get("password")) }
                });
                break;
            case "apikey":
            case "api-key":
                auth.type = "apikey";
                auth.apikey = authAttributes(new String[][] {
                    { "key", str(m.get("key")) },
                    { "value", str(m.get("value")) },
                    { "in", firstNonBlank(str(m.get("placement")), str(m.get("in"))) }
                });
                break;
            case "oauth2":
                Map<String, Object> src = new LinkedHashMap<>(m);
                src.remove("type");
                auth.oauth2 = src;
                break;
            case "digest":
                auth.digest = authAttributes(new String[][] {
                    { "username", str(m.get("username")) },
                    { "password", str(m.get("password")) }
                });
                break;
            default:
                break;
        }
        return auth;
    }

    private static List<PostmanCollection.AuthAttribute> authAttributes(String[][] pairs) {
        List<PostmanCollection.AuthAttribute> out = new ArrayList<>();
        for (String[] p : pairs) {
            if (p == null || p.length < 2 || p[1] == null) continue;
            PostmanCollection.AuthAttribute a = new PostmanCollection.AuthAttribute();
            a.key = p[0];
            a.value = p[1];
            a.type = "string";
            out.add(a);
        }
        return out;
    }

    private static List<PostmanCollection.Event> parseRuntimeScripts(Map<String, Object> runtime) {
        List<PostmanCollection.Event> events = new ArrayList<>();
        if (runtime == null) return events;
        List<Object> scripts = asList(runtime.get("scripts"));
        if (scripts == null) return events;

        StringBuilder pre = new StringBuilder();
        StringBuilder test = new StringBuilder();
        for (Object entry : scripts) {
            Map<String, Object> s = asMap(entry);
            if (s == null) continue;
            String type = str(s.get("type"));
            String code = str(s.get("code"));
            if (code == null || code.trim().isEmpty()) continue;
            String norm = type == null ? "" : type.toLowerCase(Locale.ROOT).replace("_", "-");
            if (norm.equals("pre-request") || norm.equals("prerequest") || norm.equals("pre")
                || norm.equals("before-request") || norm.equals("beforerequest")) {
                appendScript(pre, code);
            } else if (norm.equals("after-response") || norm.equals("post-response") || norm.equals("tests") || norm.equals("test") || norm.isEmpty()) {
                appendScript(test, code);
            }
        }
        if (pre.length() > 0) events.add(makeEvent("prerequest", pre.toString()));
        if (test.length() > 0) events.add(makeEvent("test", test.toString()));
        return events;
    }

    private static void appendScript(StringBuilder sb, String code) {
        if (sb.length() > 0) sb.append("\n\n// --- next script ---\n\n");
        sb.append(code);
    }

    private static PostmanCollection.Event makeEvent(String listen, String code) {
        PostmanCollection.Event event = new PostmanCollection.Event();
        event.listen = listen;
        event.script = new PostmanCollection.Script();
        event.script.type = "text/javascript";
        event.script.exec = new ArrayList<>();
        for (String line : code.split("\\R", -1)) {
            event.script.exec.add(line);
        }
        return event;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        if (o instanceof Map) return (Map<String, Object>) o;
        return null;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object o) {
        if (o instanceof List) return (List<Object>) o;
        return null;
    }

    private static String str(Object o) {
        if (o == null) return null;
        if (o instanceof String) {
            String s = (String) o;
            return s.isEmpty() ? "" : s;
        }
        return String.valueOf(o);
    }

    private static String firstNonBlank(String... vals) {
        if (vals == null) return null;
        for (String v : vals) {
            if (v != null && !v.trim().isEmpty()) return v;
        }
        return null;
    }

    private static String stripExtension(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }
}
