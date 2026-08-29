package burp.auth;

import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import burp.utils.RequestUrlResolver;
import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects possible token-source requests inferred from scripts
 * (pm.sendRequest/bru.setEnvVar/pm.environment.set token-like writes).
 */
public class ScriptTokenSourceDetector {
    private static final Pattern SEND_REQUEST_CALL = Pattern.compile(
            "(?is)(?:pm|bru)\\.sendRequest\\s*\\(");
    private static final Pattern TOKEN_SETTER = Pattern.compile(
            "(?is)(?:pm\\.(?:environment|globals|collectionVariables|variables)\\.set|postman\\.set(?:Environment|Global)Variable|bru\\.setEnvVar)\\s*\\(\\s*([\"'`])([^\"'`]+)\\1");
    private static final Pattern TOKEN_FIELDS = Pattern.compile(
            "(?is)\\b(access[_-]?token|id[_-]?token|refresh[_-]?token|jwt|bearer|authorization)\\b");
    private static final Pattern TOKENISH_URL = Pattern.compile(
            "(?is)(login|oauth|auth|token|openid|connect/token)");
    private static final Pattern VARIABLE_GETTER = Pattern.compile(
            "(?is)(?:pm\\.(?:environment|globals|collectionVariables|variables)\\.get|postman\\.get(?:Environment|Global)Variable|bru\\.getEnvVar)\\s*\\(\\s*([\"'`])([^\"'`]+)\\1\\s*\\)");
    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");

    private final Gson gson = new Gson();

    public List<JwtEndpointCandidate> detect(PostmanCollection collection, VariableResolver resolver) {
        List<JwtEndpointCandidate> out = new ArrayList<>();
        if (collection == null) return out;

        String collectionName = collection != null && collection.info != null
                && collection.info.name != null ? collection.info.name : "";

        // Root-level collection scripts (no concrete request context).
        collectFromEvents(collection.event, collectionName, collectionName, out, resolver);
        walk(collection.item, out, resolver, collectionName, "");
        out.sort((a, b) -> b.score - a.score);
        return out;
    }

    private void walk(
            List<PostmanCollection.Item> items,
            List<JwtEndpointCandidate> out,
            VariableResolver resolver,
            String collectionName,
            String parentPath) {
        if (items == null) return;
        for (PostmanCollection.Item item : items) {
            if (item == null) continue;
            String itemName = item.name == null ? "" : item.name;
            String currentPath = parentPath.isEmpty() ? itemName : parentPath + "/" + itemName;
            String effectiveCollection = item.isCollectionWrapper && !itemName.isEmpty()
                    ? itemName : collectionName;

            collectFromEvents(item.event, currentPath, effectiveCollection, out, resolver);
            if (item.item != null && !item.item.isEmpty()) {
                walk(item.item, out, resolver, effectiveCollection, currentPath);
            }
        }
    }

    private void collectFromEvents(
            List<PostmanCollection.Event> events,
            String path,
            String collectionName,
            List<JwtEndpointCandidate> out,
            VariableResolver resolver) {
        if (events == null) return;
        for (PostmanCollection.Event ev : events) {
            if (ev == null || ev.script == null || ev.script.exec == null) continue;
            String script = joinScript(ev.script.exec);
            if (script.trim().isEmpty()) continue;

            boolean tokenScript = isTokenScript(script);
            extractSendRequestCandidates(script, path, collectionName, tokenScript, out, resolver);
        }
    }

    private void extractSendRequestCandidates(
            String script,
            String path,
            String collectionName,
            boolean tokenScript,
            List<JwtEndpointCandidate> out,
            VariableResolver resolver) {
        Matcher callMatcher = SEND_REQUEST_CALL.matcher(script);
        while (callMatcher.find()) {
            ParsedArgument parsed = parseFirstArgument(script, callMatcher.end());
            if (parsed == null || parsed.argument == null || parsed.argument.isEmpty()) continue;
            PostmanCollection.Request synthetic =
                    buildRequestFromSendRequestArg(script, parsed.argument, callMatcher.start());
            if (synthetic == null) continue;
            addSyntheticCandidate(synthetic, script, path, collectionName, tokenScript, out, resolver);
        }
    }

    private void addSyntheticCandidate(
            PostmanCollection.Request scriptRequest,
            String scriptSource,
            String path,
            String collectionName,
            boolean tokenScript,
            List<JwtEndpointCandidate> out,
            VariableResolver resolver) {
        if (scriptRequest == null) return;
        PostmanCollection.Request resolvedRequest = deepCopy(scriptRequest);
        if (resolvedRequest == null) return;

        String rawUrl = RequestUrlResolver.extractRawUrl(resolvedRequest.url);
        if ((rawUrl == null || rawUrl.trim().isEmpty()) && resolvedRequest.rawUrlTemplate != null) {
            rawUrl = resolvedRequest.rawUrlTemplate;
        }
        rawUrl = safe(rawUrl);
        if (rawUrl.isEmpty()) return;

        String resolvedUrl = resolver == null ? rawUrl : resolver.resolve(rawUrl);
        if (resolvedUrl == null || resolvedUrl.trim().isEmpty()) resolvedUrl = rawUrl;
        String method = resolvedRequest.method == null || resolvedRequest.method.trim().isEmpty()
                ? defaultMethodForUrl(resolvedUrl)
                : resolvedRequest.method.trim().toUpperCase(Locale.ROOT);

        int score = tokenScript ? 90 : 65;
        if (isTokenishUrl(resolvedUrl) || isTokenishUrl(rawUrl)) score += 15;
        if ("POST".equalsIgnoreCase(method)) score += 10;

        resolvedRequest.method = method;
        resolvedRequest.url = rawUrl;
        resolvedRequest.rawUrlTemplate = rawUrl;
        if (resolvedRequest.header == null) resolvedRequest.header = new ArrayList<>();

        JwtEndpointCandidate cand = new JwtEndpointCandidate(resolvedRequest, resolvedUrl, method, score);
        cand.confidence = "SCRIPT";
        cand.path = path == null ? "" : path;
        cand.collectionName = collectionName == null ? "" : collectionName;
        cand.fromScriptSendRequest = true;
        cand.scriptSource = scriptSource;
        out.add(cand);
    }

    private boolean isTokenScript(String script) {
        if (script == null || script.isEmpty()) return false;

        Matcher setter = TOKEN_SETTER.matcher(script);
        while (setter.find()) {
            String key = safe(setter.group(2)).toLowerCase(Locale.ROOT);
            if (isTokenishKey(key)) return true;
        }

        // Fallback: token fields referenced in script body.
        return TOKEN_FIELDS.matcher(script).find();
    }

    private boolean isTokenishKey(String key) {
        if (key == null || key.isEmpty()) return false;
        return key.contains("token")
                || key.contains("jwt")
                || key.contains("authorization")
                || key.contains("bearer");
    }

    private boolean isTokenishUrl(String url) {
        return url != null && TOKENISH_URL.matcher(url).find();
    }

    private static String defaultMethodForUrl(String url) {
        if (url != null && TOKENISH_URL.matcher(url).find()) return "POST";
        return "GET";
    }

    private PostmanCollection.Request buildRequestFromSendRequestArg(String script, String argExpr, int callStart) {
        String arg = safe(trimTrailingSemicolon(argExpr));
        if (arg.isEmpty()) return null;

        if (isWrapped(arg, '\'', '\'') || isWrapped(arg, '"', '"') || isWrapped(arg, '`', '`')) {
            String rawUrl = normalizeScriptExpression(arg);
            if (rawUrl == null || rawUrl.trim().isEmpty()) return null;
            PostmanCollection.Request req = new PostmanCollection.Request();
            req.method = defaultMethodForUrl(rawUrl);
            req.url = rawUrl;
            req.rawUrlTemplate = rawUrl;
            req.header = new ArrayList<>();
            return req;
        }

        if (arg.startsWith("{")) {
            return parseRequestObject(arg);
        }

        if (IDENTIFIER.matcher(arg).matches()) {
            String objectLiteral = findAssignedObjectLiteral(script, arg, callStart);
            if (objectLiteral != null) {
                return parseRequestObject(objectLiteral);
            }
        }

        return null;
    }

    private PostmanCollection.Request parseRequestObject(String objectLiteral) {
        Map<String, String> props = parseObjectProperties(objectLiteral);
        if (props.isEmpty()) return null;

        String rawUrl = normalizeScriptExpression(props.get("url"));
        if (rawUrl == null || rawUrl.trim().isEmpty()) return null;

        String method = normalizeScriptExpression(props.get("method"));
        if (method == null || method.trim().isEmpty()) {
            method = defaultMethodForUrl(rawUrl);
        } else {
            method = method.trim().toUpperCase(Locale.ROOT);
        }

        PostmanCollection.Request req = new PostmanCollection.Request();
        req.method = method;
        req.url = rawUrl;
        req.rawUrlTemplate = rawUrl;
        req.header = parseHeaders(props.get("header"));
        req.body = parseBody(props.get("body"));
        if (req.header == null) req.header = new ArrayList<>();
        return req;
    }

    private List<PostmanCollection.Header> parseHeaders(String headerExpr) {
        List<PostmanCollection.Header> out = new ArrayList<>();
        String raw = safe(headerExpr);
        if (raw.isEmpty()) return out;

        if (raw.startsWith("{")) {
            Map<String, String> map = parseObjectProperties(raw);
            for (Map.Entry<String, String> e : map.entrySet()) {
                addHeader(out, e.getKey(), normalizeScriptExpression(e.getValue()));
            }
            return out;
        }

        if (raw.startsWith("[")) {
            for (Map<String, String> obj : parseObjectArray(raw)) {
                String key = normalizeScriptExpression(obj.get("key"));
                String value = normalizeScriptExpression(obj.get("value"));
                addHeader(out, key, value == null ? "" : value);
            }
            return out;
        }

        String s = normalizeScriptExpression(raw);
        if (s == null || s.isEmpty()) return out;
        String[] lines = s.split("[\\r\\n,]+");
        for (String line : lines) {
            int idx = line.indexOf(':');
            if (idx <= 0) continue;
            String key = line.substring(0, idx).trim();
            String value = line.substring(idx + 1).trim();
            addHeader(out, key, value);
        }
        return out;
    }

    private void addHeader(List<PostmanCollection.Header> out, String key, String value) {
        String headerKey = safe(key);
        if (headerKey.isEmpty()) return;
        PostmanCollection.Header h = new PostmanCollection.Header();
        h.key = headerKey;
        h.value = value == null ? "" : value;
        out.add(h);
    }

    private PostmanCollection.Body parseBody(String bodyExpr) {
        String raw = safe(bodyExpr);
        if (raw.isEmpty() || !raw.startsWith("{")) return null;

        Map<String, String> props = parseObjectProperties(raw);
        if (props.isEmpty()) return null;

        PostmanCollection.Body body = new PostmanCollection.Body();
        String mode = normalizeScriptExpression(props.get("mode"));
        if (mode != null) mode = mode.trim().toLowerCase(Locale.ROOT);
        if (mode == null || mode.isEmpty()) {
            if (props.containsKey("formdata")) mode = "formdata";
            else if (props.containsKey("urlencoded")) mode = "urlencoded";
            else if (props.containsKey("raw")) mode = "raw";
        }
        body.mode = mode;

        if ("raw".equals(mode)) {
            body.raw = normalizeScriptExpression(props.get("raw"));
        } else if ("urlencoded".equals(mode) || "formdata".equals(mode)) {
            String itemsExpr = props.get(mode);
            if (itemsExpr == null && "formdata".equals(mode)) itemsExpr = props.get("formData");
            if (itemsExpr == null && "urlencoded".equals(mode)) itemsExpr = props.get("urlEncoded");
            List<Map<String, String>> entries = parseObjectArray(itemsExpr);
            if ("urlencoded".equals(mode)) {
                List<PostmanCollection.UrlEncoded> params = new ArrayList<>();
                for (Map<String, String> entry : entries) {
                    String key = normalizeScriptExpression(entry.get("key"));
                    if (key == null || key.trim().isEmpty()) continue;
                    PostmanCollection.UrlEncoded ue = new PostmanCollection.UrlEncoded();
                    ue.key = key;
                    ue.value = normalizeScriptExpression(entry.get("value"));
                    ue.type = normalizeScriptExpression(entry.get("type"));
                    ue.disabled = parseBooleanExpression(entry.get("disabled"));
                    params.add(ue);
                }
                if (!params.isEmpty()) body.urlencoded = params;
            } else {
                List<PostmanCollection.FormData> parts = new ArrayList<>();
                for (Map<String, String> entry : entries) {
                    String key = normalizeScriptExpression(entry.get("key"));
                    if (key == null || key.trim().isEmpty()) continue;
                    PostmanCollection.FormData fd = new PostmanCollection.FormData();
                    fd.key = key;
                    fd.value = normalizeScriptExpression(entry.get("value"));
                    fd.type = normalizeScriptExpression(entry.get("type"));
                    fd.disabled = parseBooleanExpression(entry.get("disabled"));
                    parts.add(fd);
                }
                if (!parts.isEmpty()) body.formdata = parts;
            }
        }

        boolean emptyRaw = body.raw == null || body.raw.trim().isEmpty();
        boolean emptyForm = body.formdata == null || body.formdata.isEmpty();
        boolean emptyEncoded = body.urlencoded == null || body.urlencoded.isEmpty();
        if (emptyRaw && emptyForm && emptyEncoded) return null;
        if ((body.mode == null || body.mode.isEmpty()) && !emptyForm) body.mode = "formdata";
        if ((body.mode == null || body.mode.isEmpty()) && !emptyEncoded) body.mode = "urlencoded";
        if ((body.mode == null || body.mode.isEmpty()) && !emptyRaw) body.mode = "raw";
        return body;
    }

    private static boolean parseBooleanExpression(String expr) {
        String normalized = normalizeScriptExpression(expr);
        return normalized != null && "true".equalsIgnoreCase(normalized.trim());
    }

    private static String normalizeScriptExpression(String expr) {
        String raw = safe(trimTrailingSemicolon(expr));
        if (raw.isEmpty()) return "";

        String unwrapped = unwrapOuterParens(raw);
        Matcher wholeGetter = VARIABLE_GETTER.matcher(unwrapped);
        if (wholeGetter.matches()) {
            return "{{" + safe(wholeGetter.group(2)) + "}}";
        }

        List<String> plusParts = splitTopLevel(unwrapped, '+');
        if (plusParts.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (String part : plusParts) {
                sb.append(normalizeScriptExpression(part));
            }
            return sb.toString();
        }

        if (isWrapped(unwrapped, '`', '`')) {
            return normalizeTemplateLiteral(unwrapped);
        }
        if (isWrapped(unwrapped, '\'', '\'') || isWrapped(unwrapped, '"', '"')) {
            String inner = unwrapped.substring(1, unwrapped.length() - 1);
            return replaceVariableGetterCalls(unescapeJsString(inner));
        }

        return replaceVariableGetterCalls(unwrapped).trim();
    }

    private static String normalizeTemplateLiteral(String ticked) {
        if (!isWrapped(ticked, '`', '`')) return replaceVariableGetterCalls(ticked);
        String inner = ticked.substring(1, ticked.length() - 1);
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < inner.length()) {
            int start = inner.indexOf("${", i);
            if (start < 0) {
                out.append(inner, i, inner.length());
                break;
            }
            out.append(inner, i, start);
            int end = findTemplateExprEnd(inner, start + 2);
            if (end < 0) {
                out.append(inner.substring(start));
                break;
            }
            String expr = inner.substring(start + 2, end);
            out.append(normalizeScriptExpression(expr));
            i = end + 1;
        }
        return replaceVariableGetterCalls(out.toString());
    }

    private static int findTemplateExprEnd(String s, int from) {
        int depth = 0;
        char quote = 0;
        boolean esc = false;
        for (int i = from; i < s.length(); i++) {
            char c = s.charAt(i);
            if (quote != 0) {
                if (esc) {
                    esc = false;
                    continue;
                }
                if (c == '\\') {
                    esc = true;
                    continue;
                }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '\'' || c == '"' || c == '`') {
                quote = c;
                continue;
            }
            if (c == '{') depth++;
            else if (c == '}') {
                if (depth == 0) return i;
                depth--;
            }
        }
        return -1;
    }

    private static String replaceVariableGetterCalls(String input) {
        if (input == null || input.isEmpty()) return "";
        Matcher m = VARIABLE_GETTER.matcher(input);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            MatchResult mr = m.toMatchResult();
            String key = safe(mr.group(2));
            m.appendReplacement(sb, Matcher.quoteReplacement("{{" + key + "}}"));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private Map<String, String> parseObjectProperties(String objectLiteral) {
        String content = stripOuter(objectLiteral, '{', '}');
        Map<String, String> out = new LinkedHashMap<>();
        if (content == null || content.trim().isEmpty()) return out;

        int i = 0;
        while (i < content.length()) {
            while (i < content.length() && (Character.isWhitespace(content.charAt(i)) || content.charAt(i) == ',')) i++;
            if (i >= content.length()) break;

            char c = content.charAt(i);
            String key;
            if (c == '\'' || c == '"' || c == '`') {
                int end = findQuotedEnd(content, i);
                if (end < 0) break;
                key = content.substring(i + 1, end);
                i = end + 1;
            } else {
                int start = i;
                while (i < content.length() && isKeyChar(content.charAt(i))) i++;
                key = content.substring(start, i).trim();
            }
            if (key == null || key.trim().isEmpty()) {
                i++;
                continue;
            }

            while (i < content.length() && Character.isWhitespace(content.charAt(i))) i++;
            if (i >= content.length() || content.charAt(i) != ':') {
                int skip = findTopLevelDelimiter(content, i, ',');
                if (skip < 0) break;
                i = skip + 1;
                continue;
            }
            i++; // :
            while (i < content.length() && Character.isWhitespace(content.charAt(i))) i++;
            int valueStart = i;
            int valueEnd = findTopLevelValueEnd(content, valueStart);
            if (valueEnd < valueStart) break;
            String value = content.substring(valueStart, Math.min(valueEnd, content.length())).trim();
            out.put(key.trim(), value);
            i = valueEnd;
            if (i < content.length() && content.charAt(i) == ',') i++;
        }
        return out;
    }

    private List<Map<String, String>> parseObjectArray(String arrayExpr) {
        List<Map<String, String>> out = new ArrayList<>();
        String content = stripOuter(arrayExpr, '[', ']');
        if (content == null || content.trim().isEmpty()) return out;
        List<String> items = splitTopLevel(content, ',');
        for (String item : items) {
            String raw = safe(item);
            if (!raw.startsWith("{")) continue;
            Map<String, String> props = parseObjectProperties(raw);
            if (!props.isEmpty()) out.add(props);
        }
        return out;
    }

    private static String findAssignedObjectLiteral(String script, String variableName, int beforeIndex) {
        if (script == null || variableName == null || variableName.isEmpty()) return null;
        Pattern assignment = Pattern.compile(
                "(?is)(?:\\b(?:const|let|var)\\s+)?"
                        + Pattern.quote(variableName)
                        + "\\s*=\\s*\\{");
        Matcher m = assignment.matcher(script);
        String best = null;
        int bestStart = -1;
        while (m.find()) {
            if (m.start() >= beforeIndex) break;
            int open = script.indexOf('{', m.end() - 1);
            if (open < 0 || open >= beforeIndex) continue;
            int close = findMatchingBracket(script, open, '{', '}');
            if (close < 0 || close >= beforeIndex) continue;
            if (m.start() >= bestStart) {
                bestStart = m.start();
                best = script.substring(open, close + 1);
            }
        }
        return best;
    }

    private static ParsedArgument parseFirstArgument(String script, int startIndex) {
        if (script == null || startIndex < 0 || startIndex >= script.length()) return null;
        int i = startIndex;
        while (i < script.length() && Character.isWhitespace(script.charAt(i))) i++;
        int start = i;

        int depthBrace = 0;
        int depthBracket = 0;
        int depthParen = 0;
        char quote = 0;
        boolean esc = false;
        for (; i < script.length(); i++) {
            char c = script.charAt(i);
            if (quote != 0) {
                if (esc) {
                    esc = false;
                    continue;
                }
                if (c == '\\') {
                    esc = true;
                    continue;
                }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '\'' || c == '"' || c == '`') {
                quote = c;
                continue;
            }
            switch (c) {
                case '{': depthBrace++; break;
                case '}': if (depthBrace > 0) depthBrace--; break;
                case '[': depthBracket++; break;
                case ']': if (depthBracket > 0) depthBracket--; break;
                case '(':
                    depthParen++;
                    break;
                case ')':
                    if (depthBrace == 0 && depthBracket == 0 && depthParen == 0) {
                        return new ParsedArgument(script.substring(start, i).trim(), i);
                    }
                    if (depthParen > 0) depthParen--;
                    break;
                case ',':
                    if (depthBrace == 0 && depthBracket == 0 && depthParen == 0) {
                        return new ParsedArgument(script.substring(start, i).trim(), i);
                    }
                    break;
                default:
                    break;
            }
        }
        return new ParsedArgument(script.substring(start).trim(), script.length());
    }

    private static int findMatchingBracket(String text, int openIndex, char openChar, char closeChar) {
        if (text == null || openIndex < 0 || openIndex >= text.length()) return -1;
        int depth = 0;
        char quote = 0;
        boolean esc = false;
        for (int i = openIndex; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quote != 0) {
                if (esc) {
                    esc = false;
                    continue;
                }
                if (c == '\\') {
                    esc = true;
                    continue;
                }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '\'' || c == '"' || c == '`') {
                quote = c;
                continue;
            }
            if (c == openChar) depth++;
            else if (c == closeChar) {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private static int findQuotedEnd(String s, int quoteStart) {
        char q = s.charAt(quoteStart);
        boolean esc = false;
        for (int i = quoteStart + 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) {
                esc = false;
                continue;
            }
            if (c == '\\') {
                esc = true;
                continue;
            }
            if (c == q) return i;
        }
        return -1;
    }

    private static int findTopLevelDelimiter(String s, int from, char delimiter) {
        int depthBrace = 0, depthBracket = 0, depthParen = 0;
        char quote = 0;
        boolean esc = false;
        for (int i = Math.max(0, from); i < s.length(); i++) {
            char c = s.charAt(i);
            if (quote != 0) {
                if (esc) {
                    esc = false;
                    continue;
                }
                if (c == '\\') {
                    esc = true;
                    continue;
                }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '\'' || c == '"' || c == '`') {
                quote = c;
                continue;
            }
            switch (c) {
                case '{': depthBrace++; break;
                case '}': if (depthBrace > 0) depthBrace--; break;
                case '[': depthBracket++; break;
                case ']': if (depthBracket > 0) depthBracket--; break;
                case '(': depthParen++; break;
                case ')': if (depthParen > 0) depthParen--; break;
                default:
                    if (c == delimiter && depthBrace == 0 && depthBracket == 0 && depthParen == 0) return i;
                    break;
            }
        }
        return -1;
    }

    private static int findTopLevelValueEnd(String s, int from) {
        int idx = findTopLevelDelimiter(s, from, ',');
        return idx < 0 ? s.length() : idx;
    }

    private static List<String> splitTopLevel(String s, char delimiter) {
        List<String> out = new ArrayList<>();
        if (s == null || s.isEmpty()) return out;
        int start = 0;
        int depthBrace = 0, depthBracket = 0, depthParen = 0;
        char quote = 0;
        boolean esc = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (quote != 0) {
                if (esc) {
                    esc = false;
                    continue;
                }
                if (c == '\\') {
                    esc = true;
                    continue;
                }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '\'' || c == '"' || c == '`') {
                quote = c;
                continue;
            }
            switch (c) {
                case '{': depthBrace++; break;
                case '}': if (depthBrace > 0) depthBrace--; break;
                case '[': depthBracket++; break;
                case ']': if (depthBracket > 0) depthBracket--; break;
                case '(': depthParen++; break;
                case ')': if (depthParen > 0) depthParen--; break;
                default:
                    if (c == delimiter && depthBrace == 0 && depthBracket == 0 && depthParen == 0) {
                        out.add(s.substring(start, i).trim());
                        start = i + 1;
                    }
                    break;
            }
        }
        out.add(s.substring(start).trim());
        return out;
    }

    private static String stripOuter(String text, char open, char close) {
        String s = safe(text);
        if (s.isEmpty() || s.charAt(0) != open) return s;
        int end = findMatchingBracket(s, 0, open, close);
        if (end == s.length() - 1) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    private static String unwrapOuterParens(String text) {
        String out = safe(text);
        while (isWrapped(out, '(', ')')) {
            out = out.substring(1, out.length() - 1).trim();
        }
        return out;
    }

    private static boolean isWrapped(String s, char open, char close) {
        if (s == null || s.length() < 2) return false;
        if (s.charAt(0) != open || s.charAt(s.length() - 1) != close) return false;
        if (open == '\'' || open == '"' || open == '`') return true;
        int end = findMatchingBracket(s, 0, open, close);
        return end == s.length() - 1;
    }

    private static String trimTrailingSemicolon(String s) {
        if (s == null) return null;
        String out = s.trim();
        while (out.endsWith(";")) {
            out = out.substring(0, out.length() - 1).trim();
        }
        return out;
    }

    private static boolean isKeyChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$' || c == '-';
    }

    private static String unescapeJsString(String s) {
        if (s == null || s.isEmpty()) return "";
        StringBuilder out = new StringBuilder(s.length());
        boolean esc = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!esc) {
                if (c == '\\') {
                    esc = true;
                } else {
                    out.append(c);
                }
                continue;
            }
            switch (c) {
                case 'n': out.append('\n'); break;
                case 'r': out.append('\r'); break;
                case 't': out.append('\t'); break;
                case '\\': out.append('\\'); break;
                case '\'': out.append('\''); break;
                case '"': out.append('"'); break;
                default: out.append(c); break;
            }
            esc = false;
        }
        if (esc) out.append('\\');
        return out.toString();
    }

    private static String joinScript(List<String> lines) {
        if (lines == null || lines.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (String line : lines) sb.append(line == null ? "" : line).append('\n');
        return sb.toString();
    }

    private PostmanCollection.Request deepCopy(PostmanCollection.Request req) {
        if (req == null) return null;
        return gson.fromJson(gson.toJson(req), PostmanCollection.Request.class);
    }

    private void resolveRequestFields(PostmanCollection.Request req, VariableResolver resolver) {
        if (req == null || resolver == null) return;

        if (req.header != null) {
            for (PostmanCollection.Header h : req.header) {
                if (h == null) continue;
                if (h.key != null) h.key = resolver.resolve(h.key);
                if (h.value != null) h.value = resolver.resolve(h.value);
            }
        }

        if (req.body != null) {
            if (req.body.raw != null) req.body.raw = resolver.resolve(req.body.raw);
            if (req.body.urlencoded != null) {
                for (PostmanCollection.UrlEncoded ue : req.body.urlencoded) {
                    if (ue == null) continue;
                    if (ue.key != null) ue.key = resolver.resolve(ue.key);
                    if (ue.value != null) ue.value = resolver.resolve(ue.value);
                }
            }
            if (req.body.formdata != null) {
                for (PostmanCollection.FormData fd : req.body.formdata) {
                    if (fd == null) continue;
                    if (fd.key != null) fd.key = resolver.resolve(fd.key);
                    if (fd.value != null) fd.value = resolver.resolve(fd.value);
                    String src = fd.getSrcAsString();
                    if (src != null) fd.src = resolver.resolve(src);
                }
            }
        }
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }

    private static final class ParsedArgument {
        final String argument;
        final int endIndex;

        ParsedArgument(String argument, int endIndex) {
            this.argument = argument;
            this.endIndex = endIndex;
        }
    }
}
