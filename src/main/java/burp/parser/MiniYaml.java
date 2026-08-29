package burp.parser;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Purpose-built YAML reader for Bruno's {@code opencollection: 1.0.0}
 * schema. Not a general YAML parser — supports only the subset Bruno
 * actually emits:
 *
 * <ul>
 *   <li>Scalar {@code key: value} (unquoted, single-, or double-quoted)
 *   <li>Nested mappings via indentation</li>
 *   <li>Lists of mappings: {@code - name: k\n  value: v}</li>
 *   <li>Literal block scalars: {@code |}, {@code |-}, {@code |+}</li>
 *   <li>Folded block scalars: {@code >}, {@code >-}, {@code >+}</li>
 *   <li>Line comments starting with {@code #}</li>
 *   <li>Empty lines</li>
 * </ul>
 *
 * <p>Returns nested {@code Map<String, Object>} trees whose leaf values
 * are {@code String}, {@code Map<String, Object>}, or {@code List<Object>}.
 * Bruno's YAML never uses anchors, aliases, tags, flow syntax, or complex
 * keys — so those are intentionally unsupported.
 *
 * <p>Rationale: adding SnakeYAML (~300 KB) to the jar solely for this
 * one narrow file format would bloat the lite build (2.55 MB → ~2.85 MB)
 * for every user, even those who only import Postman JSON.
 */
final class MiniYaml {

    private MiniYaml() {}

    @SuppressWarnings("unchecked")
    static Map<String, Object> parse(String content) {
        if (content == null || content.isEmpty()) return new LinkedHashMap<>();
        String[] lines = content.split("\\R", -1);
        Object root = parseBlock(lines, 0, 0, new int[]{lines.length});
        if (root instanceof Map) return (Map<String, Object>) root;
        Map<String, Object> wrapper = new LinkedHashMap<>();
        if (root != null) wrapper.put("_root", root);
        return wrapper;
    }

    /** Parses a mapping or sequence block starting at {@code lines[start]}
     *  whose entries are indented at exactly {@code baseIndent} columns.
     *  Advances the shared {@code cursor[0]} past the last line consumed. */
    private static Object parseBlock(String[] lines, int start, int baseIndent, int[] cursor) {
        Map<String, Object> map = null;
        List<Object> list = null;
        int i = start;
        while (i < lines.length) {
            String line = lines[i];
            if (isBlank(line) || isComment(line)) { i++; continue; }
            int indent = leadingSpaces(line);
            if (indent < baseIndent) break;
            if (indent > baseIndent) {
                i++;
                continue;
            }
            String trimmed = line.substring(indent);

            if (trimmed.startsWith("- ") || trimmed.equals("-")) {
                if (list == null) list = new ArrayList<>();
                String afterDash = trimmed.equals("-") ? "" : trimmed.substring(2).trim();
                if (afterDash.isEmpty()) {
                    i++;
                    int[] sub = { i };
                    Object child = parseBlock(lines, i, baseIndent + 2, sub);
                    list.add(child == null ? new LinkedHashMap<>() : child);
                    i = sub[0];
                } else {
                    int colon = findColon(afterDash);
                    if (colon > 0) {
                        Map<String, Object> item = new LinkedHashMap<>();
                        String key = afterDash.substring(0, colon).trim();
                        String rest = afterDash.substring(colon + 1).trim();
                        Object[] valueAndCursor = readValue(rest, lines, i + 1, indent + 2);
                        item.put(unquote(key), valueAndCursor[0]);
                        int nextIdx = (int) valueAndCursor[1];
                        int[] sub = { nextIdx };
                        while (sub[0] < lines.length) {
                            String peek = lines[sub[0]];
                            if (isBlank(peek) || isComment(peek)) { sub[0]++; continue; }
                            int peekIndent = leadingSpaces(peek);
                            if (peekIndent < indent + 2) break;
                            if (peekIndent > indent + 2) { sub[0]++; continue; }
                            String peekTrim = peek.substring(peekIndent);
                            if (peekTrim.startsWith("- ") || peekTrim.equals("-")) break;
                            int c = findColon(peekTrim);
                            if (c <= 0) { sub[0]++; continue; }
                            String k2 = peekTrim.substring(0, c).trim();
                            String r2 = peekTrim.substring(c + 1).trim();
                            Object[] v2 = readValue(r2, lines, sub[0] + 1, indent + 4);
                            item.put(unquote(k2), v2[0]);
                            sub[0] = (int) v2[1];
                        }
                        list.add(item);
                        i = sub[0];
                    } else {
                        list.add(unquote(afterDash));
                        i++;
                    }
                }
                continue;
            }

            int colon = findColon(trimmed);
            if (colon <= 0) { i++; continue; }
            String key = unquote(trimmed.substring(0, colon).trim());
            String rest = trimmed.substring(colon + 1).trim();
            Object[] valueAndCursor = readValue(rest, lines, i + 1, baseIndent + 2);
            if (map == null) map = new LinkedHashMap<>();
            map.put(key, valueAndCursor[0]);
            i = (int) valueAndCursor[1];
        }
        cursor[0] = i;
        return map != null ? map : (list != null ? list : new LinkedHashMap<>());
    }

    /** Given the text right of the colon and the following lines, return
     *  {@code [value, nextLineIndex]}. Handles scalars, block scalars
     *  ({@code |}, {@code |-}, {@code |+}, {@code >}, {@code >-}, {@code >+}),
     *  inline flow (skipped), and nested map/list continuations. */
    private static Object[] readValue(String rest, String[] lines, int nextIndex, int childIndent) {
        if (rest.isEmpty()) {
            if (nextIndex >= lines.length) return new Object[] { "", nextIndex };
            int p = nextIndex;
            while (p < lines.length && (isBlank(lines[p]) || isComment(lines[p]))) p++;
            if (p >= lines.length) return new Object[] { "", nextIndex };
            int probeIndent = leadingSpaces(lines[p]);
            if (probeIndent < childIndent) return new Object[] { "", nextIndex };
            String probe = lines[p].substring(probeIndent);
            int actualChildIndent = probeIndent;
            int[] sub = { nextIndex };
            Object child = parseBlock(lines, nextIndex, actualChildIndent, sub);
            return new Object[] { child, sub[0] };
        }

        char first = rest.charAt(0);
        if (first == '|' || first == '>') {
            boolean fold = first == '>';
            boolean stripFinal = rest.length() > 1 && rest.charAt(1) == '-';
            boolean keepAll   = rest.length() > 1 && rest.charAt(1) == '+';
            StringBuilder sb = new StringBuilder();
            int p = nextIndex;
            int blockIndent = -1;
            List<String> collected = new ArrayList<>();
            while (p < lines.length) {
                String ln = lines[p];
                if (ln.isEmpty()) { collected.add(""); p++; continue; }
                int in = leadingSpaces(ln);
                if (in < childIndent && !ln.trim().isEmpty()) break;
                if (blockIndent < 0 && !ln.trim().isEmpty()) blockIndent = in;
                if (!ln.trim().isEmpty() && in < blockIndent) break;
                if (blockIndent > 0 && ln.length() >= blockIndent) {
                    collected.add(ln.substring(blockIndent));
                } else {
                    collected.add(ln.trim());
                }
                p++;
            }
            if (fold) {
                for (int k = 0; k < collected.size(); k++) {
                    String s = collected.get(k);
                    if (s.isEmpty()) {
                        sb.append('\n');
                    } else {
                        if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') sb.append(' ');
                        sb.append(s);
                    }
                }
            } else {
                for (String s : collected) sb.append(s).append('\n');
            }
            String val = sb.toString();
            if (stripFinal) {
                while (val.endsWith("\n")) val = val.substring(0, val.length() - 1);
            } else if (!keepAll) {
                while (val.endsWith("\n\n")) val = val.substring(0, val.length() - 1);
            }
            return new Object[] { val, p };
        }

        int hashIdx = findUnquotedComment(rest);
        String scalar = hashIdx >= 0 ? rest.substring(0, hashIdx).trim() : rest;
        return new Object[] { unquote(scalar), nextIndex };
    }

    private static int leadingSpaces(String line) {
        int i = 0;
        while (i < line.length() && line.charAt(i) == ' ') i++;
        return i;
    }

    private static boolean isBlank(String line) {
        return line == null || line.trim().isEmpty();
    }

    private static boolean isComment(String line) {
        String t = line.trim();
        return t.startsWith("#");
    }

    /** Find the first colon that's not inside quotes and is followed by
     *  end-of-line or whitespace (YAML's rule for map key separator). */
    private static int findColon(String s) {
        boolean inSingle = false, inDouble = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && (inSingle || inDouble) && i + 1 < s.length()) { i++; continue; }
            if (c == '"' && !inSingle) inDouble = !inDouble;
            else if (c == '\'' && !inDouble) inSingle = !inSingle;
            else if (c == ':' && !inSingle && !inDouble) {
                if (i == s.length() - 1) return i;
                char next = s.charAt(i + 1);
                if (next == ' ' || next == '\t') return i;
            }
        }
        return -1;
    }

    private static int findUnquotedComment(String s) {
        boolean inSingle = false, inDouble = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && (inSingle || inDouble) && i + 1 < s.length()) { i++; continue; }
            if (c == '"' && !inSingle) inDouble = !inDouble;
            else if (c == '\'' && !inDouble) inSingle = !inSingle;
            else if (c == '#' && !inSingle && !inDouble) {
                if (i == 0 || s.charAt(i - 1) == ' ' || s.charAt(i - 1) == '\t') return i;
            }
        }
        return -1;
    }

    static String unquote(String v) {
        if (v == null) return null;
        String t = v.trim();
        if (t.length() >= 2) {
            char first = t.charAt(0), last = t.charAt(t.length() - 1);
            if (first == '"' && last == '"') {
                return decodeDoubleQuoted(t.substring(1, t.length() - 1));
            }
            if (first == '\'' && last == '\'') {
                return t.substring(1, t.length() - 1).replace("''", "'");
            }
        }
        return t;
    }

    private static String decodeDoubleQuoted(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                out.append(c);
                i++;
                continue;
            }
            char e = s.charAt(i + 1);
            switch (e) {
                case 'n': out.append('\n'); i += 2; break;
                case 'r': out.append('\r'); i += 2; break;
                case 't': out.append('\t'); i += 2; break;
                case '"': out.append('"');  i += 2; break;
                case '\\': out.append('\\'); i += 2; break;
                case '/': out.append('/'); i += 2; break;
                case '0': out.append('\0'); i += 2; break;
                case 'a': out.append((char) 0x07); i += 2; break;
                case 'b': out.append('\b'); i += 2; break;
                case 'f': out.append('\f'); i += 2; break;
                case 'v': out.append((char) 0x0B); i += 2; break;
                case 'e': out.append((char) 0x1B); i += 2; break;
                case ' ': out.append(' '); i += 2; break;
                case 'N': out.append((char) 0x85); i += 2; break;
                case '_':
                    out.append(' ');
                    i += 2;
                    break;
                case 'L': out.append('\u2028'); i += 2; break;
                case 'P': out.append('\u2029'); i += 2; break;
                case 'x': {
                    if (i + 3 < s.length()) {
                        try {
                            int v = Integer.parseInt(s.substring(i + 2, i + 4), 16);
                            out.append((char) v);
                            i += 4;
                            break;
                        } catch (NumberFormatException ignored) {}
                    }
                    out.append(c);
                    i++;
                    break;
                }
                case 'u': {
                    if (i + 5 < s.length()) {
                        try {
                            int v = Integer.parseInt(s.substring(i + 2, i + 6), 16);
                            out.append((char) v);
                            i += 6;
                            break;
                        } catch (NumberFormatException ignored) {}
                    }
                    out.append(c);
                    i++;
                    break;
                }
                case 'U': {
                    if (i + 9 < s.length()) {
                        try {
                            int v = Integer.parseInt(s.substring(i + 2, i + 10), 16);
                            out.appendCodePoint(v);
                            i += 10;
                            break;
                        } catch (NumberFormatException ignored) {}
                    }
                    out.append(c);
                    i++;
                    break;
                }
                default:
                    out.append(c);
                    i++;
                    break;
            }
        }
        return out.toString();
    }
}
