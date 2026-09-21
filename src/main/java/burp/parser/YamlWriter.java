package burp.parser;

import java.util.List;
import java.util.Locale;

/**
 * Emits YAML that {@link MiniYaml} and Bruno both read back.
 *
 * <p>Only the shapes an OpenCollection needs are supported: nested maps, sequences of maps, and
 * scalars. The interesting part is deciding how to write a scalar, since a value that looks like
 * a number, a boolean or a YAML indicator has to be quoted or it changes meaning on the way
 * back in.
 */
final class YamlWriter {

   private final StringBuilder out = new StringBuilder();

   String text() {
      return this.out.toString();
   }

   /** {@code key: value} at the given depth, skipped entirely when the value is null. */
   YamlWriter field(int indent, String key, String value) {
      if (value == null) return this;
      this.indent(indent).append(key).append(": ").append(scalar(value, indent)).append('\n');
      return this;
   }

   YamlWriter field(int indent, String key, boolean value) {
      this.indent(indent).append(key).append(": ").append(value).append('\n');
      return this;
   }

   YamlWriter field(int indent, String key, int value) {
      this.indent(indent).append(key).append(": ").append(value).append('\n');
      return this;
   }

   /** A key introducing a nested block, i.e. {@code key:} on its own line. */
   YamlWriter open(int indent, String key) {
      this.indent(indent).append(key).append(":\n");
      return this;
   }

   /** The first field of a sequence entry, i.e. {@code - key: value}. */
   YamlWriter itemField(int indent, String key, String value) {
      if (value == null) value = "";
      this.indent(indent).append("- ").append(key).append(": ")
         .append(scalar(value, indent + 1)).append('\n');
      return this;
   }

   /** A key whose value is written verbatim, for shapes like {@code pkce: {}}. */
   YamlWriter literal(int indent, String key, String rawValue) {
      this.indent(indent).append(key).append(": ").append(rawValue).append('\n');
      return this;
   }

   /**
    * Writes a value that is semantically a boolean but held as text. Emitting {@code "true"}
    * quoted would come back as the string rather than the flag it stands for.
    */
   YamlWriter booleanish(int indent, String key, String value) {
      if (value == null) return this;
      String v = value.trim().toLowerCase(Locale.ROOT);
      if (v.equals("true") || v.equals("false")) {
         return this.literal(indent, key, v);
      }
      return this.field(indent, key, value);
   }

   /** A bare sequence entry, i.e. {@code - value}. */
   YamlWriter indentedListItem(int indent, String value) {
      this.indent(indent).append("- ").append(scalar(value, indent)).append('\n');
      return this;
   }

   YamlWriter blank() {
      this.out.append('\n');
      return this;
   }

   private StringBuilder indent(int indent) {
      for (int i = 0; i < indent; i++) this.out.append("  ");
      return this.out;
   }

   /**
    * Renders a scalar, choosing the representation that survives a round trip.
    *
    * <p>Anything spanning several lines becomes a literal block, which keeps the text readable
    * and avoids the folding rules entirely. Text carrying carriage returns or trailing spaces
    * cannot use a block, because those are invisible and a parser is entitled to trim them, so
    * it falls back to a double-quoted string with explicit escapes.
    */
   private String scalar(String value, int indent) {
      if (value.isEmpty()) return "\"\"";

      boolean multiLine = value.indexOf('\n') >= 0;
      if (multiLine && blockSafe(value)) {
         return literalBlock(value, indent + 1);
      }
      if (multiLine || needsQuoting(value)) {
         return doubleQuoted(value);
      }
      return value;
   }

   /**
    * A literal block cannot represent text whose whitespace matters, because leading indentation
    * is stripped by position and trailing spaces are not guaranteed to survive.
    */
   private static boolean blockSafe(String value) {
      if (value.indexOf('\r') >= 0 || value.indexOf('\t') >= 0) return false;
      for (String line : value.split("\n", -1)) {
         if (!line.isEmpty() && line.charAt(line.length() - 1) == ' ') return false;
         for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c < 0x20) return false;
         }
      }
      // Leading whitespace on the first line would be swallowed as indentation.
      return !value.startsWith(" ");
   }

   private static String literalBlock(String value, int indent) {
      StringBuilder sb = new StringBuilder();
      // "|-" keeps interior newlines and drops the trailing one, matching the value we hold.
      sb.append("|-");
      String pad = repeat("  ", indent);
      for (String line : value.split("\n", -1)) {
         sb.append('\n');
         if (!line.isEmpty()) sb.append(pad).append(line);
      }
      return sb.toString();
   }

   private static String repeat(String s, int times) {
      StringBuilder sb = new StringBuilder(s.length() * Math.max(0, times));
      for (int i = 0; i < times; i++) sb.append(s);
      return sb.toString();
   }

   /**
    * True when writing the text bare would change its meaning, e.g. {@code 10000042} coming back
    * as a number or {@code yes} as a boolean.
    */
   static boolean needsQuoting(String value) {
      if (value.isEmpty()) return true;
      char first = value.charAt(0);
      if ("-?:,[]{}#&*!|>'\"%@`".indexOf(first) >= 0) return true;
      if (Character.isWhitespace(first) || Character.isWhitespace(value.charAt(value.length() - 1))) return true;
      if (value.contains(": ") || value.contains(" #") || value.endsWith(":")) return true;
      for (int i = 0; i < value.length(); i++) {
         char c = value.charAt(i);
         if (c < 0x20 || c == 0x7F) return true;
      }
      String lower = value.toLowerCase(Locale.ROOT);
      switch (lower) {
         case "true": case "false": case "yes": case "no": case "on": case "off":
         case "null": case "~": case "y": case "n":
            return true;
         default:
            break;
      }
      // A bare number would come back as a number rather than the text it started as.
      return looksNumeric(value);
   }

   private static boolean looksNumeric(String value) {
      try {
         Double.parseDouble(value);
         return true;
      } catch (NumberFormatException ex) {
         return false;
      }
   }

   static String doubleQuoted(String value) {
      StringBuilder sb = new StringBuilder(value.length() + 8);
      sb.append('"');
      for (int i = 0; i < value.length(); i++) {
         char c = value.charAt(i);
         switch (c) {
            case '"':  sb.append("\\\""); break;
            case '\\': sb.append("\\\\"); break;
            case '\n': sb.append("\\n"); break;
            case '\r': sb.append("\\r"); break;
            case '\t': sb.append("\\t"); break;
            default:
               if (c < 0x20 || c == 0x7F) {
                  sb.append(String.format("\\x%02x", (int) c));
               } else {
                  sb.append(c);
               }
         }
      }
      sb.append('"');
      return sb.toString();
   }

   /** Turns a collection or request name into something every filesystem accepts. */
   static String safeFileName(String name, String fallback) {
      String base = name == null ? "" : name.trim();
      if (base.isEmpty()) base = fallback;
      StringBuilder sb = new StringBuilder(base.length());
      for (int i = 0; i < base.length(); i++) {
         char c = base.charAt(i);
         sb.append("\\/:*?\"<>|".indexOf(c) >= 0 || c < 0x20 ? '-' : c);
      }
      // Windows also rejects a name ending in a dot or space.
      String cleaned = sb.toString().trim();
      while (cleaned.endsWith(".")) cleaned = cleaned.substring(0, cleaned.length() - 1).trim();
      // A leading dot hides the file on Unix, and a leading ".." reads as a parent reference
      // even once the separators are gone. Neither is worth carrying over from a request name.
      while (!cleaned.isEmpty() && (cleaned.charAt(0) == '.' || cleaned.charAt(0) == '-')) {
         cleaned = cleaned.substring(1).trim();
      }
      if (cleaned.isEmpty()) cleaned = fallback;
      return cleaned.length() > 120 ? cleaned.substring(0, 120).trim() : cleaned;
   }

   /** Ensures a name is unique within a directory by adding a numeric suffix. */
   static String uniqueName(String candidate, List<String> taken) {
      String name = candidate;
      int n = 2;
      while (taken.contains(name.toLowerCase(Locale.ROOT))) {
         name = candidate + " " + n;
         n++;
      }
      taken.add(name.toLowerCase(Locale.ROOT));
      return name;
   }
}
