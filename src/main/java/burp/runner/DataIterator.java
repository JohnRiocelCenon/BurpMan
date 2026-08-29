package burp.runner;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

public final class DataIterator {
   private final List<Map<String, String>> rows;
   private int index = 0;

   private DataIterator(List<Map<String, String>> rows) {
      this.rows = rows;
   }

   public static DataIterator fromFile(File file) throws IOException {
      if (file != null && file.isFile()) {
         String name = file.getName().toLowerCase(Locale.ROOT);
         if (name.endsWith(".json")) {
            return fromJson(file);
         } else if (name.endsWith(".csv")) {
            return fromCsv(file);
         } else {
            String snippet = new String(Files.readAllBytes(file.toPath())).trim();
            return snippet.startsWith("[") ? fromJson(file) : fromCsv(file);
         }
      } else {
         throw new IllegalArgumentException("Not a readable file: " + file);
      }
   }

   public static DataIterator fromCsv(File file) throws IOException {
      try (BufferedReader r = new BufferedReader(new FileReader(file))) {
         List<String[]> raw = parseCsv(r);
         if (!raw.isEmpty()) {
            String[] header = raw.get(0);
            List<Map<String, String>> rows = new ArrayList<>(raw.size() - 1);

            for (int i = 1; i < raw.size(); i++) {
               String[] line = raw.get(i);
               Map<String, String> row = new LinkedHashMap<>();

               for (int j = 0; j < header.length; j++) {
                  String key = header[j] == null ? "" : header[j].trim();
                  String val = j < line.length && line[j] != null ? line[j] : "";
                  row.put(key, val);
               }

               rows.add(row);
            }

            return new DataIterator(rows);
         }

         return new DataIterator(new ArrayList<>());
      }
   }

   private static List<String[]> parseCsv(Reader in) throws IOException {
      List<String[]> rows = new ArrayList<>();
      List<String> currentRow = new ArrayList<>();
      StringBuilder field = new StringBuilder();
      boolean inQuotes = false;

      int c;
      while ((c = in.read()) != -1) {
         char ch = (char)c;
         if (inQuotes) {
            if (ch == '"') {
               int next = in.read();
               if (next == 34) {
                  field.append('"');
               } else {
                  inQuotes = false;
                  if (next == -1) {
                     break;
                  }

                  if (next == 44) {
                     currentRow.add(field.toString());
                     field.setLength(0);
                  } else if (next == 10) {
                     currentRow.add(field.toString());
                     field.setLength(0);
                     rows.add(currentRow.toArray(new String[0]));
                     currentRow = new ArrayList<>();
                  } else if (next == 13) {
                     currentRow.add(field.toString());
                     field.setLength(0);
                     rows.add(currentRow.toArray(new String[0]));
                     currentRow = new ArrayList<>();
                     int peek = in.read();
                     if (peek != -1 && peek != 10) {
                        ch = (char)peek;
                        if (ch == ',') {
                           currentRow.add("");
                        } else if (ch == '"') {
                           inQuotes = true;
                        } else {
                           field.append(ch);
                        }
                     }
                  } else {
                     field.append((char)next);
                  }
               }
            } else {
               field.append(ch);
            }
         } else if (ch == '"' && field.length() == 0) {
            inQuotes = true;
         } else if (ch == ',') {
            currentRow.add(field.toString());
            field.setLength(0);
         } else if (ch == '\n') {
            currentRow.add(field.toString());
            field.setLength(0);
            rows.add(currentRow.toArray(new String[0]));
            currentRow = new ArrayList<>();
         } else if (ch != '\r') {
            field.append(ch);
         }
      }

      if (field.length() > 0 || !currentRow.isEmpty()) {
         currentRow.add(field.toString());
         rows.add(currentRow.toArray(new String[0]));
      }

      return rows;
   }

   public static DataIterator fromJson(File file) throws IOException {
      try {
         try (Reader r = new FileReader(file)) {
            JsonElement el = (JsonElement)new Gson().fromJson(r, JsonElement.class);
            if (el == null || !el.isJsonArray()) {
               throw new IOException("Expected JSON array of objects at top level: " + file);
            }

            JsonArray arr = el.getAsJsonArray();
            List<Map<String, String>> rows = new ArrayList<>(arr.size());

            for (JsonElement item : arr) {
               if (item.isJsonObject()) {
                  Map<String, String> row = new LinkedHashMap<>();

                  for (Entry<String, JsonElement> ex : item.getAsJsonObject().entrySet()) {
                     JsonElement v = ex.getValue();
                     if (v.isJsonNull()) {
                        row.put(ex.getKey(), "");
                     } else if (v.isJsonPrimitive()) {
                        row.put(ex.getKey(), v.getAsString());
                     } else {
                        row.put(ex.getKey(), v.toString());
                     }
                  }

                  rows.add(row);
               }
            }

            return new DataIterator(rows);
         }
      } catch (Exception var21) {
         throw new IOException("Failed to read JSON: " + file + " — " + var21.getMessage(), var21);
      }
   }

   public int size() {
      return this.rows.size();
   }

   public boolean hasNext() {
      return this.index < this.rows.size();
   }

   public Map<String, String> next() {
      if (!this.hasNext()) {
         throw new IllegalStateException("No more rows");
      } else {
         return this.rows.get(this.index++);
      }
   }

   public void reset() {
      this.index = 0;
   }

   public int currentIndex() {
      return this.index;
   }

   public List<Map<String, String>> allRows() {
      return new ArrayList<>(this.rows);
   }
}
