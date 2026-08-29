package burp.service;

import burp.models.PostmanCollection;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class CookieJar {
   private final Map<String, Map<String, CookieJar.Cookie>> byHost = new LinkedHashMap<>();
   private final List<Runnable> listeners = new ArrayList<>();

   public synchronized void capture(String host, List<PostmanCollection.Header> responseHeaders) {
      if (host != null && responseHeaders != null) {
         String h = host.toLowerCase();
         boolean changed = false;

         for (PostmanCollection.Header header : responseHeaders) {
            if (header.key != null && "set-cookie".equalsIgnoreCase(header.key.trim()) && header.value != null) {
               CookieJar.Cookie c = parseSetCookie(h, header.value);
               if (c != null) {
                  this.byHost.computeIfAbsent(h, k -> new LinkedHashMap<>()).put(c.name, c);
                  changed = true;
               }
            }
         }

         if (changed) {
            this.fireChanged();
         }
      }
   }

   public synchronized String buildCookieHeader(String host) {
      if (host == null) {
         return null;
      } else {
         long now = System.currentTimeMillis();
         LinkedHashMap<String, CookieJar.Cookie> merged = new LinkedHashMap<>();
         String h = host.toLowerCase();

         while (h != null && !h.isEmpty()) {
            Map<String, CookieJar.Cookie> map = this.byHost.get(h);
            if (map != null) {
               for (CookieJar.Cookie c : map.values()) {
                  if (!c.isExpired(now)) {
                     merged.putIfAbsent(c.name, c);
                  }
               }
            }

            int dot = h.indexOf(46);
            if (dot < 0 || dot == h.length() - 1) {
               break;
            }

            h = h.substring(dot + 1);
         }

         if (merged.isEmpty()) {
            return null;
         } else {
            StringBuilder sb = new StringBuilder();

            for (CookieJar.Cookie cx : merged.values()) {
               if (sb.length() > 0) {
                  sb.append("; ");
               }

               sb.append(cx.name).append("=").append(cx.value);
            }

            return sb.length() == 0 ? null : sb.toString();
         }
      }
   }

   public synchronized List<CookieJar.Cookie> getAll() {
      List<CookieJar.Cookie> out = new ArrayList<>();
      long now = System.currentTimeMillis();

      for (Map<String, CookieJar.Cookie> m : this.byHost.values()) {
         for (CookieJar.Cookie c : m.values()) {
            if (!c.isExpired(now)) {
               out.add(c);
            }
         }
      }

      return out;
   }

   public synchronized void remove(String host, String name) {
      if (host != null && name != null) {
         Map<String, CookieJar.Cookie> m = this.byHost.get(host.toLowerCase());
         if (m != null) {
            m.remove(name);
            this.fireChanged();
         }
      }
   }

   public synchronized void addOrUpdate(CookieJar.Cookie c) {
      if (c != null && c.domain != null && c.name != null) {
         this.byHost.computeIfAbsent(c.domain.toLowerCase(), k -> new LinkedHashMap<>()).put(c.name, c);
         this.fireChanged();
      }
   }

   public synchronized void clear() {
      this.byHost.clear();
      this.fireChanged();
   }

   public void addChangeListener(Runnable r) {
      this.listeners.add(r);
   }

   private void fireChanged() {
      for (Runnable r : this.listeners) {
         try {
            r.run();
         } catch (Exception var4) {
         }
      }
   }

   private static CookieJar.Cookie parseSetCookie(String host, String header) {
      String[] parts = header.split(";");
      if (parts.length == 0) {
         return null;
      } else {
         String nameValue = parts[0].trim();
         int eq = nameValue.indexOf(61);
         if (eq <= 0) {
            return null;
         } else {
            CookieJar.Cookie c = new CookieJar.Cookie();
            c.name = nameValue.substring(0, eq).trim();
            c.value = nameValue.substring(eq + 1).trim();
            c.domain = host;

            for (int i = 1; i < parts.length; i++) {
               String attr = parts[i].trim();
               String key = attr;
               String val = "";
               int e = attr.indexOf(61);
               if (e > 0) {
                  key = attr.substring(0, e).trim();
                  val = attr.substring(e + 1).trim();
               }

               if (key.equalsIgnoreCase("Path")) {
                  c.path = val.isEmpty() ? "/" : val;
               } else if (key.equalsIgnoreCase("Domain") && !val.isEmpty()) {
                  c.domain = val.toLowerCase().replaceFirst("^\\.", "");
               } else if (key.equalsIgnoreCase("Max-Age")) {
                  try {
                     c.expiresMs = System.currentTimeMillis() + Long.parseLong(val) * 1000L;
                  } catch (Exception var13) {
                  }
               } else if (key.equalsIgnoreCase("Expires") && !val.isEmpty()) {
                  try {
                     SimpleDateFormat fmt = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
                     c.expiresMs = fmt.parse(val).getTime();
                  } catch (Exception var12) {
                  }
               }
            }

            return c;
         }
      }
   }

   public static class Cookie {
      public String name;
      public String value;
      public String domain;
      public String path = "/";
      public long expiresMs = 0L;

      public boolean isExpired(long now) {
         return this.expiresMs > 0L && now > this.expiresMs;
      }
   }
}
