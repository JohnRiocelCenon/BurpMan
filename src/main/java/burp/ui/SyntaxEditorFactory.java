package burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.lang.reflect.Method;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.text.JTextComponent;

public final class SyntaxEditorFactory {
   private static volatile Boolean availableCache = null;

   public static boolean isAvailable() {
      Boolean c = availableCache;
      if (c != null) {
         return c;
      } else {
         try {
            Class.forName("org.fife.ui.rsyntaxtextarea.RSyntaxTextArea");
            availableCache = Boolean.TRUE;
         } catch (Throwable var2) {
            availableCache = Boolean.FALSE;
         }

         return availableCache;
      }
   }

   private SyntaxEditorFactory() {
   }

   public static JTextComponent create(String mode) {
      if (!isAvailable()) {
         JTextArea fallback = new JTextArea();
         fallback.setFont(new Font("Monospaced", 0, 12));
         fallback.setTabSize(2);
         return fallback;
      } else {
         try {
            Class<?> rstaCls = Class.forName("org.fife.ui.rsyntaxtextarea.RSyntaxTextArea");
            JTextComponent rsta = (JTextComponent)rstaCls.getDeclaredConstructor().newInstance();
            applyMode(rsta, mode);
            Method setCodeFoldingEnabled = rstaCls.getMethod("setCodeFoldingEnabled", boolean.class);
            setCodeFoldingEnabled.invoke(rsta, true);
            Method setAntiAliasingEnabled = rstaCls.getMethod("setAntiAliasingEnabled", boolean.class);
            setAntiAliasingEnabled.invoke(rsta, true);
            Method setTabSize = rstaCls.getMethod("setTabSize", int.class);
            setTabSize.invoke(rsta, 2);
            Method setMarkOccurrences = rstaCls.getMethod("setMarkOccurrences", boolean.class);
            setMarkOccurrences.invoke(rsta, true);
            return rsta;
         } catch (Throwable var7) {
            JTextArea fallback = new JTextArea();
            fallback.setFont(new Font("Monospaced", 0, 12));
            fallback.setTabSize(2);
            return fallback;
         }
      }
   }

   public static void applyMode(JTextComponent component, String mode) {
      if (component != null) {
         try {
            Class<?> rstaCls = Class.forName("org.fife.ui.rsyntaxtextarea.RSyntaxTextArea");
            if (!rstaCls.isInstance(component)) {
               return;
            }

            String style = mapMode(mode);
            Method setSyntax = rstaCls.getMethod("setSyntaxEditingStyle", String.class);
            setSyntax.invoke(component, style);
         } catch (Throwable var5) {
         }
      }
   }

   public static JScrollPane wrap(JTextComponent component) {
      if (component == null) {
         return null;
      } else {
         if (isAvailable()) {
            try {
               Class<?> rstaCls = Class.forName("org.fife.ui.rsyntaxtextarea.RSyntaxTextArea");
               if (rstaCls.isInstance(component)) {
                  Class<?> rtspCls = Class.forName("org.fife.ui.rtextarea.RTextScrollPane");
                  return (JScrollPane)rtspCls.getDeclaredConstructor(Component.class).newInstance(component);
               }
            } catch (Throwable var3) {
            }
         }

         return new JScrollPane(component);
      }
   }

   private static String mapMode(String mode) {
      if (mode == null) {
         return "text/plain";
      } else {
         String var1;
         switch ((var1 = mode.toLowerCase()).hashCode()) {
            case 3401:
               if (var1.equals("js")) {
                  return "text/javascript";
               }
               break;
            case 98819:
               if (var1.equals("css")) {
                  return "text/css";
               }
               break;
            case 114126:
               if (var1.equals("sql")) {
                  return "text/sql";
               }
               break;
            case 118807:
               if (var1.equals("xml")) {
                  return "text/xml";
               }
               break;
            case 119768:
               if (var1.equals("yml")) {
                  return "text/yaml";
               }
               break;
            case 3213227:
               if (var1.equals("html")) {
                  return "text/html";
               }
               break;
            case 3271912:
               if (var1.equals("json")) {
                  return "text/json";
               }
               break;
            case 3701415:
               if (var1.equals("yaml")) {
                  return "text/yaml";
               }
               break;
            case 188995949:
               if (var1.equals("javascript")) {
                  return "text/javascript";
               }
         }

         return "text/plain";
      }
   }
}
