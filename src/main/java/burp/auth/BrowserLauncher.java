package burp.auth;

import java.awt.Desktop;
import java.net.URI;
import java.util.Locale;

final class BrowserLauncher {
   private BrowserLauncher() {
   }

   static void open(String url) throws Exception {
      if (url == null || url.trim().isEmpty()) {
         throw new IllegalArgumentException("Authorization URL is empty.");
      }

      Exception desktopError = null;
      try {
         if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(new URI(url));
            return;
         }
      } catch (Exception ex) {
         desktopError = ex;
      }

      String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      try {
         if (os.contains("win")) {
            new ProcessBuilder("cmd", "/c", "start", "", url).start();
            return;
         } else if (os.contains("mac")) {
            new ProcessBuilder("open", url).start();
            return;
         } else {
            new ProcessBuilder("xdg-open", url).start();
            return;
         }
      } catch (Exception ex) {
         if (desktopError != null) {
            throw new IllegalStateException("Failed to open browser: " + desktopError.getMessage() + " / " + ex.getMessage(), ex);
         }
         throw new IllegalStateException("Failed to open browser: " + ex.getMessage(), ex);
      }
   }
}
