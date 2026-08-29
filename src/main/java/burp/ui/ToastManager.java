package burp.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JWindow;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

public class ToastManager {
   private static final List<JWindow> active = new ArrayList<>();
   private static final int MARGIN = 16;
   private static final int SPACING = 8;
   private static final int DEFAULT_MS = 3000;

   public static void show(Component anchor, String message) {
      show(anchor, message, ToastManager.Level.INFO, 3000);
   }

   public static void show(Component anchor, String message, ToastManager.Level level) {
      show(anchor, message, level, 3000);
   }

   public static void show(Component anchor, String message, ToastManager.Level level, int durationMs) {
      if (message != null && !message.isEmpty()) {
         SwingUtilities.invokeLater(() -> {
            Window owner = anchor != null ? SwingUtilities.getWindowAncestor(anchor) : null;
            final JWindow toast = new JWindow(owner);
            toast.setFocusableWindowState(false);
            toast.setAlwaysOnTop(true);
            JPanel content = new JPanel(new BorderLayout(8, 0));
            content.setBackground(level.bg);
            content.setBorder(BorderFactory.createEmptyBorder(10, 14, 10, 14));
            JLabel label = new JLabel(message);
            label.setForeground(Color.WHITE);
            label.setFont(label.getFont().deriveFont(0, 12.0F));
            content.add(label, "Center");
            toast.setContentPane(content);
            toast.pack();
            Rectangle anchorBounds;
            if (owner != null) {
               anchorBounds = owner.getBounds();
            } else {
               anchorBounds = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDefaultConfiguration().getBounds();
            }

            synchronized (active) {
               int stackOffset = 0;

               for (JWindow w : active) {
                  stackOffset += w.getHeight() + 8;
               }

               int x = anchorBounds.x + anchorBounds.width - toast.getWidth() - 16;
               int y = anchorBounds.y + anchorBounds.height - toast.getHeight() - 16 - stackOffset;
               toast.setLocation(x, y);
               active.add(toast);
            }

            toast.setVisible(true);
            Timer t = new Timer(durationMs, e -> dismiss(toast));
            t.setRepeats(false);
            t.start();
            content.addMouseListener(new MouseAdapter() {
               @Override
               public void mouseClicked(MouseEvent ev) {
                  ToastManager.dismiss(toast);
               }
            });
         });
      }
   }

   private static void dismiss(JWindow w) {
      SwingUtilities.invokeLater(() -> {
         synchronized (active) {
            active.remove(w);
         }

         w.dispose();
      });
   }

   public static enum Level {
      INFO(new Color(60, 90, 140)),
      SUCCESS(new Color(46, 125, 50)),
      WARNING(new Color(204, 134, 0)),
      ERROR(new Color(176, 0, 32));

      final Color bg;

      private Level(Color c) {
         this.bg = c;
      }
   }
}
