package burp.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;

public final class UITheme {
   public static final Color ACCENT = new Color(255, 108, 55);
   public static final Color PRIMARY = new Color(50, 126, 255);
   public static final Color SUCCESS = new Color(46, 204, 113);
   public static final Color SUCCESS_HV = new Color(39, 174, 96);
   public static final Color DANGER = new Color(217, 83, 79);
   public static final Color WARNING = new Color(241, 196, 15);
   public static final Color WHITE = Color.WHITE;

   private UITheme() {
   }

   public static boolean isDark() {
      Color bg = UIManager.getColor("Panel.background");
      if (bg == null) {
         return false;
      } else {
         int l = (bg.getRed() * 299 + bg.getGreen() * 587 + bg.getBlue() * 114) / 1000;
         return l < 128;
      }
   }

   public static Color surface() {
      return isDark() ? new Color(30, 30, 30) : new Color(250, 250, 250);
   }

   public static Color surfaceAlt() {
      return isDark() ? new Color(45, 45, 45) : new Color(240, 240, 240);
   }

   public static Color border() {
      return isDark() ? new Color(85, 85, 85) : new Color(221, 221, 221);
   }

   public static Color subtleText() {
      return isDark() ? new Color(204, 204, 204) : new Color(85, 85, 85);
   }

   public static Color foreground() {
      Color c = UIManager.getColor("Label.foreground");
      return c != null ? c : (isDark() ? new Color(232, 232, 232) : new Color(32, 32, 32));
   }

   public static Color ghostBg() {
      return isDark() ? new Color(60, 63, 65) : new Color(240, 240, 240);
   }

   public static Color ghostHover() {
      return isDark() ? new Color(78, 82, 85) : new Color(224, 224, 224);
   }

   public static Font baseFont() {
      Font f = UIManager.getFont("Label.font");
      return f != null ? f : new Font("SansSerif", 0, 12);
   }

   public static Font boldFont(float size) {
      return baseFont().deriveFont(1, size);
   }

   public static Font monoFont() {
      return new Font("Monospaced", 0, 12);
   }

   public static Border padded(int top, int left, int bottom, int right) {
      return new EmptyBorder(top, left, bottom, right);
   }

   public static Border card() {
      return new CompoundBorder(BorderFactory.createLineBorder(border(), 1, true), new EmptyBorder(8, 10, 8, 10));
   }

   public static Border titled(String title) {
      return BorderFactory.createTitledBorder(BorderFactory.createLineBorder(border(), 1, true), title, 1, 2, boldFont(12.0F), subtleText());
   }

   public static JButton button(String text, UITheme.BtnStyle style) {
      JButton b = new JButton(text) {
         @Override
         public void setEnabled(boolean enabled) {
            super.setEnabled(enabled);
            Object stored = this.getClientProperty("uiTheme.fg");
            Color base = stored instanceof Color ? (Color)stored : UITheme.foreground();
            this.setForeground(enabled ? base : UITheme.subtleText());
         }
      };
      b.setFocusPainted(false);
      b.setFont(baseFont().deriveFont(1, 12.0F));
      b.setBorder(new EmptyBorder(6, 14, 6, 14));
      b.setContentAreaFilled(true);
      b.putClientProperty("JButton.buttonType", "roundRect");
      apply(b, style);
      return b;
   }

   public static void apply(JButton b, UITheme.BtnStyle style) {
      Color bg;
      Color hover;
      Color fg;
      switch (style) {
         case PRIMARY:
            bg = PRIMARY;
            hover = new Color(31, 102, 224);
            fg = WHITE;
            break;
         case SUCCESS:
            bg = SUCCESS;
            hover = SUCCESS_HV;
            fg = WHITE;
            break;
         case DANGER:
            bg = DANGER;
            hover = new Color(184, 63, 60);
            fg = WHITE;
            break;
         case GHOST:
         default:
            bg = ghostBg();
            hover = ghostHover();
            fg = isDark() ? new Color(236, 236, 236) : new Color(32, 32, 32);
            break;
         case ACCENT:
            bg = ACCENT;
            hover = new Color(227, 87, 40);
            fg = WHITE;
      }

      b.setBackground(bg);
      b.setForeground(fg);
      b.putClientProperty("uiTheme.fg", fg);
      b.setOpaque(true);
      b.setContentAreaFilled(true);
      b.setBorderPainted(false);
      b.putClientProperty("JButton.background", bg);
      b.putClientProperty("JComponent.outline", bg);

      MouseListener[] var10;
      for (MouseListener ml : var10 = b.getMouseListeners()) {
         if (ml instanceof UITheme.HoverListener) {
            b.removeMouseListener(ml);
         }
      }

      b.addMouseListener(new UITheme.HoverListener(b, bg, hover));
   }

   public static JLabel sectionLabel(String text) {
      JLabel l = new JLabel(text);
      l.setFont(boldFont(13.0F));
      l.setForeground(subtleText());
      l.setBorder(new EmptyBorder(4, 2, 6, 2));
      return l;
   }

   public static JComponent hr() {
      JPanel p = new JPanel();
      p.setBackground(border());
      p.setPreferredSize(new Dimension(1, 1));
      p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
      return p;
   }

   public static enum BtnStyle {
      PRIMARY,
      SUCCESS,
      DANGER,
      GHOST,
      ACCENT;
   }

   private static class HoverListener extends MouseAdapter {
      final JButton b;
      final Color base;
      final Color hov;

      HoverListener(JButton b, Color base, Color hov) {
         this.b = b;
         this.base = base;
         this.hov = hov;
      }

      @Override
      public void mouseEntered(MouseEvent e) {
         if (this.b.isEnabled()) {
            this.b.setBackground(this.hov);
         }
      }

      @Override
      public void mouseExited(MouseEvent e) {
         if (this.b.isEnabled()) {
            this.b.setBackground(this.base);
         }
      }
   }
}
