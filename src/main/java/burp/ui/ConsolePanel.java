package burp.ui;

import burp.service.ScriptExecutor;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public final class ConsolePanel extends JPanel {
   private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
   private final JTextPane logArea;
   private final JComboBox<ConsolePanel.Level> levelFilter;
   private final JTextField searchField;
   private final AtomicReference<Consumer<String>> chainedSink = new AtomicReference<>();

   public ConsolePanel() {
      this.setLayout(new BorderLayout(0, 4));
      this.setBorder(BorderFactory.createEmptyBorder(4, 6, 6, 6));
      this.logArea = new JTextPane();
      this.logArea.setEditable(false);
      this.logArea.setFont(new Font("Monospaced", 0, 12));
      UndoSupport.install(this.logArea);
      JPanel toolbar = new JPanel(new BorderLayout());
      JPanel left = new JPanel(new FlowLayout(0, 4, 0));
      JLabel hdr = new JLabel("Console");
      hdr.setFont(hdr.getFont().deriveFont(1, 13.0F));
      left.add(hdr);
      this.levelFilter = new JComboBox<>(ConsolePanel.Level.values());
      this.levelFilter.setSelectedItem(ConsolePanel.Level.DEBUG);
      this.levelFilter.setToolTipText("Minimum level to display");
      left.add(new JLabel("Min level:"));
      left.add(this.levelFilter);
      this.searchField = new JTextField(20);
      this.searchField.putClientProperty("JTextField.placeholderText", "Filter…");
      left.add(this.searchField);
      toolbar.add(left, "West");
      JPanel right = new JPanel(new FlowLayout(2, 4, 0));
      JButton clear = new JButton("Clear");
      clear.addActionListener(e -> this.logArea.setText(""));
      right.add(clear);
      JCheckBox autoScroll = new JCheckBox("Auto-scroll", true);
      right.add(autoScroll);
      toolbar.add(right, "East");
      this.add(toolbar, "North");
      JScrollPane scroll = new JScrollPane(this.logArea);
      scroll.setPreferredSize(new Dimension(0, 180));
      this.add(scroll, "Center");
      Consumer<String> existing = ScriptExecutor.UI_LOG;
      if (existing != null) {
         this.chainedSink.set(existing);
      }

      ScriptExecutor.UI_LOG = msg -> {
         try {
            Consumer<String> next = this.chainedSink.get();
            if (next != null) {
               next.accept(msg);
            }
         } catch (Throwable var4x) {
         }

         SwingUtilities.invokeLater(() -> this.append(classify(msg), msg, autoScroll.isSelected()));
      };
   }

   public void append(ConsolePanel.Level level, String msg, boolean autoScroll) {
      ConsolePanel.Level min = (ConsolePanel.Level)this.levelFilter.getSelectedItem();
      if (min == null || level.ordinal() >= min.ordinal()) {
         String filter = this.searchField.getText();
         if (filter == null || filter.isEmpty() || msg.toLowerCase(Locale.ROOT).contains(filter.toLowerCase(Locale.ROOT))) {
            StyledDocument doc = this.logArea.getStyledDocument();

            try {
               SimpleAttributeSet ts = new SimpleAttributeSet();
               StyleConstants.setForeground(ts, new Color(144, 144, 144));
               doc.insertString(doc.getLength(), TS.format(new Date()) + " ", ts);
               SimpleAttributeSet lvl = new SimpleAttributeSet();
               StyleConstants.setForeground(lvl, colorFor(level));
               StyleConstants.setBold(lvl, true);
               doc.insertString(doc.getLength(), String.format("[%-5s] ", level.name()), lvl);
               SimpleAttributeSet body = new SimpleAttributeSet();
               doc.insertString(doc.getLength(), msg + "\n", body);
               if (doc.getLength() > 200000) {
                  doc.remove(0, 50000);
               }

               if (autoScroll) {
                  this.logArea.setCaretPosition(doc.getLength());
               }
            } catch (BadLocationException var10) {
            }
         }
      }
   }

   private static ConsolePanel.Level classify(String msg) {
      if (msg == null) {
         return ConsolePanel.Level.INFO;
      } else {
         String low = msg.toLowerCase(Locale.ROOT);
         if (low.startsWith("[console.error]") || low.contains("✗") || low.contains("error")) {
            return ConsolePanel.Level.ERROR;
         } else if (low.startsWith("[console.warn]") || low.contains("⚠")) {
            return ConsolePanel.Level.WARN;
         } else {
            return !low.startsWith("[console.debug]") && !low.startsWith("⚙") ? ConsolePanel.Level.INFO : ConsolePanel.Level.DEBUG;
         }
      }
   }

   private static Color colorFor(ConsolePanel.Level level) {
      switch (level) {
         case DEBUG:
            return new Color(128, 128, 128);
         case INFO:
            return new Color(41, 182, 246);
         case WARN:
            return new Color(255, 167, 38);
         case ERROR:
            return new Color(239, 83, 80);
         default:
            return Color.GRAY;
      }
   }

   public static enum Level {
      DEBUG,
      INFO,
      WARN,
      ERROR;
   }
}
