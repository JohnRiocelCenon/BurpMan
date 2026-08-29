package burp.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.Dialog.ModalityType;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.plaf.basic.BasicProgressBarUI;

public class AutoRunProgressDialog extends JDialog {
   private final JProgressBar bar;
   private final JLabel statusLabel;
   private final JButton stopButton;
   private final AtomicBoolean cancelled = new AtomicBoolean(false);
   private Runnable onCancel;

   public void setOnCancel(Runnable r) {
      this.onCancel = r;
   }

   public AutoRunProgressDialog(Window owner, int totalRequests) {
      super(owner, "Analyze Collection", ModalityType.MODELESS);
      this.setDefaultCloseOperation(0);
      JPanel content = new JPanel(new BorderLayout(12, 12));
      content.setBorder(BorderFactory.createEmptyBorder(16, 20, 14, 20));
      this.statusLabel = new JLabel("Preparing 0 / " + totalRequests + " request(s)…");
      this.statusLabel.setFont(this.statusLabel.getFont().deriveFont(0, 13.0F));
      this.bar = new JProgressBar(0, 100);
      this.bar.setStringPainted(true);
      this.bar.setValue(0);
      this.bar.setPreferredSize(new Dimension(420, 22));
      Color green = new Color(40, 160, 70);
      this.bar.setForeground(green);
      this.bar.setUI(new BasicProgressBarUI() {
         @Override
         protected Color getSelectionBackground() {
            return Color.WHITE;
         }

         @Override
         protected Color getSelectionForeground() {
            return Color.WHITE;
         }
      });
      this.bar.setBackground(new Color(230, 230, 230));
      this.stopButton = new JButton("Stop");
      this.stopButton.setForeground(new Color(180, 30, 30));
      this.stopButton.addActionListener(e -> {
         this.cancelled.set(true);
         this.stopButton.setEnabled(false);
         this.statusLabel.setText("Stopping…");
         if (this.onCancel != null) {
            try {
               this.onCancel.run();
            } catch (Exception var3x) {
            }
         }

         this.setVisible(false);
         Timer t = new Timer(200, ev -> this.dispose());
         t.setRepeats(false);
         t.start();
      });
      JPanel btnPanel = new JPanel(new FlowLayout(2, 0, 0));
      btnPanel.add(this.stopButton);
      content.add(this.statusLabel, "North");
      content.add(this.bar, "Center");
      content.add(btnPanel, "South");
      this.setContentPane(content);
      this.pack();
      this.setLocationRelativeTo(owner);
   }

   public boolean isCancelled() {
      return this.cancelled.get();
   }

   public void update(int pct, int currentIdx, int total, String requestName) {
      SwingUtilities.invokeLater(() -> {
         this.bar.setValue(pct);
         String safe = requestName == null ? "" : (requestName.length() > 60 ? requestName.substring(0, 57) + "…" : requestName);
         this.statusLabel.setText(currentIdx + " / " + total + " — " + safe);
      });
   }

   public void finishAndClose() {
      SwingUtilities.invokeLater(() -> {
         this.bar.setValue(100);
         this.statusLabel.setText("Complete");
         Timer t = new Timer(450, e -> this.dispose());
         t.setRepeats(false);
         t.start();
      });
   }
}
