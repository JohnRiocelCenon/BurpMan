package burp.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSeparator;

public final class AppToolbar extends JPanel {
   private final JComboBox<String> envCombo;

   public AppToolbar(AppToolbar.Handlers handlers) {
      this.setLayout(new BorderLayout(0, 0));
      this.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(204, 204, 204)));
      JPanel left = new JPanel(new FlowLayout(0, 4, 4));
      JLabel brand = new JLabel(" BurpMan ");
      brand.setFont(brand.getFont().deriveFont(1, 14.0F));
      brand.setForeground(new Color(255, 111, 0));
      left.add(brand);
      left.add(separator());
      left.add(toolbarButton("+ New", "New blank request (Ctrl+T)", e -> handlers.onNewRequest()));
      left.add(toolbarButton("Import…", "Import a Postman / Bruno collection", e -> handlers.onImportCollection()));
      left.add(toolbarButton("OpenAPI…", "Import an OpenAPI 3 / Swagger 2 JSON spec", e -> handlers.onImportOpenApi()));
      left.add(toolbarButton("\ud83d\udcbe Save…", "Export the loaded collection back to .postman_collection.json (Ctrl+S)", e -> handlers.onSaveCollection()));
      left.add(separator());
      JButton run = toolbarButton("▶ Run Collection", "Run all analyzed requests in sequence", e -> handlers.onRunCollection());
      run.putClientProperty("JButton.buttonType", "default");
      left.add(run);
      left.add(separator());
      left.add(toolbarButton("\ud83c\udf6a Cookies", "Manage captured cookies", e -> handlers.onManageCookies()));
      this.add(left, "West");
      JPanel right = new JPanel(new FlowLayout(2, 6, 4));
      right.add(new JLabel("Env:"));
      this.envCombo = new JComboBox<>();
      this.envCombo.addItem("— No Environment —");
      this.envCombo.setPreferredSize(new Dimension(200, 28));
      this.envCombo.addActionListener(e -> {
         String sel = (String)this.envCombo.getSelectedItem();
         if (sel != null) {
            handlers.onEnvironmentSelected(sel);
         }
      });
      right.add(this.envCombo);
      right.add(separator());
      JLabel online = new JLabel(" ● Online ");
      online.setForeground(new Color(102, 187, 106));
      online.setFont(online.getFont().deriveFont(1, 11.0F));
      right.add(online);
      this.add(right, "East");
   }

   public void setEnvironments(List<String> envs, String selected) {
      this.envCombo.removeAllItems();
      this.envCombo.addItem("— No Environment —");
      if (envs != null) {
         for (String e : envs) {
            this.envCombo.addItem(e);
         }
      }

      if (selected != null) {
         this.envCombo.setSelectedItem(selected);
      }
   }

   private static JButton toolbarButton(String text, String tip, Consumer<ActionEvent> handler) {
      JButton b = new JButton(text);
      b.setToolTipText(tip);
      b.setFocusable(false);
      b.addActionListener(handler::accept);
      return b;
   }

   private static JComponent separator() {
      JSeparator s = new JSeparator(1);
      s.setPreferredSize(new Dimension(1, 24));
      return s;
   }

   public interface Handlers {
      void onNewRequest();

      void onImportCollection();

      void onImportOpenApi();

      void onSaveCollection();

      void onRunCollection();

      void onManageCookies();

      void onEnvironmentSelected(String var1);
   }
}
