package burp.ui;

import burp.models.AnalyzedRequest;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

public final class OpenRequestTabsStrip extends JPanel {
   private static final int MAX_TABS = 20;
   private final OpenRequestTabsStrip.OnTabSelected listener;
   private final JPanel tabsContainer;
   private final JScrollPane scrollPane;
   private final Map<String, OpenRequestTabsStrip.TabUi> tabs = new LinkedHashMap<>();
   private String activeKey = null;

   public OpenRequestTabsStrip(OpenRequestTabsStrip.OnTabSelected listener) {
      this.listener = listener;
      this.setLayout(new BorderLayout(0, 0));
      this.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(204, 204, 204)));
      this.setBackground(new Color(247, 247, 247));
      this.tabsContainer = new JPanel(new FlowLayout(0, 2, 2));
      this.tabsContainer.setOpaque(false);
      this.scrollPane = new JScrollPane(this.tabsContainer, 21, 30);
      this.scrollPane.setBorder(BorderFactory.createEmptyBorder());
      this.scrollPane.getHorizontalScrollBar().setUnitIncrement(20);
      this.add(this.scrollPane, "Center");
      this.setPreferredSize(new Dimension(0, 30));
      this.setMinimumSize(new Dimension(0, 30));
      this.setVisible(false);
   }

   public void openOrFocus(String key, AnalyzedRequest request) {
      if (key != null && request != null) {
         OpenRequestTabsStrip.TabUi existing = this.tabs.get(key);
         if (existing != null) {
            this.activateByKey(key);
         } else {
            if (this.tabs.size() >= 20) {
               String oldest = this.tabs.keySet().iterator().next();
               this.removeTab(oldest);
            }

            OpenRequestTabsStrip.TabUi tab = new OpenRequestTabsStrip.TabUi(key, request);
            this.tabs.put(key, tab);
            this.tabsContainer.add(tab);
            this.activateByKey(key);
            this.setVisible(true);
            this.revalidate();
            this.repaint();
         }
      }
   }

   public void activateByKey(String key) {
      this.activeKey = key;

      for (Entry<String, OpenRequestTabsStrip.TabUi> e : this.tabs.entrySet()) {
         e.getValue().renderActive(e.getKey().equals(key));
      }

      this.repaint();
   }

   public void renameTab(String key, String newName) {
      OpenRequestTabsStrip.TabUi tab = this.tabs.get(key);
      if (tab != null) {
         tab.renderName(newName);
      }
   }

   public void removeTab(String key) {
      OpenRequestTabsStrip.TabUi tab = this.tabs.remove(key);
      if (tab != null) {
         this.tabsContainer.remove(tab);
         if (this.tabs.isEmpty()) {
            this.setVisible(false);
            this.activeKey = null;
         } else if (key.equals(this.activeKey)) {
            String next = this.tabs.keySet().iterator().next();
            this.activateByKey(next);
            OpenRequestTabsStrip.TabUi nextTab = this.tabs.get(next);
            if (nextTab != null && this.listener != null) {
               this.listener.onTabSelected(nextTab.request);
            }
         }

         this.revalidate();
         this.repaint();
      }
   }

   public void clear() {
      this.tabs.clear();
      this.tabsContainer.removeAll();
      this.activeKey = null;
      this.setVisible(false);
      this.revalidate();
      this.repaint();
   }

   public List<String> openKeys() {
      return new ArrayList<>(this.tabs.keySet());
   }

   private static Color methodColor(String method) {
      String var1;
      switch ((var1 = method == null ? "" : method).hashCode()) {
         case -531492226:
            if (var1.equals("OPTIONS")) {
               return new Color(255, 112, 67);
            }
            break;
         case 70454:
            if (var1.equals("GET")) {
               return new Color(41, 182, 246);
            }
            break;
         case 79599:
            if (var1.equals("PUT")) {
               return new Color(255, 167, 38);
            }
            break;
         case 2213344:
            if (var1.equals("HEAD")) {
               return new Color(171, 71, 188);
            }
            break;
         case 2461856:
            if (var1.equals("POST")) {
               return new Color(102, 187, 106);
            }
            break;
         case 75900968:
            if (var1.equals("PATCH")) {
               return new Color(128, 203, 196);
            }
            break;
         case 2012838315:
            if (var1.equals("DELETE")) {
               return new Color(239, 83, 80);
            }
      }

      return new Color(144, 144, 144);
   }

   public interface OnTabSelected {
      void onTabSelected(AnalyzedRequest var1);
   }

   private final class TabUi extends JPanel {
      final String key;
      final AnalyzedRequest request;
      private final JLabel nameLabel;
      private boolean active;

      TabUi(String key, AnalyzedRequest request) {
         this.key = key;
         this.request = request;
         this.setLayout(new FlowLayout(0, 3, 0));
         this.setOpaque(true);
         this.setCursor(Cursor.getPredefinedCursor(12));
         this.setBorder(
            BorderFactory.createCompoundBorder(
               BorderFactory.createMatteBorder(1, 1, 0, 1, new Color(204, 204, 204)), BorderFactory.createEmptyBorder(2, 8, 2, 4)
            )
         );
         String method = "GET";
         if (request.getRequest() != null && request.getRequest().method != null) {
            method = request.getRequest().method.toUpperCase();
         }

         JLabel methodChip = new JLabel(method);
         methodChip.setForeground(OpenRequestTabsStrip.methodColor(method));
         methodChip.setFont(methodChip.getFont().deriveFont(1, 10.0F));
         this.add(methodChip);
         String name = request.getName() == null ? "Request" : request.getName();
         String display = name.length() > 24 ? name.substring(0, 22) + "…" : name;
         this.nameLabel = new JLabel(display);
         this.nameLabel.setFont(this.nameLabel.getFont().deriveFont(0, 12.0F));
         this.nameLabel.setToolTipText(request.getPath() == null ? name : request.getPath());
         this.add(this.nameLabel);
         final JLabel closeBtn = new JLabel("✕");
         closeBtn.setFont(closeBtn.getFont().deriveFont(0, 11.0F));
         closeBtn.setForeground(new Color(136, 136, 136));
         closeBtn.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
         closeBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
               closeBtn.setForeground(new Color(198, 40, 40));
            }

            @Override
            public void mouseExited(MouseEvent e) {
               closeBtn.setForeground(new Color(136, 136, 136));
            }

            @Override
            public void mouseClicked(MouseEvent e) {
               e.consume();
               OpenRequestTabsStrip.this.removeTab(TabUi.this.key);
            }
         });
         this.add(closeBtn);
         MouseAdapter activate = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
               if (e.getSource() != closeBtn) {
                  OpenRequestTabsStrip.this.activateByKey(TabUi.this.key);
                  if (OpenRequestTabsStrip.this.listener != null) {
                     OpenRequestTabsStrip.this.listener.onTabSelected(TabUi.this.request);
                  }
               }
            }
         };
         this.addMouseListener(activate);
         this.nameLabel.addMouseListener(activate);
         methodChip.addMouseListener(activate);
      }

      void renderActive(boolean a) {
         this.active = a;
         this.setBackground(a ? Color.WHITE : new Color(238, 238, 238));
         this.setBorder(
            BorderFactory.createCompoundBorder(
               BorderFactory.createMatteBorder(a ? 2 : 1, 1, 0, 1, a ? new Color(255, 111, 0) : new Color(204, 204, 204)),
               BorderFactory.createEmptyBorder(a ? 1 : 2, 8, 2, 4)
            )
         );
      }

      void renderName(String name) {
         if (name != null) {
            this.nameLabel.setText(name.length() > 24 ? name.substring(0, 22) + "…" : name);
            this.nameLabel.setToolTipText(name);
         }
      }
   }
}
