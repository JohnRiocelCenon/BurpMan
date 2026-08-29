package burp.ui;

import burp.models.AnalyzedRequest;
import burp.models.RequestHistory;
import burp.service.RequestExecutor;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.border.EmptyBorder;

public final class RequestTabsPanel extends JPanel {
   private final burp.PostmanImporter importer;
   private final JTabbedPane tabs;
   private final ResponsePanel sharedResponsePanel;
   private final Map<String, RequestBuilderPanel> openTabs = new LinkedHashMap<>();
   private int untitledCounter = 0;

   public RequestTabsPanel(burp.PostmanImporter importer, ResponsePanel sharedResponsePanel) {
      this.importer = importer;
      this.sharedResponsePanel = sharedResponsePanel;
      this.setLayout(new BorderLayout());
      this.setBackground(UITheme.surface());
      this.tabs = new JTabbedPane(1, 1);
      this.tabs.putClientProperty("JTabbedPane.tabsPopupPolicy", "asNeeded");
      this.tabs.putClientProperty("JTabbedPane.scrollButtonsPolicy", "asNeededSingle");
      this.tabs.putClientProperty("JTabbedPane.tabType", "card");
      this.tabs.setBorder(BorderFactory.createEmptyBorder());
      this.add(this.tabs, "Center");
      this.addNewTabHandle();
      this.openBlankTab();
   }

   public RequestBuilderPanel openRequest(AnalyzedRequest analyzed) {
      if (analyzed == null) {
         return null;
      } else {
         String key = analyzed.getPath() == null ? analyzed.getName() + "@" + System.identityHashCode(analyzed) : analyzed.getPath();
         RequestBuilderPanel existing = this.openTabs.get(key);
         if (existing != null) {
            int idx = this.tabs.indexOfComponent(existing);
            if (idx >= 0) {
               this.tabs.setSelectedIndex(idx);
               return existing;
            }
         }

         RequestBuilderPanel panel = this.newBuilder();

         try {
            panel.loadRequest(analyzed.getRequest());
            panel.setScripts(analyzed.getPreScript(), analyzed.getPostScript());
         } catch (Throwable var7) {
         }

         String label = analyzed.getName() == null ? "Request" : analyzed.getName();
         String method = analyzed.getRequest() == null ? "GET" : (analyzed.getRequest().method == null ? "GET" : analyzed.getRequest().method);
         this.addRequestTab(key, label, method, panel);
         return panel;
      }
   }

   public void openBlankTab() {
      String key = "untitled-" + UUID.randomUUID();
      RequestBuilderPanel panel = this.newBuilder();
      this.addRequestTab(key, "Untitled " + ++this.untitledCounter, "GET", panel);
   }

   private RequestBuilderPanel newBuilder() {
      RequestHistory tabHistory = new RequestHistory();
      RequestExecutor tabExecutor = new RequestExecutor(this.importer.getApi());
      tabExecutor.setVariableResolver(this.importer.getVariableResolver());
      tabExecutor.setCookieJar(this.importer.getCookieJar());
      tabExecutor.setAuthManager(this.importer.getAuthManager());
      return new RequestBuilderPanel(tabExecutor, tabHistory);
   }

   private void addRequestTab(String key, String label, String method, RequestBuilderPanel panel) {
      this.openTabs.put(key, panel);
      int insertAt = Math.max(0, this.tabs.getTabCount() - 1);
      this.tabs.insertTab(label, null, panel, label, insertAt);
      this.tabs.setTabComponentAt(insertAt, this.buildTabHeader(label, method, panel, key));
      this.tabs.setSelectedIndex(insertAt);
   }

   private void closeTab(String key, RequestBuilderPanel panel) {
      int idx = this.tabs.indexOfComponent(panel);
      if (idx >= 0) {
         this.tabs.remove(idx);
      }

      this.openTabs.remove(key);
      if (this.tabs.getTabCount() == 0 || !"+".equals(this.tabs.getTitleAt(this.tabs.getTabCount() - 1))) {
         this.addNewTabHandle();
      }

      if (this.tabs.getTabCount() == 1) {
         this.openBlankTab();
      }
   }

   private void addNewTabHandle() {
      JPanel placeholder = new JPanel(new BorderLayout());
      placeholder.add(new JLabel("Click + to open a new request", 0), "Center");
      int idx = this.tabs.getTabCount();
      this.tabs.insertTab("+", null, placeholder, "New request", idx);
      JLabel plus = new JLabel(" + ");
      plus.setFont(plus.getFont().deriveFont(1, 14.0F));
      plus.setBorder(new EmptyBorder(2, 8, 2, 8));
      plus.setCursor(Cursor.getPredefinedCursor(12));
      plus.setToolTipText("New blank request (Ctrl+T)");
      plus.addMouseListener(new MouseAdapter() {
         @Override
         public void mouseClicked(MouseEvent e) {
            RequestTabsPanel.this.openBlankTab();
         }
      });
      this.tabs.setTabComponentAt(idx, plus);
   }

   private Component buildTabHeader(String label, String method, final RequestBuilderPanel panel, String key) {
      JPanel header = new JPanel(new FlowLayout(0, 4, 0));
      header.setOpaque(false);
      header.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
      JLabel methodChip = new JLabel(method);
      methodChip.setForeground(methodColor(method));
      methodChip.setFont(methodChip.getFont().deriveFont(1, 10.0F));
      methodChip.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 4));
      JLabel name = new JLabel(label.length() > 28 ? label.substring(0, 26) + "…" : label);
      name.setFont(name.getFont().deriveFont(0, 12.0F));
      name.setToolTipText(label);
      JButton close = new JButton("×");
      close.setMargin(new Insets(0, 4, 0, 4));
      close.setFont(close.getFont().deriveFont(1, 14.0F));
      close.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
      close.setContentAreaFilled(false);
      close.setBorderPainted(false);
      close.setFocusable(false);
      close.setCursor(Cursor.getPredefinedCursor(12));
      close.setToolTipText("Close tab");
      close.addActionListener(e -> this.closeTab(key, panel));
      header.add(methodChip);
      header.add(name);
      header.add(close);
      header.addMouseListener(new MouseAdapter() {
         @Override
         public void mouseClicked(MouseEvent e) {
            int idx = RequestTabsPanel.this.tabs.indexOfComponent(panel);
            if (idx >= 0) {
               RequestTabsPanel.this.tabs.setSelectedIndex(idx);
            }
         }
      });
      return header;
   }

   private static Color methodColor(String method) {
      if (method == null) {
         return new Color(144, 144, 144);
      } else {
         String var1;
         switch ((var1 = method.toUpperCase()).hashCode()) {
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
   }

   public RequestBuilderPanel activeBuilder() {
      Component c = this.tabs.getSelectedComponent();
      return c instanceof RequestBuilderPanel ? (RequestBuilderPanel)c : null;
   }

   public List<RequestBuilderPanel> allBuilders() {
      return new ArrayList<>(this.openTabs.values());
   }

   public void resetTabs() {
      this.openTabs.clear();
      this.tabs.removeAll();
      this.addNewTabHandle();
      this.openBlankTab();
   }

   public JTabbedPane tabs() {
      return this.tabs;
   }
}
