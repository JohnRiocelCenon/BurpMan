package burp.ui;

import burp.auth.AuthManager;
import burp.auth.FolderAuthOverride;
import burp.auth.FolderAuthRegistry;
import burp.auth.JwtEndpointCandidate;
import burp.auth.OAuth2Config;
import burp.auth.OAuth2ConfigDialog;
import burp.models.PostmanCollection;
import burp.parser.VariableResolver;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;

public class FolderAuthEditorPanel extends JPanel {
   private static final String TYPE_INHERIT = "Inherit auth from parent";
   private static final String TYPE_NO_AUTH = "No Auth";
   private static final String TYPE_BEARER = "Bearer Token";
   private static final String TYPE_BASIC = "Basic Auth";
   private static final String TYPE_OAUTH2 = "OAuth 2.0";
   private final JLabel header;
   private final JLabel hintLabel;
   private JPanel detectBanner;
   private JLabel detectBannerLabel;
   private JButton detectUseBtn;
   private final JComboBox<String> typeCombo;
   private final JTextField bearerField;
   private final JTextField basicUserField;
   private final JPasswordField basicPassField;
   private final JPanel detailsPanel;
   private JTextArea oauth2Summary;
   private JButton oauth2EditBtn;
   private JButton oauth2GetTokenBtn;
   private OAuth2Config currentOAuth2Config;
   private final CardLayout cards;
   private final FolderAuthRegistry registry;
   private final AuthManager authManager;
   private final burp.PostmanImporter importer;
   private JTable jwtTable;
   private DefaultTableModel jwtTableModel;
   private JButton fetchTokenBtn;
   private JLabel jwtNoneLabel;
   private List<JwtEndpointCandidate> folderCandidates = new ArrayList<>();
   private List<JwtEndpointCandidate> allCandidates;
   private String currentPath = "";
   private boolean isCollection = false;
   private boolean suppressEvents = false;

   public FolderAuthEditorPanel(FolderAuthRegistry registry, AuthManager authManager) {
      this(registry, authManager, null);
   }

   public FolderAuthEditorPanel(FolderAuthRegistry registry, AuthManager authManager, burp.PostmanImporter importer) {
      this.registry = registry;
      this.authManager = authManager;
      this.importer = importer;
      this.setLayout(new BorderLayout(8, 8));
      this.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
      this.header = new JLabel("Folder");
      this.header.setFont(this.header.getFont().deriveFont(1, this.header.getFont().getSize2D() + 2.0F));
      this.hintLabel = new JLabel("This authorization method will be used for every request in this folder. You can override it per request.");
      this.hintLabel.setForeground(Color.GRAY);
      JPanel top = new JPanel();
      top.setLayout(new BoxLayout(top, 1));
      this.header.setAlignmentX(0.0F);
      this.hintLabel.setAlignmentX(0.0F);
      top.add(this.header);
      top.add(Box.createVerticalStrut(4));
      top.add(this.hintLabel);
      top.add(Box.createVerticalStrut(10));
      JPanel typeRow = new JPanel(new FlowLayout(0, 6, 0));
      typeRow.add(new JLabel("Auth Type:"));
      this.typeCombo = new JComboBox<>(new String[]{"Inherit auth from parent", "No Auth", "Bearer Token", "Basic Auth", "OAuth 2.0"});
      this.typeCombo.setPreferredSize(new Dimension(220, 26));
      typeRow.add(this.typeCombo);
      typeRow.setAlignmentX(0.0F);
      top.add(typeRow);
      this.detectBanner = new JPanel(new BorderLayout(8, 0));
      this.detectBanner
         .setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(14723072), 1), BorderFactory.createEmptyBorder(6, 8, 6, 8)));
      this.detectBanner.setBackground(new Color(16775393));
      this.detectBanner.setOpaque(true);
      this.detectBanner.setAlignmentX(0.0F);
      this.detectBanner.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
      this.detectBannerLabel = new JLabel(" ");
      this.detectBannerLabel.setForeground(new Color(6046720));
      this.detectUseBtn = new JButton("Use & Fetch Token");
      this.detectUseBtn.setToolTipText("Switch this folder's auth to Bearer and fetch from the detected endpoint");
      this.detectUseBtn.addActionListener(e -> {
         this.typeCombo.setSelectedItem("Bearer Token");
         if (this.jwtTableModel != null && this.jwtTableModel.getRowCount() > 0) {
            this.jwtTableModel.setValueAt(Boolean.TRUE, 0, 0);
         }

         this.doFetchToken();
      });
      this.detectBanner.add(this.detectBannerLabel, "Center");
      this.detectBanner.add(this.detectUseBtn, "East");
      this.detectBanner.setVisible(false);
      top.add(Box.createVerticalStrut(6));
      top.add(this.detectBanner);
      this.add(top, "North");
      this.cards = new CardLayout();
      this.detailsPanel = new JPanel(this.cards);
      JPanel inheritCard = new JPanel(new BorderLayout());
      JLabel inheritMsg = new JLabel("Inherits auth from the parent collection/folder.");
      inheritMsg.setForeground(Color.GRAY);
      inheritCard.add(inheritMsg, "North");
      this.detailsPanel.add(inheritCard, "Inherit auth from parent");
      JPanel noAuthCard = new JPanel(new BorderLayout());
      JLabel noAuthMsg = new JLabel("Requests in this folder will not use any authorization.");
      noAuthMsg.setForeground(Color.GRAY);
      noAuthCard.add(noAuthMsg, "North");
      this.detailsPanel.add(noAuthCard, "No Auth");
      this.bearerField = new JTextField(20);
      this.bearerField.setMinimumSize(new Dimension(80, this.bearerField.getPreferredSize().height));
      JPanel bearerCard = new JPanel(new BorderLayout(0, 8));
      JPanel bearerTop = new JPanel();
      bearerTop.setLayout(new BoxLayout(bearerTop, 1));
      JPanel bearerRow = new JPanel(new FlowLayout(0, 6, 0));
      bearerRow.add(new JLabel("Token:"));
      bearerRow.setAlignmentX(0.0F);
      JPanel bearerFieldRow = new JPanel(new BorderLayout());
      bearerFieldRow.add(this.bearerField, "Center");
      bearerFieldRow.setAlignmentX(0.0F);
      bearerTop.add(bearerRow);
      bearerTop.add(Box.createVerticalStrut(4));
      bearerTop.add(bearerFieldRow);
      JPanel bearerCenter = new JPanel(new BorderLayout(0, 4));
      JLabel candidatesHeader = new JLabel("Possible token source:");
      bearerCenter.add(candidatesHeader, "North");
      this.jwtTableModel = new DefaultTableModel(new Object[]{"Use", "Endpoint", "Method", "Confidence"}, 0) {
         @Override
         public Class<?> getColumnClass(int c) {
            return c == 0 ? Boolean.class : String.class;
         }

         @Override
         public boolean isCellEditable(int r, int c) {
            return c == 0;
         }
      };
      this.jwtTable = new JTable(this.jwtTableModel);
      this.jwtTable.setRowHeight(22);
      this.jwtTable.getColumnModel().getColumn(0).setMaxWidth(45);
      this.jwtTable.getColumnModel().getColumn(2).setMaxWidth(70);
      this.jwtTable.getColumnModel().getColumn(3).setMaxWidth(90);
      this.jwtTableModel.addTableModelListener(ev -> {
         if (ev.getColumn() == 0) {
            int row = ev.getFirstRow();
            Object v = this.jwtTableModel.getValueAt(row, 0);
            if (Boolean.TRUE.equals(v)) {
               for (int i = 0; i < this.jwtTableModel.getRowCount(); i++) {
                  if (i != row) {
                     this.jwtTableModel.setValueAt(Boolean.FALSE, i, 0);
                  }
               }

               if (row < this.folderCandidates.size() && authManager != null) {
                  authManager.setTokenSourceRequest(this.folderCandidates.get(row).request);
               }
            } else if (authManager != null) {
               authManager.setTokenSourceRequest(null);
            }
         }
      });
      JScrollPane tableScroll = new JScrollPane(this.jwtTable);
      this.jwtNoneLabel = new JLabel("(none detected)");
      this.jwtNoneLabel.setForeground(Color.GRAY);
      JPanel tableAndNone = new JPanel(new BorderLayout());
      tableAndNone.add(tableScroll, "Center");
      tableAndNone.add(this.jwtNoneLabel, "South");
      bearerCenter.add(tableAndNone, "Center");
      this.fetchTokenBtn = new JButton("Fetch Token");
      this.fetchTokenBtn.setToolTipText("Send the checked endpoint and put the returned token into the field above");
      this.fetchTokenBtn.addActionListener(e -> this.doFetchToken());
      JCheckBox autoRefresh = new JCheckBox("Auto-refresh when expired");
      autoRefresh.setToolTipText(
         "Before sending any request that uses this Bearer token, decode the JWT exp claim. If expired (or within ~30s), auto-fetch a fresh one from the checked endpoint above."
      );
      if (authManager != null) {
         autoRefresh.setSelected(authManager.isAutoRefreshEnabled());
         autoRefresh.addActionListener(e -> authManager.setAutoRefreshEnabled(autoRefresh.isSelected()));
      }

      JPanel fetchRow = new JPanel(new FlowLayout(0, 6, 0));
      fetchRow.add(this.fetchTokenBtn);
      fetchRow.add(autoRefresh);
      bearerCard.add(bearerTop, "North");
      bearerCard.add(bearerCenter, "Center");
      bearerCard.add(fetchRow, "South");
      this.detailsPanel.add(bearerCard, "Bearer Token");
      this.basicUserField = new JTextField();
      this.basicPassField = new JPasswordField();
      JPanel basicCard = new JPanel(new GridBagLayout());
      GridBagConstraints gbc = new GridBagConstraints();
      gbc.insets = new Insets(4, 4, 4, 4);
      gbc.anchor = 17;
      gbc.fill = 2;
      gbc.gridx = 0;
      gbc.gridy = 0;
      basicCard.add(new JLabel("Username:"), gbc);
      gbc.gridx = 1;
      gbc.weightx = 1.0;
      basicCard.add(this.basicUserField, gbc);
      gbc.gridx = 0;
      gbc.gridy = 1;
      gbc.weightx = 0.0;
      basicCard.add(new JLabel("Password:"), gbc);
      gbc.gridx = 1;
      gbc.weightx = 1.0;
      basicCard.add(this.basicPassField, gbc);
      JPanel basicWrap = new JPanel(new BorderLayout());
      basicWrap.add(basicCard, "North");
      this.detailsPanel.add(basicWrap, "Basic Auth");
      JPanel oauth2Card = new JPanel(new BorderLayout(6, 6));
      this.oauth2Summary = new JTextArea();
      this.oauth2Summary.setEditable(false);
      this.oauth2Summary.setLineWrap(true);
      this.oauth2Summary.setWrapStyleWord(true);
      this.oauth2Summary.setFont(new Font("Monospaced", 0, 12));
      this.oauth2Summary.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
      JScrollPane oauth2Scroll = new JScrollPane(this.oauth2Summary);
      oauth2Scroll.setBorder(BorderFactory.createTitledBorder("OAuth 2.0 Config"));
      JPanel oauth2Buttons = new JPanel(new FlowLayout(0, 6, 4));
      this.oauth2EditBtn = new JButton("Edit Config…");
      this.oauth2GetTokenBtn = new JButton("Get New Access Token");
      oauth2Buttons.add(this.oauth2EditBtn);
      oauth2Buttons.add(this.oauth2GetTokenBtn);
      oauth2Card.add(oauth2Scroll, "Center");
      oauth2Card.add(oauth2Buttons, "South");
      this.detailsPanel.add(oauth2Card, "OAuth 2.0");
      this.oauth2EditBtn.addActionListener(e -> this.openOAuth2Dialog(false));
      this.oauth2GetTokenBtn.addActionListener(e -> this.openOAuth2Dialog(true));
      this.add(this.detailsPanel, "Center");
      this.typeCombo.addActionListener(e -> {
         Object sel = this.typeCombo.getSelectedItem();
         if (sel != null) {
            this.cards.show(this.detailsPanel, sel.toString());
         }

         if ("OAuth 2.0".equals(sel)) {
            this.refreshOAuth2Summary();
         }

         this.updateDetectBanner();
         if (!this.suppressEvents) {
            this.saveCurrent();
         }
      });
      DocumentListener docL = new DocumentListener() {
         @Override
         public void insertUpdate(DocumentEvent e) {
            if (!FolderAuthEditorPanel.this.suppressEvents) {
               FolderAuthEditorPanel.this.saveCurrent();
            }
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            if (!FolderAuthEditorPanel.this.suppressEvents) {
               FolderAuthEditorPanel.this.saveCurrent();
            }
         }

         @Override
         public void changedUpdate(DocumentEvent e) {
            if (!FolderAuthEditorPanel.this.suppressEvents) {
               FolderAuthEditorPanel.this.saveCurrent();
            }
         }
      };
      this.bearerField.getDocument().addDocumentListener(docL);
      this.basicUserField.getDocument().addDocumentListener(docL);
      this.basicPassField.getDocument().addDocumentListener(docL);
      this.cards.show(this.detailsPanel, "Inherit auth from parent");
   }

   public void setJwtCandidates(List<JwtEndpointCandidate> candidates) {
      this.allCandidates = candidates;
      this.refreshJwtSuggestion();
   }

   public void applyBearerToken(String token) {
      if (token != null) {
         try {
            String current = (String)this.typeCombo.getSelectedItem();
            if ("Bearer Token".equals(current) || "OAuth 2.0".equals(current)) {
               this.suppressEvents = true;

               try {
                  this.bearerField.setText(token);
               } finally {
                  this.suppressEvents = false;
               }

               try {
                  this.saveCurrent();
               } catch (Exception var9) {
               }
            }
         } catch (Exception var11) {
         }

         try {
            this.revalidate();
            this.repaint();
         } catch (Exception var8) {
         }
      }
   }

   private void refreshJwtSuggestion() {
      if (this.jwtTableModel != null) {
         this.folderCandidates.clear();
         this.jwtTableModel.setRowCount(0);
         if (this.allCandidates != null) {
            List<JwtEndpointCandidate> inScope = new ArrayList<>();

            for (JwtEndpointCandidate c : this.allCandidates) {
               if (c.path != null
                  && this.currentPath != null
                  && (this.currentPath.isEmpty() || c.path.equals(this.currentPath) || c.path.startsWith(this.currentPath + "/"))) {
                  inScope.add(c);
               }
            }

            int basePartsLen = this.currentPath.isEmpty() ? 0 : this.currentPath.split("/").length;
            int minDepth = Integer.MAX_VALUE;

            for (JwtEndpointCandidate cx : inScope) {
               int depth = cx.path.isEmpty() ? 0 : cx.path.split("/").length;
               int rel = Math.max(0, depth - basePartsLen);
               if (rel < minDepth) {
                  minDepth = rel;
               }
            }

            Map<String, JwtEndpointCandidate> bestByKey = new LinkedHashMap<>();

            for (JwtEndpointCandidate cxx : inScope) {
               int depth = cxx.path.isEmpty() ? 0 : cxx.path.split("/").length;
               int rel = Math.max(0, depth - basePartsLen);
               if (rel == minDepth) {
                  String key = (cxx.method == null ? "" : cxx.method.toUpperCase()) + " " + cxx.url;
                  JwtEndpointCandidate prev = bestByKey.get(key);
                  if (prev == null || cxx.path.length() < prev.path.length()) {
                     bestByKey.put(key, cxx);
                  }
               }
            }

            for (JwtEndpointCandidate cxxx : bestByKey.values()) {
               this.folderCandidates.add(cxxx);
               this.jwtTableModel.addRow(new Object[]{Boolean.FALSE, cxxx.url, cxxx.method, cxxx.confidence});
            }
         }

         boolean any = !this.folderCandidates.isEmpty();
         if (!any) {
            this.jwtNoneLabel.setText("(none detected)");
            this.jwtNoneLabel.setForeground(Color.GRAY);
            this.jwtNoneLabel.setVisible(true);
         } else {
            int n = this.folderCandidates.size();
            this.jwtNoneLabel
               .setText(
                  n == 1
                     ? "⚠ Tick the row below to use this endpoint, then click Fetch Token."
                     : "⚠ " + n + " candidates found — tick exactly ONE before Fetch Token."
               );
            this.jwtNoneLabel.setForeground(new Color(12082176));
            this.jwtNoneLabel.setVisible(true);
         }

         this.updateDetectBanner();
         this.revalidate();
         this.repaint();
      }
   }

   private void updateDetectBanner() {
      if (this.detectBanner != null) {
         Object sel = this.typeCombo.getSelectedItem();
         boolean inheritOrNone = "Inherit auth from parent".equals(sel) || "No Auth".equals(sel);
         boolean hasCandidate = this.folderCandidates != null && !this.folderCandidates.isEmpty();
         if (inheritOrNone && hasCandidate) {
            JwtEndpointCandidate top = this.folderCandidates.get(0);
            String name = top.url == null ? "" : top.url;
            if (name.length() > 55) {
               name = "..." + name.substring(name.length() - 52);
            }

            this.detectBannerLabel.setText("Auth endpoint detected: " + (top.method == null ? "" : top.method + " ") + name + " — switch to Bearer?");
            this.detectBanner.setVisible(true);
         } else {
            this.detectBanner.setVisible(false);
         }

         this.detectBanner.revalidate();
      }
   }

   private void doFetchToken() {
      if (this.importer == null) {
         JOptionPane.showMessageDialog(this, "Importer not available — use 'Fetch Token' in Auth Manager.", "Unavailable", 2);
      } else {
         JwtEndpointCandidate target = null;
         int checkedCount = 0;

         for (int i = 0; i < this.jwtTableModel.getRowCount(); i++) {
            if (Boolean.TRUE.equals(this.jwtTableModel.getValueAt(i, 0))) {
               checkedCount++;
               if (i < this.folderCandidates.size() && target == null) {
                  target = this.folderCandidates.get(i);
               }
            }
         }

         if (target == null) {
            JOptionPane.showMessageDialog(this, "Tick exactly one candidate row in the table first.", "No Selection", 2);
         } else if (checkedCount > 1) {
            JOptionPane.showMessageDialog(
               this,
               checkedCount + " rows are ticked. Please tick exactly ONE endpoint so the right token is fetched for this folder.",
               "Multiple Selections",
               2
            );
         } else {
            this.fetchTokenBtn.setEnabled(false);
            this.fetchTokenBtn.setText("Fetching...");
            this.importer.autoFetchFromJwt(target.request, token -> SwingUtilities.invokeLater(() -> {
               this.fetchTokenBtn.setEnabled(true);
               this.fetchTokenBtn.setText("Fetch Token");
               if (token != null && !token.isEmpty()) {
                  this.bearerField.setText(token);
                  this.saveCurrent();
                  ToastManager.show(this, "Token fetched and applied", ToastManager.Level.SUCCESS);
               } else {
                  ToastManager.show(this, "Fetch completed but no token extracted", ToastManager.Level.WARNING);
               }
            }));
         }
      }
   }

   public void reset() {
      this.suppressEvents = true;

      try {
         this.currentPath = "";
         this.isCollection = false;
         this.header.setText("Folder");
         this.hintLabel.setText("Select a folder or collection in the tree to edit its authorization.");
         this.typeCombo.setSelectedItem("Inherit auth from parent");
         this.bearerField.setText("");
         this.basicUserField.setText("");
         this.basicPassField.setText("");
         this.folderCandidates.clear();
         this.allCandidates = null;
         if (this.jwtTableModel != null) {
            this.jwtTableModel.setRowCount(0);
         }

         if (this.jwtNoneLabel != null) {
            this.jwtNoneLabel.setVisible(true);
         }

         this.cards.show(this.detailsPanel, "Inherit auth from parent");
         if (this.detectBanner != null) {
            this.detectBanner.setVisible(false);
         }
      } finally {
         this.suppressEvents = false;
      }

      this.revalidate();
      this.repaint();
   }

   public void loadFor(String folderPath, String displayName, boolean isCollection) {
      this.suppressEvents = true;

      try {
         this.currentPath = folderPath == null ? "" : folderPath;
         this.isCollection = isCollection;
         this.header.setText((isCollection ? "Collection: " : "Folder: ") + (displayName == null ? "" : displayName));
         this.hintLabel
            .setText(
               "This authorization method will be used for every request in this "
                  + (isCollection ? "collection. " : "folder. ")
                  + "You can override it per request."
            );
         FolderAuthOverride ov = this.registry != null ? this.registry.get(this.currentPath) : null;
         FolderAuthOverride.Type t = ov != null ? ov.type : FolderAuthOverride.Type.INHERIT;
         if (ov == null && this.importer != null) {
            PostmanCollection.Auth original = !isCollection || this.currentPath != null && !this.currentPath.isEmpty()
               ? this.importer.resolveFolderAuthObjectExact(this.currentPath)
               : this.importer.getCollectionRootAuth();
            if (original != null && original.type != null) {
               String origType = original.type.toLowerCase(Locale.ROOT);
               switch (origType.hashCode()) {
                  case -1393032351:
                     if (origType.equals("bearer")) {
                        t = FolderAuthOverride.Type.BEARER;
                     }
                     break;
                  case -1040243991:
                     if (origType.equals("noauth")) {
                        t = FolderAuthOverride.Type.NO_AUTH;
                     }
                     break;
                  case -1023949701:
                     if (origType.equals("oauth2")) {
                        t = FolderAuthOverride.Type.OAUTH2;
                     }
                     break;
                  case 93508654:
                     if (origType.equals("basic")) {
                        t = FolderAuthOverride.Type.BASIC;
                     }
               }
            } else if (isCollection) {
               t = FolderAuthOverride.Type.NO_AUTH;
            }
         }

         switch (t) {
            case NO_AUTH:
               this.typeCombo.setSelectedItem("No Auth");
               break;
            case INHERIT:
            case DIGEST:
            case APIKEY:
            case OAUTH1:
            default:
               this.typeCombo.setSelectedItem("Inherit auth from parent");
               break;
            case BEARER:
               this.typeCombo.setSelectedItem("Bearer Token");
               break;
            case BASIC:
               this.typeCombo.setSelectedItem("Basic Auth");
               break;
            case OAUTH2:
               this.typeCombo.setSelectedItem("OAuth 2.0");
         }

         String preBearer = ov != null && ov.get("token") != null ? ov.get("token") : "";
         String preUser = ov != null && ov.get("username") != null ? ov.get("username") : "";
         String prePass = ov != null && ov.get("password") != null ? ov.get("password") : "";
         if (ov == null && this.importer != null) {
            PostmanCollection.Auth original2 = !isCollection || this.currentPath != null && !this.currentPath.isEmpty()
               ? this.importer.resolveFolderAuthObjectExact(this.currentPath)
               : this.importer.getCollectionRootAuth();
            if (original2 != null && original2.type != null) {
               String ot = original2.type.toLowerCase(Locale.ROOT);
               if ("bearer".equals(ot)) {
                  String tok = extractAuthAttr(original2, "bearer", "token");
                  if (tok != null) {
                     preBearer = tok;
                  }
               } else if ("basic".equals(ot)) {
                  String u = extractAuthAttr(original2, "basic", "username");
                  String p = extractAuthAttr(original2, "basic", "password");
                  if (u != null) {
                     preUser = u;
                  }

                  if (p != null) {
                     prePass = p;
                  }
               }
            }
         }

         this.bearerField.setText(preBearer);
         this.basicUserField.setText(preUser);
         this.basicPassField.setText(prePass);
         if (t == FolderAuthOverride.Type.OAUTH2) {
            this.refreshOAuth2Summary();
         }

         this.cards.show(this.detailsPanel, String.valueOf(this.typeCombo.getSelectedItem()));
         this.refreshJwtSuggestion();
      } finally {
         this.suppressEvents = false;
      }
   }

   private void refreshOAuth2Summary() {
      this.currentOAuth2Config = null;
      if (this.importer == null) {
         this.oauth2Summary.setText("OAuth2 details unavailable.");
      } else {
         this.currentOAuth2Config = this.importer.findOAuth2ConfigForPath(this.currentPath);
         if (this.currentOAuth2Config == null) {
            this.oauth2Summary.setText("No OAuth2 config detected yet. Run Analyze first.");
         } else {
            VariableResolver resolver = this.importer.getVariableResolver();
            Function<String, String> r = s -> {
               if (s == null) {
                  return "";
               } else {
                  try {
                     return resolver.resolve(s);
                  } catch (Exception var3x) {
                     return s;
                  }
               }
            };
            StringBuilder sb = new StringBuilder();
            sb.append("Token Name:        ").append(safe(this.currentOAuth2Config.name)).append("\n");
            sb.append("Grant Type:        ").append(safe(this.currentOAuth2Config.grantType)).append("\n");
            sb.append("Access Token URL:  ").append(r.apply(this.currentOAuth2Config.accessTokenUrl)).append("\n");
            sb.append("Auth URL:          ").append(r.apply(this.currentOAuth2Config.authUrl)).append("\n");
            sb.append("Client ID:         ").append(r.apply(this.currentOAuth2Config.clientId)).append("\n");
            sb.append("Client Secret:     ").append(mask(r.apply(this.currentOAuth2Config.clientSecret))).append("\n");
            sb.append("Scope:             ").append(r.apply(this.currentOAuth2Config.scope)).append("\n");
            sb.append("Client Auth:       ").append(safe(this.currentOAuth2Config.clientAuthenticationMethod)).append("\n");
            this.oauth2Summary.setText(sb.toString());
            this.oauth2Summary.setCaretPosition(0);
         }
      }
   }

   private static String safe(String s) {
      return s == null ? "" : s;
   }

   private static String extractAuthAttr(PostmanCollection.Auth a, String typeBlock, String key) {
      if (a == null) {
         return null;
      } else {
         Object block = null;
         if ("bearer".equals(typeBlock)) {
            block = a.bearer;
         } else if ("basic".equals(typeBlock)) {
            block = a.basic;
         } else if ("apikey".equals(typeBlock)) {
            block = a.apikey;
         } else if ("oauth2".equals(typeBlock)) {
            block = a.oauth2;
         }

         if (block == null) {
            return null;
         } else {
            try {
               if (block instanceof List) {
                  for (Object o : (List)block) {
                     if (o instanceof Map) {
                        Map<?, ?> m = (Map<?, ?>)o;
                        if (key.equalsIgnoreCase(String.valueOf(m.get("key")))) {
                           Object v = m.get("value");
                           return v == null ? null : String.valueOf(v);
                        }
                     } else if (o instanceof PostmanCollection.AuthAttribute) {
                        PostmanCollection.AuthAttribute aa = (PostmanCollection.AuthAttribute)o;
                        if (key.equalsIgnoreCase(aa.key)) {
                           return aa.value;
                        }
                     }
                  }
               } else if (block instanceof Map) {
                  Object v = ((Map)block).get(key);
                  return v == null ? null : String.valueOf(v);
               }
            } catch (Exception var8) {
            }

            return null;
         }
      }
   }

   private static String mask(String s) {
      if (s != null && !s.isEmpty()) {
         return s.length() <= 6 ? "******" : s.substring(0, 3) + "***" + s.substring(s.length() - 2);
      } else {
         return "";
      }
   }

   private void openOAuth2Dialog(boolean autoFetch) {
      if (this.importer != null) {
         if (this.currentOAuth2Config == null) {
            this.refreshOAuth2Summary();
         }

         if (this.currentOAuth2Config == null) {
            OAuth2Config created = new OAuth2Config();
            String path = this.currentPath == null ? "" : this.currentPath.trim();
            created.path = path.isEmpty() ? "Collection" : path;
            created.name = (this.isCollection ? "Collection OAuth2" : "Folder OAuth2") + " - " + created.path;
            created.grantType = "client_credentials";
            created.clientAuthenticationMethod = "header";
            created.rawAttributes = new LinkedHashMap<>();

            List<OAuth2Config> cfgs = this.authManager == null ? new ArrayList<>() : this.authManager.getOAuth2Configs();
            cfgs.add(created);
            if (this.authManager != null) {
               this.authManager.setOAuth2Configs(cfgs);
               this.authManager.setPreferredOAuth2Config(created);
            }
            this.currentOAuth2Config = created;
            this.refreshOAuth2Summary();
         }

         if (this.currentOAuth2Config != null) {
            Window owner = SwingUtilities.getWindowAncestor(this);
            OAuth2ConfigDialog dlg = new OAuth2ConfigDialog(owner, this.currentOAuth2Config, this.importer, this.authManager, this.importer.getApi());
            dlg.setVisible(true);
            this.refreshOAuth2Summary();
         }
      }
   }

   private void saveCurrent() {
      if (this.registry != null && this.currentPath != null) {
         Object sel = this.typeCombo.getSelectedItem();
         String s = sel == null ? "Inherit auth from parent" : sel.toString();
         FolderAuthOverride ov = new FolderAuthOverride();
         if ("No Auth".equals(s)) {
            ov.type = FolderAuthOverride.Type.NO_AUTH;
         } else if ("Bearer Token".equals(s)) {
            ov.type = FolderAuthOverride.Type.BEARER;
            ov.put("token", this.bearerField.getText());
         } else if ("Basic Auth".equals(s)) {
            ov.type = FolderAuthOverride.Type.BASIC;
            ov.put("username", this.basicUserField.getText());
            ov.put("password", new String(this.basicPassField.getPassword()));
         } else if ("OAuth 2.0".equals(s)) {
            ov.type = FolderAuthOverride.Type.OAUTH2;
         } else {
            ov.type = FolderAuthOverride.Type.INHERIT;
         }

         this.registry.set(this.currentPath, ov);
      }
   }
}
