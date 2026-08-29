package burp.ui;

import burp.auth.AuthManager;
import burp.models.PostmanCollection;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class AuthorizationPanel extends JPanel {
   public static final String TYPE_INHERIT = "Inherit auth from parent";
   public static final String TYPE_NO_AUTH = "No Auth";
   public static final String TYPE_BEARER = "Bearer Token";
   public static final String TYPE_OAUTH2 = "OAuth 2.0";
   public static final String TYPE_BASIC = "Basic Auth";
   private final JComboBox<String> typeCombo;
   private final JTextField bearerField;
   private final JTextField basicUserField;
   private final JPasswordField basicPassField;
   private final JPanel detailsPanel;
   private final CardLayout details;
   private final JLabel inheritedLabel;
   private AuthManager authManager;
   private Runnable changeListener;
   private boolean suppressEvents = false;
   private PostmanCollection.Auth loadedAuth;
   private boolean authDirty = false;

   public AuthorizationPanel() {
      this.setLayout(new BorderLayout(8, 8));
      this.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
      JPanel top = new JPanel(new FlowLayout(0, 6, 0));
      top.add(new JLabel("Auth Type:"));
      this.typeCombo = new JComboBox<>(new String[]{
         TYPE_INHERIT, TYPE_NO_AUTH, TYPE_BEARER, TYPE_OAUTH2, TYPE_BASIC
      });
      this.typeCombo.setPreferredSize(new Dimension(220, 26));
      top.add(this.typeCombo);
      this.add(top, "North");
      this.details = new CardLayout();
      this.detailsPanel = new JPanel(this.details);
      this.inheritedLabel = new JLabel(
         "The authorization header will be automatically generated when you send the request, based on the parent collection/folder configuration."
      );
      this.inheritedLabel.setForeground(Color.GRAY);
      JPanel inheritCard = new JPanel(new BorderLayout());
      inheritCard.add(this.inheritedLabel, "North");
      this.detailsPanel.add(inheritCard, "Inherit auth from parent");
      JPanel noAuthCard = new JPanel(new BorderLayout());
      JLabel noAuthLabel = new JLabel("This request does not use any authorization.");
      noAuthLabel.setForeground(Color.GRAY);
      noAuthCard.add(noAuthLabel, "North");
      this.detailsPanel.add(noAuthCard, "No Auth");
      this.bearerField = new JTextField(20);
      this.bearerField.setMinimumSize(new Dimension(80, this.bearerField.getPreferredSize().height));
      JPanel bearerCard = new JPanel(new BorderLayout(6, 6));
      JPanel bLabelRow = new JPanel(new FlowLayout(0, 6, 0));
      bLabelRow.add(new JLabel("Token:"));
      bearerCard.add(bLabelRow, "North");
      bearerCard.add(this.bearerField, "Center");
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
      gbc.weightx = 0.0;
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
      this.add(this.detailsPanel, "Center");
      this.typeCombo.addActionListener(e -> {
         if (this.suppressEvents) {
            Object sel = this.typeCombo.getSelectedItem();
            if (sel != null) {
               this.details.show(this.detailsPanel, this.toDetailsCard(sel.toString()));
            }
         } else {
            Object sel = this.typeCombo.getSelectedItem();
            if (sel != null) {
               this.details.show(this.detailsPanel, this.toDetailsCard(sel.toString()));
            }

            this.fireChanged();
         }
      });
      DocumentListener docL = new DocumentListener() {
         @Override
         public void insertUpdate(DocumentEvent e) {
            AuthorizationPanel.this.fireChanged();
         }

         @Override
         public void removeUpdate(DocumentEvent e) {
            AuthorizationPanel.this.fireChanged();
         }

         @Override
         public void changedUpdate(DocumentEvent e) {
            AuthorizationPanel.this.fireChanged();
         }
      };
      this.bearerField.getDocument().addDocumentListener(docL);
      this.basicUserField.getDocument().addDocumentListener(docL);
      this.basicPassField.getDocument().addDocumentListener(docL);
      this.details.show(this.detailsPanel, "Inherit auth from parent");
   }

   public void setInheritedDescription(String description) {
      if (description != null && !description.isEmpty()) {
         this.inheritedLabel.setText("Inherited: " + description);
      } else {
         this.inheritedLabel
            .setText("The authorization header will be automatically generated when you send the request, based on the parent collection/folder configuration.");
      }
   }

   public void setAuth(PostmanCollection.Auth auth) {
      this.loadedAuth = auth;
      this.authDirty = false;
      this.suppressEvents = true;

      try {
         this.bearerField.setText("");
         this.basicUserField.setText("");
         this.basicPassField.setText("");
         if (auth != null && auth.type != null && !auth.type.isEmpty()) {
            String t = auth.type.toLowerCase();
            if ("noauth".equals(t)) {
               this.typeCombo.setSelectedItem(TYPE_NO_AUTH);
            } else if ("bearer".equals(t) || "jwt".equals(t)) {
               this.typeCombo.setSelectedItem(TYPE_BEARER);
               this.bearerField.setText(extractDisplayBearerToken(auth));
            } else if ("oauth2".equals(t)) {
               this.typeCombo.setSelectedItem(TYPE_OAUTH2);
               this.bearerField.setText(extractDisplayBearerToken(auth));
            } else if ("basic".equals(t)) {
               this.typeCombo.setSelectedItem(TYPE_BASIC);
               String user = extractAuthValue(auth.basic, "username");
               String pass = extractAuthValue(auth.basic, "password");
               this.basicUserField.setText(user == null ? "" : user);
               this.basicPassField.setText(pass == null ? "" : pass);
            } else {
               this.typeCombo.setSelectedItem(TYPE_INHERIT);
            }
         } else {
            this.typeCombo.setSelectedItem(TYPE_INHERIT);
         }
         Object sel = this.typeCombo.getSelectedItem();
         if (sel != null) {
            this.details.show(this.detailsPanel, this.toDetailsCard(sel.toString()));
         }
      } finally {
         this.suppressEvents = false;
      }

      this.notifyChangeNoDirty();
   }

   public PostmanCollection.Auth getAuth() {
      if (!this.authDirty) {
         return this.loadedAuth;
      }
      Object sel = this.typeCombo.getSelectedItem();
      String s = sel == null ? TYPE_INHERIT : sel.toString();
      if (TYPE_INHERIT.equals(s)) {
         return null;
      } else {
         PostmanCollection.Auth a = new PostmanCollection.Auth();
         if (TYPE_NO_AUTH.equals(s)) {
            a.type = "noauth";
         } else if (TYPE_BEARER.equals(s)) {
            a.type = "bearer";
            List<Map<String, String>> list = new ArrayList<>();
            Map<String, String> entry = new LinkedHashMap<>();
            entry.put("key", "token");
            entry.put("value", this.bearerField.getText());
            entry.put("type", "string");
            list.add(entry);
            a.bearer = list;
         } else if (TYPE_OAUTH2.equals(s)) {
            a.type = "oauth2";
            a.oauth2 = buildOAuth2Attrs(this.bearerField.getText());
         } else if (TYPE_BASIC.equals(s)) {
            a.type = "basic";
         }

         return a;
      }
   }

   public void clear() {
      this.suppressEvents = true;
      this.loadedAuth = null;
      this.authDirty = false;

      try {
         this.bearerField.setText("");
         this.basicUserField.setText("");
         this.basicPassField.setText("");
         this.typeCombo.setSelectedItem(TYPE_INHERIT);
         this.details.show(this.detailsPanel, TYPE_INHERIT);
         this.setInheritedDescription(null);
      } finally {
         this.suppressEvents = false;
      }

      this.notifyChangeNoDirty();
   }

   public void setBearerToken(String token) {
      if (token == null) {
         token = "";
      }

      this.suppressEvents = true;

      try {
         Object sel = this.typeCombo.getSelectedItem();
         String selectedType = sel == null ? TYPE_BEARER : sel.toString();
         if (!TYPE_OAUTH2.equals(selectedType)) {
            selectedType = TYPE_BEARER;
         }
         this.typeCombo.setSelectedItem(selectedType);
         this.details.show(this.detailsPanel, this.toDetailsCard(selectedType));
         this.bearerField.setText(token);
      } finally {
         this.suppressEvents = false;
      }

      this.notifyChangeNoDirty();
   }

   public void setAuthManager(AuthManager am) {
      this.authManager = am;
   }

   public void setChangeListener(Runnable r) {
      this.changeListener = r;
   }

   private void fireChanged() {
      if (!this.suppressEvents) {
         this.authDirty = true;
         if (this.changeListener != null) {
            try {
               this.changeListener.run();
            } catch (Exception var2) {
            }
         }
      }
   }

   private void notifyChangeNoDirty() {
      if (this.changeListener != null) {
         try {
            this.changeListener.run();
         } catch (Exception var2) {
         }
      }
   }

   public String getBearerToken() {
      return this.bearerField.getText();
   }

   public String getBasicCredentialsBase64() {
      String u = this.basicUserField.getText();
      String p = new String(this.basicPassField.getPassword());
      if (u.isEmpty() && p.isEmpty()) {
         return "";
      } else {
         String creds = u + ":" + p;
         return Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8));
      }
   }

   private static String extractBearerToken(PostmanCollection.Auth auth) {
      if (auth == null || auth.bearer == null) {
         return "";
      }

      Object b = auth.bearer;
      if (b instanceof List) {
         for (Object o : (List)b) {
            if (o instanceof PostmanCollection.AuthAttribute) {
               PostmanCollection.AuthAttribute aa = (PostmanCollection.AuthAttribute)o;
               if (aa.key != null && "token".equalsIgnoreCase(aa.key)) {
                  return aa.value == null ? "" : aa.value;
               }
            } else if (o instanceof Map) {
               Map<String, Object> m = (Map<String, Object>)o;
               Object key = m.get("key");
               if (key != null && "token".equalsIgnoreCase(key.toString())) {
                  Object v = m.get("value");
                  return v == null ? "" : v.toString();
               }
            }
         }
      } else if (b instanceof Map) {
         Object v = ((Map)b).get("token");
         if (v != null) {
            return v.toString();
         }
      }

      return "";
   }

   private static String extractDisplayBearerToken(PostmanCollection.Auth auth) {
      if (auth == null) return "";
      String token = extractBearerToken(auth);
      if (token != null && !token.isEmpty()) return token;
      if (auth.type != null && "oauth2".equalsIgnoreCase(auth.type)) {
         String accessToken = extractAuthValue(auth.oauth2, "accessToken");
         if (accessToken != null && !accessToken.isEmpty()) return accessToken;
         String tokenName = extractAuthValue(auth.oauth2, "tokenName");
         if (tokenName != null && !tokenName.isEmpty()) {
            if (tokenName.contains("{{")) return tokenName;
            return "{{" + tokenName + "}}";
         }
         return "{{token}}";
      }
      return "";
   }

   private String toDetailsCard(String selectedType) {
      if (TYPE_OAUTH2.equals(selectedType)) {
         return TYPE_BEARER;
      }
      return selectedType == null ? TYPE_INHERIT : selectedType;
   }

   private static List<Map<String, String>> buildOAuth2Attrs(String tokenFieldValue) {
      List<Map<String, String>> list = new ArrayList<>();
      String value = tokenFieldValue == null ? "" : tokenFieldValue.trim();

      if (value.startsWith("{{") && value.endsWith("}}")) {
         String tokenName = value.substring(2, value.length() - 2).trim();
         if (tokenName.isEmpty()) tokenName = "token";
         list.add(attr("tokenName", tokenName));
      } else if (!value.isEmpty()) {
         list.add(attr("accessToken", value));
      } else {
         list.add(attr("tokenName", "token"));
      }

      return list;
   }

   private static Map<String, String> attr(String key, String value) {
      Map<String, String> entry = new LinkedHashMap<>();
      entry.put("key", key);
      entry.put("value", value);
      entry.put("type", "string");
      return entry;
   }

   private static String extractAuthValue(Object authData, String key) {
      if (authData == null || key == null) return null;
      try {
         if (authData instanceof List) {
            for (Object item : (List<?>) authData) {
               if (item instanceof PostmanCollection.AuthAttribute) {
                  PostmanCollection.AuthAttribute aa = (PostmanCollection.AuthAttribute) item;
                  if (aa.key != null && key.equalsIgnoreCase(aa.key)) {
                     return aa.value == null ? null : aa.value;
                  }
               } else if (item instanceof Map) {
                  Map<?, ?> m = (Map<?, ?>) item;
                  Object k = m.get("key");
                  if (k != null && key.equalsIgnoreCase(String.valueOf(k))) {
                     Object v = m.get("value");
                     return v == null ? null : String.valueOf(v);
                  }
               }
            }
         } else if (authData instanceof Map) {
            Object v = ((Map<?, ?>) authData).get(key);
            return v == null ? null : String.valueOf(v);
         }
      } catch (Exception ignore) {
      }
      return null;
   }

   private static String escape(String s) {
      return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
   }
}
