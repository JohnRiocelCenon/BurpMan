package burp.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.parser.VariableResolver;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.Dialog.ModalityType;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

public class OAuth2ConfigDialog extends JDialog {
   private static final String[] GRANT_TYPES = new String[]{"authorization_code", "client_credentials", "password", "implicit", "refresh_token"};
   private static final String[] CLIENT_AUTH_METHODS = new String[]{"header", "body"};
   private static final int OAUTH_HTTP_TIMEOUT_MS = 25000;
   private static final int OAUTH_BROWSER_LOCAL_CAPTURE_TIMEOUT_SECONDS = 25;
   private static final int OAUTH_BROWSER_PROXY_CAPTURE_TIMEOUT_SECONDS = 20;
   private static final int OAUTH_BROWSER_PROXY_FALLBACK_TIMEOUT_SECONDS = 10;
   private final OAuth2Config config;
   private final burp.PostmanImporter importer;
   private final AuthManager authManager;
   private final MontoyaApi api;
   private String origCallbackUrl;
   private String origAuthUrl;
   private String origAccessTokenUrl;
   private String origClientId;
   private String origClientSecret;
   private String origScope;
   private String origState;
   private String origRefreshTokenUrl;
   private final JTextField tokenName = new JTextField();
   private final JComboBox<String> grantType = new JComboBox<>(GRANT_TYPES);
   private final JTextField callbackUrl = new JTextField();
   private final JTextField authUrl = new JTextField();
   private final JTextField accessTokenUrl = new JTextField();
   private final JTextField clientId = new JTextField();
   private final JPasswordField clientSecret = new JPasswordField();
   private final JTextField scope = new JTextField();
   private final JTextField state = new JTextField();
   private final JComboBox<String> clientAuthMethod = new JComboBox<>(CLIENT_AUTH_METHODS);
   private final JTextField refreshTokenUrl = new JTextField();
   private final DefaultTableModel authParamsModel = newKvModel();
   private final DefaultTableModel tokenParamsModel = newKvModel();
   private final DefaultTableModel refreshParamsModel = newKvModel();
   private final JTextArea statusArea = new JTextArea(4, 40);

   public OAuth2ConfigDialog(Window owner, OAuth2Config config, burp.PostmanImporter importer, AuthManager authManager, MontoyaApi api) {
      super(owner, "OAuth 2.0 Configuration — " + (config != null && config.name != null ? config.name : ""), ModalityType.APPLICATION_MODAL);
      this.config = config;
      this.importer = importer;
      this.authManager = authManager;
      this.api = api;
      this.buildUi();
      this.loadFromConfig();
      this.setSize(720, 720);
      this.setLocationRelativeTo(owner);
      this.addWindowListener(new WindowAdapter() {
         @Override
         public void windowClosing(WindowEvent e) {
            OAuth2ConfigDialog.this.dispose();
         }
      });
   }

   private void buildUi() {
      this.setLayout(new BorderLayout(0, 0));
      JTabbedPane tabs = new JTabbedPane();
      tabs.addTab("Configuration", this.buildConfigPanel());
      tabs.addTab("Advanced", this.buildAdvancedPanel());
      this.add(tabs, "Center");
      this.statusArea.setEditable(false);
      this.statusArea.setFont(new Font("Monospaced", 0, 11));
      this.statusArea.setForeground(new Color(70, 70, 70));
      JScrollPane statusScroll = new JScrollPane(this.statusArea);
      statusScroll.setBorder(BorderFactory.createTitledBorder("Status"));
      JPanel buttons = new JPanel(new FlowLayout(2, 6, 4));
      JButton sendBtn = new JButton("Send Token Request to Repeater");
      JButton getTokenBtn = new JButton("Get New Access Token");
      JButton saveBtn = new JButton("Save");
      JButton closeBtn = new JButton("Close");
      sendBtn.addActionListener(e -> this.saveAndSendToRepeater());
      getTokenBtn.addActionListener(e -> this.saveAndFetchToken());
      saveBtn.addActionListener(e -> {
         this.saveToConfig();
         this.appendStatus("✅ Saved.");
      });
      closeBtn.addActionListener(e -> this.dispose());
      buttons.add(sendBtn);
      buttons.add(getTokenBtn);
      buttons.add(saveBtn);
      buttons.add(closeBtn);
      JPanel south = new JPanel(new BorderLayout());
      south.add(statusScroll, "Center");
      south.add(buttons, "South");
      this.add(south, "South");
   }

   private JPanel buildConfigPanel() {
      JPanel p = new JPanel(new GridBagLayout());
      p.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
      GridBagConstraints gc = new GridBagConstraints();
      gc.fill = 2;
      gc.insets = new Insets(4, 4, 4, 4);
      gc.weightx = 0.0;
      gc.gridx = 0;
      gc.gridy = 0;
      this.addRow(p, gc, "Token Name:", this.tokenName);
      this.addRow(p, gc, "Grant Type:", this.grantType);
      this.addRow(p, gc, "Callback URL:", this.callbackUrl);
      this.addRow(p, gc, "Auth URL:", this.authUrl);
      this.addRow(p, gc, "Access Token URL:", this.accessTokenUrl);
      this.addRow(p, gc, "Client ID:", this.clientId);
      this.addRow(p, gc, "Client Secret:", this.clientSecret);
      this.addRow(p, gc, "Scope:", this.scope);
      this.addRow(p, gc, "State:", this.state);
      this.addRow(p, gc, "Client Authentication:", this.clientAuthMethod);
      gc.gridy++;
      gc.weighty = 1.0;
      gc.fill = 1;
      p.add(Box.createGlue(), gc);
      return p;
   }

   private JPanel buildAdvancedPanel() {
      JPanel p = new JPanel(new BorderLayout(6, 6));
      p.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
      JPanel top = new JPanel(new GridBagLayout());
      GridBagConstraints gc = new GridBagConstraints();
      gc.fill = 2;
      gc.insets = new Insets(4, 4, 4, 4);
      gc.gridx = 0;
      gc.gridy = 0;
      this.addRow(top, gc, "Refresh Token URL:", this.refreshTokenUrl);
      p.add(top, "North");
      JPanel tables = new JPanel(new GridLayout(3, 1, 6, 6));
      tables.add(this.buildKvTable("Auth Request Params", this.authParamsModel));
      tables.add(this.buildKvTable("Token Request Params", this.tokenParamsModel));
      tables.add(this.buildKvTable("Refresh Request Params", this.refreshParamsModel));
      p.add(tables, "Center");
      return p;
   }

   private JPanel buildKvTable(String title, DefaultTableModel model) {
      JTable table = new JTable(model);
      table.setRowHeight(22);
      JScrollPane sp = new JScrollPane(table);
      JPanel toolbar = new JPanel(new FlowLayout(0, 4, 2));
      JButton add = new JButton("+");
      JButton remove = new JButton("−");
      add.setMargin(new Insets(0, 8, 0, 8));
      remove.setMargin(new Insets(0, 8, 0, 8));
      add.addActionListener(e -> model.addRow(new Object[]{"", ""}));
      remove.addActionListener(e -> {
         int r = table.getSelectedRow();
         if (r >= 0) {
            model.removeRow(r);
         }
      });
      toolbar.add(add);
      toolbar.add(remove);
      JPanel wrap = new JPanel(new BorderLayout());
      wrap.setBorder(BorderFactory.createTitledBorder(title));
      wrap.add(toolbar, "North");
      wrap.add(sp, "Center");
      return wrap;
   }

   private void addRow(JPanel parent, GridBagConstraints gc, String label, JComponent field) {
      gc.gridx = 0;
      gc.weightx = 0.0;
      parent.add(new JLabel(label), gc);
      gc.gridx = 1;
      gc.weightx = 1.0;
      parent.add(field, gc);
      gc.gridy++;
   }

   private static DefaultTableModel newKvModel() {
      return new DefaultTableModel(new Object[]{"Key", "Value"}, 0);
   }

   private void loadFromConfig() {
      if (this.config != null) {
         this.tokenName.setText(nullSafe(this.config.name));
         selectOrAdd(this.grantType, this.config.grantType);
         this.callbackUrl.setText(this.resolve(this.config.callbackUrl));
         this.authUrl.setText(this.resolve(this.config.authUrl));
         this.accessTokenUrl.setText(this.resolve(this.config.accessTokenUrl));
         this.clientId.setText(this.resolve(this.config.clientId));
         this.clientSecret.setText(this.resolve(this.config.clientSecret));
         this.scope.setText(this.resolve(this.config.scope));
         this.state.setText(this.resolve(this.config.state));
         selectOrAdd(this.clientAuthMethod, nullSafe(this.config.clientAuthenticationMethod));
         resetHorizontalScroll(this.callbackUrl, this.authUrl, this.accessTokenUrl, this.clientId, this.scope, this.state);
         this.origCallbackUrl = this.callbackUrl.getText();
         this.origAuthUrl = this.authUrl.getText();
         this.origAccessTokenUrl = this.accessTokenUrl.getText();
         this.origClientId = this.clientId.getText();
         this.origClientSecret = new String(this.clientSecret.getPassword());
         this.origScope = this.scope.getText();
         this.origState = this.state.getText();
         String refresh = this.config.rawAttributes != null ? this.config.rawAttributes.get("refresh_token_url") : null;
         if (refresh == null && this.config.rawAttributes != null) {
            refresh = this.config.rawAttributes.get("refreshTokenUrl");
         }

         this.refreshTokenUrl.setText(this.resolve(refresh));
         resetHorizontalScroll(this.refreshTokenUrl);
         this.origRefreshTokenUrl = this.refreshTokenUrl.getText();
         if (this.config.rawAttributes != null) {
            for (Entry<String, String> e : this.config.rawAttributes.entrySet()) {
               String k = e.getKey();
               if (k != null && !this.isWellKnownKey(k)) {
                  this.tokenParamsModel.addRow(new Object[]{k, this.resolve(e.getValue())});
               }
            }
         }
      }
   }

   private static void resetHorizontalScroll(JTextField... fields) {
     if (fields == null) return;
     for (JTextField f : fields) {
        if (f == null) continue;
        try {
           f.setCaretPosition(0);
        } catch (Exception ignore) {
        }
     }
   }

   private String resolve(String s) {
     if (s != null && !s.isEmpty()) {
        try {
            return this.importer.getVariableResolver().resolve(s);
         } catch (Exception var3) {
            return s;
         }
      } else {
         return "";
      }
   }

   private boolean isWellKnownKey(String k) {
      String lk = k.toLowerCase();
      return lk.equals("grant_type")
         || lk.equals("granttype")
         || lk.equals("accesstokenurl")
         || lk.equals("access_token_url")
         || lk.equals("tokenurl")
         || lk.equals("token_url")
         || lk.equals("authurl")
         || lk.equals("authorizationurl")
         || lk.equals("authorization_url")
         || lk.equals("clientid")
         || lk.equals("client_id")
         || lk.equals("clientsecret")
         || lk.equals("client_secret")
         || lk.equals("scope")
         || lk.equals("state")
         || lk.equals("callbackurl")
         || lk.equals("redirect_uri")
         || lk.equals("client_authentication")
         || lk.equals("refresh_token_url")
         || lk.equals("refreshtokenurl")
         || lk.equals("tokenname");
   }

   private void saveToConfig() {
      if (this.config != null) {
         String newCallbackUrl = textOrNull(this.callbackUrl);
         String newAuthUrl = textOrNull(this.authUrl);
         String newAccessTokenUrl = textOrNull(this.accessTokenUrl);
         String newScope = textOrNull(this.scope);
         String newState = textOrNull(this.state);
         String newClientId = textOrNull(this.clientId);
         String newClientSecret = passwordOrNull(this.clientSecret);
         String newRefresh = textOrNull(this.refreshTokenUrl);
         String rawCallbackUrl = this.config.callbackUrl;
         String rawAuthUrl = this.config.authUrl;
         String rawAccessTokenUrl = this.config.accessTokenUrl;
         String rawScope = this.config.scope;
         String rawState = this.config.state;
         String rawClientId = this.config.clientId;
         String rawClientSecret = this.config.clientSecret;
         String rawRefresh = null;
         if (this.config.rawAttributes != null) {
            rawRefresh = this.config.rawAttributes.get("refresh_token_url");
            if (rawRefresh == null) {
               rawRefresh = this.config.rawAttributes.get("refreshTokenUrl");
            }
         }

         this.config.name = textOrNull(this.tokenName);
         this.config.grantType = (String)this.grantType.getSelectedItem();
         this.config.clientAuthenticationMethod = (String)this.clientAuthMethod.getSelectedItem();
         this.propagateFieldEdit(rawClientId, this.origClientId, newClientId);
         this.propagateFieldEdit(rawClientSecret, this.origClientSecret, newClientSecret);
         this.propagateFieldEdit(rawAccessTokenUrl, this.origAccessTokenUrl, newAccessTokenUrl);
         this.propagateFieldEdit(rawAuthUrl, this.origAuthUrl, newAuthUrl);
         this.propagateFieldEdit(rawCallbackUrl, this.origCallbackUrl, newCallbackUrl);
         this.propagateFieldEdit(rawScope, this.origScope, newScope);
         this.propagateFieldEdit(rawState, this.origState, newState);
         this.propagateFieldEdit(rawRefresh, this.origRefreshTokenUrl, newRefresh);
         this.config.clientId = updateConfigField(rawClientId, newClientId);
         this.config.clientSecret = updateConfigField(rawClientSecret, newClientSecret);
         this.config.accessTokenUrl = updateConfigField(rawAccessTokenUrl, newAccessTokenUrl);
         this.config.authUrl = updateConfigField(rawAuthUrl, newAuthUrl);
         this.config.callbackUrl = updateConfigField(rawCallbackUrl, newCallbackUrl);
         this.config.scope = updateConfigField(rawScope, newScope);
         this.config.state = updateConfigField(rawState, newState);
         if (this.config.rawAttributes != null) {
            String persistedRefresh = updateConfigField(rawRefresh, newRefresh);
            if (persistedRefresh != null) {
               this.config.rawAttributes.put("refresh_token_url", persistedRefresh);
            } else {
               this.config.rawAttributes.remove("refresh_token_url");
            }
         }
      }
   }

   private static String updateConfigField(String existing, String newValue) {
      return existing != null && existing.contains("{{") ? existing : newValue;
   }

   private void propagateFieldEdit(String configRaw, String originalLoaded, String newValue) {
      if (newValue == null) {
         newValue = "";
      }

      if (originalLoaded == null) {
         originalLoaded = "";
      }

      if (!newValue.equals(originalLoaded)) {
         try {
            VariableResolver r = this.importer.getVariableResolver();
            if (configRaw != null && configRaw.contains("{{")) {
               int a = configRaw.indexOf("{{");
               int b = configRaw.indexOf("}}", a + 2);
               if (a >= 0 && b > a) {
                  String varName = configRaw.substring(a + 2, b).trim();
                  if (!varName.isEmpty()) {
                     r.updateVariableEverywhere(varName, newValue);
                  }
               }
            }

            Map<String, String> globals = r.getVariables();
            if (globals != null) {
               List<String> matches = new ArrayList<>();

               for (Entry<String, String> e : globals.entrySet()) {
                  if (originalLoaded.equals(e.getValue())) {
                     matches.add(e.getKey());
                  }
               }

               for (String name : matches) {
                  r.updateVariableEverywhere(name, newValue);
               }
            }
         } catch (Exception var9) {
         }
      }
   }

   private void writeBackVar(String template, String resolvedValue) {
      int a = template.indexOf("{{");
      int b = template.indexOf("}}", a + 2);
      if (a >= 0 && b >= 0) {
         String varName = template.substring(a + 2, b).trim();
         if (!varName.isEmpty()) {
            try {
               this.importer.getVariableResolver().updateVariableEverywhere(varName, resolvedValue);
            } catch (Exception var7) {
            }
         }
      }
   }

   private void saveAndSendToRepeater() {
      this.saveToConfig();

      try {
         OAuth2RequestFactory factory = new OAuth2RequestFactory(this.importer.getVariableResolver());
         HttpRequest req = factory.buildTokenRequest(this.config);
         this.importer.sendOAuthToRepeater(req);
         this.appendStatus("✅ Token request sent to Repeater.");
      } catch (Exception var3) {
         this.appendStatus("❌ " + var3.getMessage());
      }
   }

   private void saveAndFetchToken() {
      this.saveToConfig();
      this.appendStatus("⏳ Requesting access token...");
      try {
         OAuth2RequestFactory factory = new OAuth2RequestFactory(this.importer.getVariableResolver());
         if (factory.isBrowserInteractiveFlow(this.config)) {
            this.fetchTokenViaBrowser(factory);
            return;
         }
         this.fetchTokenWithRequest(factory.buildTokenRequest(this.config), "oauth2-fetch");
      } catch (Exception var2) {
         this.appendStatus("❌ " + var2.getClass().getSimpleName() + ": " + var2.getMessage());
      }
   }

   private void fetchTokenViaBrowser(OAuth2RequestFactory factory) {
      new Thread(() -> runTokenViaBrowser(factory), "oauth2-browser-auth").start();
   }

   private void runTokenViaBrowser(OAuth2RequestFactory factory) {
      try {
         OAuth2RequestFactory.PkcePair pkce = factory.generatePkcePair();
         String authRequestUrl = factory.buildAuthorizationRequestUrl(this.config, pkce.challenge);
         String callbackUrl = factory.resolveBrowserCallbackUrl(this.config);
         String code = null;
         long captureStartMillis = System.currentTimeMillis();
         boolean canAutoCapture = OAuthBrowserCallbackServer.canAutoCapture(callbackUrl);
         boolean canProxyCapture = OAuthProxyCallbackCapture.canCapture(callbackUrl);
         int waitBudgetSeconds =
            (canAutoCapture ? OAUTH_BROWSER_LOCAL_CAPTURE_TIMEOUT_SECONDS : 0)
               + (canProxyCapture ? OAUTH_BROWSER_PROXY_CAPTURE_TIMEOUT_SECONDS : 0)
               + OAUTH_BROWSER_PROXY_FALLBACK_TIMEOUT_SECONDS;
         boolean browserOpened = false;

         if (canAutoCapture) {
            try {
               browserOpened = true;
               code = OAuthBrowserCallbackServer.openBrowserAndAwaitCode(
                  authRequestUrl,
                  callbackUrl,
                  OAUTH_BROWSER_LOCAL_CAPTURE_TIMEOUT_SECONDS
               );
            } catch (Exception ex) {
               // Fall back to manual paste mode.
            }
         }

         if (code == null || code.isEmpty()) {
            if (!browserOpened) {
               openBrowser(authRequestUrl);
            }
            if (canProxyCapture) {
               try {
                  code = OAuthProxyCallbackCapture.awaitCodeFromProxy(
                     this.api,
                     callbackUrl,
                     OAUTH_BROWSER_PROXY_CAPTURE_TIMEOUT_SECONDS,
                     captureStartMillis
                  );
               } catch (Exception ex) {
                  // Fall back to manual paste mode.
               }
            }
            if (code == null || code.isEmpty()) {
               try {
                  code = OAuthProxyCallbackCapture.awaitAnyCodeFromProxy(
                     this.api,
                     OAUTH_BROWSER_PROXY_FALLBACK_TIMEOUT_SECONDS,
                     captureStartMillis
                  );
               } catch (Exception ex) {
                  // Fall back to manual paste mode.
               }
            }
         }

         if (code == null || code.isEmpty()) {
            this.appendStatus(
               "⚠ Browser auth did not return a callback code automatically. "
                  + "Manual paste prompt is disabled. "
                  + "Waited about " + waitBudgetSeconds + "s. "
                  + "Ensure callback URL/port is reachable and registered, then retry."
            );
            return;
         }

         HttpRequest req = factory.buildAuthorizationCodeTokenRequest(this.config, code, pkce.verifier);
         this.fetchTokenWithRequest(req, "oauth2-browser-fetch");
      } catch (Exception ex) {
         this.appendStatus("❌ " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
      }
   }

   private String resolveCallbackUrl() {
      if (this.config == null || this.config.callbackUrl == null || this.config.callbackUrl.trim().isEmpty()) {
         return null;
      }
      try {
         return this.importer.getVariableResolver().resolve(this.config.callbackUrl);
      } catch (Exception ex) {
         return this.config.callbackUrl;
      }
   }

   private void fetchTokenWithRequest(HttpRequest req, String threadName) {
      new Thread(() -> {
         try {
            HttpRequestResponse rr = OAuthHttpClient.sendRequestWithTimeout(this.api, req, OAUTH_HTTP_TIMEOUT_MS);
            if (rr == null || rr.response() == null) {
               SwingUtilities.invokeLater(() -> this.appendStatus("❌ No response from token endpoint."));
               return;
            }

            int status = rr.response().statusCode();
            String body = rr.response().bodyToString();
            SwingUtilities.invokeLater(() -> {
               this.appendStatus("← HTTP " + status);
               if (status >= 200 && status < 300) {
                  boolean ok = this.authManager.extractAnyToken(body);
                  if (ok) {
                     String token = this.authManager.getAccessToken();
                     this.appendStatus("✅ Access token extracted (" + (token != null ? token.length() : 0) + " chars).");

                     try {
                        if (this.config.rawAttributes != null) {
                           this.config.rawAttributes.put("accessToken", token == null ? "" : token);
                        }

                        this.refreshTokenParamsTable();
                     } catch (Exception var6x) {
                     }
                  } else {
                     this.appendStatus("⚠ Response did not contain a recognizable token.\n" + truncate(body, 600));
                  }
               } else {
                  this.appendStatus("❌ Token endpoint returned " + status + "\n" + truncate(body, 600));
               }
            });
         } catch (Exception var6) {
            SwingUtilities.invokeLater(() -> this.appendStatus("❌ " + var6.getClass().getSimpleName() + ": " + var6.getMessage()));
         }
      }, threadName).start();
   }

   private static void openBrowser(String url) throws Exception {
      BrowserLauncher.open(url);
   }

   private void refreshTokenParamsTable() {
      if (this.config != null && this.config.rawAttributes != null) {
         this.tokenParamsModel.setRowCount(0);

         for (Entry<String, String> e : this.config.rawAttributes.entrySet()) {
            String k = e.getKey();
            if (k != null && !this.isWellKnownKey(k)) {
               this.tokenParamsModel.addRow(new Object[]{k, this.resolve(e.getValue())});
            }
         }
      }
   }

   private void appendStatus(String msg) {
      Runnable task = () -> {
         this.statusArea.append(msg + "\n");
         this.statusArea.setCaretPosition(this.statusArea.getDocument().getLength());
      };
      if (SwingUtilities.isEventDispatchThread()) {
         task.run();
      } else {
         SwingUtilities.invokeLater(task);
      }
   }

   private static String truncate(String s, int max) {
      if (s == null) {
         return "";
      } else {
         return s.length() <= max ? s : s.substring(0, max) + "...";
      }
   }

   private static void selectOrAdd(JComboBox<String> cb, String val) {
      if (val != null && !val.isEmpty()) {
         for (int i = 0; i < cb.getItemCount(); i++) {
            if (val.equalsIgnoreCase(cb.getItemAt(i))) {
               cb.setSelectedIndex(i);
               return;
            }
         }

         cb.addItem(val);
         cb.setSelectedItem(val);
      }
   }

   private static String nullSafe(String s) {
      return s == null ? "" : s;
   }

   private static String textOrNull(JTextField t) {
      String s = t.getText();
      return s != null && !s.trim().isEmpty() ? s.trim() : null;
   }

   private static String passwordOrNull(JPasswordField p) {
      char[] c = p.getPassword();
      if (c != null && c.length != 0) {
         return new String(c).trim().isEmpty() ? null : new String(c);
      } else {
         return null;
      }
   }
}
