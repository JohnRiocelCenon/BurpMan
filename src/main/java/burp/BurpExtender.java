
package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import javax.swing.*;

public class BurpExtender implements BurpExtension {
    private MontoyaApi api;
    private PostmanImporter importer;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("BurpManRevamped");

        // Wire MontoyaApi into the Rhino script engine so pm.sendRequest can
        // synchronously fire HTTP through Burp's stack from inside scripts.
        try {
            burp.service.RhinoScriptEngine.api = api;
        } catch (Throwable t) {
            api.logging().logToError("[BurpMan] Failed to wire MontoyaApi into script engine: " + t);
        }

        // Release background work on unload. Burp users reload extensions
        // constantly; without this the OAuth callback server keeps its port
        // bound and every executor thread survives into the next load.
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                int released = burp.util.ResourceRegistry.shutdownAll();
                burp.service.RhinoScriptEngine.api = null;
                burp.service.ScriptExecutor.UI_LOG = null;
                burp.util.Diag.setSink(null);
                api.logging().logToOutput(
                    "[BurpMan] Unloaded — released " + released + " background resource(s).");
            }
        });

        // Print extension info and author details — early so a later crash
        // still leaves a trail in the Burp Extender log.
        api.logging().logToOutput("=================================================");
        api.logging().logToOutput("BurpManRevamped v2.0.0");
        api.logging().logToOutput("Convert your API Collection into a Burp Request");
        api.logging().logToOutput("Supports Postman and Bruno Collections");
        api.logging().logToOutput("=================================================");
        api.logging().logToOutput("Author : John Riocel Cenon");
        api.logging().logToOutput("GitHub : https://github.com/JohnRiocelCenon/BurpMan");
        api.logging().logToOutput("=================================================");
        api.logging().logToOutput("Loading extension...");
        api.logging().logToOutput("=================================================");

        // All UI initialization must run on the EDT inside a defensive
        // try/catch — if anything explodes, Burp would otherwise unload the
        // whole extension and the user sees no tab at all.
        SwingUtilities.invokeLater(() -> {
            // Build the main panel + register the suite tab.
            try {
                importer = new PostmanImporter(api);
                // The tab carries the version. Several BurpMan builds now
                // exist side by side, and a tab labelled just "BurpMan" gives
                // no way to tell which jar is actually loaded — which turns
                // "did my change take effect?" into guesswork.
                api.userInterface().registerSuiteTab("BurpMan v2", importer.getMainPanel());
                api.logging().logToOutput("BurpMan tab registered successfully.");
            } catch (Throwable t) {
                // Last-ditch fallback: show a tab with the error so the user
                // sees what went wrong instead of a missing extension.
                api.logging().logToError("[BurpMan] FATAL during UI init: " + t);
                t.printStackTrace();
                try {
                    JPanel errPanel = new JPanel(new java.awt.BorderLayout());
                    javax.swing.JTextArea err = new javax.swing.JTextArea(
                            "BurpMan failed to load.\n\n"
                                    + t.getClass().getName() + ": " + t.getMessage()
                                    + "\n\nCheck Extender → Errors for the full stack trace.");
                    err.setEditable(false);
                    err.setMargin(new java.awt.Insets(20, 20, 20, 20));
                    errPanel.add(new javax.swing.JScrollPane(err), java.awt.BorderLayout.CENTER);
                    api.userInterface().registerSuiteTab("BurpMan v2 (error)", errPanel);
                } catch (Throwable t2) {
                    api.logging().logToError("[BurpMan] Could not register error fallback tab: " + t2);
                }
            }
        });
    }
}

