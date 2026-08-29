package burp.service;

import java.util.prefs.Preferences;

/**
 * Global proxy settings for BurpMan's outbound HTTP traffic.
 *
 * <p>When enabled, every {@code sendRequest} call made by the runner is
 * routed through the configured upstream proxy — typically Burp's own
 * Proxy listener at {@code 127.0.0.1:8080} — so the traffic shows up in
 * <b>Burp Proxy → HTTP history</b> (not just Logger).
 *
 * <p>Persisted to {@link Preferences}; survives Burp restarts.
 */
public final class ProxySettings {

    private static final String PREF_NODE = "burpman";
    private static final String KEY_ENABLED = "proxy.enabled";
    private static final String KEY_HOST    = "proxy.host";
    private static final String KEY_PORT    = "proxy.port";
    private static final String KEY_BYPASS  = "proxy.bypassLocalhost";
    private static final String KEY_INSECURE = "proxy.trustAllCerts";

    private static volatile ProxySettings INSTANCE;

    private volatile boolean enabled;
    private volatile String host;
    private volatile int port;
    private volatile boolean bypassLocalhost;
    private volatile boolean trustAllCerts;

    private ProxySettings() {
        Preferences p = prefs();
        this.enabled = p.getBoolean(KEY_ENABLED, false);
        this.host = p.get(KEY_HOST, "127.0.0.1");
        this.port = p.getInt(KEY_PORT, 8080);
        this.bypassLocalhost = p.getBoolean(KEY_BYPASS, false);
        this.trustAllCerts = p.getBoolean(KEY_INSECURE, true);
    }

    public static ProxySettings get() {
        ProxySettings s = INSTANCE;
        if (s == null) {
            synchronized (ProxySettings.class) {
                s = INSTANCE;
                if (s == null) INSTANCE = s = new ProxySettings();
            }
        }
        return s;
    }

    private static Preferences prefs() {
        return Preferences.userRoot().node(PREF_NODE);
    }

    public boolean isEnabled()          { return enabled; }
    public String  getHost()            { return host == null ? "" : host; }
    public int     getPort()            { return port; }
    public boolean isBypassLocalhost()  { return bypassLocalhost; }
    public boolean isTrustAllCerts()    { return trustAllCerts; }

    public synchronized void update(boolean enabled, String host, int port,
                                    boolean bypassLocalhost, boolean trustAllCerts) {
        this.enabled = enabled;
        this.host = (host == null || host.trim().isEmpty()) ? "127.0.0.1" : host.trim();
        this.port = (port <= 0 || port > 65535) ? 8080 : port;
        this.bypassLocalhost = bypassLocalhost;
        this.trustAllCerts = trustAllCerts;
        Preferences p = prefs();
        p.putBoolean(KEY_ENABLED, this.enabled);
        p.put(KEY_HOST, this.host);
        p.putInt(KEY_PORT, this.port);
        p.putBoolean(KEY_BYPASS, this.bypassLocalhost);
        p.putBoolean(KEY_INSECURE, this.trustAllCerts);
        try { p.flush(); } catch (Throwable ignore) {}
    }

    /** Compact status label for the toolbar button. */
    public String statusLabel() {
        if (!enabled) return "\uD83C\uDF10 Proxy: OFF";
        return "\uD83C\uDF10 Proxy: " + getHost() + ":" + port;
    }

    /** True if the given target host should skip the proxy. */
    public boolean shouldBypass(String targetHost) {
        if (!enabled) return true;
        if (!bypassLocalhost) return false;
        if (targetHost == null) return false;
        String h = targetHost.toLowerCase();
        return h.equals("localhost")
            || h.equals("127.0.0.1")
            || h.equals("::1")
            || h.equals("0.0.0.0");
    }
}
