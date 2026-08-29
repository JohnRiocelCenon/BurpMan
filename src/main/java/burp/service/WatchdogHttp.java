package burp.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Fires script-initiated HTTP requests and credits the wait back to the script
 * watchdog.
 *
 * <h2>Why this is a separate class</h2>
 * It exists to keep Montoya types out of {@link RhinoScriptEngine}'s own method
 * signatures. {@code RhinoScriptEngine} registers {@code atob} and {@code btoa}
 * into the script scope via {@code Class.getDeclaredMethod}, and the JVM
 * resolves the parameter types of <em>every</em> declared method on that class
 * when it does so. The Montoya API is {@code provided} scope — present inside
 * Burp but absent from the packaged jar — so a single Montoya-typed parameter
 * on the outer class was enough to make {@code atob} silently fail to register
 * outside Burp, surfacing much later as "atob is not a function".
 *
 * <p>Keeping the Montoya surface in a class that is only touched at call time
 * means {@code RhinoScriptEngine} loads cleanly anywhere.
 */
final class WatchdogHttp {

    private WatchdogHttp() {}

    /**
     * Sends {@code request} through Burp, excluding the network wait from the
     * script's time budget.
     *
     * <p>{@code pm.sendRequest} blocks the script thread on a real round-trip.
     * An OAuth chain hitting three token endpoints can spend tens of seconds
     * there through no fault of the script, so charging it against the budget
     * would kill legitimate auth flows.
     */
    static HttpRequestResponse send(MontoyaApi api, HttpRequest request) {
        long started = System.currentTimeMillis();
        try {
            return ProxyRouter.sendRequest(api, request);
        } finally {
            ScriptSandbox.creditBlockedTime(System.currentTimeMillis() - started);
        }
    }
}
