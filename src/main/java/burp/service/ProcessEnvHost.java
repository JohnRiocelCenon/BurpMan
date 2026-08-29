package burp.service;

/**
 * Java facade exposing OS environment variables to Bruno scripts as
 * {@code process.env.NAME}. Bruno collections commonly do
 * <pre>
 *   {
 *     "name": "client_secret",
 *     "value": "{{process.env.US_QQ_CLIENT_SECRET}}"
 *   }
 * </pre>
 * to keep secrets out of the committed collection file — the real value
 * lives in the shell's environment (or Bruno's {@code .env} file) and is
 * substituted at send time.
 *
 * <p>Rhino wraps this instance as a {@code NativeJavaObject}. A JS Proxy
 * in the runtime bootstrap forwards {@code process.env.FOO} lookups to
 * {@link #get(String)}, which returns the OS env value (or {@code null}
 * so JS sees {@code undefined}).
 */
public final class ProcessEnvHost {
    /** Returns the OS env var for {@code name}, or {@code null} if unset. */
    public String get(String name) {
        if (name == null || name.isEmpty()) return null;
        return System.getenv(name);
    }
}
