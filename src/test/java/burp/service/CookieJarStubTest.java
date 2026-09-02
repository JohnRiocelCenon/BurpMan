package burp.service;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;

/**
 * The surface {@code bru.cookies.jar()} exposes to scripts.
 *
 * <p>Rhino reports a missing method as a hard {@code TypeError}, which aborts
 * the whole hook. A collection calling {@code jar.deleteCookies(url)} in its
 * first pre-request script therefore never cleared the stale session cookie it
 * was trying to remove, and the resulting mid-chain failures pointed nowhere
 * near the actual cause. These names come from Bruno's documented jar API.
 */
class CookieJarStubTest {

    private static Class<?> stub() throws Exception {
        return Class.forName("burp.service.RhinoScriptEngine$BruHost$CookieJarStub");
    }

    private static void assertCallable(String name, Class<?>... args) throws Exception {
        Method m = stub().getMethod(name, args);
        assertNotNull(m, name + " must be callable from a script");
    }

    @Test
    void exposesBrunoDeleteNames() throws Exception {
        assertCallable("deleteCookies");
        assertCallable("deleteCookies", String.class);
        assertCallable("deleteCookies", String.class, Object.class);
        assertCallable("deleteAllCookies");
        assertCallable("deleteCookie", String.class, String.class);
    }

    @Test
    void exposesBrunoAccessorNames() throws Exception {
        assertCallable("getCookie", String.class, String.class);
        assertCallable("getCookies", String.class);
        assertCallable("setCookie", String.class, String.class, String.class);
    }

    /** The names BurpMan already supported must not regress. */
    @Test
    void keepsTheOriginalClearNames() throws Exception {
        assertCallable("clear");
        assertCallable("clear", String.class);
        assertCallable("clear", String.class, Object.class);
    }
}
