package burp.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards extension-unload cleanup.
 *
 * <p>Burp reloads extensions frequently. The previous build implemented no
 * unloading handler at all, so the OAuth callback server kept its port bound
 * across reloads and background threads accumulated.
 */
@DisplayName("Resources are released on unload")
class ResourceRegistryTest {

    @Test
    @DisplayName("registered cleanups all run")
    void runsAllCleanups() {
        ResourceRegistry.shutdownAll(); // start from empty
        List<String> released = new ArrayList<>();

        ResourceRegistry.register("first", () -> released.add("first"));
        ResourceRegistry.register("second", () -> released.add("second"));

        assertEquals(2, ResourceRegistry.shutdownAll());
        assertTrue(released.contains("first") && released.contains("second"), released.toString());
    }

    @Test
    @DisplayName("cleanups run newest first")
    void newestFirst() {
        ResourceRegistry.shutdownAll();
        List<String> order = new ArrayList<>();

        ResourceRegistry.register("a", () -> order.add("a"));
        ResourceRegistry.register("b", () -> order.add("b"));
        ResourceRegistry.shutdownAll();

        // Later registrations often depend on earlier ones, so unwind in
        // reverse — the same discipline as a stack of try-with-resources.
        assertEquals(List.of("b", "a"), order);
    }

    @Test
    @DisplayName("one failing cleanup does not strand the others")
    void failureIsIsolated() {
        ResourceRegistry.shutdownAll();
        List<String> released = new ArrayList<>();

        ResourceRegistry.register("ok-before", () -> released.add("ok-before"));
        ResourceRegistry.register("broken", () -> { throw new IllegalStateException("stuck"); });
        ResourceRegistry.register("ok-after", () -> released.add("ok-after"));

        ResourceRegistry.shutdownAll();

        assertTrue(released.contains("ok-before"), "cleanup before the failure must run");
        assertTrue(released.contains("ok-after"), "cleanup after the failure must still run");
    }

    @Test
    @DisplayName("an executor is actually shut down")
    void executorIsShutDown() {
        ResourceRegistry.shutdownAll();
        ExecutorService pool = Executors.newSingleThreadExecutor();

        ResourceRegistry.registerExecutor("pool", pool);
        ResourceRegistry.shutdownAll();

        assertTrue(pool.isShutdown(), "executor must be shut down on unload");
    }

    @Test
    @DisplayName("shutdown is idempotent")
    void idempotent() {
        ResourceRegistry.shutdownAll();
        ResourceRegistry.register("once", () -> { });

        assertEquals(1, ResourceRegistry.shutdownAll());
        assertEquals(0, ResourceRegistry.shutdownAll(), "second call must be a no-op");
        assertEquals(0, ResourceRegistry.size());
    }
}
