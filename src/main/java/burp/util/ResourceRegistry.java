package burp.util;

import java.io.Closeable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Tracks resources that must be released when the extension unloads.
 *
 * <h2>Why this exists</h2>
 * Burp users reload extensions constantly during development and between
 * engagements. Nothing in the previous build implemented
 * {@code ExtensionUnloadingHandler}, so every reload leaked whatever was
 * running: the OAuth browser-callback HTTP server kept its port bound (making
 * the next OAuth flow fail with "address already in use"), executor threads
 * accumulated, and stale UI sinks kept references to a dead panel.
 *
 * <p>Registration is deliberately cheap and unconditional at each creation
 * site, so a new background task cannot be added without also being cleaned
 * up. Shutdown runs newest-first and isolates failures, because one component
 * refusing to stop must not strand the rest.
 */
public final class ResourceRegistry {

    private static final Deque<Entry> ENTRIES = new ArrayDeque<>();

    private ResourceRegistry() {}

    private static final class Entry {
        final String name;
        final Runnable action;

        Entry(String name, Runnable action) {
            this.name = name;
            this.action = action;
        }
    }

    /** Registers arbitrary cleanup. */
    public static synchronized void register(String name, Runnable cleanup) {
        if (cleanup != null) ENTRIES.push(new Entry(name, cleanup));
    }

    /** Registers an executor to be shut down, interrupting stragglers. */
    public static synchronized void registerExecutor(String name, ExecutorService executor) {
        if (executor == null) return;
        register(name, () -> {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        });
    }

    /** Registers a socket, server, or stream to be closed. */
    public static synchronized void registerCloseable(String name, Closeable closeable) {
        if (closeable == null) return;
        register(name, () -> {
            try {
                closeable.close();
            } catch (Exception e) {
                Diag.warn("closing " + name, e);
            }
        });
    }

    /**
     * Releases everything, newest first. Safe to call more than once — the
     * registry is emptied as it drains, so a second call is a no-op.
     *
     * @return the number of resources released
     */
    public static int shutdownAll() {
        List<Entry> snapshot;
        synchronized (ResourceRegistry.class) {
            snapshot = new ArrayList<>(ENTRIES);
            ENTRIES.clear();
        }
        int released = 0;
        for (Entry e : snapshot) {
            try {
                e.action.run();
                released++;
            } catch (Throwable t) {
                // One stubborn resource must not strand the others.
                Diag.warn("releasing " + e.name, t);
            }
        }
        return released;
    }

    /** Number of resources currently registered. */
    public static synchronized int size() {
        return ENTRIES.size();
    }
}
