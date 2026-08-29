package burp.ui;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trip and durability coverage for the workspace store.
 *
 * <p>The previous implementation was decompiler output whose {@code save()}
 * truncated the file before serialising, so any failure mid-write destroyed
 * the user's saved session list.
 */
@DisplayName("Workspace persistence")
class WorkspaceStoreTest {

    @Test
    @DisplayName("a recorded session survives a reload")
    void roundTrip(@TempDir Path dir) {
        File store = dir.resolve("workspaces.json").toFile();

        WorkspaceStore first = new WorkspaceStore(store);
        first.recordSession(
            Arrays.asList("C:\\collections\\api.postman_collection.json"),
            Arrays.asList("C:\\collections\\dev.postman_environment.json"),
            "C:\\collections\\dev.postman_environment.json",
            "Auth/Login");

        WorkspaceStore reloaded = new WorkspaceStore(store);
        WorkspaceStore.Workspace w = reloaded.getDefault();

        assertNotNull(w);
        assertEquals(Arrays.asList("C:\\collections\\api.postman_collection.json"),
            w.collectionPaths);
        assertEquals("Auth/Login", w.activeRequestKey);
        assertTrue(w.savedAtEpochMs > 0, "timestamp should be recorded");
    }

    @Test
    @DisplayName("a corrupt store degrades to empty instead of failing to load")
    void corruptStoreIsTolerated(@TempDir Path dir) throws Exception {
        File store = dir.resolve("workspaces.json").toFile();
        Files.write(store.toPath(), "{ this is not valid json".getBytes(StandardCharsets.UTF_8));

        // Construction must not throw — a bad file cannot block the extension.
        WorkspaceStore s = new WorkspaceStore(store);
        assertTrue(s.getWorkspaceNames().isEmpty());
    }

    @Test
    @DisplayName("no temporary files are left behind after a save")
    void noTempFilesLeak(@TempDir Path dir) throws Exception {
        File store = dir.resolve("workspaces.json").toFile();
        WorkspaceStore s = new WorkspaceStore(store);
        s.recordSession(Arrays.asList("a.json"), Arrays.asList(), null, null);

        try (Stream<Path> entries = Files.list(dir)) {
            assertTrue(entries.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")),
                "atomic save must clean up its temporary file");
        }
    }

    @Test
    @DisplayName("an absent store starts empty rather than throwing")
    void missingStoreIsFine(@TempDir Path dir) {
        WorkspaceStore s = new WorkspaceStore(dir.resolve("never-written.json").toFile());
        assertTrue(s.getWorkspaceNames().isEmpty());
        assertNotNull(s.getDefault(), "a default workspace is created on demand");
    }
}
