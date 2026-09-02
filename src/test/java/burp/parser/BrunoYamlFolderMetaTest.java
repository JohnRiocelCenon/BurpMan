package burp.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.models.PostmanCollection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Folder-level inheritance in Bruno's {@code opencollection: 1.0.0} format.
 *
 * <p>A folder descriptor carries headers, auth, and scripts that apply to every
 * request beneath it. Reading only the auth produced requests that were
 * authenticated but not identified: the server answered 401 while the
 * Authorization header looked perfectly valid, which sends the reader after the
 * token rather than the six missing headers.
 */
class BrunoYamlFolderMetaTest {

    @TempDir
    Path tmp;

    private PostmanCollection.Item folderFrom(String yaml) throws Exception {
        File f = tmp.resolve("folder.yml").toFile();
        Files.write(f.toPath(), yaml.getBytes(StandardCharsets.UTF_8));
        PostmanCollection.Item folder = new PostmanCollection.Item();
        BrunoYamlParser.applyFolderMeta(folder, f);
        return folder;
    }

    private String headerValue(PostmanCollection.Item folder, String key) {
        if (folder.folderHeaders == null) return null;
        for (PostmanCollection.Header h : folder.folderHeaders) {
            if (key.equalsIgnoreCase(h.key)) return h.value;
        }
        return null;
    }

    private boolean hasScript(PostmanCollection.Item folder, String listen) {
        if (folder.event == null) return false;
        for (PostmanCollection.Event e : folder.event) {
            if (e != null && listen.equalsIgnoreCase(e.listen)) return true;
        }
        return false;
    }

    @Test
    void folderHeadersAreRead() throws Exception {
        PostmanCollection.Item folder = folderFrom(
                "info:\n"
                        + "  name: Member\n"
                        + "  type: folder\n"
                        + "request:\n"
                        + "  headers:\n"
                        + "    - name: x-identity-id\n"
                        + "      value: \"{{gb.identity.id}}\"\n"
                        + "    - name: x-provider\n"
                        + "      value: \"{{gb.provider}}\"\n"
                        + "  auth:\n"
                        + "    type: bearer\n"
                        + "    token: \"{{gb.apim.access.token}}\"\n");

        assertNotNull(folder.folderHeaders, "folder headers must be captured");
        assertEquals(2, folder.folderHeaders.size());
        assertEquals("{{gb.identity.id}}", headerValue(folder, "x-identity-id"));
        assertEquals("{{gb.provider}}", headerValue(folder, "x-provider"));
    }

    /** Auth must keep working alongside the newly-read headers. */
    @Test
    void folderAuthStillParses() throws Exception {
        PostmanCollection.Item folder = folderFrom(
                "info:\n"
                        + "  name: Member\n"
                        + "request:\n"
                        + "  headers:\n"
                        + "    - name: x-provider\n"
                        + "      value: gb\n"
                        + "  auth:\n"
                        + "    type: bearer\n"
                        + "    token: \"{{tok}}\"\n");

        assertNotNull(folder.auth);
        assertEquals("bearer", folder.auth.type);
        assertNotNull(folder.folderHeaders);
    }

    /**
     * OpenCollection nests folder scripts under {@code request.scripts}; older
     * Bruno YAML uses a top-level {@code runtime.scripts}. Reading only the
     * latter means the folder's pre-request hook never runs, and nothing says so.
     */
    @Test
    void folderScriptsUnderRequestAreRead() throws Exception {
        PostmanCollection.Item folder = folderFrom(
                "info:\n"
                        + "  name: Member\n"
                        + "request:\n"
                        + "  scripts:\n"
                        + "    - type: before-request\n"
                        + "      code: |-\n"
                        + "        bru.setVar(\"ran\", \"yes\");\n");

        assertTrue(hasScript(folder, "prerequest"),
                "a script under request.scripts must still register");
    }

    /** The older location must keep working. */
    @Test
    void folderScriptsUnderRuntimeAreStillRead() throws Exception {
        PostmanCollection.Item folder = folderFrom(
                "info:\n"
                        + "  name: Member\n"
                        + "runtime:\n"
                        + "  scripts:\n"
                        + "    - type: before-request\n"
                        + "      code: |-\n"
                        + "        bru.setVar(\"ran\", \"yes\");\n");

        assertTrue(hasScript(folder, "prerequest"));
    }

    /** A folder with neither headers nor scripts stays clean, not empty-listed. */
    @Test
    void folderWithoutHeadersLeavesFieldNull() throws Exception {
        PostmanCollection.Item folder = folderFrom(
                "info:\n"
                        + "  name: Member\n"
                        + "request:\n"
                        + "  auth:\n"
                        + "    type: bearer\n"
                        + "    token: \"{{tok}}\"\n");

        assertEquals(null, folder.folderHeaders);
    }

    /** A disabled folder header is captured as disabled, not silently active. */
    @Test
    void disabledFolderHeaderIsMarkedDisabled() throws Exception {
        PostmanCollection.Item folder = folderFrom(
                "info:\n"
                        + "  name: Member\n"
                        + "request:\n"
                        + "  headers:\n"
                        + "    - name: x-live\n"
                        + "      value: yes\n"
                        + "    - name: x-off\n"
                        + "      value: no\n"
                        + "      disabled: true\n");

        assertNotNull(folder.folderHeaders);
        for (PostmanCollection.Header h : folder.folderHeaders) {
            if ("x-off".equalsIgnoreCase(h.key)) assertTrue(h.disabled);
            if ("x-live".equalsIgnoreCase(h.key)) assertFalse(h.disabled);
        }
    }
}
