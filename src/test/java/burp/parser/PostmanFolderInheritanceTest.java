package burp.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.models.PostmanCollection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Postman v2.1 folder inheritance, alongside the Bruno work.
 *
 * <p>Adding folder headers for Bruno introduced a field Postman has no concept
 * of — its v2.1 schema gives a folder {@code name}, {@code item}, {@code event},
 * {@code auth}, {@code description} and {@code variable}, but no headers. The
 * field is therefore {@code transient} so Gson can never populate it from
 * collection JSON, and these tests pin that: a Postman collection must behave
 * exactly as it did before.
 */
class PostmanFolderInheritanceTest {

    @TempDir
    Path tmp;

    private PostmanCollection parse(String json) throws Exception {
        File f = tmp.resolve("c.postman_collection.json").toFile();
        Files.write(f.toPath(), json.getBytes(StandardCharsets.UTF_8));
        return new PostmanParser().parseCollection(f);
    }

    private static final String NESTED =
            "{\n"
                    + "  \"info\": { \"name\": \"PM\", \"schema\": \"https://schema.getpostman.com/json/collection/v2.1.0/collection.json\" },\n"
                    + "  \"auth\": { \"type\": \"bearer\", \"bearer\": [ { \"key\": \"token\", \"value\": \"{{collToken}}\" } ] },\n"
                    + "  \"event\": [ { \"listen\": \"prerequest\", \"script\": { \"exec\": [ \"console.log('coll');\" ] } } ],\n"
                    + "  \"item\": [\n"
                    + "    {\n"
                    + "      \"name\": \"Secure\",\n"
                    + "      \"auth\": { \"type\": \"bearer\", \"bearer\": [ { \"key\": \"token\", \"value\": \"{{folderToken}}\" } ] },\n"
                    + "      \"event\": [ { \"listen\": \"prerequest\", \"script\": { \"exec\": [ \"console.log('folder');\" ] } } ],\n"
                    + "      \"item\": [\n"
                    + "        { \"name\": \"Get Thing\",\n"
                    + "          \"request\": { \"method\": \"GET\", \"url\": { \"raw\": \"https://example.com/thing\" },\n"
                    + "            \"header\": [ { \"key\": \"X-Own\", \"value\": \"mine\" } ] } }\n"
                    + "      ]\n"
                    + "    }\n"
                    + "  ]\n"
                    + "}\n";

    private PostmanCollection.Item folder(PostmanCollection c, String name) {
        for (PostmanCollection.Item it : c.item) {
            if (name.equals(it.name)) return it;
        }
        return null;
    }

    private boolean hasEvent(List<PostmanCollection.Event> events, String listen) {
        if (events == null) return false;
        for (PostmanCollection.Event e : events) {
            if (e != null && listen.equalsIgnoreCase(e.listen)) return true;
        }
        return false;
    }

    /** The field added for Bruno must stay absent on the Postman path. */
    @Test
    void postmanFoldersGainNoHeaders() throws Exception {
        PostmanCollection c = parse(NESTED);

        assertNull(c.folderHeaders, "a Postman collection declares no folder headers");
        assertNull(folder(c, "Secure").folderHeaders,
                "a Postman folder has no headers in the v2.1 schema");
    }

    /** Gson must not populate the transient field even if JSON supplies it. */
    @Test
    void folderHeadersAreNotDeserializedFromJson() throws Exception {
        PostmanCollection c = parse(
                "{\n"
                        + "  \"info\": { \"name\": \"PM\", \"schema\": \"https://schema.getpostman.com/json/collection/v2.1.0/collection.json\" },\n"
                        + "  \"folderHeaders\": [ { \"key\": \"X-Injected\", \"value\": \"nope\" } ],\n"
                        + "  \"item\": [\n"
                        + "    { \"name\": \"F\",\n"
                        + "      \"folderHeaders\": [ { \"key\": \"X-Injected\", \"value\": \"nope\" } ],\n"
                        + "      \"item\": [ { \"name\": \"R\", \"request\": { \"method\": \"GET\", \"url\": \"https://e.com/\" } } ] }\n"
                        + "  ]\n"
                        + "}\n");

        assertNull(c.folderHeaders, "transient must keep Gson out");
        assertNull(folder(c, "F").folderHeaders);
    }

    /** Folder and collection auth must still parse as before. */
    @Test
    void folderAndCollectionAuthStillParse() throws Exception {
        PostmanCollection c = parse(NESTED);

        assertNotNull(c.auth);
        assertEquals("bearer", c.auth.type);
        assertNotNull(folder(c, "Secure").auth);
        assertEquals("bearer", folder(c, "Secure").auth.type);
    }

    /** Folder and collection scripts must still parse as before. */
    @Test
    void folderAndCollectionScriptsStillParse() throws Exception {
        PostmanCollection c = parse(NESTED);

        assertTrue(hasEvent(c.event, "prerequest"), "collection pre-request script");
        assertTrue(hasEvent(folder(c, "Secure").event, "prerequest"), "folder pre-request script");
    }

    /** A request's own headers are untouched. */
    @Test
    void requestHeadersAreUnchanged() throws Exception {
        PostmanCollection c = parse(NESTED);
        PostmanCollection.Item request = folder(c, "Secure").item.get(0);

        assertNotNull(request.request.header);
        assertEquals(1, request.request.header.size());
        assertEquals("X-Own", request.request.header.get(0).key);
    }
}
