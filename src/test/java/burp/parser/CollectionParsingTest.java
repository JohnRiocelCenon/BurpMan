package burp.parser;

import burp.models.PostmanCollection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trip coverage for the collection formats BurpMan claims to support.
 *
 * <p>Format detection used to be validated only by opening real files by hand.
 * These fixtures pin the behaviour so a change to one parser cannot silently
 * regress a neighbouring format.
 */
@DisplayName("Collection format detection and parsing")
class CollectionParsingTest {

    private static File write(Path dir, String name, String body) throws Exception {
        File f = dir.resolve(name).toFile();
        Files.write(f.toPath(), body.getBytes(StandardCharsets.UTF_8));
        return f;
    }

    @Test
    @DisplayName("Postman v2.1 collection is detected and parsed")
    void postmanCollection(@TempDir Path dir) throws Exception {
        File f = write(dir, "sample.postman_collection.json",
            "{\"info\":{\"name\":\"Sample\",\"schema\":"
          + "\"https://schema.getpostman.com/json/collection/v2.1.0/collection.json\"},"
          + "\"item\":[{\"name\":\"Ping\",\"request\":{\"method\":\"GET\","
          + "\"url\":{\"raw\":\"https://example.test/ping\"}}}]}");

        assertEquals(CollectionFormatDetector.Format.POSTMAN_COLLECTION_JSON,
            CollectionFormatDetector.detect(f));

        PostmanCollection c = new PostmanParser().parseCollection(f);
        assertNotNull(c, "collection must parse");
        assertNotNull(c.item, "items must parse");
        assertEquals(1, c.item.size());
        assertEquals("Ping", c.item.get(0).name);
    }

    @Test
    @DisplayName("Postman environment is detected as an environment, not a collection")
    void postmanEnvironment(@TempDir Path dir) throws Exception {
        File f = write(dir, "sample.postman_environment.json",
            "{\"id\":\"e1\",\"name\":\"Dev\",\"values\":["
          + "{\"key\":\"host\",\"value\":\"example.test\",\"enabled\":true}]}");

        assertEquals(CollectionFormatDetector.Format.POSTMAN_ENVIRONMENT_JSON,
            CollectionFormatDetector.detect(f));

        burp.models.PostmanEnvironment env = new PostmanParser().parseEnvironment(f);
        assertNotNull(env.values, "environment values must parse");
        assertTrue(env.values.stream().anyMatch(v ->
                "host".equals(v.key) && "example.test".equals(v.value) && v.enabled),
            "the enabled host variable must survive");
    }

    @Test
    @DisplayName("Bruno .bru request is detected")
    void brunoRequest(@TempDir Path dir) throws Exception {
        File f = write(dir, "ping.bru",
            "meta {\n  name: Ping\n  type: http\n  seq: 1\n}\n\n"
          + "get {\n  url: https://example.test/ping\n}\n");

        assertEquals(CollectionFormatDetector.Format.BRUNO_REQUEST_BRU,
            CollectionFormatDetector.detect(f));
    }

    @Test
    @DisplayName("Bruno environment .bru is detected as an environment")
    void brunoEnvironment(@TempDir Path dir) throws Exception {
        Path envDir = dir.resolve("environments");
        Files.createDirectories(envDir);
        File f = write(envDir, "dev.bru", "vars {\n  host: example.test\n}\n");

        assertEquals(CollectionFormatDetector.Format.BRUNO_ENVIRONMENT_BRU,
            CollectionFormatDetector.detect(f));
    }

    @Test
    @DisplayName("cURL with headers and a JSON body parses")
    void curlImport() {
        PostmanCollection.Request r = new CurlCommandParser().parse(
            "curl -X POST 'https://example.test/api/v1/login' "
          + "-H 'Content-Type: application/json' "
          + "-H 'X-Trace: abc' "
          + "--data '{\"user\":\"alice\"}'");

        assertNotNull(r, "curl must parse");
        assertEquals("POST", r.method);
        assertTrue(String.valueOf(r.url).contains("example.test/api/v1/login"),
            "url was: " + r.url);
        assertNotNull(r.header);
        assertTrue(r.header.stream().anyMatch(h ->
                "Content-Type".equalsIgnoreCase(h.key) && "application/json".equals(h.value)),
            "Content-Type header must survive");
        assertTrue(r.header.stream().anyMatch(h -> "X-Trace".equalsIgnoreCase(h.key)),
            "custom headers must survive");
        assertNotNull(r.body);
        assertTrue(String.valueOf(r.body.raw).contains("alice"), "body must survive");
    }

    @Test
    @DisplayName("cURL defaults to GET when no method is given")
    void curlDefaultsToGet() {
        PostmanCollection.Request r =
            new CurlCommandParser().parse("curl https://example.test/health");
        assertNotNull(r);
        assertEquals("GET", r.method);
    }
}
