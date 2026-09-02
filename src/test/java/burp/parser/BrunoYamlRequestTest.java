package burp.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.models.PostmanCollection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Request parsing for Bruno's {@code opencollection: 1.0.0} format.
 *
 * <p>OpenCollection switches an entry off with {@code disabled: true}; older
 * Bruno YAML uses {@code enabled: false}. Reading only the latter sent headers
 * the author had explicitly turned off — a disabled {@code ip: 127.0.0.1}
 * spoofing header went out to a live host, which is both wrong and the kind of
 * thing that gets noticed at the far end.
 */
class BrunoYamlRequestTest {

    @TempDir
    Path tmp;

    private PostmanCollection.Item parse(String yaml) throws Exception {
        File f = tmp.resolve("req.yml").toFile();
        Files.write(f.toPath(), yaml.getBytes(StandardCharsets.UTF_8));
        return BrunoYamlParser.parseRequestFile(f);
    }

    private PostmanCollection.Header header(PostmanCollection.Item item, String key) {
        for (PostmanCollection.Header h : item.request.header) {
            if (key.equalsIgnoreCase(h.key)) return h;
        }
        return null;
    }

    @Test
    void headerMarkedDisabledIsNotActive() throws Exception {
        PostmanCollection.Item item = parse(
                "info:\n"
                        + "  name: initialize\n"
                        + "  type: http\n"
                        + "http:\n"
                        + "  method: POST\n"
                        + "  url: https://example.com/a\n"
                        + "  headers:\n"
                        + "    - name: Content-Type\n"
                        + "      value: application/json\n"
                        + "    - name: ip\n"
                        + "      value: 127.0.0.1\n"
                        + "      disabled: true\n");

        assertFalse(header(item, "Content-Type").disabled, "an unmarked header stays active");
        assertTrue(header(item, "ip").disabled, "disabled: true must switch the header off");
    }

    /** The older Bruno spelling must keep working. */
    @Test
    void headerMarkedEnabledFalseIsNotActive() throws Exception {
        PostmanCollection.Item item = parse(
                "info:\n"
                        + "  name: initialize\n"
                        + "http:\n"
                        + "  method: GET\n"
                        + "  url: https://example.com/a\n"
                        + "  headers:\n"
                        + "    - name: ip\n"
                        + "      value: 127.0.0.1\n"
                        + "      enabled: false\n");

        assertTrue(header(item, "ip").disabled);
    }

    @Test
    void formFieldMarkedDisabledIsNotActive() throws Exception {
        PostmanCollection.Item item = parse(
                "info:\n"
                        + "  name: form\n"
                        + "http:\n"
                        + "  method: POST\n"
                        + "  url: https://example.com/a\n"
                        + "  body:\n"
                        + "    type: form-urlencoded\n"
                        + "    data:\n"
                        + "      - name: live\n"
                        + "        value: yes\n"
                        + "      - name: off\n"
                        + "        value: no\n"
                        + "        disabled: true\n");

        PostmanCollection.UrlEncoded live = null;
        PostmanCollection.UrlEncoded off = null;
        for (PostmanCollection.UrlEncoded p : item.request.body.urlencoded) {
            if ("live".equals(p.key)) live = p;
            if ("off".equals(p.key)) off = p;
        }
        assertFalse(live.disabled);
        assertTrue(off.disabled, "disabled: true must switch the field off");
    }

    /**
     * A URL keeps the space its author wrote; encoding happens at send time.
     *
     * <p>Note this parser stores {@code url} as a plain string, while the
     * Postman path stores a {@code Url} object — {@code request.url} is declared
     * {@code Object} for exactly that reason.
     */
    @Test
    void urlWithASpaceInAQueryValueIsPreserved() throws Exception {
        PostmanCollection.Item item = parse(
                "info:\n"
                        + "  name: authorize\n"
                        + "http:\n"
                        + "  method: GET\n"
                        + "  url: https://example.com/authorize?scope=openid ciam&state=x\n");

        assertEquals("https://example.com/authorize?scope=openid ciam&state=x",
                String.valueOf(item.request.url));
    }
}
