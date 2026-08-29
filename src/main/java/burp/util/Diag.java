package burp.util;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Opt-in diagnostic logging with secret redaction and bounded growth.
 *
 * <h2>Why this replaced the previous logger</h2>
 * The original wrote every script execution — including an 80-character
 * preview of the script source — to {@code ~/BurpMan-scripts.log}. It was
 * always on, never rotated, and had no opt-out. A real installation was found
 * carrying 1.9 MB across 16,474 lines accumulated over two months.
 *
 * <p>That is a client-data problem, not just a tidiness one. Collections used
 * on an engagement routinely contain lines like
 * {@code let jwtSecret = atob('Nnc5...=');} — comfortably inside 80
 * characters — so signing keys belonging to a client were being written to the
 * tester's home directory and left there indefinitely.
 *
 * <p>Three changes address it:
 * <ul>
 *   <li><b>Off by default.</b> Enable with {@code -Dburpman.debug=true} or
 *       {@link #setEnabled}.</li>
 *   <li><b>Redacted.</b> Long base64/hex runs, JWTs, and
 *       {@code secret=}/{@code password=} style assignments are masked before
 *       anything is written.</li>
 *   <li><b>Bounded.</b> Rotates at 5 MB keeping one previous generation, and
 *       lives beside the workspace rather than in {@code $HOME}.</li>
 * </ul>
 */
public final class Diag {

    private static final long MAX_BYTES = 5L * 1024 * 1024;

    private static final DateTimeFormatter TS =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static volatile boolean enabled =
        Boolean.parseBoolean(System.getProperty("burpman.debug", "false"));

    private static volatile Path logFile = defaultLogFile();

    /** Notified for every message so the in-app console can mirror it. */
    private static volatile java.util.function.Consumer<String> sink;

    private Diag() {}

    public static boolean isEnabled() {
        return enabled;
    }

    /** Turns file logging on or off at runtime. Off by default. */
    public static void setEnabled(boolean value) {
        enabled = value;
    }

    public static void setLogFile(Path file) {
        if (file != null) logFile = file;
    }

    public static Path getLogFile() {
        return logFile;
    }

    public static void setSink(java.util.function.Consumer<String> consumer) {
        sink = consumer;
    }

    private static Path defaultLogFile() {
        String home = System.getProperty("user.home", ".");
        return Paths.get(home, "BurpMan-Workspaces", "diagnostics", "burpman.log");
    }

    /** Records a diagnostic line. No-op unless debug logging is enabled. */
    public static void log(String message) {
        if (message == null) return;
        String safe = redact(message);

        java.util.function.Consumer<String> s = sink;
        if (s != null) {
            try {
                s.accept(safe);
            } catch (RuntimeException e) {
                // A failing UI sink must never break the caller's work.
            }
        }

        if (!enabled) return;
        write("[" + LocalDateTime.now().format(TS) + "] " + safe);
    }

    /** Records a failure that would otherwise be swallowed by an empty catch. */
    public static void warn(String context, Throwable t) {
        if (t == null) {
            log("WARN  " + context);
            return;
        }
        log("WARN  " + context + " — " + t.getClass().getSimpleName()
            + ": " + t.getMessage());
    }

    private static synchronized void write(String line) {
        try {
            Path file = logFile;
            Path parent = file.getParent();
            if (parent != null) Files.createDirectories(parent);
            rotateIfOversized(file);
            try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw")) {
                raf.seek(raf.length());
                raf.write((line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            // Diagnostics are best-effort; never let them break a request.
        }
    }

    private static void rotateIfOversized(Path file) throws IOException {
        if (!Files.exists(file) || Files.size(file) < MAX_BYTES) return;
        Path previous = file.resolveSibling(file.getFileName() + ".1");
        Files.move(file, previous, StandardCopyOption.REPLACE_EXISTING);
    }

    // ---------------------------------------------------------------
    // Redaction
    // ---------------------------------------------------------------

    /** {@code eyJ...} JWTs, which carry claims and are signed with a client key. */
    private static final Pattern JWT =
        Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]+");

    /** {@code secret: "..."} / {@code password=...} / {@code apiKey: ...} assignments. */
    private static final Pattern NAMED_SECRET = Pattern.compile(
        "(?i)\\b(secret|password|passwd|pwd|api[-_]?key|access[-_]?token|refresh[-_]?token"
      + "|client[-_]?secret|authorization|bearer)\\b(\\s*[:=]\\s*)"
      + "(\"[^\"]*\"|'[^']*'|[^\\s,;)}]+)");

    /** Standalone base64/hex runs long enough to be key material. */
    private static final Pattern LONG_OPAQUE =
        Pattern.compile("\\b[A-Za-z0-9+/_-]{24,}={0,2}");

    static String redact(String input) {
        String out = JWT.matcher(input).replaceAll("<redacted-jwt>");
        out = NAMED_SECRET.matcher(out).replaceAll("$1$2<redacted>");

        // Mask long opaque runs, but keep anything that reads as a normal
        // identifier — a readable log is the whole point.
        Matcher m = LONG_OPAQUE.matcher(out);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String token = m.group();
            m.appendReplacement(sb, Matcher.quoteReplacement(
                looksLikeProse(token) ? token : "<redacted:" + token.length() + "ch>"));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Heuristic: real key material is dense in digits and mixed case, whereas
     * a long identifier such as {@code getCascadedTestScriptsForFolder} is not.
     */
    private static boolean looksLikeProse(String token) {
        int digits = 0, uppers = 0;
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (Character.isDigit(c)) digits++;
            else if (Character.isUpperCase(c)) uppers++;
        }
        double digitRatio = digits / (double) token.length();
        double upperRatio = uppers / (double) token.length();
        return digitRatio < 0.15 && upperRatio < 0.35;
    }
}
