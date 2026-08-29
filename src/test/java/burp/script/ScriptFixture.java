package burp.script;

import burp.models.ScriptContext;
import burp.service.RhinoScriptEngine;

/** Shared helper for script-level tests: run a snippet, return what it logged. */
final class ScriptFixture {

    private ScriptFixture() {}

    /** Runs {@code js} and returns the text of the final {@code console.log}. */
    static String lastLog(String js) throws Exception {
        ScriptContext ctx = new ScriptContext();
        new RhinoScriptEngine(ctx, null).run(js);
        return tailLog(ctx);
    }

    /** Runs {@code js}, swallowing script errors, and returns the final log line. */
    static String lastLogQuiet(String js) {
        ScriptContext ctx = new ScriptContext();
        try {
            new RhinoScriptEngine(ctx, null).run(js);
        } catch (Throwable ignored) {
            // Caller is asserting on logged output, not on the throw.
        }
        return tailLog(ctx);
    }

    private static String tailLog(ScriptContext ctx) {
        String all = String.valueOf(ctx.getConsoleOutput());
        int i = all.lastIndexOf("[script log] ");
        if (i < 0) return "";
        String tail = all.substring(i + "[script log] ".length());
        int nl = tail.indexOf('\n');
        return (nl < 0 ? tail : tail.substring(0, nl)).trim();
    }
}
