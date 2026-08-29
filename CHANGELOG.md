# CHANGELOG

## 2.0.0 — Revamp

A correctness and safety pass over BurpMan 1.0.0. Every issue below was found
by auditing the 1.0.0 codebase, reproduced with a failing test, then fixed. The
suite went from **no tests at all** to **59 passing**, and the audit's original
probes now pass against the packaged jar rather than only in a test classpath.

---

### Fixed — script semantics no longer silently differ from Postman

`RhinoScriptEngine` rewrote every `let` and `const` to `var` before evaluation.
That made concatenated collection scripts parse, but it changed the meaning of
correct code. Measured against Node/V8:

| Case | 1.0.0 | 2.0.0 |
|---|---|---|
| `for (let i…)` closure capture | `3,3,3` | `0,1,2` |
| `let` shadowing in a nested block | leaks `inner` | `outer` |
| `const` reassignment | silently discarded | still rejected |

The shadowing case was the dangerous one. A script that shadows `jwtSecret`
inside a branch would sign with the wrong key and get a 401 that looks like a
server problem — no error, no warning, just a wrong value.

**Now:** the original source is compiled first, so correct scripts keep exact
V8 scoping. The `var` downgrade is applied only on retry, and only when Rhino
rejects the source for a genuine duplicate declaration. Cascaded scripts that
declare `const CryptoJS` two or three times still work.

Rhino has no per-iteration `let` binding of its own (confirmed against the raw
engine in `RawRhinoBaselineTest`), so loop bodies that create closures are
wrapped to restore it. Where the body uses `break`, `continue`, or `return` at
loop level the wrap would change control flow, so it is skipped and an explicit
warning is logged instead. Trading one silent wrong answer for another would
have missed the point.

### Fixed — collection scripts could reach the whole JVM

Scripts arrive inside `.postman_collection.json` and `.bru` files, which a
tester routinely receives from a client. `run()` used `initStandardObjects()`
with no `ClassShutter`, so all of the following were reachable from an imported
file — verified, not theorised:

```
java / Packages / JavaAdapter          reachable
java.lang.System.getProperty           reachable
java.io.File (arbitrary read/write)    reachable
java.lang.Runtime (process spawn)      reachable
Class.forName(...).getField("api")     reachable  ← the live MontoyaApi handle
```

That last one is the worst: `MontoyaApi` carries the tester's proxy history,
session state, and project credentials. Meanwhile `require()` rejected unknown
modules with *"not available in BurpMan script sandbox"* — telling users they
were contained when they were not.

**Now:** `initSafeStandardObjects()` removes the Java bridge entirely, and a
`ClassShutter` allowlist closes the residual `hostObject.getClass()` route. All
seven escapes are blocked in the shipped jar. `require('crypto-js')` and the
other supported shims are unaffected.

### Fixed — a runaway script pinned a core until Burp restarted

There was no instruction observer, so `while(true){}` in a pre-request script
consumed a thread and a CPU core forever with no way to cancel. This hung the
build the first time it was written as a test.

**Now:** a 15-second budget enforced through Rhino's instruction observer.
Time blocked in `pm.sendRequest` is credited back, so an OAuth chain calling
three token endpoints is not penalised for network wait.

### Fixed — client secrets accumulated in the tester's home directory

`ScriptExecutor.diag()` appended to `~/BurpMan-scripts.log` on every script
execution: always on, never rotated, no opt-out. The installation this was
found on had **1.9 MB across 16,474 lines** going back two months. Each entry
carried the first 80 characters of the script — comfortably enough for
`let jwtSecret = atob('Nnc5…=');`.

**Now:** `burp.util.Diag` is off by default (`-Dburpman.debug=true` to enable),
redacts JWTs / long base64 / named secrets, rotates at 5 MB, and writes beside
the workspace instead of `$HOME`. Script bodies are no longer logged at all;
redaction is the safety net, not the licence. The resolver diagnostic that
echoed the first 30 characters of the live token now reports only whether it
changed and its length.

### Fixed — every script ran twice

`runAndApply` executed the script through Rhino and then, if a JSR-223 engine
was present, ran the *same script again* "additively". Any `pm.sendRequest` in
a pre-request script fired twice. The JSR-223 setup also requested
`polyglot.js.allowAllAccess=true` and `allowHostClassLookup → true`, a wider
escape than the Rhino default it sat beside.

Separately, the regex scraper ran unconditionally after successful execution,
so a literal `pm.environment.set('token','PLACEHOLDER')` in a dead branch could
overwrite the value the engine had just computed.

**Now:** one execution path. The regex scraper is a recovery path that runs
only when execution failed.

### Fixed — `atob` silently returned empty for valid-in-practice base64

A 41-character key (`length % 4 == 1`) is rejected by Java's strict decoder.
The shim caught the exception and returned `""`, which flowed 60 lines
downstream into `HmacSHA256` and failed as *"Empty key"* — reported to the user
as a 401. Browsers and Node accept it.

**Now:** sanitised, re-padded, and decoded with a fallback chain, with an
empty-key guard in `CryptoJsHost`. Both are covered by `Base64ToleranceTest`
using the exact value from the original incident.

### Fixed — the packaged jar behaved differently from the test classpath

Discovered while verifying this release. `Class.getDeclaredMethod` resolves the
parameter types of *every* declared method on a class. A single helper with a
`MontoyaApi` parameter — `provided` scope, so present in Burp but absent from
the jar — made the whole `atob`/`btoa` registration throw
`NoClassDefFoundError`. `registerGlobalFn` swallowed it, and the user saw
"atob is not a function" pointing at line 1 of their own script.

The full suite passed throughout, because tests run against `target/classes`
with Montoya present. Only the artifact users install was broken.

**Now:** Montoya types are confined to `WatchdogHttp`, `registerGlobalFn`
throws instead of swallowing, and `EngineClassLoadingTest` fails the build if
any signature on `RhinoScriptEngine` reintroduces a provided-scope type.

### Fixed — saving a workspace could destroy it

`WorkspaceStore` was decompiler output, complete with unreachable `Throwable`
juggling and Vineflower's *"please report this to the issue tracker"* comments
shipped in a public MIT repo. Its `save()` truncated the file before
serialising, so a failure mid-write left an empty or half-written
`workspaces.json`.

**Now:** rewritten from intent. Saves go through a temporary file and an atomic
move, with a non-atomic fallback for OneDrive and network volumes that refuse
it. A corrupt store degrades to an empty list rather than blocking startup.

### Fixed — extension reloads leaked resources

Nothing implemented `ExtensionUnloadingHandler`. Reloading left the OAuth
callback server holding its port, so the next OAuth flow failed with "address
already in use", and static sinks kept references to a dead panel.

**Now:** `burp.util.ResourceRegistry` tracks cleanups and runs them
newest-first on unload, isolating failures so one stuck resource cannot strand
the rest. Static handles are cleared.

### Changed — one script engine instead of three

Removed `NashornScriptEngine` (666 LOC) and `ScriptInterpreter` (1,586 LOC),
along with the dead JSR-223 path and the `nashorn-core` dependency. Rhino
handles every real-world case and is bundled in both flavours.

The cost of three engines was concrete, not theoretical: the `atob` fix had to
be applied in three separate files to take effect. The user-facing
`Engine: Auto/Full/Legacy` toggle is gone rather than left as a control that
does nothing.

The full jar is **4.16 MB, down from 6.59 MB**.

### Changed — failures are observable

240 `catch (Throwable ignore) {}` blocks made problems invisible; the `atob`
bug survived as long as it did because of one of them. The core script, request,
and parser paths now report through `Diag.warn` with the originating file and
line, behind the same debug flag.

### Changed — the build enforces its own standards

Compiles clean at `-Xlint:all` (100 warnings → 0). `serial` and `this-escape`
are suppressed in the POM with a written rationale: Swing components are
subclassed throughout and never serialised, and `this-escape` fires on the
conventional listener-registration pattern. Every other category must stay at
zero.

---

### Test suite

59 tests across 10 classes, from zero.

| Class | Guards |
|---|---|
| `ScriptSemanticsTest` | 16 V8-parity cases, including the three 1.0.0 failed |
| `SandboxTest` | all 7 escapes, the watchdog, and that legitimate shims still work |
| `Base64ToleranceTest` | the exact value from the 401 incident, end to end |
| `EngineClassLoadingTest` | provided-scope types cannot break the packaged jar |
| `CollectionParsingTest` | Postman v2.1, environments, Bruno `.bru`, cURL |
| `DiagTest` | off by default, redaction, sink isolation |
| `ResourceRegistryTest` | unload ordering, failure isolation, idempotence |
| `WorkspaceStoreTest` | round-trip, corruption tolerance, no temp-file leaks |
| `RawRhinoBaselineTest` | records raw-engine behaviour, so "ours or theirs?" is answerable |

### Known limitations

- **`const` reassignment does not throw `TypeError`.** Rhino discards the write
  silently. The value is never corrupted, which is the property that matters,
  but it is not strict V8 behaviour. Recorded in `RawRhinoBaselineTest`.
- **Loop bodies using `break`/`continue`/`return` do not get per-iteration
  bindings.** The rewrite would change control flow, so a warning is logged and
  the source left alone.
- **The 15-second script budget is not yet user-configurable** from the UI.
  `RhinoScriptEngine.withTimeout(long)` exists for callers.
