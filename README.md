# BurpManRevamped

[![Burp Suite Extension](https://img.shields.io/badge/Burp%20Suite-Extension-orange)](https://portswigger.net/burp)
[![Java](https://img.shields.io/badge/Java-11+-blue)](https://www.java.com)
[![Version](https://img.shields.io/badge/Version-2.1.0-brightgreen)](https://github.com/JohnRiocelCenon/BurpMan/releases)
[![Tests](https://img.shields.io/badge/Tests-231%20passing-brightgreen)](#-testing)

A Burp Suite extension that imports **Postman** and **Bruno** API collections, with full variable resolution, pre/post-request script execution, OAuth2/JWT auth management, and a built-in request builder — all without leaving Burp.

If you know Postman, you already know 90% of this tool. The big difference: every request you send also goes through Burp Suite, so you can scan it.

> **This is the revamped 2.x line.** It fixes script-semantics bugs that
> produced silently-wrong values, sandboxes collection scripts, and adds the
> first regression suite. See [CHANGELOG.md](CHANGELOG.md) for the full list
> with reproductions.

---

## 🚀 Features

- 📁 **Postman Collection v2.0 & v2.1** support
- 🐾 **Bruno collection** support — `.bru` files, single-file JSON exports, and **OpenCollection 1.0.0** YAML directories
- 📤 **Export to Postman or Bruno** — write the loaded collection back out as `.postman_collection.json`, or as an OpenCollection folder Bruno opens directly
- 📥 **OpenAPI 3.x / Swagger 2 import** — load any `.json` / `.yaml` spec straight into a collection
- 🔧 **Variable resolution** — environment files, manual entry, smart detection
- 🎲 **80+ dynamic faker variables** — `{{$randomFullName}}`, `{{$randomCity}}`, `{{$randomMacAddress}}`, `{{$randomLoremParagraph}}`, …
- 📝 **Pre/Post-request scripts** — ES2015+ with real closures, destructuring, template literals, optional chaining, nullish coalescing, and **V8-faithful `let`/`const` scoping**; Postman and Bruno scripts run unmodified
- 🔒 **Sandboxed script execution** — imported collections cannot reach the JVM, the filesystem, or your Burp session
- 🔐 **11 auth schemes** — Bearer, Basic, API Key, OAuth2, OAuth 1.0a, AWS Signature v4, Digest, Hawk, Akamai EdgeGrid, ASAP, NTLM
- 🪟 **Interactive OAuth2 without a proxy** — the authorization-code flow runs in a dedicated Chromium window and the callback is read straight from the browser, so the callback host never has to be reachable and nothing has to be proxied
- 🗂️ **Folder-level auth overrides**
- 📊 **Data-driven runs** — feed a CSV or JSON-array file and a folder runs once per row (Postman-style)
- 📋 **Copy as code** — generate snippets in **15 languages / libraries**: curl (bash / cmd), Python (requests / httpx), JavaScript (fetch / axios), Node http, Java (OkHttp / HttpClient5), Go, PowerShell, PHP, Ruby, Rust, C#
- 📜 **Request history** with full response details
- 🍪 **Cookie jar** management with parent-domain replay (SSO-friendly)
- 🌲 **Collection tree** with drag-and-drop reordering
- ⚡ **Auto-run** collections with progress tracking
- 🎨 **Custom UI theme** integrated into Burp Suite

---

## 🔒 Security model

Collection files are **untrusted input**. A `.postman_collection.json` handed
over at the start of an engagement contains executable JavaScript, and it runs
inside your Burp process alongside your proxy history and project credentials.

BurpManRevamped treats it that way:

| Control | Behaviour |
|---|---|
| **Java bridge** | Removed. No `java`, `Packages`, `JavaAdapter`, or `importClass`. |
| **Reflection** | Blocked by a `ClassShutter` allowlist, including the `hostObject.getClass()` route. |
| **Filesystem / process** | Unreachable. `java.io.File` and `java.lang.Runtime` are not visible to scripts. |
| **Runaway scripts** | 15-second budget via Rhino's instruction observer. Network wait in `pm.sendRequest` is credited back. |
| **Diagnostic logging** | Off by default. When enabled, JWTs, long base64, and named secrets are redacted; script bodies are never written. |

`require()` resolves `crypto-js`, `atob`, `btoa`, and `moment`. Anything else
is rejected — and that rejection is now genuinely enforced rather than advisory.

Enable debug logging when you need it:

```bash
# Writes to ~/BurpMan-Workspaces/diagnostics/burpman.log (redacted, 5 MB cap)
-Dburpman.debug=true
```

---

## 📋 Requirements

- Burp Suite Professional or Community Edition
- **Java 11+**; Burp 2024+ ships with JDK 21 — no extra setup needed
- Maven (to build from source)

---

## 🛠️ Installation

### Option 1: Download Release

1. Download the latest JAR from [Releases](https://github.com/JohnRiocelCenon/BurpMan/releases)
2. In Burp Suite: `Extensions` → `Add` → Select the JAR file
3. The **BurpMan** tab will appear

### Option 2: Build from Source

```bash
git clone https://github.com/JohnRiocelCenon/BurpMan.git
cd BurpMan

# Lite build (~1 MB) — Rhino script engine, core auth, all parsers
mvn clean package
# → target/BurpManRevamped-2.1.0-lite-jar-with-dependencies.jar

# Full build (~4.2 MB) — adds RSyntaxTextArea syntax highlighting and
# commons-codec for AWS SigV4 / OAuth1 / EdgeGrid signing
mvn -Pfull clean package
# → target/BurpManRevamped-2.1.0-full-jar-with-dependencies.jar
```

Both flavours bundle the Rhino script engine, so scripts behave identically in
each. The difference is optional extras, not script capability.

---

## 🧪 Testing

```bash
mvn test              # 231 tests
mvn clean verify      # tests + both jars
```

The suite exists because 1.0.0 had none, and the bugs it shipped were the kind
only a test catches — wrong values rather than exceptions.

| Class | Guards |
|---|---|
| `ScriptSemanticsTest` | V8 parity: loop capture, block scoping, `const`, spread, optional chaining |
| `SandboxTest` | Every known escape path, the watchdog, and that `crypto-js` still works |
| `Base64ToleranceTest` | The malformed-base64 key that caused a production 401 |
| `EngineClassLoadingTest` | A `provided`-scope type cannot silently break the packaged jar |
| `CollectionParsingTest` | Postman v2.1, environments, Bruno `.bru`, cURL round-trips |
| `MultiLineScalarTest` | Quoted YAML scalars that run past their own line, so a JSON body is not truncated |
| `BrunoCollectionExporterTest` | Every export round-trips back through the Bruno parser; names cannot escape the folder |
| `OpenCollectionOAuth2Test` | The nested `credentials.clientId` shape OpenCollection uses |
| `OAuthCallbackParserTest` | Authorization responses in a query, a fragment, or pasted bare |
| `DiagTest` | Logging off by default, redaction, sink isolation |
| `ResourceRegistryTest` | Unload ordering, failure isolation, idempotence |
| `WorkspaceStoreTest` | Round-trip, corruption tolerance, no temp-file leaks |
| `RawRhinoBaselineTest` | Records raw-engine behaviour so "our bug or theirs?" is answerable |

The build compiles clean at `-Xlint:all`.

---

## 📖 Quick Start

| In Postman you do this... | In BurpMan you do this... |
|---|---|
| Import a collection | Click **Browse...** next to *Collection:* |
| Pick an environment | Use the **Environment** dropdown |
| Edit globals | Nothing — loaded automatically from the same folder |
| Open a request | Click it in the tree on the left |
| Run one folder only | Right-click folder → **▶ Analyze this Folder** |
| Set variables manually | Click **Set Variables** |
| Write a pre-request script | Open the **Pre-request Script** tab |
| Send the request | Click **Send** |
| Get an OAuth 2 token | Auth Manager → pick config → **Get New Access Token** |

### Basic workflow

1. Click **Browse...** and load your `.postman_collection.json` or Bruno file — the tree fills up instantly.
2. Click **Add...** to load an environment file, then select it from the dropdown.
3. Click **Analyze** (or right-click a folder → **▶ Analyze this Folder**) to resolve variables, detect auth, and run scripts.
4. Click any request → review in the **Request Builder** → click **Send**.
5. Right-click any request to **Send to Repeater**, **Send to Intruder**, or **Send to Organizer**.

---

## 🖼️ Screenshots

Screenshots are not committed to this repository. They were captured against
real client collections during testing, and a public repository is the wrong
place for that, so they were removed rather than redacted.

---

## 🔧 Variables

| Source | Priority |
|---|---|
| Manual (Set Variables) | Highest |
| Environment file | High |
| Globals file (auto-loaded) | Medium |
| Collection variables | Lowest |

**Built-in dynamic variables:** `{{$guid}}`, `{{$timestamp}}`, `{{$isoTimestamp}}`, `{{$randomInt}}`, `{{$randomEmail}}`, `{{$randomFirstName}}`, `{{$randomBoolean}}`

---

## 📝 Scripts (`pm.*`)

Write JavaScript-style scripts in the **Pre-request Script** and **Tests** tabs:

```js
// Pre-request: set a value before sending
pm.environment.set("nonce", Date.now().toString());

// Tests: capture a token from the response
const data = pm.response.json();
pm.environment.set("token", data.access_token);
```

Supported: `pm.environment`, `pm.globals`, `pm.collectionVariables`, `pm.response.json/text/headers`, `console.log`, standard `Math.*` / `JSON.*` / `Date`.

---

## 🔐 Authentication

- **Bearer / Basic / API Key** — set per-request or inherit from parent folder
- **OAuth2** — all grant types (client_credentials, password, authorization_code, implicit)
- **JWT** — auto-detected; auto-refreshes when within 30s of expiry
- **Folder-level overrides** — right-click any folder to set its own auth

---

> For a full step-by-step guide, see [TUTORIAL.md](TUTORIAL.md).

---

## 🙏 Inspiration

This project was inspired by [**postman-burp-importer**](https://github.com/nerdygenii/postman-burp-importer) by [@nerdygenii](https://github.com/nerdygenii) — a great Burp Suite extension for importing Postman collections. BurpMan builds on that concept with extended format support, script execution, and a richer auth/variable management system.

---

## 📄 License

MIT — see [LICENSE](LICENSE) and [NOTICES](NOTICES) for third-party attributions.
