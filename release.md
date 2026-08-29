# BurpMan v1.0.0 — Postman/Bruno-style API testing inside Burp Suite

First public release of **BurpMan** — a Burp Suite extension that gives you a Postman/Bruno-style workspace for API testing without ever leaving Burp. Import your collections, edit requests with a familiar UI, run pre-request scripts and tests, and fire everything straight through Burp's HTTP stack.

---

## 🔌 Downloads

| File | Description |
|---|---|
| `BurpMan-1.0.0-lite.jar` | Lite build (~2.6 MB) — everything you need for day-to-day use. Recommended. |
| `BurpMan-1.0.0-full.jar` | Full build (~6.6 MB) — same code, includes extra script and integration dependencies. |

Pick the **lite** build unless you know you need the full one.

---

## ✨ Highlights

### Postman-like UI
- Collection tree on the left, request builder on the right, tabs for **Params / Headers / Body / Auth / Pre-request Script / Tests**, and a response viewer underneath.
- Proper dark mode, themed buttons, no readability issues with tokens or labels.
- **Recent files dropdown** — quick-open the last 5 collections.
- **Status dots in the collection tree** — 🟢 analyzed, 🟠 pending — see at a glance which are ready.
- **Right-click Expand All / Collapse All** on the tree.
- **Smart scope filter** — toggles between *Filter* and *Clear Filter* so you can re-apply your last scope with one click; auto-resets on reload.
- Token field no longer stretches the panel when you paste a long JWT.
- Empty-state hint when no collection is loaded, tooltips on **Analyze** and other key controls.
- **Adaptive layout for 1366×768 single screens** — the tab strip no longer gets cropped when the extension pane is narrow.
- **Environment dropdown popup** clamped to the combo's width — no more popup opening off-screen or on the wrong monitor.

### Bruno parity
- **Auto-discovery** of `environments/` folder next to imported collections (Bruno workspace convention).
- **Dual environment + `.env` overlay** — pick one env file *and* keep one `.env` always-on for `process.env.*` secrets. Env swaps no longer drop `.env` values.
- **`+ Add .env`** button with per-row **Activate / Edit / Remove** controls. Semi-strict Bruno mode: multiple `.env` files allowed, one active at a time.
- **In-app text editor** (Ctrl+S save, Esc close) for both env and `.env` files — no more jumping to Notepad. OneDrive-placeholder-safe atomic save.
- **`process.env.<key>` namespace** with bare-key fallback, so both Postman-style and Bruno-style scripts resolve the same secrets.
- Bruno YAML env parser (`.bru` environment blocks), plus a mini-YAML helper for edge cases.
- `clearProcessEnvVariables()` on workspace swap — prevents secret leakage across collections.

### Scripting & auth
- **`CryptoJsHost`** — `CryptoJS.HmacSHA256`, `SHA1`, `MD5`, `enc.Base64`, `enc.Hex`, `enc.Utf8` etc. available inside pre-request / test scripts.
- **`ProcessEnvHost`** — Bruno-compatible `process.env.*` access from scripts.
- **`ScriptRequestContextBuilder`** — clean request-context building for `pm.*` / `bru.*` calls.
- **`OAuthHttpClient`** + **`ScriptTokenSourceDetector`** — script-driven token flows and JWT source detection.
- Tight OAuth path matching + scoped auth isolation across collections.
- Form-data / file-upload UI in the Body tab.

### Runner & I/O
- **Outbound proxy** (`ProxyRouter` + `ProxySettings` + `ProxySettingsDialog`) — route BurpMan's own outbound HTTP through Burp's proxy or a custom upstream.
- **Import Collection dialog** — Postman-style import chooser (Bruno detects and routes to the correct workspace picker).
- **cURL import**, **HTML docs export**, **Save-as-Example**, **Newman sidecar runner**.
- **Save Collection** + **Save Env** buttons.
- Data-driven runner fires through Burp's HTTP stack (no Repeater spam).
- Response cache per request.

---

## 🛠️ Installation

1. Download `BurpMan-1.0.0-lite.jar` below.
2. In Burp Suite: **Extensions → Installed → Add → Java**.
3. Select the JAR file. The **BurpMan** tab will appear.

Full guide: [TUTORIAL.md](https://github.com/JohnRiocelCenon/BurpMan/blob/main/TUTORIAL.md)

---

## 🔒 Design promise

Repeater-first design, no auto-crawl, nothing leaves your machine. Try it on your next engagement and let me know if you spot anything weird or want a feature added.

---

## 💡 Credits

Inspired by [postman-burp-importer](https://github.com/nerdygenii/postman-burp-importer) by [@nerdygenii](https://github.com/nerdygenii). MIT licensed — see [NOTICES](https://github.com/JohnRiocelCenon/BurpMan/blob/main/NOTICES).
