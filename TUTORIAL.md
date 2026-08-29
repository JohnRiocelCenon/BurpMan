# BurpMan — How to Use It (Easy Guide)

This is a beginner-friendly guide. If you know Postman, you already know 90% of this tool.
The big difference: every request you send here also goes through Burp Suite, so you can scan it.

---

## 1. Install the Extension

1. Open Burp Suite.
2. Go to **Extensions → Installed → Add**.
3. Choose **Java** as the type.
4. Pick the file `BurpMan-1.0.0-jar-with-dependencies.jar`.
5. A new tab called **BurpMan** will appear at the top.

That's it. You're ready.

---

## 2. What Each Postman Action Looks Like Here

| In Postman you do this... | In BurpMan you do this... |
|---|---|
| Import a collection | Click **Browse...** next to *Collection:* |
| Pick an environment | Use the **Environment** dropdown |
| Edit globals | Nothing! It loads them by itself |
| Open a request | Click it in the tree on the left |
| Run one folder only | **Right-click the folder → ▶ Analyze this Folder** |
| Stop a long run | Click **Stop** while **Run Scripts** is executing |
| Set variables manually | Click **Edit Variables** |
| Write a pre-request script | Open the **Pre-request Script** tab |
| Write tests | Open the **Tests** tab |
| Send the request | Click **Send** |
| Get an OAuth 2 token | Auth Manager → pick token source or OAuth2 config → **Fetch Token** |

---

## 3. The Screen Explained

```
┌────────────────────────────────────────────────────────────────┐
│ Collection: <your file>           [Browse]   [Restart]         │
│ Environment: [— No Environment —] [Add] [Clear]                │
├────────────────────────────────────────────────────────────────┤
│ ┌─────────────┐  ┌────────────────────────────────────────┐    │
│ │ Tree of     │  │ Auth Manager | Request Builder | ...   │    │
│ │ folders     │  ├────────────────────────────────────────┤    │
│ │ and         │  │ POST  https://api.example.com/x  [Send]│    │
│ │ requests    │  │ Params | Auth | Headers | Body | ...   │    │
│ │             │  │                                        │    │
│ └─────────────┘  │ Status: 200 OK · Time: 142ms           │    │
│                  │ Pretty | Raw | Headers | Preview       │    │
│                  └────────────────────────────────────────┘    │
│ ─────────────────── Logs ───────────────────                   │
└────────────────────────────────────────────────────────────────┘
```

- **Left side**: Your collection tree (folders + requests).
- **Right side**: Tabs to set up auth, build requests, view history, and see cookies.
- **Bottom**: The log tells you what just happened.

---

## 4. Send Your First Request (Step by Step)

### Step 1 — Pick your collection

Click **Browse...** next to *Collection:* and select your `.postman_collection.json` or Bruno `.bru` file.

The tree on the left fills up.

> **Tip:** If you have a globals file (something like `myproject.postman_globals.json`) in the **same folder** as your collection, the tool will load it for you. You'll see a log line like `🌐 Auto-loaded globals: ...`.

### Step 2 — Pick your environment

Click **Add...** next to *Environment:* and pick your `.postman_environment.json` file.

Then choose it from the dropdown. Your variables are now loaded.

> **Variable priority** (same as Postman):
> Environment wins over Globals, which wins over Collection variables.

### Step 3 — Click **Analyze** (or analyze a single folder)

**Two options:**

- **Full Analyze** — click the green **Analyze** button at the bottom of Auth Manager. This scans the whole collection.
- **Folder-only Analyze** — *right-click any folder in the tree* → **▶ Analyze this Folder (run scripts)**. Use this for big collections (hundreds of requests) where you only care about one area.

Either option does four useful things:

1. Replaces all the `{{variables}}` with their real values.
2. Finds OAuth2/JWT/token-source candidates in your collection.
3. Maps token endpoints and script-based token sources.
4. Shows a **▶ Run Scripts** CTA when scripted requests are detected.

Then click **▶ Run Scripts** to execute the script chain and populate tokens/variables.

> **Tip:** The tree shows up the moment you Browse a collection — you do **not** have to click Analyze first to right-click a folder.

> **Stop button:** While **Run Scripts** is executing, click **Stop** to abort — the run halts after the current in-flight request.

### Step 4 — Get an OAuth token (only if your API needs one)

1. Open the **Auth Manager** tab.
2. Pick either:
   - a token-source row (checkbox in the table), or
   - an OAuth2 config from the dropdown.
3. Click **Fetch Token** (or **Refresh** for a fresh copy).
4. Optional: click **OAuth2** to open the full OAuth dialog, then use **Get New Access Token** there.

Done. The token is saved as `{{token}}`. Every Bearer request from now on will use it.

> If something is missing (like `clientId` or `clientSecret`), open **Edit Variables** and type it in.

### Step 5 — Send a request

1. Click any request in the tree.
2. It loads in the **Request Builder**.
3. Check the tabs:
   - **Params** — query string keys/values (you can disable each row).
   - **Authorization** — pick "Inherit from parent" or override.
   - **Headers** — add/remove/disable headers.
   - **Body** — Raw, JSON, XML, form-data, urlencoded, or GraphQL.
   - **Pre-request Script** — runs before sending.
   - **Tests** — runs after sending. Capture tokens here.
4. Click **Send**.

The response shows below: **Pretty / Raw / Headers / Preview / Details**.

> **Bonus:** If your JSON body has comments like `// note` or `/* note */`, the tool removes them automatically before sending. You don't have to clean them up yourself.

---

## 5. Variables — Where They Come From

| Source | How it loads | Priority |
|---|---|---|
| Environment | You pick it from the dropdown | Highest |
| Globals | Loaded automatically from the same folder | Middle |
| Collection | Comes from inside the collection JSON | Lowest |
| Manual (Edit Variables) | You type them yourself | Beats everything |

**Special variables you can use anywhere:**

| Type this | And you get... |
|---|---|
| `{{$guid}}` | A new random ID each time |
| `{{$timestamp}}` | The current Unix time |
| `{{$timestamp+60}}` | Unix time + 60 seconds |
| `{{$isoTimestamp}}` | The current time in ISO format |
| `{{$randomInt}}` | A random number |
| `{{$randomInt(10,99)}}` | A random number between 10 and 99 |
| `{{$randomEmail}}` | A fake email address |
| `{{$randomFirstName}}` | A fake first name |
| `{{$randomBoolean}}` | `true` or `false` |

---

## 6. Scripts — The `pm.*` Commands

You can write small JavaScript-style scripts in the **Pre-request Script** and **Tests** tabs.

### Examples

**Pre-request:** stamp a fresh value before sending
```js
pm.environment.set("nonce", Date.now().toString());
```

**Tests:** save the token from the response
```js
const data = pm.response.json();
pm.environment.set("token", data.access_token);
```

**Tests:** read a header
```js
const ct = pm.response.headers.get("content-type");
console.log("Content type was:", ct);
```

**Old style also works:**
```js
postman.setEnvironmentVariable("apiKey", "secret");
```

### What's supported

- `pm.environment.get/set`
- `pm.globals.get/set`
- `pm.collectionVariables.get/set`
- `pm.variables.get/set`
- `pm.response.code`, `pm.response.text()`, `pm.response.json()`
- `pm.response.headers.get(name)`
- `console.log / warn / error`
- Standard JS: `Math.*`, `Date.now()`, `JSON.parse / JSON.stringify`, `parseInt`, `parseFloat`

> Tokens you save in a Tests script are **immediately available to the next request**. No need to click Analyze again.

---

## 7. Authentication

### How it inherits

Just like Postman: if a request says "Inherit from parent", it picks up the auth from its folder, then from the collection root.

### Tokens — Three ways to get one

**1. Fetch from a detected endpoint (one click)**

After you click **Analyze**, the **Auth Manager → Possible token source** table lists every URL in the collection that looks like a token endpoint (e.g. `/oauth2/token`, `/login`).

1. **Tick the row** of the endpoint you want to use.
2. Click **Fetch Token**.
3. The token lands in the **Token** field on the right and is saved as `{{token}}`. A green toast says *"Token fetched and applied"*.

**2. Paste a token manually**

If you already have a token from another tool:

1. Paste it into the **Token** field on the right side of Auth Manager.
2. Click **Apply**. It's saved as `{{token}}` and reused by every Bearer request.

**3. OAuth 2.0 dialog (full flow)**

1. Pick a config from the **OAuth2 Config** dropdown.
2. Click **OAuth2** to review/adjust Client ID, Secret, Scope, etc.
3. Click **Get New Access Token** at the bottom.

All Postman grant types are supported: **client_credentials**, **password**, **authorization_code**, **implicit**.

### Auto-refresh expired tokens

Auto-refresh is controlled in the **Folder Auth Editor** (folder-level auth), where you can enable **Auto-refresh when expired**.

When enabled:

- Before each request, the tool checks the JWT `exp` claim.
- If the token is expired (or near expiry), it fetches a fresh token from the selected endpoint.
- Your request uses the refreshed token automatically.

### Send Token Request to Repeater

Want to tweak the token request body, headers, or scope by hand before sending?

1. Open the **OAuth 2.0 Configuration** dialog (**OAuth2** button in Auth Manager).
2. Click **Send Token Request to Repeater** at the bottom.
3. The crafted token request opens as a new tab in Burp's **Repeater** — edit anything, send it, and read the response.

This is the easiest way to debug 400/401 errors from your auth server.

### Other auth types

- Bearer Token
- Basic Auth
- API Key (in header or query)
- JWT (auto-detected and refreshed)

---

## 7b. Sending Requests to Burp Tools

Every request in the tree can be pushed into Burp's other tools with full variable resolution and the latest token applied.

### Single request → Repeater / Intruder / Organizer

**Right-click a request** in the tree:

| Menu item | What it does |
|---|---|
| **Send to Repeater (with Auth)** | Substitutes `{{vars}}`, attaches Bearer token, opens in Repeater. |
| **Send to Repeater (no Auth)** | Same but skips the Authorization header — useful for auth-bypass testing. |
| **Send to Intruder (with Auth)** | Same substitution, opens in Intruder ready for payloads. |
| **Send to Intruder (no Auth)** | No Authorization header. |
| **Send to Organizer (with Auth)** | Saves the request to Burp's Organizer for later. |

### Whole folder → Repeater / Intruder

Right-click a **folder** node:

- **Send Folder to Repeater (with Auth)** — every request in the folder lands in Repeater as separate tabs.
- **Send Folder to Repeater (no Auth)** — same, no Bearer header.
- **Send Folder to Intruder (with Auth)** — bulk-send to Intruder.

### Send button vs Send to Repeater

In the **Request Builder** the top toolbar has three buttons:

- **Send** (blue) — fires the request inline; response appears in the bottom panel.
- **Send to Repeater** — opens the resolved request in Repeater so you can edit & replay.
- **Save** — keeps your edits in memory for this session.

---

## 8. Cookies

Cookies just work:

- Any `Set-Cookie` from a response is saved.
- Future requests to the same site send those cookies back automatically.
- See them in the **Cookies** tab.

You don't have to do anything.

---

## 9. Drag and Drop to Reorder

Want to change the order of requests?

- Drag a request **on top of** a folder → it moves into that folder.
- Drag a request **between two siblings** → it changes position.

> Note: This is in-memory only. Your original JSON file isn't changed.

---

## 10. Run scripted flows and previews

You now have two run modes:

1. **Analyze → ▶ Run Scripts**
   - Analyze detects scripted requests, then shows a **Run Scripts** CTA.
   - Clicking it executes the script chain (token minting, variable writes, tests).
   - Results stream into **Run Results**.

2. **Tree right-click → Run (Preview)**
   - Use this for single request/folder preview sends without full scripted chain orchestration.
   - Good for quick response checks and replay setup.

> Important: Preview/script runs are controlled workflows and are not silently bulk-added to Site Map/Scanner.

---

## 11. Saving Your Edits

In **Request Builder**, click **Save** to keep your edits while the session is open.

> Saving back to the original JSON file is not supported yet.

---

## 12. Common Problems and Quick Fixes

| Problem | Fix |
|---|---|
| OAuth dropdown is empty after Analyze | Open **Edit Variables**, fill in `clientId`, `clientSecret`, `scope`. Click Analyze again. |
| `{{token}}` still has the old value | Click the request again. The script saved it, but the builder may show a cached body. |
| Got `400 Bad Request` on a JSON body | Usually a comment is breaking the JSON. The tool strips them, but click **Format** to double-check. |
| Variables show in red (not resolved) | Make sure the environment is selected and that your variable names match exactly (case-sensitive). |
| Globals didn't load | The file name must contain the word `globals`, OR the JSON must have `"_postman_variable_scope":"globals"`. Otherwise, rename or re-export. |
| Analyze runs too long on a big collection | Right-click just the folder you need → **▶ Analyze this Folder**. Or click **Stop** in the progress dialog. |
| Can't see the tree right after Browse | The tree now loads automatically when you Browse — no need to Analyze first. If empty, check the log for a parse error. |
| Stop button feels slow | It aborts after the current in-flight request. With long-running APIs allow a second or two. |

---

## 13. Recent UI updates (2026)

- **Auth Manager stays compact:** long tokens now scroll inside the token pane, so bottom action buttons stay visible.
- **Send keeps results visible:** Request Builder no longer auto-expands the body pane after Send.
- **Advanced button is hidden by default:** press **Ctrl+Shift+/** to show or hide it.
- **Inline body variable editing:** double-click `{{variable}}` in Body/GraphQL editors to edit values (same behavior as URL).
- **Script compatibility improved (lite + full):**
  - `pm.request.body.raw` is safe to read (no undefined crash on bodyless requests).
  - `pm.response.to.be.json` is supported.

---

## 14. Try It Yourself (Copy-Paste Test)

Save these three files in the same folder, then click **Browse...** and pick the collection.

### `tutorial.postman_collection.json`
```json
{
  "info": {
    "name": "Tutorial",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Echo",
      "request": {
        "method": "POST",
        "header": [{ "key": "X-Api-Key", "value": "{{globalApiKey}}" }],
        "body": {
          "mode": "raw",
          "raw": "{\n  // this comment will be removed\n  \"hello\": \"{{whom}}\",\n  \"ts\": \"{{$isoTimestamp}}\"\n}",
          "options": { "raw": { "language": "json" } }
        },
        "url": {
          "raw": "{{baseUrl}}/post",
          "host": ["{{baseUrl}}"],
          "path": ["post"]
        }
      },
      "event": [
        {
          "listen": "test",
          "script": {
            "type": "text/javascript",
            "exec": [
              "const j = pm.response.json();",
              "pm.environment.set('echoedAt', (j.headers && j.headers['x-amzn-trace-id']) || 'n/a');"
            ]
          }
        }
      ]
    }
  ],
  "variable": [{ "key": "whom", "value": "world" }]
}
```

### `tutorial.postman_environment.json`
```json
{
  "id": "11111111-2222-3333-4444-555566667777",
  "name": "Tutorial Env",
  "values": [
    { "key": "baseUrl", "value": "https://postman-echo.com", "enabled": true }
  ],
  "_postman_variable_scope": "environment"
}
```

### `tutorial.postman_globals.json`
```json
{
  "id": "00000000-1111-2222-3333-444455556666",
  "name": "Tutorial Globals",
  "values": [
    { "key": "globalApiKey", "value": "DEMO-KEY-abc123", "enabled": true }
  ],
  "_postman_variable_scope": "globals"
}
```

### What you should see

1. Globals load automatically when you pick the collection.
2. The environment loads after you click **Add...**.
3. Click the `Echo` request → click **Send** → you get **200 OK**.
4. Look at the response — `{{whom}}` is now `world`, the comment is gone, and the timestamp is filled in.
5. Open **Edit Variables** — you'll see a new variable called `echoedAt`, set by the Tests script.

That's the full workflow. Once this works, your real collection will work the same way.

---

Have fun! 🚀
