# Tatar Relay — Burp extension (v0.2)

A Burp Suite (Montoya API) frontend for Tatar Relay. It adds a **Tatar Relay**
tab to the request editor (Repeater, Proxy, etc.) that shows the **decrypted
plaintext** of an encrypted body, lets you edit it like normal HTTP, and
**re-encrypts + reseals** it on send.

The heavy lifting stays in the Python core; the extension is a thin client that
talks to the local bridge over JSON-RPC (Frozen Contract #5). This is why we do
not reimplement any crypto in Java.

```
Burp (Java)  ──HTTP JSON-RPC──►  relay bridge (Python)  ──►  pipeline engine
   Repeater tab                    localhost:8799              (decrypt/encrypt)
```

## 1. Start the bridge (Python side)

```bash
pip install -e .            # from the repo root
relay bridge examples/acme-bank-mobile.yaml --var session_key=<hex>
# serves http://127.0.0.1:8799
```

`--var` supplies the session key for now (live key extraction from the handshake
is v0.3). You can pass several profiles; the extension can name one, or if only
one is loaded it is used automatically.

## 2. Build the extension jar

Requires a JDK 17+. Gradle wrapper or a local Gradle 8:

```bash
cd burp
gradle build          # or: ./gradlew build
# -> build/libs/tatar-relay-burp.jar   (Gson bundled)
```

## 3. Load in Burp

Burp → **Extensions** → **Add** → Extension type **Java** →
select `build/libs/tatar-relay-burp.jar`.

Optional config (JVM args in Burp, or environment):

```
-Dtatar.bridge=http://127.0.0.1:8799
-Dtatar.profile=acme-bank-mobile
```

## 4. Use it

Send an in-scope encrypted request to **Repeater**, open the **Tatar Relay 🔓**
tab: you'll see plaintext JSON. Edit it, hit **Send** — the extension
re-encrypts and reseals automatically. If the bridge is down or the key is
wrong, the tab shows the reason and the original request is sent unchanged.

## Notes / roadmap

- v0.2 shows a raw plaintext editor. Live Preview (per-step view) and a byte-diff
  panel are next.
- Response editor tab, Intruder support, and in-Burp key extraction come later.
- The extension never sends a broken request: any bridge/pipeline error falls
  back to the original bytes and logs a reason.
