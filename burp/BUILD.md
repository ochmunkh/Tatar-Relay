# Building the Tatar Relay Burp extension

Exact, copy-pasteable steps. Three routes: **Gradle** (declarative, needs
Gradle), **plain `javac`** (needs only a JDK — this is the one verified below),
and **`build.ps1`** (the same `javac` route, wrapped for Windows).

Output in every case: `build/libs/tatar-relay-burp.jar`, loaded into Burp via
*Extensions → Add → Java*.

> **What was actually executed when this file was written** is called out at the
> end of each section. Burp itself is not available in this environment, so
> **step 4 (loading the jar) is unverified** — it is written from the Montoya
> API contract, not from a run.

---

## 1. Prerequisites

| Tool | Version needed | Why |
| --- | --- | --- |
| JDK (`javac` **and** `jar`) | 17 or newer | `build.gradle` sets a Java 17 toolchain; Burp runs on a Java 17+ JRE |
| `curl` (or any downloader) | any | fetch the two jars from Maven Central, for the `javac` route |
| Gradle | 8.x | **only** for the Gradle route |
| Burp Suite | Community or Professional, 2023.12 or newer | to load the built jar |

Check the JDK:

```bash
javac -version    # verified with: javac 21.0.10
jar --version     # ships with the same JDK
```

A JDK newer than 17 is fine — the build pins the bytecode level with
`--release 17`, so the jar still loads in Burp's JRE.

## 2. Dependencies

Both versions come from [`build.gradle`](build.gradle); keep this file and that
one in step.

| Dependency | Version | Scope |
| --- | --- | --- |
| `net.portswigger.burp.extensions:montoya-api` | `2023.12.1` | **compile only** — Burp supplies it at runtime, so it must *not* go in the jar |
| `com.google.code.gson:gson` | `2.10.1` | **bundled** — Burp does not supply it |

Getting the Montoya jar is the step that used to block this build. There are
two ways and they are equivalent:

**Gradle resolves it for you** from `mavenCentral()`, declared as `compileOnly`
in `build.gradle`. Nothing to download by hand.

**Or fetch it directly from Maven Central** (what the `javac` route does):

```bash
cd burp
mkdir -p lib
curl -L -o lib/montoya-api.jar \
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2023.12.1/montoya-api-2023.12.1.jar
curl -L -o lib/gson.jar \
  https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar
```

`lib/` is in [`.gitignore`](.gitignore) on purpose — the jars are fetched, never
committed.

Expected sizes/digests for the two files above:

```
140273  sha256 f7e33a403e9c3760deb727ca05ec5ca2624d0a55b44b317717d4188432d1b4b1  lib/montoya-api.jar
283367  sha256 4241c14a7727c34feea6507ec801318a3d4a90f070e4525681079fb94ee4c593  lib/gson.jar
```

*Executed:* both `curl` commands, against `repo1.maven.org`, HTTP 200.

## 3. Build

### Route A — plain `javac` (Linux/macOS, no Gradle)

From `burp/`, with `lib/` populated as above:

```bash
rm -rf out build && mkdir -p out build/libs

# compile — --release 17 pins the bytecode level regardless of your JDK
javac --release 17 -Xlint:all -encoding UTF-8 \
  -cp "lib/montoya-api.jar:lib/gson.jar" \
  -d out $(find src/main/java/relay -name '*.java' | sort)

# bundle Gson into the jar (Burp does not provide it); drop its META-INF,
# which carries a module-info and Maven metadata we do not want to re-ship
(cd out && jar xf ../lib/gson.jar)
rm -rf out/META-INF out/module-info.class

# package — Montoya is NOT bundled, Burp provides it at runtime
jar cf build/libs/tatar-relay-burp.jar -C out .
```

On Windows replace the classpath separator `:` with `;` and the `/` with `\`,
or just use route C.

*Executed:* yes, exactly as written.
**`javac` exited 0 with no errors and no warnings**, even with `-Xlint:all`, and
produced seven class files:

```
out/relay/BridgeClient$DecryptResult.class
out/relay/BridgeClient.class
out/relay/RelayHttpRequestEditor.class
out/relay/RelayHttpResponseEditor.class
out/relay/RelayRequestEditorProvider.class
out/relay/RelayResponseEditorProvider.class
out/relay/TatarRelayExtension.class
```

The packaged jar is 291,401 bytes / 238 entries.

### Route B — Gradle

```bash
cd burp
gradle build          # or: ./gradlew build
# -> build/libs/tatar-relay-burp.jar
```

`build.gradle` applies the Shadow plugin, so `build` depends on `shadowJar` and
the Gson classes are relocated into the same fat jar route A builds by hand.

*Executed:* **no.** Gradle is not installed in the environment this file was
written in, and there is no `gradlew` wrapper checked in
(`burp/.gitignore` keeps `!gradle/wrapper/gradle-wrapper.jar`, but no wrapper
has been generated). Route B is unverified; route A is the proven one.

### Route C — `build.ps1` (Windows)

```powershell
cd burp
powershell -ExecutionPolicy Bypass -File build.ps1
```

It does exactly what route A does — downloads both jars into `lib\`, compiles
with `--release 17`, unpacks Gson, packages `build\libs\tatar-relay-burp.jar` —
plus it hunts for a real `jar.exe` under `C:\Program Files\...`, because the
Windows `javapath` shim often ships `java.exe`/`javac.exe` without `jar.exe`.

*Executed:* attempted under PowerShell 7 **on Linux**, where it fails — by
design, not by defect. The script hard-codes the Windows classpath separator
(`lib\montoya-api.jar;lib\gson.jar`), which a POSIX `javac` reads as one
nonexistent path, so every `com.google.gson` / `burp.api.montoya` import fails
to resolve. **`build.ps1` is Windows-only; on Linux/macOS use route A.**

## 4. Does it load?

Two different questions, with two different answers.

### What CI checks, automatically

`.github/test-extension.sh` (run by the `build-jar` job on every push) compiles
the extension together with `burp/src/test/java/relay/ExtensionLoadTest.java`
and runs it. That test calls the real entry point —
`TatarRelayExtension.initialize(MontoyaApi)` — against a **mock** `MontoyaApi`
and asserts that it:

- completes without throwing;
- names itself `Tatar Relay`;
- registers **both** the request and the response editor provider;
- logs the bridge URL and profile it will use;
- defaults to `http://127.0.0.1:8799` when neither property nor environment
  variable is set.

```bash
bash .github/build-jar.sh        # produces burp/build/libs/tatar-relay-burp.jar
bash .github/test-extension.sh   # -> RESULT  extension loads and registers correctly
```

The mock is a `java.lang.reflect.Proxy` that records every call and returns a
recording proxy for any interface-typed result, so the test needs no Mockito
and no JUnit, and does not have to be rewritten when PortSwigger widens
`MontoyaApi`. The test classes compile to `burp/test-out/`, never to the jar —
verified: `unzip -l` on the shipped jar lists only the seven `relay/*.class`
production entries.

Note this is the **Montoya** entry point. `registerExtenderCallbacks` belongs to
the legacy Extender API; this extension implements `BurpExtension`, so
`initialize(MontoyaApi)` is what Burp calls.

### What is still unverified

**The jar has never been loaded into Burp.** Burp Community is GUI-only —
loading an extension and reading back that it registered is a
Professional/Enterprise capability, and there is no supported headless path, so
no CI job can do it. The mock test proves the extension's own logic runs and
registers; it does **not** prove that Burp accepts the jar, that the editor tabs
render, or that the bridge round-trips.

Everything in the rest of this section therefore comes from the Montoya API
contract and has **not** been run.

1. Start the Python bridge first (the extension is a thin JSON-RPC client and
   shows an error in its tab if the bridge is down):

   ```bash
   pip install -e .              # from the repo root
   relay bridge examples/acme-bank-mobile.yaml --capture
   # serves http://127.0.0.1:8799
   ```

2. Burp → **Extensions** → **Add** → *Extension type*: **Java** → select
   `burp/build/libs/tatar-relay-burp.jar` → **Next**.

3. Optional configuration, as JVM system properties or environment variables:

   | Property | Environment variable | Default |
   | --- | --- | --- |
   | `-Dtatar.bridge=http://127.0.0.1:8799` | `TATAR_BRIDGE` | `http://127.0.0.1:8799` |
   | `-Dtatar.profile=acme-bank-mobile` | `TATAR_PROFILE` | empty — uses the single loaded profile |
   | `-Dtatar.relay.token=<secret>` | `TATAR_RELAY_TOKEN` | none — set it only if the bridge runs with `--token` |

### Verifying it loaded

1. The **Output** tab of the extension shows:

   ```
   Tatar Relay loaded. bridge=http://127.0.0.1:8799 profile=(single/auto)
   Open a request/response in Repeater and select the 'Tatar Relay' tab.
   ```

   `TatarRelayExtension.initialize` logs this via `api.logging().logToOutput`,
   so an empty Output tab means the entry point never ran.

2. The extension is named **Tatar Relay** in the extension list
   (`api.extension().setName`).

3. Send an in-scope request with an encrypted body to **Repeater**. A
   **Tatar Relay 🔓** tab appears next to *Pretty* / *Raw* on both the request
   and the response side. The tab is offered only when the message has a
   non-empty body (`isEnabledFor`).

4. Open that tab. Success looks like pretty-printed plaintext JSON. Failure is
   also visible rather than silent — the tab goes read-only and shows the
   reason, e.g.:

   ```
   // Tatar Relay could not decrypt this request:
   // bridge unreachable: Connection refused
   // (is the bridge running and the key set?)
   ```

5. Edit the plaintext and hit **Send**. The extension re-encrypts and reseals
   via the bridge. If that fails it logs to the **Errors** tab
   (`[tatar-relay] re-encrypt failed, sending original: ...`) and sends the
   original bytes — it never sends a request it could not rebuild.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `package burp.api.montoya does not exist` | `lib/montoya-api.jar` missing, or the Windows `;` classpath separator used on Linux/macOS (see route C) |
| `package com.google.gson does not exist` | same, for `lib/gson.jar` |
| Extension loads but every tab says *bridge unreachable* | the Python bridge is not running, or `-Dtatar.bridge` points elsewhere |
| `NoClassDefFoundError: com/google/gson/Gson` at runtime | Gson was not unpacked into `out/` before `jar cf` — repeat that step of route A |
| Burp rejects the jar | built for a newer bytecode level than Burp's JRE; keep `--release 17` |

## Notes

- Compiled and verified against **montoya-api 2023.12.1**, the version
  `build.gradle` declares. It also compiles clean against **2025.5**, the
  current release on Maven Central, with the same command — but 2023.12.1 is
  what ships, so bump `build.gradle` first if you want the newer one.
- Montoya is `compileOnly` / not bundled on purpose. Shipping it would shadow
  the implementation Burp itself provides.
- `lib/`, `out/` and `build/` are all git-ignored. Do not commit the downloaded
  jars or the built extension.
