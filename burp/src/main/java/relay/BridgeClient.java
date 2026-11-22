package relay;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;

/**
 * JSON-RPC client for the local Tatar Relay bridge (Frozen Contract #5).
 *
 * Thread-safe: the editors call it from a background pool and the HTTP handler
 * from Burp's tool threads ({@link HttpClient} and {@link Gson} are both safe
 * to share).
 */
public class BridgeClient {

    private final String url;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();
    private final Gson gson = new Gson();

    /** Optional shared secret. Sent as the X-Relay-Token header when the bridge
     *  is started with --token. Read from -Dtatar.relay.token or the
     *  TATAR_RELAY_TOKEN env var; null/empty means no auth (unchanged). */
    private final String token = firstNonEmpty(
            System.getProperty("tatar.relay.token"),
            System.getenv("TATAR_RELAY_TOKEN"));

    /** Decrypt runs off the UI thread, so it may wait as long as the bridge's own
     *  per-request budget (30 s) plus margin. -Dtatar.timeout / TATAR_TIMEOUT. */
    private final Duration decryptTimeout;
    /** Encrypt can run on the thread that is about to send the request. */
    private final Duration encryptTimeout = Duration.ofSeconds(15);

    public BridgeClient(String url) {
        this.url = url;
        this.decryptTimeout = Duration.ofSeconds(seconds("tatar.timeout", "TATAR_TIMEOUT", 35));
    }

    private static String firstNonEmpty(String... vals) {
        for (String v : vals) if (v != null && !v.isEmpty()) return v;
        return null;
    }

    /** Positive whole seconds from a system property / env var, else {@code def}. */
    static long seconds(String sys, String env, long def) {
        String v = firstNonEmpty(System.getProperty(sys), System.getenv(env));
        if (v == null) return def;
        try {
            long n = Long.parseLong(v.trim());
            return n > 0 ? n : def;
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** Pretty JSON for the editor. HTML escaping is OFF: Gson would otherwise
     *  show a payload such as {@code <script>} as {@code <script>}. */
    private static final Gson PRETTY = new GsonBuilder()
            .setPrettyPrinting().disableHtmlEscaping().create();

    static String pretty(JsonElement el) {
        return PRETTY.toJson(el);
    }

    public static final class DecryptResult {
        public String plaintextText;   // pretty JSON, or null on error
        public String ctxToken;
        public String error;           // null on success
    }

    private JsonObject post(JsonObject req, Duration timeout) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("Content-Type", "application/json");
        if (token != null) b.header("X-Relay-Token", token);
        HttpRequest r = b
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(req)))
                .build();
        HttpResponse<String> resp = http.send(r, HttpResponse.BodyHandlers.ofString());
        return JsonParser.parseString(resp.body()).getAsJsonObject();
    }

    public DecryptResult decrypt(String profile, String channel, String wireBase64) {
        return decrypt(profile, channel, wireBase64, null, null);
    }

    /** Decrypt the exact bytes of a message body. Use this rather than going
     *  through a String: a body that is not valid UTF-8 (raw ciphertext) would
     *  otherwise be altered before it ever reached the bridge. */
    public DecryptResult decryptBytes(String profile, String channel, byte[] wire,
                                      String host, String path) {
        return decrypt(profile, channel, Base64.getEncoder().encodeToString(wire), host, path);
    }

    /** As above, but also tells the core WHERE the flow is going so the profile's
     *  fail-closed scope can be enforced per request (Contract #5, additive).
     *  host/path are optional: null or empty are simply omitted, and the core
     *  then behaves exactly as before rather than refusing the flow. */
    public DecryptResult decrypt(String profile, String channel, String wireBase64,
                                 String host, String path) {
        DecryptResult dr = new DecryptResult();
        try {
            JsonObject req = new JsonObject();
            req.addProperty("method", "decrypt");
            if (profile != null && !profile.isEmpty()) req.addProperty("profile", profile);
            req.addProperty("channel", channel);
            req.addProperty("wire", wireBase64);
            if (host != null && !host.isEmpty()) req.addProperty("host", host);
            if (path != null && !path.isEmpty()) req.addProperty("path", path);
            req.addProperty("flow_id", Long.toHexString(System.nanoTime()));
            JsonObject out = post(req, decryptTimeout);
            if (out.has("ok") && out.get("ok").getAsBoolean()) {
                dr.plaintextText = pretty(out.get("plaintext"));
                dr.ctxToken = out.get("ctx_token").getAsString();
            } else {
                dr.error = out.has("error") ? out.get("error").toString() : "unknown error";
            }
        } catch (Exception e) {
            dr.error = "bridge unreachable: " + e.getMessage();
        }
        return dr;
    }

    /** plaintextText must be valid JSON (it is re-parsed and embedded). */
    public String encrypt(String ctxToken, String plaintextText) throws Exception {
        return encrypt(ctxToken, plaintextText, null, null);
    }

    /** Seal plaintext with the context of an earlier decrypt. A ctx_token may be
     *  reused to seal many plaintexts (the Intruder workflow); when host/path
     *  are given the core re-checks the profile's scope for them. */
    public String encrypt(String ctxToken, String plaintextText, String host, String path)
            throws Exception {
        JsonObject req = new JsonObject();
        req.addProperty("method", "encrypt");
        req.addProperty("ctx_token", ctxToken);
        req.add("plaintext", JsonParser.parseString(plaintextText));
        if (host != null && !host.isEmpty()) req.addProperty("host", host);
        if (path != null && !path.isEmpty()) req.addProperty("path", path);
        JsonObject out = post(req, encryptTimeout);
        if (out.has("ok") && out.get("ok").getAsBoolean()) {
            return out.get("wire").getAsString();
        }
        throw new RuntimeException(out.has("error") ? out.get("error").toString() : "encrypt failed");
    }
}
