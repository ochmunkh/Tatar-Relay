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

/** JSON-RPC client for the local Tatar Relay bridge (Frozen Contract #5). */
public class BridgeClient {

    private final String url;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();
    private final Gson gson = new Gson();
    private final Gson pretty = new GsonBuilder().setPrettyPrinting().create();

    /** Optional shared secret. Sent as the X-Relay-Token header when the bridge
     *  is started with --token. Read from -Dtatar.relay.token or the
     *  TATAR_RELAY_TOKEN env var; null/empty means no auth (unchanged). */
    private final String token = firstNonEmpty(
            System.getProperty("tatar.relay.token"),
            System.getenv("TATAR_RELAY_TOKEN"));

    public BridgeClient(String url) {
        this.url = url;
    }

    private static String firstNonEmpty(String... vals) {
        for (String v : vals) if (v != null && !v.isEmpty()) return v;
        return null;
    }

    public static final class DecryptResult {
        public String plaintextText;   // pretty JSON, or null on error
        public String ctxToken;
        public String error;           // null on success
    }

    private JsonObject post(JsonObject req) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json");
        if (token != null) b.header("X-Relay-Token", token);
        HttpRequest r = b
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(req)))
                .build();
        HttpResponse<String> resp = http.send(r, HttpResponse.BodyHandlers.ofString());
        return JsonParser.parseString(resp.body()).getAsJsonObject();
    }

    public DecryptResult decrypt(String profile, String channel, String wireBase64) {
        DecryptResult dr = new DecryptResult();
        try {
            JsonObject req = new JsonObject();
            req.addProperty("method", "decrypt");
            if (profile != null && !profile.isEmpty()) req.addProperty("profile", profile);
            req.addProperty("channel", channel);
            req.addProperty("wire", wireBase64);
            req.addProperty("flow_id", Long.toHexString(System.nanoTime()));
            JsonObject out = post(req);
            if (out.has("ok") && out.get("ok").getAsBoolean()) {
                JsonElement pt = out.get("plaintext");
                dr.plaintextText = pretty.toJson(pt);
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
        JsonObject req = new JsonObject();
        req.addProperty("method", "encrypt");
        req.addProperty("ctx_token", ctxToken);
        req.add("plaintext", JsonParser.parseString(plaintextText));
        JsonObject out = post(req);
        if (out.has("ok") && out.get("ok").getAsBoolean()) {
            return out.get("wire").getAsString();
        }
        throw new RuntimeException(out.has("error") ? out.get("error").toString() : "encrypt failed");
    }
}
