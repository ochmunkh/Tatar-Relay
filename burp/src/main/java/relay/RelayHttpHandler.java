package relay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Seals plaintext templates just before they leave Burp — the engine behind
 * fuzzing encrypted APIs with Intruder (and plain editing in Repeater).
 *
 * A request carrying {@link Seal#HEADER} has a PLAINTEXT body. Its JSON is
 * encrypted and resealed through the bridge with the context of the decrypt it
 * came from, and the header is removed so the bridge token never reaches the
 * target. Requests without the header pass through untouched.
 *
 * Fail-closed: if sealing fails the plaintext is NOT sent — the body is
 * withheld (empty) and the message is highlighted red with the reason.
 *
 * For sealed messages, the response is decrypted too and a one-line preview is
 * written to the message's notes, so it shows in Intruder's Comment column.
 * -Dtatar.intruder.preview=false turns that off.
 */
public class RelayHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final BridgeClient bridge;
    private final String profile;
    private final boolean preview = !"false".equalsIgnoreCase(
            System.getProperty("tatar.intruder.preview", "true"));

    public RelayHttpHandler(MontoyaApi api, BridgeClient bridge, String profile) {
        this.api = api;
        this.bridge = bridge;
        this.profile = profile;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!request.hasHeader(Seal.HEADER)) {
            return RequestToBeSentAction.continueWith(request);
        }
        String token = request.headerValue(Seal.HEADER);
        HttpRequest stripped = request.withRemovedHeader(Seal.HEADER);
        Annotations notes = request.annotations();

        if (!Seal.isToken(token)) {
            return withhold(stripped, notes, "malformed " + Seal.HEADER + " header");
        }
        try {
            String plaintext = new String(request.body().getBytes(), StandardCharsets.UTF_8);
            String wireB64 = bridge.encrypt(token.trim(), plaintext,
                    request.httpService().host(), request.path());
            HttpRequest sealed = stripped.withBody(
                    ByteArray.byteArray(Base64.getDecoder().decode(wireB64)));
            return RequestToBeSentAction.continueWith(sealed, notes.withNotes(Seal.NOTE));
        } catch (Exception e) {
            return withhold(stripped, notes, e.getMessage());
        }
    }

    private RequestToBeSentAction withhold(HttpRequest request, Annotations notes, String why) {
        api.logging().logToError("[tatar-relay] seal failed, body withheld: " + why);
        return RequestToBeSentAction.continueWith(
                request.withBody(ByteArray.byteArray(new byte[0])),
                notes.withNotes(Seal.withheldNote(why)).withHighlightColor(HighlightColor.RED));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        Annotations notes = response.annotations();
        if (!preview || notes == null || !notes.hasNotes()
                || !notes.notes().startsWith(Seal.NOTE) || response.body().length() == 0) {
            return ResponseReceivedAction.continueWith(response);
        }
        String host = null;
        String path = null;
        try {
            host = response.initiatingRequest().httpService().host();
            path = response.initiatingRequest().path();
        } catch (Exception ignored) {
            // best effort: without a host the core simply skips the scope check
        }
        BridgeClient.DecryptResult r = bridge.decryptBytes(
                profile, "response", response.body().getBytes(), host, path);
        String note = r.error == null
                ? Seal.NOTE + " | response: " + Seal.preview(r.plaintextText, 160)
                : Seal.NOTE + " | response not decrypted";
        return ResponseReceivedAction.continueWith(response, notes.withNotes(note));
    }
}
