package relay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;

import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The "Tatar Relay" tab shown on the RESPONSE side of message editors
 * (Repeater, Proxy history, etc.).
 *
 * setRequestResponse: decrypt the response body via the bridge ("response"
 *                     channel) and show plaintext JSON.
 * getResponse:        re-encrypt the (possibly edited) plaintext and return a
 *                     response with the new wire body.
 * On any bridge/pipeline failure the original response is passed through and a
 * reason is shown — Burp never breaks a response because of us.
 *
 * Mirror of RelayHttpRequestEditor; the only differences are the channel name
 * ("response"), the message side it reads/writes, and enablement.
 */
public class RelayHttpResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private final MontoyaApi api;
    private final BridgeClient bridge;
    private final String profile;
    private final RawEditor editor;

    private HttpRequestResponse current;
    private String ctxToken;

    public RelayHttpResponseEditor(MontoyaApi api, BridgeClient bridge, String profile) {
        this.api = api;
        this.bridge = bridge;
        this.profile = profile;
        this.editor = api.userInterface().createRawEditor();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return requestResponse != null
                && requestResponse.response() != null
                && requestResponse.response().body().length() > 0;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.current = requestResponse;
        this.ctxToken = null;

        String body = requestResponse.response().bodyToString();
        String wireB64 = Base64.getEncoder()
                .encodeToString(body.getBytes(StandardCharsets.UTF_8));

        BridgeClient.DecryptResult r = bridge.decrypt(profile, "response", wireB64);
        if (r.error == null) {
            this.ctxToken = r.ctxToken;
            editor.setEditable(true);
            editor.setContents(ByteArray.byteArray(r.plaintextText));
        } else {
            editor.setEditable(false);
            editor.setContents(ByteArray.byteArray(
                    "// Tatar Relay could not decrypt this response:\n// " + r.error
                            + "\n// (does the profile have a 'response' pipeline and the key set?)"));
        }
    }

    @Override
    public HttpResponse getResponse() {
        // No decrypt happened, or the user didn't edit — return the original bytes.
        if (ctxToken == null || !editor.isModified()) {
            return current.response();
        }
        try {
            String edited = editor.getContents().toString();
            String wireB64 = bridge.encrypt(ctxToken, edited);
            byte[] wire = Base64.getDecoder().decode(wireB64);
            return current.response().withBody(ByteArray.byteArray(wire));
        } catch (Exception e) {
            api.logging().logToError("[tatar-relay] response re-encrypt failed, sending original: " + e.getMessage());
            return current.response();
        }
    }

    @Override
    public boolean isModified() {
        return editor.isModified();
    }

    @Override
    public String caption() {
        return "Tatar Relay 🔓";
    }

    @Override
    public Component uiComponent() {
        return editor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return editor.selection().isPresent() ? editor.selection().get() : null;
    }
}
