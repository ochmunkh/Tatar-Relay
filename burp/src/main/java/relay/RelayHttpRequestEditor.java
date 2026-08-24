package relay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The "Tatar Relay" tab shown in Repeater / message editors.
 *
 * setRequestResponse: decrypt the body via the bridge and show plaintext JSON.
 * getRequest:         re-encrypt the (possibly edited) plaintext and return a
 *                     request with the new wire body.
 * On any bridge/pipeline failure the original request is passed through and a
 * reason is logged — Burp never sends a broken request because of us.
 */
public class RelayHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi api;
    private final BridgeClient bridge;
    private final String profile;
    private final RawEditor editor;

    private HttpRequestResponse current;
    private String ctxToken;

    public RelayHttpRequestEditor(MontoyaApi api, BridgeClient bridge, String profile) {
        this.api = api;
        this.bridge = bridge;
        this.profile = profile;
        this.editor = api.userInterface().createRawEditor();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return requestResponse != null
                && requestResponse.request() != null
                && requestResponse.request().body().length() > 0;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.current = requestResponse;
        this.ctxToken = null;

        String body = requestResponse.request().bodyToString();
        String wireB64 = Base64.getEncoder()
                .encodeToString(body.getBytes(StandardCharsets.UTF_8));

        BridgeClient.DecryptResult r = bridge.decrypt(profile, "request", wireB64);
        if (r.error == null) {
            this.ctxToken = r.ctxToken;
            editor.setEditable(true);
            editor.setContents(ByteArray.byteArray(r.plaintextText));
        } else {
            editor.setEditable(false);
            editor.setContents(ByteArray.byteArray(
                    "// Tatar Relay could not decrypt this request:\n// " + r.error
                            + "\n// (is the bridge running and the key set?)"));
        }
    }

    @Override
    public HttpRequest getRequest() {
        // No decrypt happened, or the user didn't edit — send the original bytes.
        if (ctxToken == null || !editor.isModified()) {
            return current.request();
        }
        try {
            String edited = editor.getContents().toString();
            String wireB64 = bridge.encrypt(ctxToken, edited);
            byte[] wire = Base64.getDecoder().decode(wireB64);
            return current.request().withBody(ByteArray.byteArray(wire));
        } catch (Exception e) {
            api.logging().logToError("[tatar-relay] re-encrypt failed, sending original: " + e.getMessage());
            return current.request();
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
