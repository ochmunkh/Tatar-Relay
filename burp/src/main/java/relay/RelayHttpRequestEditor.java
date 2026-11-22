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
 * setRequestResponse: decrypt the body via the bridge — in the background, so
 *                     the Burp UI never waits on the bridge — and show the
 *                     plaintext JSON when it arrives.
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
    private final AsyncDecrypt async = new AsyncDecrypt();

    private volatile HttpRequestResponse current;
    private volatile String ctxToken;

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
                && requestResponse.request().body().length() > 0
                // a plaintext template is already decrypted; it is sealed on send
                && !requestResponse.request().hasHeader(Seal.HEADER);
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.current = requestResponse;
        this.ctxToken = null;
        editor.setEditable(false);
        editor.setContents(utf8("// Tatar Relay: decrypting..."));

        // Exact body bytes: a non-UTF-8 body must reach the bridge unaltered.
        final byte[] wire = requestResponse.request().body().getBytes();
        final String host = hostOf(requestResponse);
        final String path = pathOf(requestResponse);

        async.submit(() -> bridge.decryptBytes(profile, "request", wire, host, path), r -> {
            if (r.error == null) {
                ctxToken = r.ctxToken;
                editor.setContents(utf8(r.plaintextText));
                editor.setEditable(true);
            } else {
                editor.setContents(utf8(
                        "// Tatar Relay could not decrypt this request:\n// " + r.error
                                + "\n// (is the bridge running and the key set?)"));
            }
        });
    }

    @Override
    public HttpRequest getRequest() {
        // No decrypt happened (or it is still running), or the user didn't
        // edit — send the original bytes.
        String token = ctxToken;
        HttpRequestResponse rr = current;
        if (token == null || !editor.isModified()) {
            return rr.request();
        }
        try {
            String edited = new String(editor.getContents().getBytes(), StandardCharsets.UTF_8);
            String wireB64 = bridge.encrypt(token, edited, hostOf(rr), pathOf(rr));
            byte[] wire = Base64.getDecoder().decode(wireB64);
            return rr.request().withBody(ByteArray.byteArray(wire));
        } catch (Exception e) {
            api.logging().logToError("[tatar-relay] re-encrypt failed, sending original: " + e.getMessage());
            return rr.request();
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

    /** Text as UTF-8 bytes, so non-ASCII plaintext round-trips losslessly. */
    static ByteArray utf8(String s) {
        return ByteArray.byteArray(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Host of the flow, or null when Burp has not attached a service to it.
     *  Best effort on purpose: a null here means "no host supplied", which the
     *  core treats as the previous, unchecked behaviour rather than a refusal. */
    static String hostOf(HttpRequestResponse rr) {
        try {
            return rr.request().httpService().host();
        } catch (Exception e) {
            return null;
        }
    }

    static String pathOf(HttpRequestResponse rr) {
        try {
            return rr.request().path();
        } catch (Exception e) {
            return null;
        }
    }
}
