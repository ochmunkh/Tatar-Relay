package relay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

/**
 * Right-click actions that turn an encrypted request into a plaintext template.
 *
 * "Send plaintext to Intruder / Repeater" decrypts the selected request through
 * the bridge (in the background), replaces its body with the plaintext JSON and
 * adds {@link Seal#HEADER} carrying the decrypt's ctx_token. Mark payload
 * positions in the plaintext; {@link RelayHttpHandler} encrypts and reseals
 * every attempt on send.
 */
public class RelayContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final BridgeClient bridge;
    private final String profile;

    public RelayContextMenu(MontoyaApi api, BridgeClient bridge, String profile) {
        this.api = api;
        this.bridge = bridge;
        this.profile = profile;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        HttpRequestResponse rr = event.messageEditorRequestResponse()
                .map(MessageEditorHttpRequestResponse::requestResponse)
                .orElseGet(() -> event.selectedRequestResponses().isEmpty()
                        ? null : event.selectedRequestResponses().get(0));
        if (rr == null || rr.request() == null || rr.request().body().length() == 0
                || rr.request().hasHeader(Seal.HEADER)) {
            return Collections.emptyList();
        }
        JMenuItem toIntruder = new JMenuItem("Tatar Relay: send plaintext to Intruder");
        toIntruder.addActionListener(e -> prepare(rr, true));
        JMenuItem toRepeater = new JMenuItem("Tatar Relay: send plaintext to Repeater");
        toRepeater.addActionListener(e -> prepare(rr, false));
        return List.of(toIntruder, toRepeater);
    }

    private void prepare(HttpRequestResponse rr, boolean intruder) {
        final HttpRequest request = rr.request();
        final byte[] wire = request.body().getBytes();
        final String host = RelayHttpRequestEditor.hostOf(rr);
        final String path = RelayHttpRequestEditor.pathOf(rr);
        AsyncDecrypt.sharedWorker().execute(() -> {
            BridgeClient.DecryptResult r = bridge.decryptBytes(profile, "request", wire, host, path);
            if (r.error != null) {
                api.logging().logToError("[tatar-relay] cannot prepare plaintext: " + r.error);
                return;
            }
            HttpRequest template = request
                    .withRemovedHeader(Seal.HEADER)
                    .withAddedHeader(Seal.HEADER, r.ctxToken)
                    .withBody(ByteArray.byteArray(r.plaintextText.getBytes(StandardCharsets.UTF_8)));
            if (intruder) {
                api.intruder().sendToIntruder(template);
            } else {
                api.repeater().sendToRepeater(template, "Tatar Relay (plaintext)");
            }
            api.logging().logToOutput("[tatar-relay] plaintext template sent to "
                    + (intruder ? "Intruder" : "Repeater")
                    + " — it is encrypted and resealed on send.");
        });
    }
}
