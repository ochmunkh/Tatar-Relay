package relay;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Tatar Relay — Burp frontend.
 *
 * Registers:
 *  - request AND response editor tabs that show the DECRYPTED plaintext of an
 *    encrypted body (via the local Python bridge, off the UI thread), let you
 *    edit it like normal HTTP in Repeater, and re-encrypt + reseal on send;
 *  - right-click "send plaintext to Intruder / Repeater", which builds a
 *    plaintext template;
 *  - an HTTP handler that encrypts and reseals those templates on send, so
 *    Intruder fuzzes the plaintext of an encrypted API.
 *
 * Config (system properties or environment):
 *   -Dtatar.bridge=http://127.0.0.1:8799   (TATAR_BRIDGE)
 *   -Dtatar.profile=acme-bank-mobile        (TATAR_PROFILE; blank = the only loaded profile)
 *   -Dtatar.relay.token=...                 (TATAR_RELAY_TOKEN; when the bridge uses --token)
 *   -Dtatar.timeout=35                      (TATAR_TIMEOUT; decrypt wait, seconds)
 *   -Dtatar.intruder.preview=false          (skip decrypting responses of sealed requests)
 *
 * Start the bridge first, e.g.:
 *   relay bridge examples/acme-bank-mobile.yaml --var session_key=HEX
 */
public class TatarRelayExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Tatar Relay");

        String bridgeUrl = prop("tatar.bridge", "TATAR_BRIDGE", "http://127.0.0.1:8799");
        String profile = prop("tatar.profile", "TATAR_PROFILE", "");

        BridgeClient bridge = new BridgeClient(bridgeUrl);
        api.userInterface().registerHttpRequestEditorProvider(
                new RelayRequestEditorProvider(api, bridge, profile));
        api.userInterface().registerHttpResponseEditorProvider(
                new RelayResponseEditorProvider(api, bridge, profile));
        api.userInterface().registerContextMenuItemsProvider(
                new RelayContextMenu(api, bridge, profile));
        api.http().registerHttpHandler(new RelayHttpHandler(api, bridge, profile));
        api.extension().registerUnloadingHandler(AsyncDecrypt::shutdown);

        api.logging().logToOutput(
                "Tatar Relay loaded. bridge=" + bridgeUrl
                        + " profile=" + (profile.isEmpty() ? "(single/auto)" : profile)
                        + ". Open a request/response in Repeater and select the "
                        + "Tatar Relay tab, or right-click to send plaintext to Intruder.");
    }

    private static String prop(String sys, String env, String def) {
        String v = System.getProperty(sys);
        if (v == null || v.isEmpty()) v = System.getenv(env);
        return (v == null || v.isEmpty()) ? def : v;
    }
}
