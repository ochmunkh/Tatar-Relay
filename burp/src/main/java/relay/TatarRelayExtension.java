package relay;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Tatar Relay — Burp frontend (v0.2).
 *
 * Registers request AND response editor tabs that show the DECRYPTED plaintext
 * of an encrypted body (via the local Python bridge), let you edit it like
 * normal HTTP in Repeater, and re-encrypt + reseal on send. The response tab
 * uses the profile's 'response' pipeline.
 *
 * Config (system properties or environment):
 *   -Dtatar.bridge=http://127.0.0.1:8799   (TATAR_BRIDGE)
 *   -Dtatar.profile=acme-bank-mobile        (TATAR_PROFILE; blank = the only loaded profile)
 *
 * Start the bridge first:
 *   relay bridge examples/acme-bank-mobile.yaml --var session_key=&lt;hex&gt;
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

        api.logging().logToOutput(
                "Tatar Relay loaded. bridge=" + bridgeUrl
                        + " profile=" + (profile.isEmpty() ? "(single/auto)" : profile)
                        + "\nOpen a request/response in Repeater and select the 'Tatar Relay' tab.");
    }

    private static String prop(String sys, String env, String def) {
        String v = System.getProperty(sys);
        if (v == null || v.isEmpty()) v = System.getenv(env);
        return (v == null || v.isEmpty()) ? def : v;
    }
}
