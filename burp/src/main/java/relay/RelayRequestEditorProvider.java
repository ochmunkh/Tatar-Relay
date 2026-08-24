package relay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

public class RelayRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final BridgeClient bridge;
    private final String profile;

    public RelayRequestEditorProvider(MontoyaApi api, BridgeClient bridge, String profile) {
        this.api = api;
        this.bridge = bridge;
        this.profile = profile;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
        return new RelayHttpRequestEditor(api, bridge, profile);
    }
}
