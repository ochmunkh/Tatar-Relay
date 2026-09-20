package relay;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

public class RelayResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final BridgeClient bridge;
    private final String profile;

    public RelayResponseEditorProvider(MontoyaApi api, BridgeClient bridge, String profile) {
        this.api = api;
        this.bridge = bridge;
        this.profile = profile;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext ctx) {
        return new RelayHttpResponseEditor(api, bridge, profile);
    }
}
