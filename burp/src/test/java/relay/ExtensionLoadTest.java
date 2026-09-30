package relay;

import burp.api.montoya.MontoyaApi;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

/**
 * Does the extension actually load?
 *
 * Burp itself cannot answer that in CI. Burp Community is GUI-only — loading an
 * extension and reading back "it registered" is a Professional/Enterprise
 * feature, and there is no supported headless path. So this stands in for the
 * part that can be checked without Burp: that {@code initialize()} runs to
 * completion against a well-behaved API and registers what it promises.
 *
 * Note this is the MONTOYA entry point. {@code registerExtenderCallbacks} is
 * the legacy Extender API; this extension implements {@code BurpExtension}, so
 * {@code initialize(MontoyaApi)} is the method Burp calls.
 *
 * MontoyaApi is a wide interface and its sub-interfaces are wider. Rather than
 * hand-writing stubs for all of it — which would need updating whenever
 * PortSwigger adds a method — the API is a dynamic proxy that records every
 * call and hands back a recording proxy for any interface-typed return. That
 * keeps the test dependency-free: no Mockito, no JUnit, just a main().
 *
 * What this does NOT prove: that Burp accepts the jar, that the editor tabs
 * render, or that the bridge round-trips. Those need a real Burp — see
 * burp/BUILD.md.
 */
public final class ExtensionLoadTest {

    private static final List<String> CALLS = new ArrayList<>();
    private static int failures = 0;

    public static void main(String[] args) {
        MontoyaApi api = (MontoyaApi) recorder(MontoyaApi.class, "api");

        try {
            new TatarRelayExtension().initialize(api);
        } catch (Throwable t) {
            fail("initialize() threw " + t.getClass().getName() + ": " + t.getMessage());
            t.printStackTrace();
            System.exit(1);
        }
        pass("initialize() completed without throwing");

        expect("api.extension().setName", "the extension names itself");
        expectArg("Tatar Relay", "it registers under the name 'Tatar Relay'");
        expect("api.userInterface().registerHttpRequestEditorProvider",
                "a request editor tab is registered");
        expect("api.userInterface().registerHttpResponseEditorProvider",
                "a response editor tab is registered");
        expect("api.logging().logToOutput", "it reports the bridge/profile it will use");

        // The defaults matter: a user who sets neither property gets the local
        // bridge, not a null URL that only fails later inside an editor tab.
        expectArg("http://127.0.0.1:8799", "the default bridge URL is logged");

        System.out.println();
        if (failures > 0) {
            System.out.println("RESULT  " + failures + " check(s) failed");
            System.out.println("calls recorded:");
            for (String c : CALLS) System.out.println("  " + c);
            System.exit(1);
        }
        System.out.println("RESULT  extension loads and registers correctly");
    }

    // ---- assertions ------------------------------------------------------

    private static void expect(String prefix, String what) {
        for (String c : CALLS) {
            if (c.startsWith(prefix)) { pass(what); return; }
        }
        fail(what + "  (no call matching '" + prefix + "')");
    }

    /** Some recorded call passed this exact argument. */
    private static void expectArg(String needle, String what) {
        for (String c : CALLS) {
            if (c.contains(needle)) { pass(what); return; }
        }
        fail(what + "  (no call carried '" + needle + "')");
    }

    private static void pass(String what) { System.out.println("  PASS  " + what); }

    private static void fail(String what) { System.out.println("  FAIL  " + what); failures++; }

    // ---- the recording proxy --------------------------------------------

    private static Object recorder(Class<?> iface, String path) {
        return Proxy.newProxyInstance(
                ExtensionLoadTest.class.getClassLoader(),
                new Class<?>[]{iface},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method m, Object[] a) {
                        // Object's own methods must not be recorded or proxied,
                        // or printing/equality inside the proxy recurses.
                        switch (m.getName()) {
                            case "toString": return path;
                            case "hashCode": return System.identityHashCode(proxy);
                            case "equals":   return proxy == (a == null ? null : a[0]);
                            default: break;
                        }

                        // `path` is already a full expression ("api",
                        // "api.logging()"), so append ".name(args)" to it.
                        String expr = path + "." + m.getName();
                        CALLS.add(expr + "(" + describe(a) + ")");

                        Class<?> ret = m.getReturnType();
                        if (ret.isInterface()) {
                            return recorder(ret, expr + "()");
                        }
                        return defaultValue(ret);
                    }
                });
    }

    private static String describe(Object[] args) {
        if (args == null || args.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < args.length; i++) {
            if (i > 0) sb.append(", ");
            Object a = args[i];
            if (a instanceof String) sb.append('"').append(a).append('"');
            else if (a == null) sb.append("null");
            else sb.append(a.getClass().getSimpleName());
        }
        return sb.toString();
    }

    private static Object defaultValue(Class<?> t) {
        if (!t.isPrimitive()) return null;
        if (t == boolean.class) return false;
        if (t == char.class) return '\0';
        if (t == byte.class) return (byte) 0;
        if (t == short.class) return (short) 0;
        if (t == int.class) return 0;
        if (t == long.class) return 0L;
        if (t == float.class) return 0f;
        if (t == double.class) return 0d;
        return null; // void
    }
}
