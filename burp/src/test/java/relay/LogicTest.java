package relay;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Pure-Java unit tests for the parts that do not need Burp: AsyncDecrypt's
 * freshness guard, the Seal template helpers, and BridgeClient parsing.
 *
 * No JUnit — a plain main() with a tiny assert helper, matching
 * ExtensionLoadTest, so the Burp module stays dependency-free.
 */
public final class LogicTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        asyncDeliversNewestOnly();
        asyncDropsStaleResult();
        asyncErrorBecomesResult();
        asyncRejectedExecutionIsReported();
        sealTokenShape();
        sealPreviewIsBoundedOneLine();
        sealWithheldNote();
        bridgeSecondsParsing();
        bridgePrettyKeepsAngleBrackets();

        if (failures > 0) {
            System.out.println("\nRESULT  " + failures + " check(s) failed");
            System.exit(1);
        }
        System.out.println("\nRESULT  logic tests pass");
    }

    // ---- AsyncDecrypt -----------------------------------------------------

    /** A direct ("same thread") executor so ordering is deterministic. */
    private static final Executor DIRECT = Runnable::run;

    private static void asyncDeliversNewestOnly() {
        AsyncDecrypt a = new AsyncDecrypt(DIRECT, DIRECT);
        AtomicReference<String> got = new AtomicReference<>();
        a.submit(() -> result("one", null), r -> got.set(r.plaintextText));
        check("newest result delivered", "one".equals(got.get()));
    }

    private static void asyncDropsStaleResult() throws Exception {
        // worker defers the first job until after a second job has superseded it.
        ExecutorService pool = Executors.newFixedThreadPool(2);
        AtomicInteger delivered = new AtomicInteger();
        AsyncDecrypt a = new AsyncDecrypt(pool, Runnable::run);
        CountDownLatch firstRunning = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        a.submit(() -> {
            firstRunning.countDown();
            await(release);
            return result("stale", null);
        }, r -> delivered.incrementAndGet());

        firstRunning.await(2, TimeUnit.SECONDS);
        a.submit(() -> result("fresh", null), r -> delivered.incrementAndGet());  // supersedes
        release.countDown();
        pool.shutdown();
        pool.awaitTermination(3, TimeUnit.SECONDS);
        check("stale result is dropped (only the fresh one is delivered)", delivered.get() == 1);
    }

    private static void asyncErrorBecomesResult() {
        AsyncDecrypt a = new AsyncDecrypt(DIRECT, DIRECT);
        AtomicReference<String> err = new AtomicReference<>();
        a.submit(() -> { throw new RuntimeException("boom"); }, r -> err.set(r.error));
        check("a thrown error arrives as a result, not an exception",
                err.get() != null && err.get().contains("boom"));
    }

    private static void asyncRejectedExecutionIsReported() {
        ExecutorService pool = Executors.newSingleThreadExecutor();
        pool.shutdownNow();                       // every execute() now rejects
        AsyncDecrypt a = new AsyncDecrypt(pool, Runnable::run);
        AtomicReference<String> err = new AtomicReference<>();
        a.submit(() -> result("x", null), r -> err.set(r.error));
        check("a rejected job reports instead of throwing",
                err.get() != null && err.get().contains("unloading"));
    }

    // ---- Seal -------------------------------------------------------------

    private static void sealTokenShape() {
        check("valid 128-bit token accepted", Seal.isToken("t-" + "0123456789abcdef".repeat(2)));
        check("uppercase hex rejected", !Seal.isToken("t-" + "0123456789ABCDEF".repeat(2)));
        check("short token rejected", !Seal.isToken("t-00"));
        check("no-prefix rejected", !Seal.isToken("0123456789abcdef0123456789abcdef"));
        check("null rejected", !Seal.isToken(null));
    }

    private static void sealPreviewIsBoundedOneLine() {
        String p = Seal.preview("line one\n   line two\t\tx", 100);
        check("preview collapses whitespace to one line", p.equals("line one line two x"));
        check("preview is length-bounded with an ellipsis",
                Seal.preview("abcdefghij", 5).equals("abcd…"));
    }

    private static void sealWithheldNote() {
        check("withheld note names the reason",
                Seal.withheldNote("scope_violation").contains("withheld")
                        && Seal.withheldNote("scope_violation").contains("scope_violation"));
    }

    // ---- BridgeClient -----------------------------------------------------

    private static void bridgeSecondsParsing() {
        System.clearProperty("x.sec");
        check("missing -> default", BridgeClient.seconds("x.sec", "X_SEC_NONE", 35) == 35);
        System.setProperty("x.sec", "60");
        check("valid -> parsed", BridgeClient.seconds("x.sec", "X_SEC_NONE", 35) == 60);
        System.setProperty("x.sec", "nonsense");
        check("garbage -> default", BridgeClient.seconds("x.sec", "X_SEC_NONE", 35) == 35);
        System.setProperty("x.sec", "-5");
        check("non-positive -> default", BridgeClient.seconds("x.sec", "X_SEC_NONE", 35) == 35);
        System.clearProperty("x.sec");
    }

    private static void bridgePrettyKeepsAngleBrackets() {
        com.google.gson.JsonObject o = new com.google.gson.JsonObject();
        o.addProperty("payload", "<script>alert(1)</script>");
        String out = BridgeClient.pretty(o);
        check("pretty JSON does not \\u-escape a payload (HTML escaping off)",
                out.contains("<script>") && !out.contains("\\u003c"));
    }

    // ---- helpers ----------------------------------------------------------

    private static BridgeClient.DecryptResult result(String plain, String err) {
        BridgeClient.DecryptResult r = new BridgeClient.DecryptResult();
        r.plaintextText = plain;
        r.ctxToken = "t-" + "0123456789abcdef".repeat(2);
        r.error = err;
        return r;
    }

    private static void await(CountDownLatch l) {
        try {
            l.await(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + what);
        if (!ok) failures++;
    }
}
