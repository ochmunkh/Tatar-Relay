package relay;

import javax.swing.SwingUtilities;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Runs bridge calls off the Swing event thread and delivers only the newest result.
 *
 * Burp calls an editor's {@code setRequestResponse} on the event-dispatch
 * thread. A synchronous bridge round-trip there froze the whole Burp UI for as
 * long as the call took. Work now runs on a small shared daemon pool and the
 * result is handed back on the UI thread — and only if no newer job was started
 * in the meantime (the operator may already have clicked another message), so a
 * slow answer can never overwrite a newer one.
 */
public final class AsyncDecrypt {

    private static final ExecutorService SHARED = Executors.newFixedThreadPool(3, r -> {
        Thread t = new Thread(r, "tatar-relay-bridge");
        t.setDaemon(true);          // never keeps Burp alive on exit
        return t;
    });

    private final Executor worker;
    private final Executor ui;
    private final AtomicLong generation = new AtomicLong();

    /** Production wiring: shared pool, results on the Swing event thread. */
    public AsyncDecrypt() {
        this(SHARED, SwingUtilities::invokeLater);
    }

    /** Injectable executors, for tests. */
    AsyncDecrypt(Executor worker, Executor ui) {
        this.worker = worker;
        this.ui = ui;
    }

    /** The shared background pool (used by the context-menu actions too). */
    public static Executor sharedWorker() {
        return SHARED;
    }

    /**
     * Start a job. Any job still in flight becomes stale and its result is
     * dropped. {@code onCurrent} runs on the UI executor with the result —
     * errors arrive as a result with {@code error} set, never as an exception.
     */
    public long submit(Supplier<BridgeClient.DecryptResult> work,
                       Consumer<BridgeClient.DecryptResult> onCurrent) {
        final long gen = generation.incrementAndGet();
        Runnable job = () -> {
            BridgeClient.DecryptResult r;
            try {
                r = work.get();
            } catch (Throwable t) {
                r = failure("internal: " + t);
            }
            deliver(gen, r, onCurrent);
        };
        try {
            worker.execute(job);
        } catch (RejectedExecutionException e) {   // pool shut down (extension unloading)
            deliver(gen, failure("extension is unloading"), onCurrent);
        }
        return gen;
    }

    private void deliver(long gen, BridgeClient.DecryptResult r,
                         Consumer<BridgeClient.DecryptResult> onCurrent) {
        ui.execute(() -> {
            if (generation.get() == gen) onCurrent.accept(r);
        });
    }

    /** Invalidate any pending job without starting a new one. */
    public void cancel() {
        generation.incrementAndGet();
    }

    public boolean isCurrent(long gen) {
        return generation.get() == gen;
    }

    static BridgeClient.DecryptResult failure(String why) {
        BridgeClient.DecryptResult r = new BridgeClient.DecryptResult();
        r.error = why;
        return r;
    }

    /** Called from the extension's unloading handler. */
    public static void shutdown() {
        SHARED.shutdownNow();
    }
}
