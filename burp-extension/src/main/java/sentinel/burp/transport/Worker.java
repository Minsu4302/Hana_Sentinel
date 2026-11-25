package sentinel.burp.transport;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * 단일 실행기 — (A) §2.9 클라이언트(v1.52): 동시 1건, 대기열 2. 넘치면 제출이 거부된다(사유 코드 client_queue_full).
 * EDT는 제출만 하고 처리는 이 스레드(데몬)에서 한다. 언로드 때 shutdown으로 멈춘다. 2부 PR-2b의 송신도 이 실행기를 쓴다.
 */
public final class Worker {
    public static final int CONCURRENCY = 1;
    public static final int QUEUE = 2;

    private final ThreadPoolExecutor pool = new ThreadPoolExecutor(CONCURRENCY, CONCURRENCY, 0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(QUEUE), r -> {
                Thread t = new Thread(r, "sentinel-worker");
                t.setDaemon(true);
                return t;
            }, new ThreadPoolExecutor.AbortPolicy());

    /** 제출했으면 true, 대기열이 찼거나 멈췄으면 false. */
    public boolean submit(Runnable task) {
        try {
            pool.execute(task);
            return true;
        } catch (RejectedExecutionException e) {
            return false;
        }
    }

    public void shutdown() {
        pool.shutdownNow();
    }
}
