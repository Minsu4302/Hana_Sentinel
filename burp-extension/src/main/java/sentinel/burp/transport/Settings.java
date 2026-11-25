package sentinel.burp.transport;

import java.util.Arrays;

/**
 * 연결 설정 — (A) §2.9 토큰·클라이언트(v1.52). 토큰은 char[]로 메모리에만 두고(디스크·preferences 0), 바꾸거나 지울 때와
 * 언로드 때 0으로 덮는다. 기본값은 Python 서버 기본값과 같다(포트 8765, 대기 상한 2, 기한 120초 — 테스트가 기계 대조).
 */
public final class Settings {
    public static final int DEFAULT_PORT = 8765;
    public static final int DEFAULT_QUEUE_LIMIT = 2;
    public static final int DEFAULT_DEADLINE_SECONDS = 120;

    private char[] token = new char[0];
    private int port = DEFAULT_PORT;
    private int queueLimit = DEFAULT_QUEUE_LIMIT;
    private int deadlineSeconds = DEFAULT_DEADLINE_SECONDS;

    /** 새 토큰을 받는다(넘겨받은 배열을 그대로 쓴다). 이전 배열은 0으로 덮는다. */
    public synchronized void replaceToken(char[] fresh) {
        Arrays.fill(token, '\0');
        token = fresh;
    }

    public synchronized boolean hasToken() {
        return token.length > 0;
    }

    public synchronized void apply(int port, int queueLimit, int deadlineSeconds) {
        if (port < 1 || port > 65535 || queueLimit < 0 || deadlineSeconds < 1) {
            return;  // 범위 밖 값은 무시하고 이전 값을 유지한다
        }
        this.port = port;
        this.queueLimit = queueLimit;
        this.deadlineSeconds = deadlineSeconds;
    }

    public synchronized int port() {
        return port;
    }

    public synchronized int queueLimit() {
        return queueLimit;
    }

    public synchronized int deadlineSeconds() {
        return deadlineSeconds;
    }

    /** 토큰을 0으로 덮고 비운다(지우기·언로드). */
    public synchronized void clear() {
        Arrays.fill(token, '\0');
        token = new char[0];
    }
}
