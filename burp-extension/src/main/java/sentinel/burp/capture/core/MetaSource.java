package sentinel.burp.capture.core;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import sentinel.burp.transport.masker.RawEnvelope;

/**
 * meta 출처 — (A) §2.2 meta 출처(v1.52). transaction_id = UUIDv4 소문자, captured_at = 메뉴 실행 시각 UTC Z(마이크로초 절사),
 * origin_ref = "ext-" + 16진 8자리(SecureRandom — 호스트 정보 없음). elapsed_ms는 Response에서 null이다.
 */
public final class MetaSource {
    private static final SecureRandom RANDOM = new SecureRandom();

    private MetaSource() {
    }

    public static RawEnvelope.Meta now() {
        return of(Instant.now());
    }

    static RawEnvelope.Meta of(Instant at) {
        String id = UUID.randomUUID().toString();
        String ref = "ext-" + hex8(RANDOM.nextInt());
        return new RawEnvelope.Meta(id, capturedAt(at), ref);
    }

    /** §2.10 시각 표기: YYYY-MM-DDTHH:MM:SS[.ffffff]Z — 소수 초가 0이 아니면 정확히 6자리. */
    public static String capturedAt(Instant at) {
        ZonedDateTime t = at.truncatedTo(ChronoUnit.MICROS).atZone(ZoneOffset.UTC);
        StringBuilder s = new StringBuilder();
        s.append(pad(t.getYear(), 4)).append('-').append(pad(t.getMonthValue(), 2)).append('-').append(pad(t.getDayOfMonth(), 2))
                .append('T').append(pad(t.getHour(), 2)).append(':').append(pad(t.getMinute(), 2)).append(':')
                .append(pad(t.getSecond(), 2));
        int micros = t.getNano() / 1000;
        if (micros != 0) {
            s.append('.').append(pad(micros, 6));
        }
        return s.append('Z').toString();
    }

    private static String pad(int v, int width) {
        String s = Integer.toString(v);
        StringBuilder out = new StringBuilder();
        for (int i = s.length(); i < width; i++) {
            out.append('0');
        }
        return out.append(s).toString();
    }

    private static String hex8(int v) {
        String s = Integer.toHexString(v);
        StringBuilder out = new StringBuilder();
        for (int i = s.length(); i < 8; i++) {
            out.append('0');
        }
        return out.append(s).toString();
    }
}
