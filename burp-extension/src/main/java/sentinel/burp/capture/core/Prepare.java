package sentinel.burp.capture.core;

import java.util.List;
import sentinel.burp.transport.masker.Masker;
import sentinel.burp.transport.masker.MaskerRejected;
import sentinel.burp.transport.masker.Policy;
import sentinel.burp.transport.masker.RawEnvelope;

/**
 * 선택 1건 처리(2부 PR-2a — 송신 0): 구문 파싱 → 마스킹(strict_redaction) → §2.10 직렬화. 결과는 로그 한 줄뿐이다:
 * "prepared bytes=N" 또는 사유 코드. host·경로·값·Envelope 내용은 로그에 쓰지 않는다. 원본 바이트는 이 호출 안에서만 쓴다.
 */
public final class Prepare {
    private Prepare() {
    }

    /** 마스킹된 Envelope(§2.10 바이트). 실패하면 사유 코드를 담은 예외. */
    public static byte[] envelope(byte[] request, byte[] response, String host, int port, boolean secure,
                                  RawEnvelope.Meta meta) throws Refusal {
        RawEnvelope.Transaction tx;
        try {
            tx = RawParser.parse(request, response, host, port, secure, meta);
        } catch (RawParser.Refused e) {
            throw new Refusal(Reasons.PARSE_REFUSED);
        }
        try {
            List<Masker.Output> outs = Masker.mask(new RawEnvelope(List.of(tx)), "strict_redaction", Policy.bundled());
            return outs.get(0).bytes();
        } catch (MaskerRejected | Policy.PolicyInvalid e) {
            throw new Refusal(Reasons.MASK_REFUSED);
        }
    }

    /** 로그 한 줄(사유 코드 + 크기). */
    public static String run(byte[] request, byte[] response, String host, int port, boolean secure, RawEnvelope.Meta meta) {
        try {
            return Reasons.PREPARED + " bytes=" + envelope(request, response, host, port, secure, meta).length;
        } catch (Refusal r) {
            return r.code();
        }
    }

    /** 처리 거부 — 사유 코드만. */
    public static final class Refusal extends Exception {
        private static final long serialVersionUID = 1L;
        private final String code;

        Refusal(String code) {
            super(code, null, false, false);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }
}
