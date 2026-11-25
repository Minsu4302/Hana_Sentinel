package sentinel.burp.capture.core;

import java.util.List;

/**
 * Java 로그 사유 코드 — (A) §2.9 사유 코드(v1.52). 닫힌 목록이고 이 목록이 정본이다.
 * 금지 토큰(판정 어휘 등)과의 교집합이 0인지 Python 테스트가 확인한다. 로그 줄은 "sentinel: <코드>"와 크기·HTTP status만 담는다.
 */
public final class Reasons {
    public static final String PREPARED = "prepared";
    public static final String SENT = "sent";
    public static final String HTTP_STATUS = "http_status";
    public static final String SERVER_BUSY = "server_busy";
    public static final String DEADLINE_PASSED = "deadline_passed";
    public static final String CONNECT_FAILED = "connect_failed";
    public static final String RESPONSE_TOO_LARGE = "response_too_large";
    public static final String RESPONSE_NOT_STRICT_JSON = "response_not_strict_json";
    public static final String ENVELOPE_TOO_LARGE = "envelope_too_large";
    public static final String CLIENT_QUEUE_FULL = "client_queue_full";
    public static final String SELECTION_NOT_SINGLE = "selection_not_single";
    public static final String NO_RESPONSE = "no_response";
    public static final String EDITABLE_MESSAGE = "editable_message";
    public static final String REPEATER_SOURCE = "repeater_source";
    public static final String PARSE_REFUSED = "parse_refused";
    public static final String MASK_REFUSED = "mask_refused";
    public static final String TOKEN_MISSING = "token_missing";

    public static final List<String> ALL = List.of(PREPARED, SENT, HTTP_STATUS, SERVER_BUSY, DEADLINE_PASSED, CONNECT_FAILED,
            RESPONSE_TOO_LARGE, RESPONSE_NOT_STRICT_JSON, ENVELOPE_TOO_LARGE, CLIENT_QUEUE_FULL, SELECTION_NOT_SINGLE,
            NO_RESPONSE, EDITABLE_MESSAGE, REPEATER_SOURCE, PARSE_REFUSED, MASK_REFUSED, TOKEN_MISSING);

    private Reasons() {
    }
}
