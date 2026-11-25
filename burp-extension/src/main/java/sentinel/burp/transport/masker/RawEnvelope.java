package sentinel.burp.transport.masker;

import java.util.List;

/**
 * 마스킹 전 원본 — (A) §2.7 RawTransaction의 메모리 표현(참조: tools/fixture_masker/raw.py). 디스크에 쓰지 않는다.
 * 필드 값은 이미 검증된 것이다: transactionId는 소문자 8-4-4-4-12, capturedAt은 §2.10 시각 표기.
 * (2부 PR-2의 capture가 원시 바이트에서 만들고, 동등성 하네스는 테스트 입력 JSON에서 만든다.)
 */
public record RawEnvelope(List<Transaction> transactions) {

    public record Transaction(Meta meta, Request request, Response response) {
    }

    public record Meta(String transactionId, String capturedAt, String originRef) {
    }

    public record Request(String method, String scheme, String host, int port, String path, List<Param> queryParams,
                          List<Header> headers, Body body) {
    }

    public record Response(int status, List<Header> headers, Body body, Long elapsedMs) {
    }

    public record Header(String name, String value) {
    }

    public record Param(String name, String value, String location) {
    }

    /** encoding = utf8 | base64 | omitted, content는 null일 수 있다. */
    public record Body(String contentType, String encoding, String content) {
    }
}
