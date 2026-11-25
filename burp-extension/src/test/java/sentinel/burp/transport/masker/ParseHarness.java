package sentinel.burp.transport.masker;

import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import sentinel.burp.capture.core.MetaSource;
import sentinel.burp.capture.core.Prepare;
import sentinel.burp.capture.core.RawParser;
import sentinel.burp.capture.core.Selection;

/**
 * 구문 파서 하네스(src/test/java — 배포 jar 밖). Python 테스트(tests/test_java_request_parse.py)가 빌드 산출물을 java -cp로 실행한다.
 * stdin 한 줄 = 한 명령(탭 구분), stdout 한 줄 = 한 결과(ASCII). 원본·결과 값을 로그로 남기지 않고 디스크에 쓰지 않는다.
 * <ul>
 *   <li>PARSE  req64 resp64 host port secure(0|1) tid captured origin → "OK raw64"(RawEnvelope §2.10 표기) | "REFUSE kind"</li>
 *   <li>PREPARE 같은 필드 → "OK env64"(마스킹된 Envelope) | "REFUSE code"</li>
 *   <li>SELECT origin(LIST|VIEWER|EDITOR) repeater(0|1) count hasResponse(0|1) → "OK code" (받아들이면 "-")</li>
 *   <li>META → "OK tid captured origin"(새로 만든 값)</li>
 * </ul>
 */
public final class ParseHarness {
    private ParseHarness() {
    }

    public static void main(String[] args) throws IOException, Canonical.CanonicalError {
        Base64.Decoder dec = Base64.getDecoder();
        Base64.Encoder enc = Base64.getEncoder();
        OutputStream out = new FileOutputStream(FileDescriptor.out);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isEmpty()) {
                continue;
            }
            String[] f = line.split("\t", -1);
            String result;
            switch (f[0]) {
                case "PARSE": {
                    RawEnvelope.Meta meta = new RawEnvelope.Meta(f[6], f[7], f[8]);
                    try {
                        RawEnvelope.Transaction tx = RawParser.parse(dec.decode(f[1]), dec.decode(f[2]), f[3],
                                Integer.parseInt(f[4]), "1".equals(f[5]), meta);
                        result = "OK\t" + enc.encodeToString(Canonical.dumps(envelope(tx)));
                    } catch (RawParser.Refused e) {
                        result = "REFUSE\t" + e.kind();
                    }
                    break;
                }
                case "PREPARE": {
                    RawEnvelope.Meta meta = new RawEnvelope.Meta(f[6], f[7], f[8]);
                    try {
                        result = "OK\t" + enc.encodeToString(Prepare.envelope(dec.decode(f[1]), dec.decode(f[2]), f[3],
                                Integer.parseInt(f[4]), "1".equals(f[5]), meta));
                    } catch (Prepare.Refusal r) {
                        result = "REFUSE\t" + r.code();
                    }
                    break;
                }
                case "SELECT": {
                    String code = Selection.decide(Selection.Origin.valueOf(f[1]), "1".equals(f[2]), Integer.parseInt(f[3]),
                            "1".equals(f[4]));
                    result = "OK\t" + (code == null ? "-" : code);
                    break;
                }
                case "META": {
                    RawEnvelope.Meta m = MetaSource.now();
                    result = "OK\t" + m.transactionId() + "\t" + m.capturedAt() + "\t" + m.originRef();
                    break;
                }
                default:
                    result = "UNKNOWN";
            }
            out.write((result + "\n").getBytes(StandardCharsets.US_ASCII));
        }
        out.flush();
    }

    /** RawEnvelope(§2.7) — 멤버 순서는 tools/fixture_masker/raw.py 선언 순서. */
    static Map<String, Object> envelope(RawEnvelope.Transaction tx) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("transaction_id", tx.meta().transactionId());
        meta.put("captured_at", tx.meta().capturedAt());
        meta.put("origin_ref", tx.meta().originRef());
        RawEnvelope.Request rq = tx.request();
        List<Object> params = new ArrayList<>();
        for (RawEnvelope.Param p : rq.queryParams()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", p.name());
            m.put("value", p.value());
            m.put("location", p.location());
            params.add(m);
        }
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("method", rq.method());
        request.put("scheme", rq.scheme());
        request.put("host", rq.host());
        request.put("port", rq.port());
        request.put("path", rq.path());
        request.put("query_params", params);
        request.put("headers", headers(rq.headers()));
        request.put("body", body(rq.body()));
        RawEnvelope.Response rs = tx.response();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", rs.status());
        response.put("headers", headers(rs.headers()));
        response.put("body", body(rs.body()));
        response.put("elapsed_ms", rs.elapsedMs());
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("meta", meta);
        t.put("request", request);
        t.put("response", response);
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("schema_version", "1.0");
        env.put("transactions", List.of(t));
        return env;
    }

    private static List<Object> headers(List<RawEnvelope.Header> hs) {
        List<Object> out = new ArrayList<>();
        for (RawEnvelope.Header h : hs) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", h.name());
            m.put("value", h.value());
            out.add(m);
        }
        return out;
    }

    private static Map<String, Object> body(RawEnvelope.Body b) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("content_type", b.contentType());
        m.put("encoding", b.encoding());
        m.put("content", b.content());
        return m;
    }
}
