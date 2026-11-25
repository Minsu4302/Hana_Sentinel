package sentinel.burp.transport.masker;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 동등성 하네스 전용(배포 jar 밖): RawEnvelope JSON 바이트 → RawEnvelope. 참조 마스커의 load_raw와 같은 순서로 거부한다:
 * UTF-8·엄격 JSON 아님 → input_not_json, schema_version이 "1.0"이 아님 → unknown_schema_version,
 * 구조 위반(모르는 필드·빠진 필드·타입·범위·path의 '?') → raw_schema_invalid.
 * 시각은 YYYY-MM-DDTHH:MM:SS[.f{1,6}](Z|±HH:MM)만 받는다(코퍼스 형식 — 그 밖의 표기는 하네스 범위 밖이라 거부).
 */
final class RawEnvelopeJson {
    private static final Pattern UUID_FORM = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern TIME_FORM = Pattern.compile(
            "(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:\\.(\\d{1,6}))?(Z|([+-])(\\d{2}):(\\d{2}))");
    private static final Pattern INT_FORM = Pattern.compile("-?(?:0|[1-9][0-9]*)");

    private RawEnvelopeJson() {
    }

    private static final class Bad extends Exception {
        private static final long serialVersionUID = 1L;

        Bad() {
            super("raw_schema_invalid", null, false, false);
        }
    }

    static RawEnvelope read(byte[] data) throws MaskerRejected {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException e) {
            throw new MaskerRejected("input_not_json");
        }
        Object doc;
        try {
            doc = StrictJson.parse(text);
        } catch (StrictJson.Invalid e) {
            throw new MaskerRejected("input_not_json");
        }
        if (!(doc instanceof Map<?, ?> top) || !"1.0".equals(top.get("schema_version"))) {
            throw new MaskerRejected("unknown_schema_version");
        }
        try {
            Map<?, ?> m = obj(top, Set.of("schema_version", "transactions"));
            List<RawEnvelope.Transaction> txs = new ArrayList<>();
            for (Object t : list(m.get("transactions"))) {
                txs.add(transaction(t));
            }
            if (txs.isEmpty()) {
                throw new Bad();
            }
            return new RawEnvelope(List.copyOf(txs));
        } catch (Bad e) {
            throw new MaskerRejected("raw_schema_invalid");
        }
    }

    private static Map<?, ?> obj(Object v, Set<String> fields) throws Bad {
        if (!(v instanceof Map<?, ?> m) || !m.keySet().equals(fields)) {
            throw new Bad();
        }
        return m;
    }

    private static List<?> list(Object v) throws Bad {
        if (!(v instanceof List<?> l)) {
            throw new Bad();
        }
        return l;
    }

    private static String str(Object v) throws Bad {
        if (!(v instanceof String s)) {
            throw new Bad();
        }
        return s;
    }

    private static String strOrNull(Object v) throws Bad {
        return v == StrictJson.NULL ? null : str(v);
    }

    private static String oneOf(Object v, Set<String> allowed) throws Bad {
        String s = str(v);
        if (!allowed.contains(s)) {
            throw new Bad();
        }
        return s;
    }

    private static long integer(Object v, long min, long max) throws Bad {
        if (!(v instanceof StrictJson.Num n) || !INT_FORM.matcher(n.token()).matches()) {
            throw new Bad();
        }
        BigInteger b = new BigInteger(n.token());
        if (b.compareTo(BigInteger.valueOf(min)) < 0 || b.compareTo(BigInteger.valueOf(max)) > 0) {
            throw new Bad();
        }
        return b.longValueExact();
    }

    private static RawEnvelope.Transaction transaction(Object v) throws Bad {
        Map<?, ?> t = obj(v, Set.of("meta", "request", "response"));
        Map<?, ?> meta = obj(t.get("meta"), Set.of("transaction_id", "captured_at", "origin_ref"));
        String id = str(meta.get("transaction_id"));
        if (!UUID_FORM.matcher(id).matches()) {
            throw new Bad();
        }
        RawEnvelope.Meta m = new RawEnvelope.Meta(id.toLowerCase(Locale.ROOT), capturedAt(str(meta.get("captured_at"))),
                str(meta.get("origin_ref")));
        Map<?, ?> rq = obj(t.get("request"), Set.of("method", "scheme", "host", "port", "path", "query_params",
                "headers", "body"));
        String path = str(rq.get("path"));
        if (path.indexOf('?') >= 0) {
            throw new Bad();
        }
        List<RawEnvelope.Param> params = new ArrayList<>();
        for (Object p : list(rq.get("query_params"))) {
            Map<?, ?> pm = obj(p, Set.of("name", "value", "location"));
            params.add(new RawEnvelope.Param(str(pm.get("name")), str(pm.get("value")),
                    oneOf(pm.get("location"), Set.of("query", "form"))));
        }
        RawEnvelope.Request request = new RawEnvelope.Request(str(rq.get("method")),
                oneOf(rq.get("scheme"), Set.of("http", "https")), str(rq.get("host")),
                (int) integer(rq.get("port"), 0, 65535), path, List.copyOf(params), headers(rq.get("headers")),
                body(rq.get("body")));
        Map<?, ?> rs = obj(t.get("response"), Set.of("status", "headers", "body", "elapsed_ms"));
        Object elapsed = rs.get("elapsed_ms");
        RawEnvelope.Response response = new RawEnvelope.Response((int) integer(rs.get("status"), 100, 599),
                headers(rs.get("headers")), body(rs.get("body")),
                elapsed == StrictJson.NULL ? null : integer(elapsed, 0, Long.MAX_VALUE));
        return new RawEnvelope.Transaction(m, request, response);
    }

    private static List<RawEnvelope.Header> headers(Object v) throws Bad {
        List<RawEnvelope.Header> out = new ArrayList<>();
        for (Object h : list(v)) {
            Map<?, ?> hm = obj(h, Set.of("name", "value"));
            out.add(new RawEnvelope.Header(str(hm.get("name")), str(hm.get("value"))));
        }
        return List.copyOf(out);
    }

    private static RawEnvelope.Body body(Object v) throws Bad {
        Map<?, ?> b = obj(v, Set.of("content_type", "encoding", "content"));
        return new RawEnvelope.Body(str(b.get("content_type")), oneOf(b.get("encoding"), Set.of("utf8", "base64", "omitted")),
                strOrNull(b.get("content")));
    }

    /** 코퍼스 시각 표기 → §2.10 표기(소수 초가 0이 아니면 6자리, 오프셋 0이면 Z). */
    static String capturedAt(String s) throws Bad {
        Matcher m = TIME_FORM.matcher(s);
        if (!m.matches()) {
            throw new Bad();
        }
        int year = Integer.parseInt(m.group(1));
        int month = Integer.parseInt(m.group(2));
        int day = Integer.parseInt(m.group(3));
        int hour = Integer.parseInt(m.group(4));
        int minute = Integer.parseInt(m.group(5));
        int second = Integer.parseInt(m.group(6));
        if (year < 1 || month < 1 || month > 12 || day < 1 || day > java.time.YearMonth.of(year, month).lengthOfMonth()
                || hour > 23 || minute > 59 || second > 59) {
            throw new Bad();
        }
        String frac = m.group(7) == null ? "" : (m.group(7) + "000000").substring(0, 6);
        StringBuilder out = new StringBuilder(s.substring(0, 19));
        if (!frac.isEmpty() && !frac.equals("000000")) {
            out.append('.').append(frac);
        }
        if (m.group(8).equals("Z")) {
            out.append('Z');
        } else {
            int oh = Integer.parseInt(m.group(10));
            int om = Integer.parseInt(m.group(11));
            if (oh > 23 || om > 59) {
                throw new Bad();
            }
            out.append(oh == 0 && om == 0 ? "Z" : m.group(9) + m.group(10) + ":" + m.group(11));
        }
        return out.toString();
    }
}
