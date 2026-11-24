package sentinel.burp.transport.masker;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 마스커 코어 — RawEnvelope → 마스킹된 Envelope(§2.10 바이트). 참조 구현 tools/fixture_masker/masker.py의 transaction 배치.
 *
 * <p>배치 = Envelope 1개(트랜잭션 하나)마다 HMAC 키·라벨 표·host 번호를 새로 만든다((A) §2.3). run 배치는 없다(데이터셋 생성기 전용).
 * HMAC 키(javax.crypto, 32바이트)는 메모리에만 두고, 배치가 끝나면(성공·실패 무관) 키 배열을 0으로 덮어쓰고 표·원본 값을 버린다.
 * 한계: SecretKeySpec·Mac이 내부에 만든 키 사본은 덮어쓸 수 없다(JCA 구현 몫) — 참조 객체는 배치 끝에 버린다.
 *
 * <p>base64 본문은 항상 omitted다((A) §2.9 — 원본값은 Java 경계를 넘지 않는다). 참조 마스커와 다르므로 동등성 범위 밖이다.
 * 출력 전 자체 검증: Body 불변식 1~6, 불변식 7, 라벨 규칙, §2.10 직렬화, 유출 검사. 하나라도 어긋나면 아무것도 내지 않는다.
 */
public final class Masker {
    public static final String FILLER = "[MASKED]";
    public static final String TRUNCATION_MARK = "[[TRUNCATED]]";
    public static final List<String> MODES = List.of("strict_redaction", "relation_preserving");
    static final int REQUEST_LIMIT = 64 * 1024;
    static final int RESPONSE_LIMIT = 256 * 1024;
    static final int MAX_LABEL = 9999;
    static final int MIN_FRAGMENT = 8;
    static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";
    private static final SecureRandom RANDOM = new SecureRandom();

    /** 파일 이름(트랜잭션 id + ".json")과 §2.10 바이트. */
    public record Output(String name, byte[] bytes) {
    }

    private Masker() {
    }

    public static List<Output> mask(RawEnvelope raw, String mode, Policy policy) throws MaskerRejected {
        if (!MODES.contains(mode)) {
            throw new MaskerRejected("unknown_mode");
        }
        if (!policy.objectIdRules.isEmpty()) {
            throw new MaskerRejected("object_id_rules_unsupported");
        }
        Globs globs = Globs.of(policy);
        List<Output> out = new ArrayList<>();
        for (RawEnvelope.Transaction tx : raw.transactions()) {
            out.add(maskBatch(tx, mode, policy, globs));
        }
        return out;
    }

    // ── 정책 body_rules → json·form glob ─────────────────────────────

    private record Globs(List<String> json, List<String> form) {
        static Globs of(Policy policy) throws MaskerRejected {
            List<String> json = new ArrayList<>();
            List<String> form = new ArrayList<>();
            for (Policy.Rule rule : policy.bodyRules) {
                String matcher = rule.pattern();
                int colon = matcher.indexOf(':');
                String kind = colon < 0 ? "" : matcher.substring(0, colon);
                String pattern = colon < 0 ? "" : matcher.substring(colon + 1);
                if (colon < 0 || !(kind.equals("json") || kind.equals("form")) || pattern.isEmpty()) {
                    throw new MaskerRejected("policy_matcher_unknown");
                }
                if (!"keep".equals(rule.action())) {
                    (kind.equals("json") ? json : form).add(PyText.lower(pattern));
                }
            }
            return new Globs(json, form);
        }
    }

    static boolean matchesAny(String name, List<String> globs) {
        String lowered = PyText.lower(name);
        for (String g : globs) {
            if (Glob.matches(lowered, g)) {
                return true;
            }
        }
        return false;
    }

    // ── 배치 상태: HMAC 키·라벨 표·원본 값 ───────────────────────────

    private static final class Batch {
        final String mode;
        byte[] key = new byte[32];
        Mac mac;
        final Map<String, String> table = new HashMap<>();
        final List<String[]> emitted = new ArrayList<>();
        final List<String> originals = new ArrayList<>();
        final List<String> droppedKinds = new ArrayList<>();
        int hosts;
        int count;

        Batch(String mode) throws GeneralSecurityException {
            this.mode = mode;
            RANDOM.nextBytes(key);
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            Arrays.fill(key, (byte) 0);
        }

        String digest(String original) throws CharacterCodingException {
            ByteBuffer bytes = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(original));
            byte[] in = new byte[bytes.remaining()];
            bytes.get(in);
            byte[] d = mac.doFinal(in);
            Arrays.fill(in, (byte) 0);
            StringBuilder hex = new StringBuilder(64);
            for (byte b : d) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            Arrays.fill(d, (byte) 0);
            return hex.toString();
        }

        String label(String digest) throws MaskerRejected {
            if (mode.equals("strict_redaction")) {
                return null;
            }
            String existing = table.get(digest);
            if (existing != null) {
                return existing;
            }
            int n = table.size() + 1;
            if (n > MAX_LABEL) {
                throw new MaskerRejected("label_space_exhausted");
            }
            String label = "ref_" + twoDigits(n);
            table.put(digest, label);
            return label;
        }

        Map<String, Object> masked(String original, String kind) throws MaskerRejected, CharacterCodingException {
            originals.add(original);
            String d = digest(original);
            String label = label(d);
            emitted.add(new String[] {d, label});
            count++;
            Map<String, Object> ref = new LinkedHashMap<>();
            ref.put("masked", Boolean.TRUE);
            ref.put("label", label);
            ref.put("kind", kind);
            return ref;
        }

        void discard() {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
            key = null;
            mac = null;
            table.clear();
            emitted.clear();
            originals.clear();
            droppedKinds.clear();
        }
    }

    static String twoDigits(int n) {
        String s = Integer.toString(n);
        return s.length() < 2 ? "0" + s : s;
    }

    // ── 변환 ──────────────────────────────────────────────────────────

    private static String headerKind(String name, Policy policy) {
        String lowered = PyText.lower(name);
        if (lowered.equals("host")) {
            return "host";
        }
        if (policy.requiresMaskedHeader(name)) {
            return lowered.contains("cookie") ? "cookie" : "token";
        }
        return null;
    }

    private static Map<String, Object> header(RawEnvelope.Header h, Batch b, Policy policy)
            throws MaskerRejected, CharacterCodingException {
        String kind = headerKind(h.name(), policy);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", h.name());
        out.put("value", kind == null ? h.value() : b.masked(h.value(), kind));
        return out;
    }

    private static String mediaType(RawEnvelope.Body body) {
        String ct = body.contentType();
        int semi = ct.indexOf(';');
        return PyText.lower(PyText.strip(semi < 0 ? ct : ct.substring(0, semi)));
    }

    /** 마스킹한 본문과 span 목록. */
    private record Masked(String content, List<Map<String, Object>> spans) {
    }

    private static Map<String, Object> textAt(int start) {
        Map<String, Object> range = new LinkedHashMap<>();
        range.put("start", start);
        range.put("end", start + FILLER.length());
        Map<String, Object> at = new LinkedHashMap<>();
        at.put("kind", "text");
        at.put("range", range);
        return at;
    }

    private static Map<String, Object> span(Map<String, Object> at, Map<String, Object> ref) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("at", at);
        s.put("ref", ref);
        return s;
    }

    private static Masked maskJson(String content, List<String> globs, Batch b)
            throws MaskerRejected, CharacterCodingException {
        if (globs.isEmpty()) {
            return new Masked(content, new ArrayList<>());
        }
        List<JsonSpans.Span> hits = new ArrayList<>();
        for (JsonSpans.Span s : JsonSpans.stringValues(content)) {
            if (s.key() != null && matchesAny(s.key(), globs)) {
                hits.add(s);
            }
        }
        List<Map<String, Object>> spans = new ArrayList<>();
        for (JsonSpans.Span h : hits) {  // 문서 순서로 라벨 발급
            Map<String, Object> at = new LinkedHashMap<>();
            at.put("kind", "json");
            at.put("path", h.pointer());
            at.put("range", null);
            spans.add(span(at, b.masked(JsonSpans.decodeString(content, h.start(), h.end()), "token")));
        }
        StringBuilder sb = new StringBuilder(content);
        for (int k = hits.size() - 1; k >= 0; k--) {  // 뒤에서부터 제자리 치환
            JsonSpans.Span h = hits.get(k);
            sb.replace(h.start(), h.end(), "\"" + FILLER + "\"");
        }
        spans.sort(Comparator.comparing((Map<String, Object> s) -> (String) at(s).get("path"), PyText::compare));
        return new Masked(sb.toString(), spans);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> at(Map<String, Object> span) {
        return (Map<String, Object>) span.get("at");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> range(Map<String, Object> span) {
        return (Map<String, Object>) at(span).get("range");
    }

    private static Masked maskForm(String content, List<String> globs, Batch b)
            throws MaskerRejected, CharacterCodingException {
        List<String> parts = new ArrayList<>();
        List<Map<String, Object>> spans = new ArrayList<>();
        int offset = 0;
        for (String pair : PyText.split(content, "&")) {
            int eq = pair.indexOf('=');
            String rawName = eq < 0 ? pair : pair.substring(0, eq);
            String rawValue = eq < 0 ? "" : pair.substring(eq + 1);
            String name = PyText.unquotePlus(rawName);
            if (eq >= 0 && !rawValue.isEmpty() && matchesAny(name, globs)) {
                Map<String, Object> ref = b.masked(PyText.unquotePlus(rawValue), "token");
                b.originals.add(rawValue);  // 인코딩된 형태도 유출 검사 대상
                int start = offset + PyText.cpLen(rawName) + 1;
                spans.add(span(textAt(start), ref));
                pair = rawName + "=" + FILLER;
            }
            parts.add(pair);
            offset += PyText.cpLen(pair) + 1;
        }
        return new Masked(String.join("&", parts), spans);
    }

    /** 각 span의 FILLER가 저장 content에서 차지하는 코드포인트 구간 [start, end). 시작 위치 순(안정 정렬). */
    private record Filler(int start, int end, Map<String, Object> span) {
    }

    private static List<Filler> fillerIntervals(String content, List<Map<String, Object>> spans) {
        Map<String, int[]> jsonAt = new HashMap<>();
        boolean anyJson = spans.stream().anyMatch(s -> "json".equals(at(s).get("kind")));
        if (anyJson) {
            for (JsonSpans.Span s : JsonSpans.stringValues(content)) {
                jsonAt.put(s.pointer(), new int[] {PyText.cpIndex(content, s.start()) + 1, PyText.cpIndex(content, s.end()) - 1});
            }
        }
        List<Filler> out = new ArrayList<>();
        for (Map<String, Object> s : spans) {
            if ("text".equals(at(s).get("kind"))) {
                Map<String, Object> r = range(s);
                out.add(new Filler((Integer) r.get("start"), (Integer) r.get("end"), s));
            } else {
                int[] se = jsonAt.get((String) at(s).get("path"));
                out.add(new Filler(se[0], se[1], s));
            }
        }
        out.sort(Comparator.comparingInt(Filler::start));
        return out;
    }

    /** 절단 결과: 저장 content, 남은 span, 절단 여부, 잘린 영역으로 버린 span의 kind. */
    private record Cut(String content, List<Map<String, Object>> spans, boolean truncated, List<String> droppedKinds) {
    }

    /**
     * (A) §2.2 절단 — 마스킹 뒤. 저장 content(표지 포함) ≤ limit UTF-8 바이트. 앞 ≤ ⌊(limit−|표지|)/2⌋바이트, 뒤 ≤ 나머지.
     * 경계는 코드포인트 경계로 안쪽으로 줄이고, FILLER에 걸치면 그 FILLER 전체를 잘린 영역에 넣는다(반쪽 FILLER 금지).
     * 남는 span은 모두 text range span으로 바꾼다. 잘린 영역의 span은 버리되 영수증에는 센다.
     */
    private static Cut truncate(String content, List<Map<String, Object>> spans, int limit) {
        if (PyText.utf8Len(content) <= limit) {
            return new Cut(content, spans, false, List.of());
        }
        int[] cps = content.codePoints().toArray();
        int budget = limit - TRUNCATION_MARK.length();
        int headBudget = budget / 2;
        int tailBudget = budget - headBudget;
        int head = 0;
        int used = 0;
        for (int cp : cps) {
            int size = PyText.utf8Len(cp);
            if (used + size > headBudget) {
                break;
            }
            used += size;
            head++;
        }
        int tail = cps.length;
        used = 0;
        for (int k = cps.length - 1; k >= 0; k--) {
            int size = PyText.utf8Len(cps[k]);
            if (used + size > tailBudget) {
                break;
            }
            used += size;
            tail--;
        }
        List<Filler> fillers = fillerIntervals(content, spans);
        for (Filler f : fillers) {
            if (f.start() < head && head < f.end()) {
                head = f.start();
            }
            if (f.start() < tail && tail < f.end()) {
                tail = f.end();
            }
        }
        int shift = head + TRUNCATION_MARK.length() - tail;
        List<Map<String, Object>> kept = new ArrayList<>();
        List<String> dropped = new ArrayList<>();
        for (Filler f : fillers) {
            int newStart;
            if (f.end() <= head) {
                newStart = f.start();
            } else if (f.start() >= tail) {
                newStart = f.start() + shift;
            } else {
                dropped.add((String) ((Map<?, ?>) f.span().get("ref")).get("kind"));
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> ref = (Map<String, Object>) f.span().get("ref");
            kept.add(span(textAt(newStart), ref));
        }
        String out = new String(cps, 0, head) + TRUNCATION_MARK + new String(cps, tail, cps.length - tail);
        return new Cut(out, kept, true, dropped);
    }

    private static Map<String, Object> bodyMap(String contentType, int size, boolean truncated, String encoding,
                                               String content, List<Map<String, Object>> spans) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("content_type", contentType);
        m.put("size_bytes", size);
        m.put("truncated", truncated);
        m.put("encoding", encoding);
        m.put("content", content);
        m.put("masked_spans", spans);
        return m;
    }

    private static Map<String, Object> omitted(RawEnvelope.Body body) {
        return bodyMap(body.contentType(), 0, false, "omitted", null, new ArrayList<>());
    }

    private static Map<String, Object> body(RawEnvelope.Body raw, Batch b, Globs globs, int limit)
            throws MaskerRejected, CharacterCodingException {
        String content = raw.content();
        List<Map<String, Object>> spans = new ArrayList<>();
        boolean utf8 = raw.encoding().equals("utf8");
        if (utf8 && content != null && content.contains(TRUNCATION_MARK)) {
            return omitted(raw);  // 원본에 표지 문자열이 이미 있음((A) §2.2 불변식 7)
        }
        if (utf8 && content != null && AmbiguousJson.check(content)) {
            return omitted(raw);  // 엄격 JSON 판정이 구현 간에 갈리는 본문 — 보내지 않는다((A) §2.2 생산자 규칙)
        }
        if (utf8 && content != null) {
            String media = mediaType(raw);
            if (StrictJson.isJson(content)) {
                Masked m = maskJson(content, globs.json(), b);
                content = m.content();
                spans = m.spans();
            } else if (media.equals(FORM_CONTENT_TYPE)) {
                Masked m = maskForm(content, globs.form(), b);
                content = m.content();
                spans = m.spans();
            } else if (media.contains("json")) {
                throw new MaskerRejected("body_unparseable");
            }
        }
        if (raw.encoding().equals("base64")) {
            return omitted(raw);  // (A) §2.9 — Java는 base64를 항상 omitted로 보낸다
        }
        if (raw.encoding().equals("omitted") || content == null) {
            return raw.encoding().equals("omitted") ? omitted(raw)
                    : bodyMap(raw.contentType(), 0, false, raw.encoding(), null, spans);
        }
        int size = PyText.utf8Len(content);  // size_bytes((A) §2.2) = 마스킹 후·절단 전 UTF-8 바이트
        Cut cut = truncate(content, spans, limit);
        b.droppedKinds.addAll(cut.droppedKinds());
        return bodyMap(raw.contentType(), size, cut.truncated(), raw.encoding(), cut.content(), cut.spans());
    }

    @SuppressWarnings("unchecked")
    private static void countVisible(Object node, Map<String, Integer> kinds) {
        if (node instanceof Map<?, ?> m) {
            if (Boolean.TRUE.equals(m.get("masked")) && m.containsKey("kind") && m.containsKey("label")) {
                kinds.merge((String) m.get("kind"), 1, Integer::sum);
                return;
            }
            for (Object v : m.values()) {
                countVisible(v, kinds);
            }
        } else if (node instanceof List<?> list) {
            for (Object v : list) {
                countVisible(v, kinds);
            }
        }
    }

    private static Map<String, Object> transaction(RawEnvelope.Transaction tx, Batch b, Policy policy, Globs globs)
            throws MaskerRejected, CharacterCodingException {
        RawEnvelope.Request req = tx.request();
        RawEnvelope.Response resp = tx.response();
        b.originals.add(req.host());
        b.hosts++;
        List<Object> headers = new ArrayList<>();
        for (RawEnvelope.Header h : req.headers()) {
            headers.add(header(h, b, policy));
        }
        Map<String, Object> reqBody = body(req.body(), b, globs, REQUEST_LIMIT);
        List<Object> params = new ArrayList<>();
        for (RawEnvelope.Param p : req.queryParams()) {
            Map<String, Object> pm = new LinkedHashMap<>();
            pm.put("name", p.name());
            pm.put("value", p.location().equals("form") && matchesAny(p.name(), globs.form())
                    ? b.masked(p.value(), "token") : p.value());
            pm.put("location", p.location());
            params.add(pm);
        }
        List<Object> respHeaders = new ArrayList<>();
        for (RawEnvelope.Header h : resp.headers()) {
            respHeaders.add(header(h, b, policy));
        }
        Map<String, Object> respBody = body(resp.body(), b, globs, RESPONSE_LIMIT);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("method", req.method());
        request.put("scheme", req.scheme());
        request.put("host", "masked-host-" + twoDigits(b.hosts) + ".invalid");
        request.put("port", req.port());
        request.put("path", req.path());
        request.put("query_params", params);
        request.put("headers", headers);
        request.put("body", reqBody);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", resp.status());
        response.put("headers", respHeaders);
        response.put("body", respBody);
        response.put("elapsed_ms", resp.elapsedMs());

        // 영수증((A) §2.3): 마스킹한 값마다 센다 — 출력에 남은 MaskedRef + 절단으로 버린 span
        Map<String, Integer> visible = new HashMap<>();
        countVisible(request, visible);
        countVisible(response, visible);
        for (String kind : b.droppedKinds) {
            visible.merge(kind, 1, Integer::sum);
        }
        Map<String, Object> kinds = new LinkedHashMap<>();
        for (String k : List.of("token", "cookie", "pii", "host")) {
            kinds.put(k, visible.getOrDefault(k, 0));
        }
        Map<String, Object> receipt = new LinkedHashMap<>();
        receipt.put("applied", true);
        receipt.put("failed", false);
        receipt.put("policy_version", policy.policyVersion);
        receipt.put("redacted_count", b.count);
        receipt.put("redacted_kinds", kinds);
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("transaction_id", tx.meta().transactionId());
        meta.put("captured_at", tx.meta().capturedAt());
        meta.put("origin_ref", tx.meta().originRef());
        meta.put("sanitization", receipt);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("meta", meta);
        out.put("request", request);
        out.put("response", response);
        return out;
    }

    // ── 출력 전 자체 검증 ───────────────────────────────────────────────

    private static int spanStart(Map<String, Object> s) {
        Map<String, Object> r = range(s);
        return r == null ? -1 : (Integer) r.get("start");
    }

    private static String spanPath(Map<String, Object> s) {
        Object p = at(s).get("path");
        return p == null ? "" : (String) p;
    }

    private static int compareKey(Map<String, Object> a, Map<String, Object> b) {
        int c = PyText.compare((String) at(a).get("kind"), (String) at(b).get("kind"));
        if (c != 0) {
            return c;
        }
        c = PyText.compare(spanPath(a), spanPath(b));
        return c != 0 ? c : Integer.compare(spanStart(a), spanStart(b));
    }

    private static String cpSlice(String s, int start, int end) {
        int len = PyText.cpLen(s);
        int from = Math.min(start, len);
        int to = Math.max(from, Math.min(end, len));
        return s.substring(s.offsetByCodePoints(0, from), s.offsetByCodePoints(0, to));
    }

    /** Body 불변식 1~6((A) §2.2). */
    @SuppressWarnings("unchecked")
    static boolean spansHold(Map<String, Object> body) {
        List<Map<String, Object>> spans = (List<Map<String, Object>>) body.get("masked_spans");
        if (spans.isEmpty()) {
            return true;
        }
        String content = (String) body.get("content");
        if (!"utf8".equals(body.get("encoding")) || content == null) {
            return false;
        }
        Object doc = null;
        for (Map<String, Object> s : spans) {
            Map<String, Object> rng = range(s);
            Object value;
            if ("text".equals(at(s).get("kind"))) {
                if (rng == null) {
                    return false;
                }
                value = content;
            } else {
                if (doc == null) {
                    try {
                        doc = StrictJson.parse(content);
                    } catch (StrictJson.Invalid e) {
                        return false;
                    }
                }
                value = JsonSpans.resolve(doc, (String) at(s).get("path"));
                if (value == null) {
                    return false;
                }
            }
            if (!(value instanceof String str)) {
                return false;
            }
            if (rng == null && !str.equals(FILLER)) {
                return false;
            }
            if (rng != null) {
                int start = (Integer) rng.get("start");
                int end = (Integer) rng.get("end");
                if (end - start != FILLER.length() || !cpSlice(str, start, end).equals(FILLER)) {
                    return false;
                }
            }
        }
        Map<String, List<Map<String, Object>>> groups = new LinkedHashMap<>();
        for (Map<String, Object> s : spans) {
            groups.computeIfAbsent(at(s).get("kind") + "\u0000" + spanPath(s), k -> new ArrayList<>()).add(range(s));
        }
        for (List<Map<String, Object>> ranges : groups.values()) {
            if (ranges.size() > 1 && ranges.contains(null)) {
                return false;
            }
            List<int[]> bounded = new ArrayList<>();
            for (Map<String, Object> r : ranges) {
                if (r != null) {
                    bounded.add(new int[] {(Integer) r.get("start"), (Integer) r.get("end")});
                }
            }
            bounded.sort((x, y) -> x[0] != y[0] ? Integer.compare(x[0], y[0]) : Integer.compare(x[1], y[1]));
            for (int k = 1; k < bounded.size(); k++) {
                if (bounded.get(k)[0] < bounded.get(k - 1)[1]) {
                    return false;
                }
            }
        }
        for (int k = 1; k < spans.size(); k++) {
            if (compareKey(spans.get(k - 1), spans.get(k)) > 0) {
                return false;
            }
        }
        return true;
    }

    private static int countMarks(String content) {
        int n = 0;
        int from = 0;
        while (true) {
            int at = content.indexOf(TRUNCATION_MARK, from);
            if (at < 0) {
                return n;
            }
            n++;
            from = at + TRUNCATION_MARK.length();
        }
    }

    /** Body 불변식 7((A) §2.2). */
    @SuppressWarnings("unchecked")
    static boolean truncationHolds(Map<String, Object> body) {
        Object c = body.get("content");
        int marks = c instanceof String s ? countMarks(s) : 0;
        if (!Boolean.TRUE.equals(body.get("truncated"))) {
            return marks == 0;
        }
        if (!"utf8".equals(body.get("encoding")) || marks != 1) {
            return false;
        }
        String content = (String) c;
        int lo = PyText.cpIndex(content, content.indexOf(TRUNCATION_MARK));
        int hi = lo + TRUNCATION_MARK.length();
        for (Map<String, Object> s : (List<Map<String, Object>>) body.get("masked_spans")) {
            Map<String, Object> r = range(s);
            if (r != null && (Integer) r.get("start") < hi && lo < (Integer) r.get("end")) {
                return false;
            }
        }
        return true;
    }

    private static boolean labelsHold(Batch b) {
        if (b.mode.equals("strict_redaction")) {
            for (String[] e : b.emitted) {
                if (e[1] != null) {
                    return false;
                }
            }
            return true;
        }
        Map<String, String> byDigest = new HashMap<>();
        Map<String, String> byLabel = new HashMap<>();
        for (String[] e : b.emitted) {
            if (e[1] == null) {
                return false;
            }
            String l = byDigest.putIfAbsent(e[0], e[1]);
            String d = byLabel.putIfAbsent(e[1], e[0]);
            if ((l != null && !l.equals(e[1])) || (d != null && !d.equals(e[0]))) {
                return false;
            }
        }
        return true;
    }

    /** 헤더 값 안의 비밀 구성요소: '이름=값'의 값, '스킴 자격증명'의 자격증명. */
    static List<String> secretParts(String value) {
        List<String> parts = new ArrayList<>();
        int from = 0;
        List<String> segments = new ArrayList<>();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ';' || c == ',') {
                segments.add(value.substring(from, i));
                from = i + 1;
            }
        }
        segments.add(value.substring(from));
        for (String raw : segments) {
            String segment = PyText.strip(raw);
            int eq = segment.indexOf('=');
            if (eq >= 0) {
                parts.add(PyText.strip(segment.substring(eq + 1)));
            } else {
                List<String> words = PyText.splitWhitespace(segment);
                parts.addAll(words.size() > 1 ? words.subList(1, words.size()) : words);
            }
        }
        return parts;
    }

    static Set<String> needles(List<String> originals) {
        Set<String> found = new HashSet<>();
        for (String o : originals) {
            if (!o.isEmpty()) {
                found.add(o);
            }
        }
        for (String o : originals) {
            for (String p : secretParts(o)) {
                if (PyText.cpLen(p) >= MIN_FRAGMENT) {
                    found.add(p);
                }
            }
        }
        return found;
    }

    private static void stringLeaves(Object node, List<String> out) {
        if (node instanceof Map<?, ?> m) {
            for (Object v : m.values()) {
                stringLeaves(v, out);
            }
        } else if (node instanceof List<?> list) {
            for (Object v : list) {
                stringLeaves(v, out);
            }
        } else if (node instanceof String s) {
            out.add(s);
        }
    }

    static boolean leaked(Object envelope, List<String> originals) {
        Set<String> needles = needles(originals);
        List<String> leaves = new ArrayList<>();
        stringLeaves(envelope, leaves);
        for (String leaf : leaves) {
            for (String n : needles) {
                if (leaf.contains(n)) {
                    return true;
                }
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static Output maskBatch(RawEnvelope.Transaction tx, String mode, Policy policy, Globs globs)
            throws MaskerRejected {
        Batch b;
        try {
            b = new Batch(mode);
        } catch (GeneralSecurityException e) {
            throw new MaskerRejected("transform_failed");
        }
        try {
            Map<String, Object> draft;
            try {
                draft = transaction(tx, b, policy, globs);
            } catch (MaskerRejected e) {
                throw e;
            } catch (CharacterCodingException | RuntimeException e) {
                throw new MaskerRejected("transform_failed");  // 원 예외에 원본 조각이 있을 수 있다 — 버린다
            }
            for (String side : List.of("request", "response")) {
                if (!spansHold((Map<String, Object>) ((Map<String, Object>) draft.get(side)).get("body"))) {
                    throw new MaskerRejected("span_invariant_violated");
                }
            }
            for (String side : List.of("request", "response")) {
                if (!truncationHolds((Map<String, Object>) ((Map<String, Object>) draft.get(side)).get("body"))) {
                    throw new MaskerRejected("truncation_invariant_violated");
                }
            }
            if (!labelsHold(b)) {
                throw new MaskerRejected("label_rule_violated");
            }
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("schema_version", "1.0");
            envelope.put("analysis_type", "single");
            envelope.put("transactions", List.of(draft));
            byte[] bytes;
            try {
                bytes = Canonical.dumps(envelope);
            } catch (Canonical.CanonicalError e) {
                throw new MaskerRejected("output_build_failed");
            }
            if (leaked(envelope, b.originals)) {
                throw new MaskerRejected("masked_value_leaked");
            }
            return new Output(tx.meta().transactionId() + ".json", bytes);
        } finally {
            b.discard();  // 성공·실패와 무관하게 키·표·원본 값을 버린다
        }
    }
}
