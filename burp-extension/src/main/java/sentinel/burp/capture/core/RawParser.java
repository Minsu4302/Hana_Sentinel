package sentinel.burp.capture.core;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import sentinel.burp.transport.masker.PyText;
import sentinel.burp.transport.masker.RawEnvelope;

/**
 * 구문 파서 — (A) §2.9 구문 파서 규칙(v1.52, `java_request_parse`). 원시 요청·응답 바이트 → RawTransaction(메모리).
 * 순수 Java다(Montoya import 0, java.net 0 — 정적 규칙). 해석(ID 분류·반사 표식 등)은 하지 않는다.
 *
 * <ul>
 *   <li>요청 줄 = METHOD SP target SP HTTP-version. method는 token 문자. target은 origin-form('/'로 시작)만, '#' 있으면 거부.</li>
 *   <li>path = 첫 '?' 앞 원문(디코딩 없음). query·form Param = '&amp;' 분할(빈 조각 무시, '=' 없으면 값 ""), unquote_plus, 출현 순서.</li>
 *   <li>헤더: 이름 token 문자·대소문자 유지, 값 OWS 제거 후 UTF-8(errors=replace), 중복은 각각, obs-fold는 거부.</li>
 *   <li>본문: Transfer-Encoding이 chunked면 엄격 디청크(형식 오류 → omitted), 그 밖의 Transfer-Encoding 값 → omitted.
 *       Content-Encoding은 풀지 않는다. 엄격 UTF-8이면 utf8, 아니면 base64. content_type = 첫 Content-Type 값(없으면 "").</li>
 *   <li>응답 = HTTP-version SP 3digit [SP reason], status 100..599.</li>
 *   <li>줄 끝은 CRLF만 받는다. 헤더 끝(빈 줄)이 없으면 거부.</li>
 * </ul>
 * 거부는 {@link Refused} 하나다. 로그 사유 코드는 parse_refused뿐이고, 내부 세부 종류(kind — 하네스·테스트 전용, 로그에 쓰지
 * 않음)는 어느 규칙이 거부했는지만 나타낸다. 값·위치는 담지 않는다.
 */
public final class RawParser {
    public static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

    /** 파싱 거부. 메시지는 사유 코드뿐. */
    public static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;
        private final String kind;

        Refused(String kind) {
            super("parse_refused", null, false, false);
            this.kind = kind;
        }

        /** 거부한 규칙: request_line, target_form, line_ending, no_header_end, obs_fold, header_syntax, status_line. */
        public String kind() {
            return kind;
        }
    }

    private RawParser() {
    }

    /** 한 메시지(요청 또는 응답)를 나눈 결과. */
    private record Message(String startLine, List<RawEnvelope.Header> headers, byte[] body) {
    }

    public static RawEnvelope.Transaction parse(byte[] request, byte[] response, String host, int port, boolean secure,
                                                RawEnvelope.Meta meta) throws Refused {
        Message rq = split(request);
        String[] line = rq.startLine().split(" ", -1);
        if (line.length != 3 || !isToken(line[0]) || !isVersion(line[2])) {
            throw new Refused("request_line");
        }
        String target = line[1];
        if (target.isEmpty() || target.charAt(0) != '/' || target.indexOf('#') >= 0) {
            throw new Refused("target_form");
        }
        int q = target.indexOf('?');
        String path = q < 0 ? target : target.substring(0, q);
        List<RawEnvelope.Param> params = new ArrayList<>();
        if (q >= 0) {
            pairs(target.substring(q + 1), "query", params);
        }
        RawEnvelope.Body reqBody = body(rq);
        if ("utf8".equals(reqBody.encoding()) && FORM_CONTENT_TYPE.equals(mediaType(reqBody.contentType()))) {
            pairs(reqBody.content(), "form", params);
        }
        Message rs = split(response);
        String status = statusOf(rs.startLine());
        RawEnvelope.Request req = new RawEnvelope.Request(line[0], secure ? "https" : "http", host, port, path,
                List.copyOf(params), rq.headers(), reqBody);
        RawEnvelope.Response resp = new RawEnvelope.Response(Integer.parseInt(status), rs.headers(), body(rs), null);
        return new RawEnvelope.Transaction(meta, req, resp);
    }

    // ── 메시지 나누기 ───────────────────────────────────────────────

    private static int headerEnd(byte[] b) {
        for (int i = 0; i + 3 < b.length; i++) {
            if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static Message split(byte[] raw) throws Refused {
        if (raw == null) {
            throw new Refused("no_header_end");
        }
        int end = headerEnd(raw);
        if (end < 0) {
            throw new Refused("no_header_end");
        }
        List<byte[]> lines = new ArrayList<>();
        int from = 0;
        for (int i = 0; i <= end; i++) {
            if (i == end || (raw[i] == '\r' && raw[i + 1] == '\n')) {
                byte[] l = new byte[i - from];
                System.arraycopy(raw, from, l, 0, l.length);
                lines.add(l);
                from = i + 2;
                i++;
            } else if (raw[i] == '\r' || raw[i] == '\n') {
                throw new Refused("line_ending");  // 맨 CR·LF(CRLF가 아닌 줄 끝)
            }
        }
        String start = PyText.decodeUtf8Replace(lines.get(0));  // 시작 줄 — 헤더 값과 같은 정의(UTF-8, 대체)
        List<RawEnvelope.Header> headers = new ArrayList<>();
        for (byte[] l : lines.subList(1, lines.size())) {
            if (l.length > 0 && (l[0] == ' ' || l[0] == '\t')) {
                throw new Refused("obs_fold");
            }
            int colon = indexOf(l, (byte) ':');
            if (colon <= 0) {
                throw new Refused("header_syntax");
            }
            String name = ascii(slice(l, 0, colon));
            if (!isToken(name)) {
                throw new Refused("header_syntax");  // 콜론 앞 공백 포함
            }
            int a = colon + 1;
            int z = l.length;
            while (a < z && (l[a] == ' ' || l[a] == '\t')) {
                a++;
            }
            while (z > a && (l[z - 1] == ' ' || l[z - 1] == '\t')) {
                z--;
            }
            headers.add(new RawEnvelope.Header(name, PyText.decodeUtf8Replace(slice(l, a, z))));
        }
        return new Message(start, List.copyOf(headers), slice(raw, end + 4, raw.length));
    }

    private static String statusOf(String startLine) throws Refused {
        String[] p = startLine.split(" ", 3);
        if (p.length < 2 || !isVersion(p[0]) || p[1].length() != 3) {
            throw new Refused("status_line");
        }
        for (int i = 0; i < 3; i++) {
            if (p[1].charAt(i) < '0' || p[1].charAt(i) > '9') {
                throw new Refused("status_line");
            }
        }
        int s = Integer.parseInt(p[1]);
        if (s < 100 || s > 599) {
            throw new Refused("status_line");
        }
        return p[1];
    }

    // ── 본문 ──────────────────────────────────────────────────────

    private static String firstHeader(List<RawEnvelope.Header> headers, String name) {
        for (RawEnvelope.Header h : headers) {
            if (h.name().equalsIgnoreCase(name)) {
                return h.value();
            }
        }
        return null;
    }

    private static RawEnvelope.Body body(Message m) {
        String ct = firstHeader(m.headers(), "Content-Type");
        String contentType = ct == null ? "" : ct;
        byte[] bytes = m.body();
        String te = firstHeader(m.headers(), "Transfer-Encoding");
        if (te != null) {
            bytes = "chunked".equals(PyText.lower(PyText.strip(te))) ? dechunk(bytes) : null;
            if (bytes == null) {
                return new RawEnvelope.Body(contentType, "omitted", null);
            }
        }
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            return new RawEnvelope.Body(contentType, "utf8", text);
        } catch (CharacterCodingException e) {
            return new RawEnvelope.Body(contentType, "base64", Base64.getEncoder().encodeToString(bytes));
        }
    }

    /** 엄격 디청크: (16진 크기 [; 확장] CRLF 데이터 CRLF)* "0" [; 확장] CRLF (트레일러 줄 CRLF)* CRLF, 뒤에 아무것도 없음. 오류면 null. */
    static byte[] dechunk(byte[] b) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(b.length);
        int i = 0;
        while (true) {
            int eol = crlf(b, i);
            if (eol < 0) {
                return null;
            }
            String sizeLine = ascii(slice(b, i, eol));
            int semi = sizeLine.indexOf(';');
            String hex = semi < 0 ? sizeLine : sizeLine.substring(0, semi);
            if (hex.isEmpty() || hex.length() > 8) {
                return null;
            }
            long size = 0;
            for (int k = 0; k < hex.length(); k++) {
                int d = hexDigit(hex.charAt(k));
                if (d < 0) {
                    return null;
                }
                size = size * 16 + d;
            }
            i = eol + 2;
            if (size == 0) {
                break;
            }
            if (i + size + 2 > b.length || b[(int) (i + size)] != '\r' || b[(int) (i + size + 1)] != '\n') {
                return null;
            }
            out.write(b, i, (int) size);
            i += (int) size + 2;
        }
        while (true) {  // 트레일러(무시) — 빈 줄로 끝나야 한다
            int eol = crlf(b, i);
            if (eol < 0) {
                return null;
            }
            boolean empty = eol == i;
            i = eol + 2;
            if (empty) {
                return i == b.length ? out.toByteArray() : null;
            }
        }
    }

    private static int crlf(byte[] b, int from) {
        for (int i = from; i + 1 < b.length; i++) {
            if (b[i] == '\r' && b[i + 1] == '\n') {
                return i;
            }
            if (b[i] == '\r' || b[i] == '\n') {
                return -1;
            }
        }
        return -1;
    }

    // ── Param ─────────────────────────────────────────────────────

    private static void pairs(String text, String location, List<RawEnvelope.Param> out) {
        for (String piece : PyText.split(text, "&")) {
            if (piece.isEmpty()) {
                continue;
            }
            int eq = piece.indexOf('=');
            String name = eq < 0 ? piece : piece.substring(0, eq);
            String value = eq < 0 ? "" : piece.substring(eq + 1);
            out.add(new RawEnvelope.Param(PyText.unquotePlus(name), PyText.unquotePlus(value), location));
        }
    }

    static String mediaType(String contentType) {
        int semi = contentType.indexOf(';');
        return PyText.lower(PyText.strip(semi < 0 ? contentType : contentType.substring(0, semi)));
    }

    // ── 문자 ──────────────────────────────────────────────────────

    private static final String TCHAR_EXTRA = "!#$%&'*+-.^_`|~";

    static boolean isToken(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean alnum = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            if (!alnum && TCHAR_EXTRA.indexOf(c) < 0) {
                return false;
            }
        }
        return true;
    }

    /** HTTP/<숫자>[.<숫자>] — HTTP/2의 Burp 텍스트 표현(HTTP/2)도 받는다. */
    static boolean isVersion(String s) {
        if (!s.startsWith("HTTP/")) {
            return false;
        }
        String v = s.substring(5);
        return v.matches("[0-9](\\.[0-9])?");
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    private static int indexOf(byte[] b, byte x) {
        for (int i = 0; i < b.length; i++) {
            if (b[i] == x) {
                return i;
            }
        }
        return -1;
    }

    private static byte[] slice(byte[] b, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(b, from, out, 0, out.length);
        return out;
    }

    /** 요청 줄·헤더 이름 — ASCII 밖 바이트는 U+FFFD(이후 token 검사에서 거부된다). */
    private static String ascii(byte[] b) {
        StringBuilder s = new StringBuilder(b.length);
        for (byte x : b) {
            s.append(x >= 0 ? (char) x : '\uFFFD');
        }
        return s.toString();
    }
}
