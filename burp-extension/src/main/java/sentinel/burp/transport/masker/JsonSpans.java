package sentinel.burp.transport.masker;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 엄격 JSON 본문의 문자열 값 토큰 위치 — 참조 구현 sentinel.strict_json.string_value_spans(_scan)를 옮긴 것.
 * Gson은 문자 오프셋을 주지 않으므로 유효성은 StrictJson이, 위치는 이 스캐너가 맡는다(Python과 같은 구조).
 * 위치는 UTF-16 인덱스이고 따옴표를 포함한다. 코드포인트가 필요한 곳은 호출자가 PyText.cpIndex로 바꾼다.
 * 입력은 StrictJson을 통과한 본문이어야 한다(여기서는 문법을 다시 검사하지 않는다).
 */
final class JsonSpans {
    /** (JSON Pointer, 멤버 이름 | null, 시작, 끝). */
    record Span(String pointer, String key, int start, int end) {
    }

    private JsonSpans() {
    }

    static List<Span> stringValues(String content) {
        List<Span> out = new ArrayList<>();
        scan(content, skipWs(content, 0), "", null, out);
        return out;
    }

    private static int skipWs(String s, int i) {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                break;
            }
            i++;
        }
        return i;
    }

    private static int stringEnd(String s, int i) {
        int j = i + 1;
        while (s.charAt(j) != '"') {
            j += s.charAt(j) == '\\' ? 2 : 1;
        }
        return j + 1;
    }

    static String escapeToken(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }

    private static int scan(String s, int i, String pointer, String key, List<Span> out) {
        char c = s.charAt(i);
        if (c == '"') {
            int end = stringEnd(s, i);
            out.add(new Span(pointer, key, i, end));
            return end;
        }
        if (c == '{' || c == '[') {
            char close = c == '{' ? '}' : ']';
            int index = 0;
            i = skipWs(s, i + 1);
            if (s.charAt(i) == close) {
                return i + 1;
            }
            while (true) {
                if (c == '{') {
                    int nameEnd = stringEnd(s, i);
                    String name = decodeString(s, i, nameEnd);
                    i = skipWs(s, skipWs(s, nameEnd) + 1);
                    i = scan(s, i, pointer + "/" + escapeToken(name), name, out);
                } else {
                    i = scan(s, i, pointer + "/" + index, null, out);
                    index++;
                }
                i = skipWs(s, i);
                if (s.charAt(i) == close) {
                    return i + 1;
                }
                i = skipWs(s, i + 1);
            }
        }
        int j = i;
        while (j < s.length() && ",]} \t\n\r".indexOf(s.charAt(j)) < 0) {
            j++;
        }
        return j;
    }

    /** 문자열 토큰 s[start, end)(따옴표 포함)의 값 — json.loads와 같다. 고립 서로게이트 이스케이프는 사전 검사가 이미 걸렀다. */
    static String decodeString(String s, int start, int end) {
        StringBuilder out = new StringBuilder(end - start);
        int i = start + 1;
        int last = end - 1;
        while (i < last) {
            char c = s.charAt(i);
            if (c != '\\') {
                out.append(c);
                i++;
                continue;
            }
            char e = s.charAt(i + 1);
            switch (e) {
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    out.append((char) Integer.parseInt(s.substring(i + 2, i + 6), 16));
                    i += 6;
                    continue;
                default:
                    out.append(e);  // '"' '\\' '/'
                    break;
            }
            i += 2;
        }
        return out.toString();
    }

    /** strict_json.resolve — (찾음, 노드). 못 찾으면 null을 돌려준다(JSON null은 StrictJson.NULL). */
    static Object resolve(Object doc, String pointer) {
        List<String> tokens = PyText.split(pointer, "/");
        Object node = doc;
        for (String raw : tokens.subList(1, tokens.size())) {
            String token = raw.replace("~1", "/").replace("~0", "~");
            if (node instanceof Map<?, ?> map && map.containsKey(token)) {
                node = map.get(token);
            } else if (node instanceof List<?> list && isIndex(token) && token.length() < 10
                    && Integer.parseInt(token) < list.size()) {
                node = list.get(Integer.parseInt(token));
            } else {
                return null;
            }
        }
        return node;
    }

    private static boolean isIndex(String token) {
        if (token.isEmpty() || (token.length() > 1 && token.charAt(0) == '0')) {
            return false;
        }
        for (int k = 0; k < token.length(); k++) {
            char c = token.charAt(k);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }
}
