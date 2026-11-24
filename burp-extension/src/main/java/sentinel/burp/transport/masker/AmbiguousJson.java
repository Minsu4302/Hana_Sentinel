package sentinel.burp.transport.masker;

/**
 * (A) §2.2 생산자 사전 검사 — 엄격 JSON 판정이 구현 간에 갈리는 본문인가. 참조 마스커의 ambiguous_json과 같은 스캐너다.
 * 문자열 상태를 따라 한 번 훑는다: 문자열 밖 '"'는 문자열 시작, 문자열 안 '\'는 다음 한 글자(또는 \\uXXXX)를 소비, '"'는 끝.
 * (가) 문자열 안의 이스케이프된 고립 서로게이트 — \\uD800–\\uDBFF 바로 뒤에 \\uDC00–\\uDFFF 이스케이프가 없거나,
 *     \\uDC00–\\uDFFF가 단독으로 옴.
 * (나) 문자열 밖 '['·'{' 중첩 깊이가 NESTING_LIMIT를 넘음. ']'·'}'는 깊이를 1 줄이되 0 아래로 내리지 않는다.
 * JSON이 아닌 본문도 같은 규칙으로 훑는다. 걸리면 마스킹 전에 omitted로 보낸다.
 */
final class AmbiguousJson {
    /** Gson JsonReader 기본 중첩 상한과 같다. */
    static final int NESTING_LIMIT = 255;

    private AmbiguousJson() {
    }

    static boolean check(String content) {
        int depth = 0;
        boolean inString = false;
        int i = 0;
        int n = content.length();
        while (i < n) {
            char c = content.charAt(i);
            if (inString) {
                if (c == '\\') {
                    int unit = escapeUnit(content, i);
                    if (unit < 0) {
                        i += 2;
                        continue;
                    }
                    if (loneSurrogateAt(content, i, unit)) {
                        return true;
                    }
                    i += Character.isHighSurrogate((char) unit) ? 12 : 6;
                    continue;
                }
                if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else if (c == '[' || c == '{') {
                depth++;
                if (depth > NESTING_LIMIT) {
                    return true;
                }
            } else if ((c == ']' || c == '}') && depth > 0) {
                depth--;
            }
            i++;
        }
        return false;
    }

    /** content[i]=='\'에서 시작하는 \\uXXXX(16진 4자리)의 코드 단위, 아니면 -1. */
    private static int escapeUnit(String content, int i) {
        if (i + 5 >= content.length() || content.charAt(i + 1) != 'u') {
            return -1;
        }
        int v = 0;
        for (int k = i + 2; k < i + 6; k++) {
            int d = asciiHex(content.charAt(k));
            if (d < 0) {
                return -1;
            }
            v = v * 16 + d;
        }
        return v;
    }

    /** [0-9A-Fa-f]만 — Character.digit은 전각 숫자 등도 받아들이므로 쓰지 않는다. */
    private static int asciiHex(char c) {
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

    /** 위치 i의 \\uXXXX(값 unit)가 고립 서로게이트인가 — 하위 단독, 또는 상위 뒤에 하위 이스케이프가 없음. */
    private static boolean loneSurrogateAt(String content, int i, int unit) {
        if (Character.isLowSurrogate((char) unit)) {
            return true;
        }
        if (Character.isHighSurrogate((char) unit)) {
            int low = i + 6 < content.length() && content.charAt(i + 6) == '\\' ? escapeUnit(content, i + 6) : -1;
            return low < 0 || !Character.isLowSurrogate((char) low);
        }
        return false;
    }
}
