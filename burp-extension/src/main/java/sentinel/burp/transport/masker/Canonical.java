package sentinel.burp.transport.masker;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * 정규 직렬화 — (A) §2.10. 참조 구현은 Python sentinel.canonical_json.dumps이고, 바이트 일치는 java_masker_parity가 본다.
 * 라이브러리 직렬화를 쓰지 않는다(Gson의 변환 메서드 금지 — 정적 검사).
 * 값: Map(멤버 순서 = 삽입 순서 = 스키마 선언 순서)·List·String·Integer/Long·Boolean·null.
 * 공백 없음, 끝 개행 없음, 고립 서로게이트는 거부(CanonicalError).
 */
final class Canonical {
    static final class CanonicalError extends Exception {
        private static final long serialVersionUID = 1L;

        CanonicalError(String code) {
            super(code, null, false, false);
        }
    }

    private Canonical() {
    }

    static byte[] dumps(Object value) throws CanonicalError {
        StringBuilder out = new StringBuilder();
        value(value, out);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void value(Object v, StringBuilder out) throws CanonicalError {
        if (v == null) {
            out.append("null");
        } else if (v instanceof Boolean b) {
            out.append(b ? "true" : "false");
        } else if (v instanceof Integer || v instanceof Long) {
            out.append(v.toString());
        } else if (v instanceof String s) {
            string(s, out);
        } else if (v instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!(e.getKey() instanceof String key)) {
                    throw new CanonicalError("non_string_key");
                }
                if (!first) {
                    out.append(',');
                }
                first = false;
                string(key, out);
                out.append(':');
                value(e.getValue(), out);
            }
            out.append('}');
        } else if (v instanceof List<?> list) {
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                value(list.get(i), out);
            }
            out.append(']');
        } else {
            throw new CanonicalError("unsupported_type");
        }
    }

    private static final String HEX = "0123456789abcdef";

    static void string(String s, StringBuilder out) throws CanonicalError {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') {
                out.append("\\\"");
            } else if (c == '\\') {
                out.append("\\\\");
            } else if (c == '\b') {
                out.append("\\b");
            } else if (c == '\t') {
                out.append("\\t");
            } else if (c == '\n') {
                out.append("\\n");
            } else if (c == '\f') {
                out.append("\\f");
            } else if (c == '\r') {
                out.append("\\r");
            } else if (c < 0x20) {
                out.append("\\u00").append(HEX.charAt(c >> 4)).append(HEX.charAt(c & 0xF));
            } else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                out.append(c).append(s.charAt(i + 1));
                i++;
            } else if (Character.isSurrogate(c)) {
                throw new CanonicalError("lone_surrogate");
            } else {
                out.append(c);
            }
        }
        out.append('"');
    }
}
