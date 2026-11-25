package sentinel.burp.transport.masker;

import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 엄격 JSON 판정 — (A) §2.6 'content 전체가 JSON으로 파싱됨'. 참조 정의는 Python sentinel.strict_json.parse다.
 * 판정 조합(2부 PR-1b 0단계 실측으로 정함):
 * JsonReader + Strictness.STRICT(NaN·Infinity·주석·작은따옴표·선행 0·제어문자 거부) + 직접 순회 중 중복 키 거부
 * + 끝이 END_DOCUMENT인지 확인(후행 문자열·빈 입력 거부) + 선행 U+FEFF 거부(Gson은 BOM을 건너뛴다 — Python은 거부).
 * 구현 간에 갈리는 나머지 두 영역(이스케이프된 고립 서로게이트, 깊이 255 초과)은 생산자 사전 검사(AmbiguousJson)가
 * 마스킹 전에 omitted로 보내므로 여기까지 오지 않는다.
 * Gson의 관대한 진입점(JsonParser·Gson 객체의 변환 메서드 등)은 쓰지 않는다 — 정적 검사가 막는다.
 */
final class StrictJson {
    /** JSON null 표지(Java null과 구분). */
    static final Object NULL = new Object();

    /** 수 토큰(원문 그대로). */
    record Num(String token) {
    }

    /** 엄격 JSON이 아님. 메시지에 값을 담지 않는다. */
    static final class Invalid extends Exception {
        private static final long serialVersionUID = 1L;

        Invalid() {
            super("not_strict_json", null, false, false);
        }
    }

    private StrictJson() {
    }

    static boolean isJson(String text) {
        try {
            parse(text);
            return true;
        } catch (Invalid e) {
            return false;
        }
    }

    /** 트리: LinkedHashMap(멤버 순서 유지)·ArrayList·String·Num·Boolean·NULL. */
    static Object parse(String text) throws Invalid {
        if (text.startsWith("\uFEFF")) {
            throw new Invalid();
        }
        try {
            JsonReader reader = new JsonReader(new StringReader(text));
            reader.setStrictness(Strictness.STRICT);
            Object value = read(reader);
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                throw new Invalid();
            }
            return value;
        } catch (IOException | IllegalStateException | NumberFormatException e) {
            throw new Invalid();
        }
    }

    private static Object read(JsonReader r) throws IOException, Invalid {
        switch (r.peek()) {
            case BEGIN_OBJECT: {
                Map<String, Object> m = new LinkedHashMap<>();
                r.beginObject();
                while (r.hasNext()) {
                    String key = r.nextName();
                    if (m.containsKey(key)) {
                        throw new Invalid();
                    }
                    m.put(key, read(r));
                }
                r.endObject();
                return m;
            }
            case BEGIN_ARRAY: {
                List<Object> list = new ArrayList<>();
                r.beginArray();
                while (r.hasNext()) {
                    list.add(read(r));
                }
                r.endArray();
                return list;
            }
            case STRING:
                return r.nextString();
            case NUMBER:
                return new Num(r.nextString());
            case BOOLEAN:
                return r.nextBoolean();
            case NULL:
                r.nextNull();
                return NULL;
            default:
                throw new Invalid();
        }
    }
}
