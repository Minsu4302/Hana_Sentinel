package sentinel.burp.capture.core;

/**
 * 선택 규칙 — (A) §2.9 선택 단위(v1.52). 순수 함수다: Montoya 이벤트를 다루는 어댑터가 사실값만 넘긴다.
 * 순서(앞이 우선): Repeater 출처 → 편집 가능한 편집기 → 건수 → 응답 유무.
 */
public final class Selection {
    /** 호출 위치: 표·트리 목록, 읽기 전용 뷰어, 편집 가능한 편집기. */
    public enum Origin { LIST, VIEWER, EDITOR }

    private Selection() {
    }

    /** 받아들이면 null, 아니면 사유 코드(Reasons의 닫힌 목록). */
    public static String decide(Origin origin, boolean fromRepeater, int count, boolean hasResponse) {
        if (fromRepeater) {
            return Reasons.REPEATER_SOURCE;
        }
        if (origin == Origin.EDITOR) {
            return Reasons.EDITABLE_MESSAGE;
        }
        if (count != 1) {
            return Reasons.SELECTION_NOT_SINGLE;
        }
        if (!hasResponse) {
            return Reasons.NO_RESPONSE;
        }
        return null;
    }
}
