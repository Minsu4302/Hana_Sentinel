package sentinel.burp.transport.masker;

import java.util.List;

/**
 * 거부·실패. 사유 코드만 담는다(값·경로·입력 필드명 없음, 원인 예외 체인 없음, 스택 없음).
 * 코드 집합은 참조 마스커(tools/fixture_masker/masker.py REASON_CODES)와 같다 — 동등성 테스트가 대조한다.
 */
public final class MaskerRejected extends Exception {
    private static final long serialVersionUID = 1L;

    public static final List<String> REASON_CODES = List.of(
            "input_inside_repo",
            "input_unreadable",
            "input_not_json",
            "unknown_schema_version",
            "raw_schema_invalid",
            "unknown_mode",
            "unknown_batch",
            "policy_matcher_unknown",
            "object_id_rules_unsupported",
            "body_unparseable",
            "transform_failed",
            "label_space_exhausted",
            "span_invariant_violated",
            "truncation_invariant_violated",
            "label_rule_violated",
            "masked_value_leaked",
            "output_build_failed",
            "output_exists");

    private final String code;

    public MaskerRejected(String code) {
        super(code, null, false, false);
        if (!REASON_CODES.contains(code)) {
            throw new IllegalArgumentException("unknown_reason_code");
        }
        this.code = code;
    }

    public String code() {
        return code;
    }
}
