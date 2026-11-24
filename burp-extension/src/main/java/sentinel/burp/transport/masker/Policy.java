package sentinel.burp.transport.masker;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SanitizationPolicy — (A) §2.3. 정본은 레포의 데이터 파일 하나(src/sentinel/sanitization_policy.json)이고, 빌드가 그 파일을
 * 이 패키지의 리소스로 넣는다(사본 커밋 없음). 구조 검사는 Python 모델(sentinel.sanitization_policy)과 같다:
 * 엄격 JSON, 모르는 필드 거부, 타입·열거값 검사. 추가로 glob에 '['가 있으면 거부한다(Glob이 지원하지 않는 문법 — fail-closed).
 * 정책이 틀리면 기동하지 않는다(PolicyInvalid).
 */
public final class Policy {
    public static final String RESOURCE = "sanitization_policy.json";

    /** 정책 파일이 틀림. 메시지에 값 없음. */
    public static final class PolicyInvalid extends Exception {
        private static final long serialVersionUID = 1L;

        PolicyInvalid() {
            super("policy_invalid", null, false, false);
        }
    }

    record Rule(String pattern, String action) {
    }

    private static final Set<String> ACTIONS = Set.of("redact", "pseudonymize", "keep");
    private static final Set<String> TOP = Set.of("policy_version", "mode", "header_rules", "body_rules",
            "object_id_policy", "object_id_rules");

    final String policyVersion;
    final List<Rule> headerRules;
    final List<Rule> bodyRules;
    final List<Rule> objectIdRules;

    private Policy(String policyVersion, List<Rule> headerRules, List<Rule> bodyRules, List<Rule> objectIdRules) {
        this.policyVersion = policyVersion;
        this.headerRules = headerRules;
        this.bodyRules = bodyRules;
        this.objectIdRules = objectIdRules;
    }

    /** 빌드가 넣은 정본 정책. */
    public static Policy bundled() throws PolicyInvalid {
        try (InputStream in = Policy.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new PolicyInvalid();
            }
            return parse(in.readAllBytes());
        } catch (IOException e) {
            throw new PolicyInvalid();
        }
    }

    public static Policy parse(byte[] data) throws PolicyInvalid {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException e) {
            throw new PolicyInvalid();
        }
        Object doc;
        try {
            doc = StrictJson.parse(text);
        } catch (StrictJson.Invalid e) {
            throw new PolicyInvalid();
        }
        if (!(doc instanceof Map<?, ?> top) || !TOP.containsAll(top.keySet())) {
            throw new PolicyInvalid();
        }
        String version = string(top.get("policy_version"));
        if (top.containsKey("mode") && !Set.of("strict_redaction", "relation_preserving").contains(string(top.get("mode")))) {
            throw new PolicyInvalid();
        }
        if (top.containsKey("object_id_policy")
                && !Set.of("pseudonymize_if_sensitive", "keep").contains(string(top.get("object_id_policy")))) {
            throw new PolicyInvalid();
        }
        if (!top.containsKey("header_rules")) {
            throw new PolicyInvalid();
        }
        List<Rule> headers = rules(top.get("header_rules"), "name_pattern", ACTIONS);
        List<Rule> body = top.containsKey("body_rules") ? rules(top.get("body_rules"), "matcher", ACTIONS) : List.of();
        List<Rule> objectId = top.containsKey("object_id_rules")
                ? rules(top.get("object_id_rules"), "matcher", Set.of("pseudonymize")) : List.of();
        return new Policy(version, headers, body, objectId);
    }

    private static String string(Object v) throws PolicyInvalid {
        if (!(v instanceof String s)) {
            throw new PolicyInvalid();
        }
        return s;
    }

    private static List<Rule> rules(Object v, String patternField, Set<String> actions) throws PolicyInvalid {
        if (!(v instanceof List<?> list)) {
            throw new PolicyInvalid();
        }
        List<Rule> out = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> m) || !m.keySet().equals(Set.of(patternField, "action"))) {
                throw new PolicyInvalid();
            }
            String pattern = string(m.get(patternField));
            String action = string(m.get("action"));
            if (!actions.contains(action) || pattern.indexOf('[') >= 0) {
                throw new PolicyInvalid();
            }
            out.add(new Rule(pattern, action));
        }
        return List.copyOf(out);
    }

    public String policyVersion() {
        return policyVersion;
    }

    /** sanitization_policy.requires_masked_header와 같다. */
    boolean requiresMaskedHeader(String name) {
        String lowered = PyText.lower(name);
        for (Rule r : headerRules) {
            if (Glob.matches(lowered, PyText.lower(r.pattern())) && !"keep".equals(r.action())) {
                return true;
            }
        }
        return false;
    }
}
