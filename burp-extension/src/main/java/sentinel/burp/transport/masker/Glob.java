package sentinel.burp.transport.masker;

/**
 * fnmatch.fnmatchcase의 '*'·'?' 부분(코드포인트 단위). '['는 지원하지 않는다 — 정책 로더가 '['가 든 패턴을 거부한다
 * (Python은 문자 집합으로 해석하므로, 지원하지 않는 문법은 기동 거부로 막는다).
 * 호출자는 이름과 패턴을 둘 다 PyText.lower로 바꿔 넘긴다(참조 마스커와 같은 대소문자 무시).
 */
final class Glob {
    private Glob() {
    }

    static boolean matches(String name, String pattern) {
        int[] s = name.codePoints().toArray();
        int[] p = pattern.codePoints().toArray();
        int si = 0;
        int pi = 0;
        int star = -1;
        int mark = 0;
        while (si < s.length) {
            if (pi < p.length && (p[pi] == '?' || (p[pi] != '*' && p[pi] == s[si]))) {
                si++;
                pi++;
            } else if (pi < p.length && p[pi] == '*') {
                star = pi++;
                mark = si;
            } else if (star >= 0) {
                pi = star + 1;
                si = ++mark;
            } else {
                return false;
            }
        }
        while (pi < p.length && p[pi] == '*') {
            pi++;
        }
        return pi == p.length;
    }
}
