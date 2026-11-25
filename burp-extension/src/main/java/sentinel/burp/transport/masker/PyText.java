package sentinel.burp.transport.masker;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 참조 마스커(Python)가 쓰는 표준 문자열 동작을 같은 의미로 옮긴 것. 결과가 달라지면 동등성이 깨진다.
 * - 코드포인트 순서 비교(Python str 비교) — Java String.compareTo는 UTF-16 단위라 보충 문자에서 순서가 다르다.
 * - str.isspace·strip·split(): Python의 유니코드 공백 집합.
 * - str.lower: Locale.ROOT 소문자화(Final_Sigma·U+0130 포함 같은 규칙).
 * - urllib.parse.unquote_plus: ASCII 구간마다 %XX를 바이트로 바꾸고 UTF-8(errors=replace, 최대 부분열마다 U+FFFD)로 디코드.
 */
public final class PyText {
    static final char REPLACEMENT = '\uFFFD';

    private PyText() {
    }

    /** Python str.isspace와 같은 집합(Unicode 공백 — 3.11 기준 29개). */
    static boolean isSpace(int cp) {
        if (cp >= 0x09 && cp <= 0x0D) {
            return true;
        }
        if (cp >= 0x1C && cp <= 0x20) {
            return true;
        }
        if (cp >= 0x2000 && cp <= 0x200A) {
            return true;
        }
        return cp == 0x85 || cp == 0xA0 || cp == 0x1680 || cp == 0x2028 || cp == 0x2029 || cp == 0x202F
                || cp == 0x205F || cp == 0x3000;
    }

    public static String strip(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && isSpace(s.charAt(start))) {
            start++;
        }
        while (end > start && isSpace(s.charAt(end - 1))) {
            end--;
        }
        return s.substring(start, end);
    }

    /** Python str.split() — 공백 연속을 구분자로, 빈 조각 없음. */
    static List<String> splitWhitespace(String s) {
        List<String> out = new ArrayList<>();
        int i = 0;
        int n = s.length();
        while (i < n) {
            while (i < n && isSpace(s.charAt(i))) {
                i++;
            }
            int j = i;
            while (j < n && !isSpace(s.charAt(j))) {
                j++;
            }
            if (j > i) {
                out.add(s.substring(i, j));
            }
            i = j;
        }
        return out;
    }

    /** Python str.split(sep) — 구분자 문자열 하나, 빈 조각 유지. */
    public static List<String> split(String s, String sep) {
        List<String> out = new ArrayList<>();
        int from = 0;
        while (true) {
            int at = s.indexOf(sep, from);
            if (at < 0) {
                out.add(s.substring(from));
                return out;
            }
            out.add(s.substring(from, at));
            from = at + sep.length();
        }
    }

    public static String lower(String s) {
        return s.toLowerCase(Locale.ROOT);
    }

    static int cpLen(String s) {
        return s.codePointCount(0, s.length());
    }

    /** UTF-16 위치 → 코드포인트 위치. */
    static int cpIndex(String s, int utf16Index) {
        return s.codePointCount(0, utf16Index);
    }

    /** Python str 비교(코드포인트 순서). */
    static int compare(String a, String b) {
        int i = 0;
        int j = 0;
        while (i < a.length() && j < b.length()) {
            int x = a.codePointAt(i);
            int y = b.codePointAt(j);
            if (x != y) {
                return Integer.compare(x, y);
            }
            i += Character.charCount(x);
            j += Character.charCount(y);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    }

    public static String unquotePlus(String s) {
        return unquote(s.replace('+', ' '));
    }

    /** urllib.parse.unquote(encoding='utf-8', errors='replace'). '%'가 없으면 그대로. */
    static String unquote(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        int n = s.length();
        while (i < n) {
            int j = i;
            if (s.charAt(i) < 0x80) {
                while (j < n && s.charAt(j) < 0x80) {
                    j++;
                }
                out.append(decodeUtf8Replace(percentBytes(s, i, j)));
            } else {
                while (j < n && s.charAt(j) >= 0x80) {
                    j++;
                }
                out.append(s, i, j);
            }
            i = j;
        }
        return out.toString();
    }

    private static int hex(char c) {
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

    /** ASCII 구간 [from, to)의 %XX(16진 2자리)를 바이트로. 그 밖의 '%'는 그대로. */
    private static byte[] percentBytes(String s, int from, int to) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(to - from);
        int i = from;
        while (i < to) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < to) {
                int hi = hex(s.charAt(i + 1));
                int lo = hex(s.charAt(i + 2));
                if (hi >= 0 && lo >= 0) {
                    out.write(hi * 16 + lo);
                    i += 3;
                    continue;
                }
            }
            out.write(c);
            i++;
        }
        return out.toByteArray();
    }

    /** bytes.decode('utf-8', 'replace') — 잘못된 최대 부분열마다 U+FFFD 하나. */
    public static String decodeUtf8Replace(byte[] b) {
        StringBuilder out = new StringBuilder(b.length);
        int i = 0;
        int n = b.length;
        while (i < n) {
            int b0 = b[i] & 0xFF;
            if (b0 < 0x80) {
                out.append((char) b0);
                i++;
                continue;
            }
            int need;
            int lo = 0x80;
            int hi = 0xBF;
            if (b0 >= 0xC2 && b0 <= 0xDF) {
                need = 1;
            } else if (b0 == 0xE0) {
                need = 2;
                lo = 0xA0;
            } else if ((b0 >= 0xE1 && b0 <= 0xEC) || b0 == 0xEE || b0 == 0xEF) {
                need = 2;
            } else if (b0 == 0xED) {
                need = 2;
                hi = 0x9F;
            } else if (b0 == 0xF0) {
                need = 3;
                lo = 0x90;
            } else if (b0 >= 0xF1 && b0 <= 0xF3) {
                need = 3;
            } else if (b0 == 0xF4) {
                need = 3;
                hi = 0x8F;
            } else {
                out.append(REPLACEMENT);
                i++;
                continue;
            }
            int cp = b0 & (need == 1 ? 0x1F : need == 2 ? 0x0F : 0x07);
            int k = 1;
            boolean bad = false;
            for (; k <= need; k++) {
                if (i + k >= n) {
                    bad = true;
                    break;
                }
                int bk = b[i + k] & 0xFF;
                int min = k == 1 ? lo : 0x80;
                int max = k == 1 ? hi : 0xBF;
                if (bk < min || bk > max) {
                    bad = true;
                    break;
                }
                cp = (cp << 6) | (bk & 0x3F);
            }
            if (bad) {
                out.append(REPLACEMENT);
                i += k;
            } else {
                out.appendCodePoint(cp);
                i += need + 1;
            }
        }
        return out.toString();
    }

    static int utf8Len(int cp) {
        return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    }

    static int utf8Len(String s) {
        return s.getBytes(StandardCharsets.UTF_8).length;
    }
}
