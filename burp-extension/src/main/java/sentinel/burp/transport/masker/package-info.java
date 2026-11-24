/**
 * 마스커 코어 — (A) §2.9 transport의 순수 Java 부분. RawEnvelope(메모리) → 마스킹 → 절단 → Envelope(§2.10 바이트).
 * 참조 구현은 Python fixture 마스커(tools/fixture_masker)이고, 같은 입력에 같은 바이트를 내는지는
 * java_masker_parity(동등성 하네스)가 매 make verify마다 확인한다.
 *
 * <p>이 패키지에는 Montoya import가 없고 java.net도 쓰지 않는다 — Burp 없이 실행된다(java_no_target_send 정적 규칙).
 * 원본 값은 메모리에서만 다루고 로그·예외 메시지에 쓰지 않는다. 거부는 사유 코드 하나뿐이다.
 */
package sentinel.burp.transport.masker;
