/**
 * 구문 파서 코어 — (A) §2.9 구문 파서 규칙(v1.52). 원시 바이트 → RawTransaction, 선택 규칙, meta, 처리(파싱 → 마스킹 → §2.10).
 * Montoya import 0, java.net 0 — Burp 없이 하네스로 실행된다(java_request_parse 정적 규칙). Montoya 이벤트는 capture.ContextMenu가 다룬다.
 */
package sentinel.burp.capture.core;
