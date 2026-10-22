<!--
PR 규율 (CLAUDE.md §3 / (B) §2):
  - 한 Issue = 한 수직 작업 = 한 PR. main 직접 병합 금지(N6).
  - merge 전 `make verify` 종료코드 0 필수.
  - 안전 불변식은 '정상 통과'가 아니라 '위조 거부'로 증명.
  값·절차의 정본은 (A) 설계확정서 = 레포 docs/design-decision.md. 이 체크리스트는 그 정본을 지키는지 확인하는 뷰.
-->

## 닫는 Issue
Closes #

## 무엇을 했나 (요약)
<!-- 1~3줄. 왜가 아니라 무엇을. 근거는 (A)에. -->

## 건드린 정본·manifest
- 건드린 (A) FROZEN 블록·절: <!-- 예: §3.1, §2.3 -->
- 관련 manifest 키: <!-- 예: request_token_validation, manifest_selfcheck -->
- manifest 상태 변경(있으면): <!-- 예: request_token_validation: not_implemented → enforced -->

## 가드레일·테스트
- [ ] **적대적(위조 거부) 테스트**를 포함했다. (정상 통과만으로 안전 주장하지 않음)
- [ ] `make verify` 종료코드 0.
- [ ] **manifest 자기검증 통과** — `enforced` 선언 = 실제 통과 테스트 존재. (과대평가 없음: 등록·수집·통과만 주장)
- [ ] `not_implemented`를 `enforced`로 참칭하지 않았다. (목표 주차 ≠ 현재 상태)

## 뷰 동기화 (낡음 방지 — 해당 변경 시 필수)
> 뷰가 정본과 어긋나 조용히 낡는 모든 경로를 봉인한다. 불일치 시 정본 (A)가 우선.
- [ ] `guardrails.yaml` 변경 시 → **(A) §3 매핑표**가 같은 PR에서 동기화됐다.
- [ ] CLAUDE.md 금지선 색인 변경 시 → **(A) §1.3 / §3**의 해당 절과 일치한다.
- [ ] manifest 생성물 ↔ **(A) §3 파생 일치** (`manifest_derivation`; CI가 검증).

## 금지선 확인 (N1~N10 — (A) §1.3 / §3)
- [ ] N1 외부 egress / N2 자율 전송 / N3 Java 로직 / N4 Burp 격리 / N5 실데이터 / N7 민감정보 커밋 / N8 자동반영 / N9 파인튜닝 / N10 멀티에이전트·RAG 위반 없음.
- [ ] N6: main 직접 병합 아님 — feature 브랜치 → 이 PR → merge.

---
<!-- 금지선을 건드리는 변경이면, 코드 전에 Issue에서 먼저 위험을 설명하고 합의했는지 확인. -->