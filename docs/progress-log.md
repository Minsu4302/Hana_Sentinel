# Progress Log — Sentinel Harness

> **용도**: 주차별 진행 요약 + 리스크 관리. (B) `claude-code-handoff.md` §6 '가정 검증 루프'의 기록처다.
> **성격**: 뷰·기록이지 정본이 아니다. manifest 상태의 정본은 `guardrails.yaml`(← (A) §3). 여기 적힌 상태가 정본과 다르면 정본이 맞다.
> **철칙(이 프로젝트가 가장 피하는 것 = 거짓 보장)**:
> - `enforced` 승격은 **실제 통과 테스트로 증명된 것만** 적는다.
> - **깨진 가정**과 **미해결**은 숨기지 말고 반드시 남긴다. 리스크는 보이게 둘 때만 관리된다.

## 작성 규칙
- 각 주차 끝(또는 의미 있는 마일스톤)에 섹션 1개 추가. 과거 섹션은 고치지 않고 누적한다(감사 추적).
- manifest 상태 변화는 '무엇을 실제 통과 테스트로 증명했나'(테스트 노드)와 함께 적는다.
- '깨진 가정'과 '미해결'은 빈칸으로 두지 말 것. 없으면 "없음"이라고 적는다(없음을 확인한 것과 안 적은 것은 다르다).

---

## Week 1 — <기간 YYYY-MM-DD ~ YYYY-MM-DD>   〔템플릿 — 작성 시 채움〕

### 완료한 작업 (Issue / PR)
| 작업 | Issue | PR | 상태 |
|---|---|---|---|
| W1-00 | #  | #  | merged / open |
| W1-01 | #  | #  |  |
| … | | | |

### manifest 상태 변화 (실제 통과 테스트로 증명된 승격만)
| manifest 키 | 이전 | 이후 | 증명한 테스트 노드 |
|---|---|---|---|
|  | not_implemented | enforced | `tests/…::…` |

> 승격하지 못한 것(계획했으나 미완)은 아래 '미해결'에 적는다 — manifest엔 계속 `not_implemented`로 남긴다.

### 깨진 가정 · 발견된 문제 (리스크)
> 설계(A)가 코드에서 성립하지 않았던 지점. 예: "SanitizationReceipt 재검증이 X 케이스를 못 잡음".
- 없음 / (있으면 적는다)

### 미해결 (명시적으로 남김 — 숨기지 않음)
> 이번 주 못 끝낸 것. '일단 enforced로 적자'의 유혹을 여기 적는 것으로 대체한다.
- 없음 / (있으면 적는다)

### (A) 정본 변경 여부
- 변경 없음 / (있으면) §?.? 변경 — 사유: … / 뷰 동기화(CLAUDE.md·`guardrails.yaml`·manifest) 완료: 예 / claude.ai 발행본 재발행: 예·보류

### 다음 주차 이월
- 

---

<!-- Week 2 이후 섹션은 같은 양식으로 아래에 누적한다. 위 템플릿 블록을 복사해 쓴다. -->

## Week 1 — 2026-10-22 ~ (진행 중)

### 완료한 작업 (Issue / PR)
| 작업 | Issue | PR | 상태 |
|---|---|---|---|
| 부트스트랩(설계 문서·템플릿) | — | #1 | merged |
| W1-00 | #2 | (이 PR) | open |

### manifest 상태 변화 (실제 통과 테스트로 증명된 승격만)
| manifest 키 | 이전 | 이후 | 증명한 테스트 노드 |
|---|---|---|---|
| `secret_scan_hook` | (manifest 없음) | enforced | `tests/test_secret_scan.py::test_precommit_blocks_fake_token_commit` 외 — 목록은 `guardrails.yaml` |
| `manifest_derivation` | (manifest 없음) | enforced | `tests/test_guardrails.py::test_committed_manifest_matches_rederivation` 외 — 목록은 `guardrails.yaml` |
| `claude_md_sync_check` | (신규 — (A) §3.1에 W1-00 리뷰로 등재) | not_implemented → 2주차 | 없음(미구현 — 추적만) |

> `secret_scan_hook`은 W1-00 리뷰에서 (A) §3.3 범위를 좁혔다: `enforced(클라이언트 훅 + make verify 전수스캔; 서버측 CI 강제는 미구현)`. 값(enforced)은 유지.

> 그 밖의 키는 최초 파생 시 (A) §3 그대로: (A)가 1주차 enforced를 목표로 둔 키는 증명 전이므로 `not_implemented`(target=1주차), 나머지는 (A) 표기대로(`not_implemented`→N주차 / `unverifiable` / `derived`).

### 깨진 가정 · 발견된 문제 (리스크)
- **(A) 목표층위 표기 ≠ (B) 어휘 1:1.** (A)에 복합 표기(`validator+테스트`, `테스트+설정`)와 `—`가 있다. `tools/guardrails/spec.py`의 `LAYER_MAP`에서 "주된 강제 지점 = 첫 항목"으로 정규화했고(`—`→외부), 매핑에 없는 표기가 나오면 파생을 거부한다. **정규화 규칙은 사람 확인 필요.**
- **(A) §3 '1주차 상태' 칸은 목표값이다.** 그대로 파생하면 증명 안 된 키가 enforced가 된다 → `sync`는 (A)=enforced 키를 증명 전까지 `not_implemented`(target=1주차)로 쓰고, 사람이 승격(state+테스트)한 것만 보존한다. (A)보다 앞선 주장(참칭)은 검증이 거부.
- pre-commit 4.4+에서 훅 language `system`이 `unsupported`로 개명됨 → `unsupported` 사용, pre-commit 버전 고정(`requirements-dev.txt`).
- 시크릿 스캐너 `secret_assignment` 패턴은 오탐 가능(예: 비밀 아닌 8자+ 문자열을 `*_password = "..."`에 대입). 허용목록(우회 구멍)은 두지 않고 fail-closed 쪽을 택함.

### 미해결 (명시적으로 남김 — 숨기지 않음)
- **`secret_scan_hook`은 클라이언트 훅이다.** `git commit --no-verify`로 우회 가능. `make verify`가 추적 파일을 전수 재스캔하지만, 서버측 CI(GitHub Actions 등)는 없다 — (A) 목표층위 'CI게이트'의 서버측 강제는 미구현. 훅 실행엔 PATH의 `python` 필요.
- W1-00의 검증 테스트 실재 확인은 **정적**(파일·함수 존재)뿐. 수집·통과 확인은 W1-09(`manifest_selfcheck`·`manifest_honesty`, 계속 not_implemented).
- `branch_protection`: GitHub main 보호 규칙(PR 필수·관리자 포함·force push/삭제 금지)을 적용했으나, 레포 설정은 시스템이 자가확인할 수 없으므로 (A)대로 `unverifiable` 유지.
- **폐쇄망 이식 과제:** 현재 개발은 인터넷망 PC(gh·pip 사용). 이식 시 사내 git + 오프라인 설치(wheelhouse)로 전환해야 함.
- **관찰(기존 상태, W1-00에서 미수정):** CLAUDE.md 색인 N3는 "(A) §3 (경계 매핑)"을 가리키지만 §3에 Java 로직 금지 전용 행은 없다. N7은 §1.3 ⓕ(원본 트래픽)만 가리키고 키·토큰 커밋 금지의 강제 키(§3.3 `secret_scan_hook`)는 색인에 없다. 불일치라기보다 색인이 느슨한 지점 — 사람 판단 필요.

### 추적됨 (미해결이었으나 현황판에 등재 — 해소 아님)
- **뷰 동기화 ②(CLAUDE.md 금지선 색인 ↔ (A) §1.3/§3) 기계 검사** → 추적됨: `claude_md_sync_check`=not_implemented→2주차. 현재는 PR 체크리스트 수동 확인. CLAUDE.md §4의 "전부 기계 강제" 표현을 사실대로 교정함(①·③=`make verify` 기계 강제, ②=수동).

### (A) 정본 변경 여부
- **변경 있음(W1-00 리뷰 교정, PR #3):** §3.1에 `claude_md_sync_check` 행 추가(not_implemented → 2주차) / §3.3 `secret_scan_hook` 상태 칸 범위 명시(값 enforced 유지). 사유: 문서가 사실과 다른 보장을 하던 지점 교정. 뷰 동기화: `guardrails.yaml` 재파생·manifest 재생성·CLAUDE.md §4 교정 — 같은 PR. claude.ai 발행본 재발행: 보류.

### 다음 주차 이월
- W1-01~W1-09 (진행 예정)