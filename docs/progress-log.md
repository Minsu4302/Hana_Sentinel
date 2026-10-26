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

## Week 1 — 2026-10-22 ~ 2026-10-23

### 완료한 작업 (Issue / PR)
| 작업 | Issue | PR | 상태 |
|---|---|---|---|
| 부트스트랩(설계 문서·템플릿) | — | #1 | merged |
| W1-00 | #2 | #3 | merged |
| W1-01 | #4 | #5 | merged |
| 문서 교정 (A) v1.3 | #6 | #7 | merged |
| W1-02 | #8 | #9 | merged |
| W1-03 | #10 | #11 | merged |
| W1-04 | #12 | #13 | merged |
| W1-05 | #14 | #15 | merged |
| W1-06 | #16 | #17 | merged |
| W1-07 | #18 | #19 | merged |
| W1-08 | #20 | #21 | merged |
| W1-09 | #22 | (이 PR) | open |

### manifest 상태 변화 (실제 통과 테스트로 증명된 승격만)
| manifest 키 | 이전 | 이후 | 증명한 테스트 노드 |
|---|---|---|---|
| `secret_scan_hook` | (manifest 없음) | enforced | `tests/test_secret_scan.py::test_precommit_blocks_fake_token_commit` 외 — 목록은 `guardrails.yaml` |
| `manifest_derivation` | (manifest 없음) | enforced | `tests/test_guardrails.py::test_committed_manifest_matches_rederivation` 외 — 목록은 `guardrails.yaml` |
| `claude_md_sync_check` | (신규 — (A) §3.1에 W1-00 리뷰로 등재) | not_implemented → 2주차 | 없음(미구현 — 추적만) |
| `engine_burp_isolation` | not_implemented(→1주차) | enforced | `tests/test_architecture.py::test_rejects_planted_burp_import` 외 — 목록은 `guardrails.yaml` (W1-01) |
| `no_autonomous_send` | not_implemented(→1주차) | enforced | `tests/test_architecture.py::test_rejects_planted_send_or_socket_import` 외 — 목록은 `guardrails.yaml` (W1-01) |
| `java_logic_isolation` | (신규 — (A) v1.3 §3.2 등재) | not_implemented → Java 연결 시 | 없음(Java 미연결 — 강제 대상 없음, 추적만) |
| `egress_static_check` | not_implemented(→1주차) | enforced | `tests/test_egress.py::test_rejects_egress_library_reached_transitively` 외 — 목록은 `guardrails.yaml` (W1-02) |
| `egress_runtime_block` | not_implemented(→1주차) | enforced(테스트환경 한정) | `tests/test_egress.py::test_urllib_external_request_fails_because_of_guard_not_network` 외 (W1-02) |
| `local_llm_vs_egress` | not_implemented(→1주차) | enforced(1주차=허용목록 빔 검사) | `tests/test_egress.py::test_local_llm_endpoint_needs_no_allowlist_entry` 외 (W1-02) |
| `egress_enforcement_owner` | unverifiable | unverifiable(유지) | — (OS/네트워크 책임, 자가확인 불가) |
| `loopback_binding` | not_implemented(→1주차) | enforced | `tests/test_server.py::test_rejects_non_loopback_bind_host` 외 — 목록은 `guardrails.yaml` (W1-03) |
| `request_token_validation` | not_implemented(→1주차) | enforced | `tests/test_auth.py::test_forged_or_missing_token_is_rejected_before_downstream_and_body` 외 (W1-04) |
| `auth_precedence_noinvoke` | not_implemented(→1주차) | enforced | `tests/test_auth.py::test_real_app_never_invokes_inner_app_parser_or_deserializer_on_auth_failure` 외 (W1-04) |
| `authfail_log_hygiene` | not_implemented(→1주차) | enforced | `tests/test_auth.py::test_auth_failure_audit_contains_no_body_or_token_values` 외 (W1-04) |

| `input_schema_gate` | not_implemented(→1주차) | enforced | `tests/test_schema.py::test_rejects_schema_violation` 외 (W1-05) |
| `envelope_arity` | not_implemented(→1주차) | enforced | `tests/test_schema.py::test_rejects_single_envelope_without_exactly_one_transaction` 외 (W1-05) |
| `maskedref_typing` | not_implemented(→1주차) | enforced | `tests/test_schema.py::test_rejects_raw_string_smuggled_into_masked_ref` 외 (W1-05) |
| `auth_precedence_noinvoke` | enforced | enforced(검증 범위 확장) | + `tests/test_auth.py::test_pipeline_spies_cover_every_stage_function_and_detect_calls_as_control` (W1-05) |

| `sanitization_trust` | not_implemented(→1주차) | enforced(값 재검증) | `tests/test_sanitization.py::test_raw_secret_is_rejected_despite_applied_true_receipt` 외 (W1-06) |

| `audit_log_present` | not_implemented(→1주차) | enforced | `tests/test_audit.py::test_persisted_audit_contains_no_sensitive_values` 외 (W1-07) |
| `audit_write_failure` | not_implemented(→2주차) | not_implemented(→2주차) 유지 | — (현재 동작을 `test_audit_write_failure_does_not_block_requests_yet_documented`가 고정: 기록 실패해도 요청을 막지 않음) |

| `no_autopatch_apply` | not_implemented(→1주차) | enforced | `tests/test_absence.py::test_engine_has_no_autopatch_path` 외 (W1-08) |
| `no_finetune_path` | not_implemented(→1주차) | enforced | `tests/test_absence.py::test_engine_has_no_finetune_path` 외 (W1-08) |
| `no_raw_persistence` | not_implemented(→1주차) | enforced | `tests/test_absence.py::test_runtime_request_processing_persists_no_raw_traffic` 외 (W1-08) |

| `manifest_honesty` | not_implemented(→1주차) | enforced | `tests/test_guardrails.py::test_rejects_not_implemented_key_claimed_as_enforced` 외 (W1-09) |
| `manifest_selfcheck` | not_implemented(→1주차) | enforced(정적 → **동적**) | `tests/test_selfcheck.py::test_rejects_statically_present_but_uncollected_node` 외 (W1-09) |
| `manifest_derivation` | enforced | enforced(유지) | 변경 없음 (W1-00) |

> **W1-09 — selfcheck 정적 → 동적**: W1-00의 확인은 *정적*(`registry.resolve_test`: 노드의 파일·함수가 소스에 있음)뿐이었다. 이제 `make verify`의 pytest 단계가 selfcheck 플러그인(`tools/guardrails/selfcheck.py`, `-p tools.guardrails.selfcheck --manifest-selfcheck=guardrails.yaml`)을 켜고, enforced 키가 가리키는 모든 노드가 **그 실행에서 실제로 수집되고 통과했는지** 확인한다. 미수집(수집 제외·`-k` 선택 해제·collection error·부재)·skip(setup skip 포함)·xfail·xpass·setup/teardown 실패·실패·미실행이면 세션을 실패시킨다. 매개변수화 함수는 모든 인스턴스가 통과해야 한다. 실제 레포에서 enforced 검증 테스트 하나를 `-k`로 빼면 pytest 자체는 성공(나머지 통과)인데 selfcheck가 종료코드 1로 바꿈을 확인.
> **정적 확인이 놓치던 것(적대 테스트로 재현)**: `__init__`이 있는 테스트 클래스의 메서드, `__test__ = False` 모듈, conftest `collect_ignore` — 셋 다 `resolve_test`는 '실재'로 보고 pytest도 종료코드 0인데 selfcheck만 잡는다.
> **과대평가 금지(경계)**: selfcheck는 '등록·수집·통과'만 확인한다. 각 검증 테스트가 그 가드레일을 *실질적으로* 검증하는지는 그 테스트 내용의 책임이며 selfcheck가 떠안지 않는다(플러그인·테스트 머리말에 명시). 참칭 차단(not_implemented·disabled·unverifiable·derived의 enforced 주장 거부)은 기존대로 `registry.validate`(`guardrails check`)가 맡고 `manifest_honesty`가 그 거부 테스트를 가리킨다.
> **변이 적용 유효성 장치(W1-08 교훈, `tools/mutation_guard.py`)**: 변이 결과를 읽기 전에 ⓐ 치환이 실제로 일어났는지(대상 문자열 정확히 1회, 결과 ≠ 원문) ⓑ 실행 중 로드된 모듈이 변이본인지(selfcheck의 활성 표지 `module=<경로>` = 변이본 경로)를 증명하고, 어긋나면 `MutationNotApplied`로 결과를 해석하지 않는다. selfcheck의 네 검사(미수집 판정·통과 판정·xfail 기록·세션 실패 반영) 각각에 대해 '원본은 위조 거부 / 그 검사를 끈 변이본은 같은 위조 통과'를 **스위트 안에서** 매번 보이며, 변이본이 실제로 로드됐음을 먼저 확인한다. W1-08 함정 재현(변이본을 만들었으나 실행은 원본 모듈) → 장치가 '다른 사본'으로 잡음.
> **'종료코드 ≠ 0'은 거부 증거가 아니다**: 플러그인 미로드·옵션 오류도 ≠ 0이다. 그래서 샌드박스 거부 판정은 활성 표지(기대 모듈) + 거부 사유 출력이 있어야 인정한다. 재현 테스트: 플러그인을 못 불러 종료코드 ≠ 0인 실행을 장치가 '활성 표지 없음'으로 거부.

> **W1-08 부재 증명 = 2겹**: ⓐ 정적(`tools/absence_check.py`) — `src/sentinel` 전체 AST에서 자동 반영(프로세스 실행·VCS·패치 라이브러리·자동반영 심볼), 파인튜닝(학습 프레임워크·Trainer류·파인튜닝 심볼), 원본 저장(파일 쓰기 open·write_text/bytes·os.write·임시파일·pickle류·파일 로그 핸들러·print·sqlite3) 통로가 없음. 허용 예외는 파일 단위 1건(`audit.py`의 sqlite3)이며 테스트가 허용 목록을 고정. ⓑ 런타임 관측(ⓕ) — 수용 + 인증·스키마·재검증 거부 + egress 시도를 원문 표지와 함께 처리하는 동안 파일 쓰기 open 0(Python 감사 이벤트), 전 로거 DEBUG 출력·stdout/stderr·**감사 SQLite 디렉터리 파일 바이트**에 원문(본문·토큰·제시 토큰·입력 헤더명·쿼리 값·egress 목적지) 0. 변이: 정적 검사기 무력화 → 심은 더미 테스트 전부 실패 / 감사 DB 파일 스캔 무력화 → '감사 지점이 본문을 적는' 변이 검출 실패 / 그 밖의 변이(디버그 로그·print·임시파일)는 각자 관측 경로가 잡음.
> **커밋 경계(보조, R-10)**: `var/`·`*.sqlite3`·캡처물 경로가 git 무시 대상이고 추적 파일 0임을 테스트로 확인. `.gitignore`는 보조일 뿐 원본 미기록의 보장은 기능 부재 + 관측.

> **W1-07 감사 저장 위치·형식(구현 재량, 기록)**: `sentinel.audit` 로거 → 로컬 SQLite 파일. 기본 `var/audit.sqlite3`(현재 작업 디렉터리 기준), 환경변수 `SENTINEL_AUDIT_DB`로 변경. 테이블 `audit_events(id, ts[UTC ISO8601], level, event, message)`. `event` = 메시지 첫 토큰(`auth_failure`·`schema_rejected`·`sanitization_rejected`·`payload_too_large`·`egress_attempt`). 저장하는 `message`는 각 감사 지점이 이미 위생 처리한 문자열(사유 코드·구조 위치·패턴 이름)뿐 — 본문·토큰·입력 이름·egress 목적지 없음. `var/`·`*.sqlite3`는 `.gitignore`. 설치는 `serve()`에서(토큰·manifest·바인드 검증이 모두 끝난 뒤).
> **egress 시도 감사**: Python 런타임 감사 훅(`sys.addaudithook`)이 `socket.connect`·`socket.getaddrinfo`·`socket.sendto` 이벤트 중 외부 목적지(egress_policy EXTERNAL)를 `egress_attempt op=… port=…`로 기록. **기록만 하고 차단하지 않는다**(운영 차단 실주체 = OS/네트워크, `egress_enforcement_owner`=unverifiable 유지). 훅은 제거 불가라 프로세스당 1회 설치.
> **ExecutionResponse**: ①②③ 통과 시 `200 {analysis_status:"not_implemented", skipped_reasons:["rule_engine_not_implemented","llm_analysis_not_implemented"], manifest_snapshot}` — findings 필드 자체가 없음(타입이 금지). `manifest_snapshot` = 커밋된 manifest의 키별 `status`·`effective_status`; 테스트가 SSOT(`guardrails.yaml`) 재파생과의 일치를 확인. manifest 없음·깨짐 → 기동 거부(fail-closed).
> 변이 확인: 저장 무력화 → 저장 존재 테스트 전부 실패 / 감사 지점이 제시 헤더 기록 → 저장소 위생 테스트 실패 / 스냅샷 거짓(전부 enforced) → 스냅샷 일치·정직 테스트 실패 / 응답에 빈 findings 삽입 → 응답 형태 테스트 실패.

> **W1-06 — 값 재검증이 돌 때만 enforced**: `sanitization_trust`의 증명은 영수증 불리언이 아니라 *값 재스캔* 테스트다. 영수증이 `applied:true, failed:false`라고 주장하는 입력에 생문자열을 10개 자리(비화이트리스트 요청·응답 헤더, 쿼리 값·이름, 퍼센트 인코딩, 경로, 요청·응답 본문, base64 본문, meta.origin_ref) × 정책 패턴 전부에 심어 전부 거부됨을 보였다. 변이: 재스캔 무력화 → 값 적대 테스트 전부 실패 / 영수증 신뢰(applied=true면 통과, R-11 재현) → 대량 실패 / 화이트리스트 제거 → 화이트리스트 테스트만 실패하고 값 재스캔 테스트는 통과(주 방어선의 독립성).
> 새 단계 함수(`sentinel.pipeline.sanitization_check.*`)는 W1-05의 자동 열거로 `auth_precedence_noinvoke` 스파이 대상에 자동 포함 — 수동 등록 없음.

> **W1-05 스파이 커버리지 확장(W1-04 회귀 리스크 차단)**: 파이프라인 단계 함수는 `sentinel.pipeline` 패키지에 둔다. `auth_precedence_noinvoke` 스파이는 이 패키지의 **모든 함수를 자동 열거**해 감시한다(이번 신규: `sentinel.pipeline.schema_gate.parse_envelope`, 그리고 `BaseModel.model_validate(_json)` 경유의 Envelope 역직렬화). 새 단계 함수는 이 패키지에 두기만 하면 '토큰 실패 시 미호출' 검사 대상이 된다 — 수동 등록 누락으로 enforced가 조용히 낡는 경로를 없앰. 호출하는 쪽은 `모듈.함수`로 참조해야 하며, 직접 import로 묶어 스파이를 우회하면 대조 테스트가 실패한다(변이로 확인). 남는 가정: 파이프라인 함수가 `sentinel.pipeline` **밖**에 생기면 자동 열거에 안 잡힌다 — 단계 함수 위치 규칙(패키지 머리말)으로 관리.

> **W1-04 인터페이스 결정(정본 미지정 → 구현 재량, 기록 필수)**: 클라이언트는 공유 토큰을 요청 헤더 **`X-Sentinel-Token`** 한 개로 보낸다(없음·중복·불일치 → 401). Java Extension 연결 시 이 헤더 이름을 그대로 써야 한다. `Authorization` 헤더를 쓰지 않은 이유: 점검 대상 앱의 `Authorization` 헤더와 혼동·충돌을 피하고, Burp 트래픽 안의 대상 인증정보와 도구 인증을 분리하기 위해. 서버 측 토큰은 환경변수 `SENTINEL_SHARED_TOKEN`(설정) — 헤더(전달)와 분리.

> `secret_scan_hook`은 W1-00 리뷰에서 (A) §3.3 범위를 좁혔다: `enforced(클라이언트 훅 + make verify 전수스캔; 서버측 CI 강제는 미구현)`. 값(enforced)은 유지.

> 그 밖의 키는 최초 파생 시 (A) §3 그대로: (A)가 1주차 enforced를 목표로 둔 키는 증명 전이므로 `not_implemented`(target=1주차), 나머지는 (A) 표기대로(`not_implemented`→N주차 / `unverifiable` / `derived`).

### 깨진 가정 · 발견된 문제 (리스크)
- **(A) 목표층위 표기 ≠ (B) 어휘 1:1.** (A)에 복합 표기(`validator+테스트`, `테스트+설정`)와 `—`가 있다. `tools/guardrails/spec.py`의 `LAYER_MAP`에서 "주된 강제 지점 = 첫 항목"으로 정규화했고(`—`→외부), 매핑에 없는 표기가 나오면 파생을 거부한다. **정규화 규칙은 사람 확인 필요.**
- **(A) §3 '1주차 상태' 칸은 목표값이다.** 그대로 파생하면 증명 안 된 키가 enforced가 된다 → `sync`는 (A)=enforced 키를 증명 전까지 `not_implemented`(target=1주차)로 쓰고, 사람이 승격(state+테스트)한 것만 보존한다. (A)보다 앞선 주장(참칭)은 검증이 거부.
- pre-commit 4.4+에서 훅 language `system`이 `unsupported`로 개명됨 → `unsupported` 사용, pre-commit 버전 고정(`requirements-dev.txt`).
- (W1-01) **`asyncio`는 `socket` import 없이도 송신 가능**(`open_connection` 등). 모듈 단위 금지만으로는 구멍 → `asyncio`·`http`·`urllib`·`xmlrpc`는 패키지는 허용하고 송신 심볼(from-import·속성 접근)만 금지. `exec`/`eval`·비리터럴 동적 import는 정적 검증 불가 경로라 그 자체로 위반 처리.
- (W1-01) 검사기 무력화 변이(visitor no-op)로 적대적 테스트가 실제로 실패함을 확인 — 테스트가 검사기에 의존함(정상·대조·fail-closed 케이스만 통과로 남음).
- (W1-02) **"허용목록"의 해석**: (A) §3.1의 "허용목록 빔"을 *외부 egress 목적지 허용목록*으로 해석해 `src/sentinel/egress_policy.py`의 `EGRESS_ALLOWLIST: Final = ()`로 구현. 로컬 LLM(루프백)은 허용목록 항목이 아니라 목적지 분류(LOCAL)로 다뤄, 허용목록은 비어 있는 채로 둔다. 사내 대역(10.x·192.168.x)도 승인 개념(4번 주제) 전에는 EXTERNAL.
- (W1-02) **W1-00 적대 테스트가 '아직 미승격인 키'(`egress_static_check`)에 고정돼 있어 승격 시 깨짐** → 이미 enforced인 키의 검증 테스트를 지우거나 바꾸는 방식으로 바꿔 승격 진행과 무관하게 함.
- (W1-02) `ipaddress`는 3.11에서 IPv4-mapped 루프백(`::ffff:127.0.0.1`)을 루프백으로 보지 않음 → EXTERNAL로 분류(fail-closed 쪽이라 그대로 둠).
- (W1-02) 변이 확인: 가드 무력화 + '네트워크 부재' 모의 시 런타임 테스트 전부 실패 — 특히 urllib 테스트는 실패 원인이 `EgressBlocked`가 아니라 일반 `OSError`라서 실패(가드 귀속 vs 네트워크 부재 구분이 실제로 작동). 의존성 금지 목록을 비우는 변이에서도 적대 테스트 전부 실패.
- (W1-03) **FastAPI 0.161이 `opentelemetry-api`를 필수 의존성으로 끌어온다**(런타임 전이 폐포: annotated-doc, annotated-types, anyio, click, fastapi, h11, idna, opentelemetry-api, pydantic, pydantic-core, starlette, typing-extensions, typing-inspection, uvicorn — 송신 클라이언트 없음). API 패키지는 exporter 없이는 송신하지 않으므로 허용하되, OTLP·Zipkin·Jaeger exporter·distro·sentry-sdk·ddtrace를 `tools/dep_egress.py` 금지 목록에 추가(W1-02 도구 정책 보강 — 이번 의존성 추가에서 나온 발견). **금지 목록 범위 추적**: `tests/test_egress.py::test_egress_denylist_matches_tracked_snapshot`이 금지 목록을 분류·추가 시점별 기대 스냅샷(`EXPECTED_EGRESS_DENYLIST`)과 대조 — 목록이 바뀌면 이 표도 같은 PR에서 바뀌어야 통과(암묵적 확장·축소 차단). `egress_static_check` 검증 테스트로 등록.
- (W1-03) **FastAPI 기본 문서 UI(/docs·/redoc)는 브라우저가 외부 CDN 자산을 받아 온다** → docs·redoc·openapi.json 비활성(N1). 테스트로 404 확인.
- (W1-03) 바인드 주소는 (A) 표기대로 `127.0.0.1` 리터럴만 허용 — `localhost`(해석 결과 가변)·다른 127/8·`::1`·변형 표기(`127.1`, 정수·16진)도 거부. 바인드 주소 CLI 옵션·환경변수는 두지 않음. **기본 포트 8765는 정본 값이 없어 임의로 고른 값이며, 정본 결정이 아니다**(`--port`로 바꿀 수 있는 설정값). 주소(127.0.0.1)=불변식이라 리터럴 고정 / 포트=설정이라 가변 — 의도된 비대칭(W1-03 리뷰 승인).
- (W1-03) 바인딩 3겹: 설정 객체 검증 → uvicorn 설정 직전 재검증(frozen 우회 대비) → `startup` 직후 실제 바인드 주소 재확인(비루프백이면 리스너 닫고 기동 중단). uvicorn의 소켓·fd·UDS 주입 경로는 거부. 변이 확인(검증 무력화 시 적대 테스트 전부 실패) — 단 실제 0.0.0.0 바인드를 일으킬 수 있는 우회 테스트는 변이 실행에서 제외(이 PC의 전 인터페이스에 포트를 열지 않기 위해).
- (W1-04) **게이트 위치 = FastAPI 바깥의 순수 ASGI 래퍼**(`TokenGate`). FastAPI 미들웨어·의존성(Depends)으로 두면 라우팅·요청 객체 생성이 먼저 일어날 수 있어 '본문 touch 전 거부'를 구조로 보장하기 어렵다 → 최외곽 래퍼로 두고, 실패 시 ASGI `receive`(본문 수신)조차 호출하지 않음을 스파이로 증명.
- (W1-04) **파서·분석·저장 함수는 아직 없다**(W1-05~07). 그래서 '미호출'은 ⓐ 하위 앱(그것들로 가는 유일한 진입로) ⓑ ASGI receive ⓒ 실제 FastAPI 안쪽의 본문 읽기·역직렬화(`Request.body/json/form/stream`, `json.loads`, pydantic `model_validate(_json)`) 스파이로 증명. 스파이가 실제로 파싱을 잡는다는 대조 테스트를 따로 둠(고장 난 스파이로 '0회'가 나오는 거짓 증명 방지). W1-05에서 스키마 검증 함수가 생기면 그 함수도 스파이 대상에 추가해야 함.
- (W1-04) 테스트 입력 `\x00`은 OS가 환경변수에 담을 수 없어(ValueError) 다른 제어문자(`\x07`)로 대체 — NUL 토큰은 애초에 설정 불가.
- (W1-04) 변이 확인: 검증 무력화 → 위조 거부·미호출·실서버 테스트 실패 / 감사 로그에 제시 헤더 기록 → 위생 테스트 실패 / 미설정 시 기본값 fallback → 기동 거부 테스트 실패.
- (W1-05) **Pydantic `Literal[True]`는 strict 모드에서도 정수 `1`을 통과시킨다**(`1 == True`). 적대 테스트(`masked: 1`)가 잡음 → `MaskedRef.masked`를 엄격 bool + `is True` 검증기로 교체.
- (W1-05) 스파이 열거를 패치 **후**에 하면 래퍼의 `__module__`이 바뀌어 열거가 비는 테스트 버그 → 패치 전 1회 열거로 고정. 대조 테스트(열거 비어 있지 않음 + 실제 호출 기록)가 이 버그를 잡았다.
- (W1-05) **MaskedRef 해석**: (A) §2.2에서 `Param.value`·`Header.value`는 `str | MaskedRef`라 평문 문자열 자체는 계약상 허용. '타입 레벨 생문자열 유입 불가'는 *MaskedRef 객체에 원문을 담을 경로가 없음*(추가 필드 금지, `masked`=true만, `label`=가명 라벨 형식 `^[a-z][a-z0-9]{0,23}_[0-9]{2,4}$`만, `kind` 폐쇄 enum, 불변)으로 구현. 평문 값에 비밀값이 남았는지는 W1-06(값 재검증).
- (W1-05) `redacted_kinds`는 (A) §2.3 표기 `[token|cookie|pii|host]`대로 *종류 목록*으로 구현(종류별 개수 맵이 아님). 주석 "종류별 카운트"가 개수 맵을 뜻한다면 정본 확인 필요.
- (W1-05) 변이 확인: arity 검증기 제거 → arity 테스트 실패 / MaskedRef 추가 필드 허용·제약 해제 → 밀반입 테스트 실패 / 앱이 파이프라인 함수를 우회 참조 → 스파이 대조 테스트 실패.
- (W1-06) **테스트 더미 버그**: `test_schema.py` TX가 요청·응답 본문에 같은 dict 객체를 써서 `deepcopy` 후에도 공유 → 응답 본문 수정이 요청 본문까지 바꿈. 상한 경계 테스트가 잡음 → 각자 사본으로.
- (W1-06) **패턴 구멍**: `session_cookie_pair`가 경로 속 `/JSESSIONID=…`(URL 재작성 세션)를 놓침. 적대 테스트(경로 자리)가 잡음 → 경계 문자에 `/` 추가.
- (W1-06) **본문 크기 판단 — 적용함.** 재검증은 본문 전체를 스캔하므로 상한 없이는 DoS 경로가 된다. ⓐ HTTP 원시 요청 1 MiB 상한: 스트림을 읽다 초과 즉시 중단 → 413, 파싱 전 차단(설정값, 정본 결정 아님 — 64KB+256KB 본문의 base64 팽창·오버헤드 여유). ⓑ 내용 상한 (A) §2.2 req 64KB / resp 256KB: 디코드 후 바이트 기준, 초과 시 `truncated` 값과 무관하게 거부(Java가 잘랐어야 할 값).
- (W1-06) `redacted_kinds`를 (A) v1.4대로 `{token, cookie, pii, host}` 개수 맵으로 스키마 변경(네 키 필수, 음수·문자열·추가 키 거부).
- (W1-07) `create_app()`이 이제 기동 시 manifest 파일을 `json.loads`로 읽어, W1-04의 '토큰 실패 시 역직렬화 미호출' 스파이가 앱 *구성 시점* 호출을 요청 처리로 오집계 → 앱 구성 후 스파이 기록을 비우고 요청 구간만 검사하도록 테스트 수정(검사 범위는 그대로 — 요청 처리 중 호출 0회).
- (W1-07) **egress 감사 훅은 테스트 egress 가드와 겹치지 않는다**: 테스트 가드는 소켓 시스템 호출 *전에* 차단하므로 감사 이벤트가 발생하지 않는다. 그래서 egress 감사 테스트는 `sys.audit(...)`로 이벤트만 직접 발생시켜 검증(실제 송신 없음).
- (W1-08) 파인튜닝 이름 패턴의 `\blora\b`는 `build_lora_adapter`를 놓친다(`\b`가 밑줄을 단어 문자로 취급) → 식별자 단위 검사이므로 밑줄 경계 `(^|_)lora(_|$)`로 교정. 적대 더미가 잡음.
- (W1-08) 변이 스크립트가 `tests.test_absence`를 import해 패치해도 pytest가 같은 파일을 다른 모듈 객체로 로드해 패치가 안 닿음(거짓 통과) → 패치 지점을 공용 객체(`Path.rglob`)로 옮겨 재확인. 변이 확인 자체도 '변이가 실제로 적용됐는지'를 봐야 함.
- (W1-09) **지시와 실제 상태의 차이**: W1-09 지시는 `manifest_selfcheck`를 '이미 enforced'로 전제했으나 실제로는 `manifest_selfcheck`·`manifest_honesty` 둘 다 W1-00 이후 `not_implemented`(→1주차)였다(정적 확인만으로는 승격하지 않았음). W1-09에서 처음 승격.
- (W1-09) **selfcheck가 레지스트리 YAML 파싱 오류에서 내부 오류로 죽었다**(`yaml.YAMLError` 미처리). 종료코드 ≠ 0이라 결과는 fail-closed였지만 활성 표지·사유가 없었다 — `_expect_rejected`가 '≠ 0'만으로 거부를 인정하지 않아 드러남 → 처리해 '레지스트리 읽기 실패' 사유로 거부.
- 시크릿 스캐너 `secret_assignment` 패턴은 오탐 가능(예: 비밀 아닌 8자+ 문자열을 `*_password = "..."`에 대입). 허용목록(우회 구멍)은 두지 않고 fail-closed 쪽을 택함.

### 미해결 (명시적으로 남김 — 숨기지 않음)
- **`secret_scan_hook`은 클라이언트 훅이다.** `git commit --no-verify`로 우회 가능. `make verify`가 추적 파일을 전수 재스캔하지만, 서버측 CI(GitHub Actions 등)는 없다 — (A) 목표층위 'CI게이트'의 서버측 강제는 미구현. 훅 실행엔 PATH의 `python` 필요.
- `branch_protection`: GitHub main 보호 규칙(PR 필수·관리자 포함·force push/삭제 금지)을 적용했으나, 레포 설정은 시스템이 자가확인할 수 없으므로 (A)대로 `unverifiable` 유지.
- **폐쇄망 이식 과제:** 현재 개발은 인터넷망 PC(gh·pip 사용). 이식 시 사내 git + 오프라인 설치(wheelhouse)로 전환해야 함.
- (W1-01) **경계 검사는 엔진 소스의 직접 import만 본다.** 제3자 패키지 내부 송신(전이 의존성), 런타임 조립 문자열로의 우회(`getattr(builtins, ...)` 등), 수신 객체를 정적으로 알 수 없는 호출(`loop.create_connection`)은 못 잡는다. 의존성 egress는 W1-02(`egress_static_check`·`egress_runtime_block`) 책임. 검사 대상은 `src/sentinel`(분석 엔진)뿐 — `tools/`·`tests/`는 범위 밖.

- (W1-02) **egress 경계가 잡는 것 / 못 잡는 것** (W1-01 이월 한계 인수):
  - 잡음 — 제품 런타임 의존성(pyproject)의 **전이 폐포**(설치 메타데이터의 Requires-Dist, 요청된 extra·marker 평가) 안의 송신 클라이언트·상용 AI SDK / 메타데이터를 못 찾는 의존성은 오류(fail-closed) / 테스트 프로세스의 Python `socket` 계층을 통한 외부 TCP 연결·DNS 해석·UDP 송신(가드 차단 + 이벤트 기록, probe 밖이면 그 테스트 실패).
  - 못 잡음 — 금지 목록에 없는 송신 패키지, 메타데이터 없이 벤더링된 송신 코드 / 하위 프로세스(git·pre-commit 등)의 네트워크 / C 확장의 `_socket`·OS API 직접 호출 / Windows asyncio Proactor의 IP 리터럴 연결(ConnectEx) / **제품 런타임**(테스트 밖)의 실제 차단 — 이는 OS/네트워크 책임(`egress_enforcement_owner` = unverifiable). 개발 도구 의존성(requirements-dev.txt)은 범위 밖.
- (W1-02) `egress_runtime_block`은 **테스트 환경 한정** enforced다. 제품이 운영에서 egress를 못 한다는 보장이 아니다.

- (W1-03) **분석 엔드포인트(`POST /v1/analyze`)는 아직 인증 없이 501을 돌려준다.** 본문을 읽지 않으므로 처리되는 데이터는 없지만, 토큰 검증(W1-04)이 붙기 전까지 루프백의 아무 프로세스나 호출할 수 있다. W1-04가 파이프라인 최선두에 토큰 검증을 둔다.
- (W1-03) 루프백 바인딩은 '외부 인터페이스에서 접근 불가'를 보장할 뿐, 같은 PC의 다른 사용자·프로세스로부터의 접근은 막지 않는다(그건 W1-04 토큰의 몫).

- (W1-03 리뷰 2ⓐ) **목록 기반 차단은 알려진 것만 막는다.** `egress_static_check`의 금지 목록(`tools/dep_egress.py`)에 없는 미래의 신규 텔레메트리·송신 패키지는 수동 추가가 필요하다(스냅샷 테스트는 '목록이 바뀌었음'을 드러낼 뿐, '빠진 패키지'를 찾아주지 않음).
- (W1-03 리뷰 2ⓑ) **이미 merge된 도구의 수정 원칙**: 그 수정을 유발한 작업과 인과가 있을 때만 허용하고 PR에 명시한다(예: W1-03의 fastapi 유입 → W1-02 금지 목록 보강).
- (W1-04) **토큰 강도는 검사하지 않는다**(길이·엔트로피). 형식(ASCII 인쇄 가능·공백 없음·비어있지 않음)만 기동 시 검사 — 강화·회전·수명은 `token_hardening`(not_implemented→2주차).
- (W1-04) **감사 로그는 아직 Python logging(`sentinel.audit`)으로만 나간다.** 기록 위치·형식·보존과 '기록 실패 시 fail-closed'는 W1-07(`audit_log_present`)·2주차(`audit_write_failure`). 현재 인증 실패만 기록(재검증 거부 등은 W1-06·07).
- (W1-04) 공유 토큰 하나라 클라이언트 구분이 없다(같은 토큰을 아는 로컬 프로세스는 통과). 루프백 + 토큰이 1주차의 로컬 경계 — 그 이상은 2주차 이후.

- (W1-05) **결정 필요 — '반드시 MaskedRef여야 하는 자리'가 정본에 없다.** (A) §2.3은 Java가 "고정 화이트리스트 헤더"를 치환한다고만 하고 그 목록(예: Cookie·Authorization·Set-Cookie)을 정하지 않는다. 그래서 W1-05는 이름 기반 강제(예: Cookie 헤더 값이 평문이면 거부)를 만들지 않았다. 목록이 정해지면 스키마(타입)에서 강제할지 W1-06(값 재검증)에서 강제할지 함께 결정.
- (W1-05) **요청 본문 크기 상한 없음**: 엔드포인트가 본문 전체를 메모리로 읽는다(루프백·토큰 뒤라 공격면은 작음). (A) §2.2의 body truncation 상한(req 64KB / resp 256KB, "config화")도 스키마에서 아직 강제하지 않는다 — Java가 자르는 값이라 Python 쪽 강제 여부·위치는 미정.
- (W1-05) 스키마 거부 감사도 `sentinel.audit`(Python logging)에 오류 유형·개수만 남긴다. 기록 위치·형식은 W1-07. 422 응답 본문은 `{"error": "schema_rejected"}` 고정(입력 미반사).

- (W1-06) **한계((A) §2.3 그대로)**: 패턴 검사는 '정책에 정의된 패턴'(`sentinel/pipeline/sanitization_check.py` `PATTERNS`)만 탐지하며 '모든 비밀값 부재'를 증명하지 않는다 — 불투명 세션 ID는 일반 문자열과 구분 불가(`test_opaque_secret_in_unlisted_place_is_not_detected_documented_limitation`이 이 한계를 고정해 둠). Python 재검증(2차)은 Java 전송 전 마스킹(1차)을 대체하지 않는다.
- (W1-06) **이름 화이트리스트는 설정값**(`sentinel/sanitization_policy.py` `DEFAULT_POLICY`, 정본 아님): Authorization·Proxy-Authorization·Cookie·Set-Cookie·X-API-Key·`*api-key*`·`*apikey*`·`*token*`·`*secret*`·`*session*`. 보조 방어선 — 주 방어선은 값 재스캔.
- (W1-06) 영수증 `policy_version`과 Python 정책 버전의 일치는 검사하지 않는다(정본 미지정). `redacted_count`와 `redacted_kinds` 합의 일치도 검사하지 않는다 — 영수증은 어차피 신뢰하지 않으며, 서명 검증은 `receipt_hmac`(2주차).
- (W1-06) `host` 값은 재스캔 대상(모든 문자열)이지만 내부 호스트명 자체를 탐지하는 패턴은 없다(가명화는 SanitizationPolicy·Java 몫, (A) §2.2).

- (W1-07) **`audit_write_failure` 미구현(2주차) — 정직 표기**: 1주차는 '감사가 남는다'만 보장한다. 저장소 기록이 실패해도(디스크·DB 오류) logging의 handleError로 넘어가고 요청 처리는 계속된다 — '못 남기면 거부'는 미정의. 테스트가 이 현재 동작을 고정해 두었다(보장이 아님).
- (W1-07) 감사 저장소 자체의 무결성(변조 방지·보존 기간·회전)은 없다. 로컬 파일을 쓸 수 있는 프로세스는 기록을 바꿀 수 있다.
- (W1-07) egress 감사 훅은 Python `socket` 계층의 감사 이벤트만 본다 — C 확장·하위 프로세스의 네트워크는 관측 못 함(W1-02 한계와 같은 성격). 관측만 하고 차단하지 않는다.
- (W1-07) 정상 요청(①②③ 통과)은 감사하지 않는다(거부 경로만 기록). 수용 기록 필요 여부는 미정.

- (W1-08) **부재 검사는 목록 기반 정적 검사**다 — 목록 밖 라이브러리, `getattr`·런타임 조립 문자열 우회, 제3자 패키지 내부 동작(예: uvicorn·FastAPI가 쓰는 파일)은 잡지 못한다. 범위는 `src/sentinel`뿐(`tools/`·`tests/`는 개발 도구라 범위 밖). 원본 저장은 런타임 관측으로 한 겹 더 막지만, 관측도 Python 감사 이벤트(`open`·`sqlite3.connect`·`tempfile.*`)가 닿는 경로만 본다(C 확장의 직접 파일 I/O는 못 봄).
- (W1-09) **selfcheck는 `make test`(= `make verify`) 실행에서만 켜진다.** 맨 `pytest` 실행에는 없다(부분 실행이 늘 실패하지 않도록). Makefile 배선이 빠지면 동적 확인이 조용히 사라지므로 `test_make_test_runs_selfcheck_against_the_real_registry`가 레시피를 고정한다 — 단 이건 정적 확인이다.
- (W1-09) selfcheck는 pytest가 보고한 결과를 믿는다. 항상 통과하는 빈 테스트(`assert True`)를 검증 노드로 등록하는 것은 못 막는다 — 과대평가 경계(테스트 내용의 책임)이며, 리뷰가 잡아야 한다.
- (W1-09) 변이 유효성 장치를 스위트 안에서 자동 적용하는 것은 selfcheck뿐이다. W1-01~W1-08의 변이 확인은 PR 시점의 수동 스크립트였고 소급 자동화하지 않았다.
- (W1-09) `tests/test_secret_scan.py`의 pre-commit 테스트 2개는 `PYTHONUTF8` 없이 실행하면 실패한다(Windows 콘솔 기본 인코딩, main에서도 동일 — 이번 변경과 무관). `make verify`는 `PYTHONUTF8=1`을 설정하므로 게이트는 통과. 인과 없는 기존 도구라 고치지 않고 기록만(W1-03 리뷰 2ⓑ).
- (W1-08) 'train' 단독 이름은 금지하지 않았다(오탐 회피) — 파인튜닝 심볼은 `fine_tune`·`trainer`·`lora`·`sft`·`dpo`·`rlhf`·`peft`·`training_data/set/args` 등으로 한정.

### 심의 전 정의 필요 (W1-07 리뷰 이월)
- **감사 변조방지·보존·회전**: 감사 SQLite에 무결성 보호·보존 기간·회전 정의가 없다. 지금 manifest 키를 성급히 만들지 않고 사내 보안 심의 전 정의 필요 사항으로 남긴다((A) 수정 없음).

### 2주차+ 이월 (W1-07 리뷰)
- **수용 요청 감사**: 1주차는 거부 경로만 감사한다(LLM 없음). 분석이 생기면(2주차+) 수용된 요청도 감사 대상으로 확장(B-6).

### Java 연결 시 설계 숙제
- **본문 내부 민감값의 마스킹 표기**(W1-06에서 드러남, W1-06 리뷰 결정 (나)): MaskedRef는 Param·Header 값에만 정의돼 있고 본문(JSON·폼) 안의 마스킹 표기는 (A)에 없다. 1주차는 현행 유지 — 본문에 평문 민감 패턴(자격증명 필드·토큰 등)이 있으면 fail-closed 거부. 로그인처럼 본문에 자격증명이 들어가는 요청의 분석은 Java 연결 시 표기 정의 이후 가능. (A) v1.4 §2.2 Body 주석으로 등재.
- `java_logic_isolation`(not_implemented → Java 연결 시)·Extension의 `X-Sentinel-Token` 헤더 사용·Java 실제 마스킹 통합 테스트((A) §3.6 원칙 단서)도 같은 시점.

### 4번 주제(LLM 전략) 이월
- **사내 승인 LLM 엔드포인트의 분류**: 사내 승인 LLM은 루프백이 아니라 사내 네트워크의 다른 호스트일 수 있어, 현재 `egress_policy`에선 EXTERNAL로 차단된다. "사내 승인 엔드포인트를 어떻게 LOCAL/허용으로 분류하느냐"는 4번 주제에서 확정 — 그때까지 EXTERNAL 유지(W1-02 리뷰 판단).
- W1-02 egress 검사의 본질적 한계(하위 프로세스·C 확장·Proactor·금지목록 밖 패키지)는 (A) 수정 없이 progress-log 이월로 관리(W1-02 리뷰 판단). 운영 실제 차단은 `egress_enforcement_owner`=unverifiable이 커버.

### 해소 (미해결·관찰에서 이동)
- **검증 테스트 실재 확인이 정적뿐(W1-00 이월)** → 해소(W1-09): 게이트 실행에서 enforced 검증 노드의 실제 수집·통과를 동적으로 확인. `manifest_selfcheck`·`manifest_honesty` enforced.
- **N3 색인 공백(거짓 색인)** → 해소: N3가 §3의 '없는 행'을 가리키던 공백을 (A) v1.3 §3.2 `java_logic_isolation` 행으로 메움. CLAUDE.md N3 → `(A) §3.2 java_logic_isolation`. (해소된 것은 '정본 공백'이며, 강제 자체는 not_implemented → Java 연결 시.)
- **N7 색인 누락** → 해소: CLAUDE.md N7 → `(A) §1.3 ⓕ + §3.3 secret_scan_hook` (ⓕ=원본 트래픽, secret_scan_hook=비밀값 커밋).

### 추적됨 (미해결이었으나 현황판에 등재 — 해소 아님)
- **뷰 동기화 ②(CLAUDE.md 금지선 색인 ↔ (A) §1.3/§3) 기계 검사** → 추적됨: `claude_md_sync_check`=not_implemented→2주차. 현재는 PR 체크리스트 수동 확인. CLAUDE.md §4의 "전부 기계 강제" 표현을 사실대로 교정함(①·③=`make verify` 기계 강제, ②=수동).

### (A) 정본 변경 여부
- **변경 있음(W1-00 리뷰 교정, PR #3):** §3.1에 `claude_md_sync_check` 행 추가(not_implemented → 2주차) / §3.3 `secret_scan_hook` 상태 칸 범위 명시(값 enforced 유지). 사유: 문서가 사실과 다른 보장을 하던 지점 교정. 뷰 동기화: `guardrails.yaml` 재파생·manifest 재생성·CLAUDE.md §4 교정 — 같은 PR. claude.ai 발행본 재발행: 보류.
- **변경 있음(문서 교정, Issue #6):** 버전 v1.2 → **v1.3**(제목·버전 줄·§3 매핑표 제목, 버전 이력 추가) / §3.2에 `java_logic_isolation` 행 추가(not_implemented → Java 연결 시). 뷰 동기화: `guardrails.yaml` 재파생·manifest 재생성·CLAUDE.md N3·N7 색인·(B) 제목 기준 버전 — 같은 PR. claude.ai 발행본 재발행: merge 후 설계자에게 전문 전달(재발행은 설계자 몫).
- **변경 있음(W1-06, Issue #16):** 버전 v1.3 → **v1.4**(제목·버전 줄·이력·개정일) / §2.3 `redacted_kinds`를 `{token:int, cookie:int, pii:int, host:int}`(종류별 개수 맵)로 명확화 + §2.2 Body에 '본문 내부 마스킹 표기는 Java 연결 시 정의' 주석(리뷰 결정 1). §3 매핑표 변경 없음(매핑표 v1.3 유지 → `guardrails.yaml` 재파생 차이 없음). CLAUDE.md 영향 없음. (B) 제목 기준 버전 v1.4. claude.ai 발행본 재발행: merge 후 설계자에게 전문 전달.

- **W1-09 (Issue #22):** 변경 없음. §3 매핑표 그대로 — `manifest_selfcheck`·`manifest_honesty`는 (A)가 enforced를 목표로 둔 키의 실제 승격. 전문 전달 불필요.

### 다음 주차 이월
- 1주차 작업 W1-00~W1-09 전부 PR 완료(W1-09는 리뷰 대기). 1주차 전체 결산은 W1-09 merge 후 설계자 요청 시.
- 2주차 대상 not_implemented 키와 위 '심의 전 정의 필요'·'2주차+ 이월'·'Java 연결 시'·'4번 주제' 항목.

---

## Week 1 결산 — 2026-10-22 ~ 2026-10-23 (α, Issue #24)

> 위 "Week 1 — 2026-10-22 ~ 2026-10-23" 섹션은 누적 규칙대로 고치지 않았다. 그 섹션의 W1-09 행("(이 PR) | open")과 '다음 주차 이월'의 "W1-09는 리뷰 대기"는 작성 시점 기록이며, 현재 상태는 이 결산이 맞다.

### 완료한 작업 (Issue / PR) — W1-09 확정
| 작업 | Issue | PR | 상태 |
|---|---|---|---|
| W1-09 | #22 (closed) | #23 | merged (2026-10-23) |

- 1주차 작업 W1-00 ~ W1-09 전부 merged. 1주차 merge 내역은 위 섹션 표 + 이 행.

### manifest 최종 상태 (`guardrails.yaml` / `manifest/capability_manifest.json`에서 읽음, 둘 일치)
- 전체 39키 — **enforced 21 / not_implemented 15 / unverifiable 2 / derived 1**.
- enforced(21): `audit_log_present`, `auth_precedence_noinvoke`, `authfail_log_hygiene`, `egress_runtime_block`(테스트환경 한정), `egress_static_check`, `engine_burp_isolation`, `envelope_arity`, `input_schema_gate`, `local_llm_vs_egress`, `loopback_binding`, `manifest_derivation`, `manifest_honesty`, `manifest_selfcheck`, `maskedref_typing`, `no_autonomous_send`, `no_autopatch_apply`, `no_finetune_path`, `no_raw_persistence`, `request_token_validation`, `sanitization_trust`, `secret_scan_hook`.
- not_implemented(15): `anomaly_aggregation`, `assertive_token_guard`, `audit_write_failure`, `category_closed_enum`, `claude_md_sync_check`, `corroboration_check`, `eval_harness`, `evidence_min_one`, `evidence_ref_integrity`, `hallucinated_literal_isolation`, `java_logic_isolation`, `no_multiagent_rag`, `receipt_hmac`, `server_assigned_status`, `token_hardening`.
- unverifiable(2): `branch_protection`, `egress_enforcement_owner`.
- derived(1): `output_schema_gate`.
- 1주차 판정 근거: `make verify` 종료코드 0 + selfcheck 활성 표지(`module=…tools\guardrails\selfcheck.py keys=21`) + "enforced 검증 노드 전부 수집·통과" — (B) §4 정직성 조건. 상태별 키 수는 성과 지표가 아니라 현황이다.

### 해소 (미해결·관찰에서 이동 — 근거 확인 후)
> 원래 항목은 위 섹션에 그대로 남는다(누적 규칙). 여기서는 해소 사실과 근거만 적는다.
- **(W1-03) 분석 엔드포인트 무인증 501** → 해소(W1-04 토큰 게이트). 근거: 최외곽 ASGI 래퍼 `src/sentinel/server/auth.py` `TokenGate` / `tests/test_auth.py::test_forged_or_missing_token_is_rejected_before_downstream_and_body`, `tests/test_auth.py::test_real_app_never_invokes_inner_app_parser_or_deserializer_on_auth_failure`. 501 응답은 `src/sentinel`에서 사라짐 — 토큰 통과 후 `tests/test_execution.py::test_valid_request_gets_not_implemented_execution_response_not_empty_findings`.
- **(W1-04) 감사가 Python logging으로만 나감** → 해소(W1-07 SQLite 감사). 근거: `src/sentinel/audit.py` `SQLiteAuditHandler` / `tests/test_audit.py::test_auth_failure_is_persisted`, `tests/test_audit.py::test_persisted_audit_contains_no_sensitive_values`. ('기록 실패 시 fail-closed'는 해소 아님 — `audit_write_failure` not_implemented→2주차 그대로.)
- **(W1-04) 스키마 함수를 스파이 대상에 추가 필요** → 해소(W1-05 자동 열거). 근거: `sentinel.pipeline` 패키지 전 함수 자동 열거 / `tests/test_auth.py::test_pipeline_spies_cover_every_stage_function_and_detect_calls_as_control`. (남는 가정 '패키지 밖 단계 함수는 안 잡힘'은 위 섹션 W1-05 기록 그대로.)
- **(W1-05) 요청 본문 크기 상한 없음** → 해소(W1-06 상한). 근거: 원시 요청 1 MiB `src/sentinel/server/app.py` `MAX_REQUEST_BYTES`(413) / `tests/test_sanitization.py::test_oversized_http_request_is_rejected_before_parsing`; 내용 상한 req 64KB·resp 256KB `src/sentinel/pipeline/sanitization_check.py` `REQ_BODY_CAP`·`RESP_BODY_CAP` / `tests/test_sanitization.py::test_body_over_cap_is_rejected_and_at_cap_passes`, `tests/test_sanitization.py::test_base64_body_cap_counts_decoded_bytes`.
- **(W1-05) redacted_kinds 형태 정본 확인 필요** → 해소((A) v1.4 개수 맵). 근거: (A) §2.3 `redacted_kinds: {token:int, cookie:int, pii:int, host:int}` / `src/sentinel/schema.py` `RedactedKinds` / `tests/test_schema.py::test_rejects_schema_violation`(케이스 `redacted_kinds_as_list`·`unknown_redacted_kind`·`redacted_kind_missing`·`redacted_kind_negative`·`redacted_kind_as_string`).
- 근거를 찾지 못해 이동하지 않은 항목: 없음.

### 미해결
- 위 5건 외의 미해결·이월(위 섹션의 '미해결'·'심의 전 정의 필요'·'2주차+ 이월'·'Java 연결 시 설계 숙제'·'4번 주제 이월')은 변경 없이 유지.
- `tests/test_auth.py::test_live_server_requires_token` — Windows에서 WinError 10053으로 1회 실패. 단독 5회 반복은 모두 통과, `make verify` 재실행 종료코드 0. 원인 미조사. 재발 시 별도 Issue. 재실행으로 통과시킨 경우 리뷰 팩 7번에 반드시 기록한다.

### (A) 정본 변경 여부
- 변경 없음(α는 docs 정리). (B) 본문 매핑표 버전 숫자 제거 — 버전 표기는 (B) 제목 "〔(A) vX 기준〕" 한 곳만. 리뷰 팩 규율 `docs/review-pack-rule.md` 신설, CLAUDE.md §3에 포인터 한 줄.

---

## 설계 트랙: 5번 평가 (진행 중)

> **성격: 큐(미확정)만 이 기록이 들고 있다. (A)에 반영된 항목은 원문을 남기되 정본은 (A)다(ε, v1.7). 이 기록은 정본이 아니다.**
> (작성 당시 성격: "확정 — (A) 미반영. 5번 결론 개정 때 (A)로 옮긴다.")

### (A) 반영됨 — ε, (A) v1.7 (원문 보존 + 절 포인터)
1. **→ (A) §2.2 Body `masked_spans` / §2.6 MaskedSpan** — Body에 masked_spans: [{pointer, ref: MaskedRef}] 가산(사이드카 방식).
   첫 평가 픽스처가 동결되기 전에 (A)에 반영한다.
2. **→ (A) §2.6 FILLER / §2.2 설계 의도(FILLER ↔ 사이드카 비대칭)** — 채움값은 kind 없는 단일 고정 토큰이고, kind·라벨은 masked_spans.ref에만 둔다.
   이 비대칭은 의도된 것이다(본문은 신뢰할 수 없으므로 정보 최소화, 권위는 사이드카).
3. **→ (A) §2.2 오프셋 / §2.6 Range** — 오프셋은 저장된 content 기준, 유니코드 코드포인트 단위. 마스커는 정규화하지 않는다.
   UTF-16 변환은 Java 쪽 책임이다.
4. **→ (A) §2.6 BodyPointer·Locator·Range** (JSONPath 대신 RFC 6901 JSON Pointer로 확정 — 이유는 §2.6) — pointer 문법은 "JSONPath + 문자열 안 범위" 형태이고, Evidence.pointer와 공유한다
   (문안은 아직 미작성).
5. **→ (A) §2.2 Body 불변식 1 / base64** — masked_spans가 비어 있지 않으면 encoding == utf8이어야 한다.
   base64 본문에서 비밀값이 발견되면 omitted로 처리한다.
6. **→ (A) §2.3 라벨 규칙** (라벨 형식 `ref_NN` — §2.6 MaskedRef) — 라벨은 양방향 동치(같은 원본값 ⇔ 같은 라벨)이고, 순번으로 할당한다(HMAC은 매핑 테이블 키로만).
   동치 기준은 원본값이며 kind와 무관하다. 라벨은 배치 안에서만 유효하다.
   (A) §2.3의 "HMAC → 짧은 라벨" 문구를 이 뜻으로 교정한다.
7. **→ (A) §2.3 라벨 규칙 + §3.3 `label_consistency`** — 6번은 생산자 쪽에서만 강제할 수 있다(Python ③은 원본을 모름).
   manifest 키 1개를 신설하되 Python 런타임 보장으로 표기하지 않는다.
8. **→ (A) §1.3 ⓕ 해석 주석** — ⓕ 해석: "사람이 Burp에서 내보낸 원본 파일은 Burp 프로젝트 파일과 같은 시스템 밖 자산이고,
   시스템(엔진·tools)은 이를 영속화하지 않는다."
9. **→ (A) §3.2 `engine_tools_isolation`(β) · §2.3 + §3.2 `masker_independence` · §3.1 `masker_no_send`(β) · §2.3 정책 데이터 파일** — fixture 마스커 불변식 4개:
   - tools/에 둔다. 엔진은 tools/를 import하지 않는다.
   - 엔진의 sanitization_check를 재사용하지 않는다.
   - N1·N2 검사 범위에 포함한다.
   - 정책은 데이터 파일로 두고 공유한다.

ε에서 함께 (A)에 반영: pointer 문법(§2.6 Locator·BodyPointer·Range), Body 불변식(§2.2), FILLER·라벨 접두사 ref(§2.6·§2.3), 버전 규칙 통합(§2 머리), 공용 소절 §2.6 + MaskedRef 이동

### 큐 (미확정)
10. (큐만, 미확정) truncation 경계 표기, 그리고 오프셋을 저장 content와 원본 중 어느 쪽 기준으로 할지.
11. (큐만, 미확정) 헤더 값·경로의 부분 마스킹 표기 — (A) §2.2가 이 큐를 가리킨다. 현재는 fail-closed.
12. 첫 소비자 경계 강제 장치 — 동결 픽스처가 현재 스키마로 검증되지 않으면 버전 증가 없이는 실패하는 테스트. 평가 데이터셋을 처음 동결할 때 키 신설.

남은 5번 결정점: TP 판정 단위 / 데이터셋 구성 / 지표 정의 / severity_if_true의 등급 값 목록 자체(미정의 — 기본값 표·보정 규칙보다 먼저 정해야 함), category 기본값 표와 신호 보정 규칙(β에서 추가 — (A) v1.5 §2.4는 셋 다 미정의로 둠).

---

## β — (A) v1.5 개정 (Issue #28)

### (A) 정본 변경 여부
- **변경 있음:** 문서 v1.4 → **v1.5**, §3 매핑표 v1.3 → **v1.4**(문서 버전과 매핑표 버전은 별개 — (A) 이력에 명시). 개정일 2026-10-26.
  - §2 머리: 데이터 계약 버전 규칙(가산 변경은 소비자 유무로 판단, 비가산은 항상 증가).
  - §2.2 Body: 본문 내부 마스킹 표기 정의처 "Java 연결 시" → "5번 설계(tools/ fixture 마스커가 참조 구현)". 현재 동작(평문 민감 패턴 fail-closed 거부) 유지.
  - §2.4: analyzed_refs·severity_if_true 서버 부여(severity 기본값 표·보정 규칙 미정의 → null), corroboration `not_run` 추가, review_required 서버 기본 true, 출력 검증 실패 시 전체 폐기 + `output_rejected`. 출력 스키마 최초 동결본에 `not_run` 포함 — 소비자 0이라 `schema_version` 유지.
  - §2.5: `analysis_status` 닫힌 enum `not_implemented | completed | output_rejected`.
  - §3: 머리·`manifest_derivation` 규칙 칸의 "CI가 검증" → "make verify(로컬 게이트)" (서버측 CI 없음).
  - §3.0·§3.1·§3.3: 이월처 재조정 — `token_hardening`·`receipt_hmac` → Java 연결 시 / `audit_write_failure`(및 §3.0 감사 기록 실패 fail-closed) → 수용 요청 감사(B-6) 범위 확정 시.
  - 신규 키(not_implemented → fixture 마스커 구현 시): `masker_no_send`(§3.1), `engine_tools_isolation`(§3.2).
  - §3.5 각주: 2주차 enforced 범위 = 검증 함수 단위(주입 테스트), 유일 통로 결선은 LLM 연동 PR에서 별도 증명.
- 뷰 동기화(같은 PR): `guardrails.yaml` 재파생(41키) + manifest 재생성 / CLAUDE.md N1·N2(+§3.1 `masker_no_send`)·N4(+§3.2 `engine_tools_isolation`) / (B) 제목 기준 버전·§5 이월 3키 분리·§3 W1-07 주의 줄.
- **CLAUDE.md 색인 동기화: β까지 수동 확인, δ(`claude_md_sync_check`)부터 기계 검사.**
- 이월 3키의 "2주차" 문구 전수 정렬: (A)·(B)·src 주석/docstring·tests docstring/주석·`tests/test_guardrails.py::test_spec_parser_rejects_unparseable_status`의 치환 문자열. 이 progress-log의 과거 섹션은 누적 규칙대로 그대로 둔다(과거 섹션의 "2주차" 표기는 작성 시점 기록).
- claude.ai 발행본 재발행: merge 후 설계자에게 (A) 전문 전달.

### manifest 상태 변화
- enforced 집합 변화 없음(21키 그대로). 신규 2키는 not_implemented. 전체 39 → 41키(enforced 21 / not_implemented 17 / unverifiable 2 / derived 1).

### 미해결
- `src/sentinel/schema.py` `ExecutionResponse.analysis_status`는 `Literal["not_implemented"]` 그대로 — (A) §2.5의 3값 enum보다 좁다. 타입은 실제로 반환할 수 있는 값만 허용하므로 **LLM 결선 시** 넓힌다.
- `tests/test_guardrails.py::test_spec_parser_rejects_unparseable_status`는 (A) 표의 특정 행 문구에 고정돼 있어 개정할 때마다 깨질 수 있다. 행을 동적으로 고르는 방식으로 바꾸는 것을 검토. 지금은 고치지 않는다.

---

## γ — 출력 스키마 게이트 (Issue #30)

### manifest 상태 변화 (실제 통과 테스트로 증명된 승격만)
| manifest 키 | 이전 | 이후 | 증명한 테스트 노드 |
|---|---|---|---|
| `evidence_min_one` | not_implemented(→2주차) | enforced(검증 함수 단위) | `tests/test_output_gate.py::test_rejects_finding_without_evidence` 외 — 목록은 `guardrails.yaml` |
| `evidence_ref_integrity` | not_implemented(→2주차) | enforced(검증 함수 단위) | `tests/test_output_gate.py::test_rejects_transaction_ref_outside_analyzed_refs` 외 |
| `server_assigned_status` | not_implemented(→2주차) | enforced(검증 함수 단위) | `tests/test_output_gate.py::test_rejects_each_server_assigned_field_injected` 외 |
| `category_closed_enum` | not_implemented(→2주차) | enforced(검증 함수 단위) | `tests/test_output_gate.py::test_rejects_category_outside_closed_four` 외 |
| `output_schema_gate` | derived(effective not_implemented) | derived(effective **enforced** — 하위 4키 AND, 손으로 쓰지 않음) | 자체 테스트 없음 |
| `assertive_token_guard`·`corroboration_check` | not_implemented(→2주차) | not_implemented(→5번 평가 데이터로 기준 확정 시) | — |

> **범위 = 검증 함수 단위((A) §3.5 각주)**: `sentinel.pipeline.output_gate.validate_draft`에 초안을 직접 주입해 증명했다. 파이프라인 ④ 결선(이 함수가 LLM 출력의 유일 통로임)은 증명하지 않았다 — LLM 연동 PR 몫. 서버는 여전히 `analysis_status="not_implemented"`만 반환한다.
> **타입 두 벌**: 초안 타입(`sentinel.output_schema.*Draft`, LLM이 채우는 필드만 + 추가 필드 금지) / 저장용 타입(서버만 구성). 저장용 타입은 지금 부여할 수 있는 값만 허용(severity_if_true = null만, anomaly_flags = 빈 목록만) — 2차 방어선이기도 해서 초안 검사 ②③을 변이로 끄면 결과는 여전히 거부되지만 사유 코드가 `result_build_failed`로 바뀌어 해당 적대 테스트가 실패한다.
> **변이 확인(스위트 안, `tools/mutation_guard.py`)**: 초안 추가 필드 허용 / 초안 category Literal 해제 / evidence 최소 개수 해제 / 참조 검사 해제 / 부분 수용(위반 항목만 빼고 반환) — 각각 변이본 로드를 활성 표지로 먼저 확인한 뒤 대응 적대 테스트 실패를 확인. '부분 수용 금지'는 ①~③에서는 구조적(Pydantic이 문서 전체를 한 번에 검증 — 항목 단위로 받는 경로가 없음)이라 변이 대상은 항목 단위인 ④.

### 깨진 가정 · 발견된 문제
- 변이 대조 테스트 초안이 '원본에 가려짐'을 재현하려고 변이본 경로를 뺐더니 `sentinel` 자체를 못 찾아 표지 부재로 통과할 뻔했다(거짓 통과) → 원본 src를 명시적으로 적재하고 표지 존재·원본 통과를 먼저 단언한 뒤 '다른 사본'으로 잡히는지 확인.
- (A) §3.5 `output_schema_gate` 상태 칸을 `derived †`로 바꾸면 파서(`tools/guardrails/spec.py` `_STATE_DERIVED_RE`)가 거부한다(목표 없는 derived 미지원). 파서를 고치지 않고 칸을 기존 `derived (→2주차) †`로 두었다 — 결정 대기(γ PR 리뷰).

### 미해결
- **pointer 형식 미검증**: `Evidence.pointer`는 str만 검사(문법은 5번 개정 대기).
- **AdvisorySignal.basis 최소 개수 미적용**: evidence ≥ 1은 Finding에만. `test_advisory_basis_may_be_empty_documented_limitation`이 현재 동작을 고정((A) 미정).
- **pipeline_mode**: 열린 str. 값 목록 미정의 → 4번(LLM 전략)에서 닫음. 서버가 넣는 값이라 LLM 경로가 아님.
- **analysis_meta 필드 타입**(str·0 이상 정수·`token_usage: dict[str, 0 이상 정수] | None`)은 (A) 미지정 → 구현 재량.
- **ExecutionResponse `Literal["not_implemented"]`** 유지 — LLM 결선 시 넓힘.
- **(A) §3 열 머리 "1주차 상태"가 낡음** — 파서(`TABLE_HEADER`)가 열 머리 문구에 의존하므로 의존 확인 후 정리(이월).
- `output_schema_gate`의 (A) 상태 칸 `(→2주차)` 표기 — 위 '깨진 가정' 참조, 결정 대기.

### (A) 정본 변경 여부
- **변경 있음:** 문서 v1.5 → **v1.6**, 매핑표 v1.4 → **v1.5**. §3.5 4키 enforced(검증 함수 단위) / `assertive_token_guard`·`corroboration_check` 목표 재조정 / §3.5 제목 "C·E (출력·검증)" / † 각주. 뷰 동기화: `guardrails.yaml` 재파생·manifest 재생성·(B) 제목 기준 버전. CLAUDE.md 영향 없음. claude.ai 발행본 재발행: merge 후 설계자에게 (A) 전달.

---

## γ 리뷰 반영 (PR #31, merge 전 추가 커밋) — 기록

> 위 γ 섹션의 '결정 대기' 두 곳은 작성 시점 기록이다(누적 규칙). 현재 상태는 아래가 맞다.
- `output_schema_gate` 상태 칸 → `derived †`(목표 없는 derived). `tools/guardrails/spec.py`가 목표 없는 `derived`만 명시적으로 수용(not_implemented는 여전히 목표 필수), manifest target 없음. 적대 테스트: `tests/test_guardrails.py::test_spec_parser_still_requires_target_for_not_implemented`, `::test_targetless_derived_without_child_list_is_rejected`, `::test_targetless_derived_is_accepted_with_no_target`.
- 파생 규칙 위조 거부: `tests/test_guardrails.py::test_real_output_schema_gate_is_not_enforced_when_any_child_is_forged_down`(실제 레지스트리, 하위 4키 × not_implemented·disabled·unverifiable). 파생기를 OR로 바꾼 변이본(로드 확인)에서 이 테스트 12개 인스턴스와 기존 `test_derived_rollup_is_enforced_only_when_every_child_is_enforced`가 실패함을 확인(수동 1회, 스위트 자동화 아님). 위 4노드는 `manifest_derivation` 검증 노드로 등록.
- `analyzed_refs` 사전조건: 비었거나 중복이면 초안 파싱 전 ValueError(값 미반사) — '아무것도 분석하지 않았는데 깨끗함' 결과 차단((A) §2.5). `tests/test_output_gate.py::test_empty_or_duplicate_analyzed_refs_is_a_server_arg_error_before_draft_parsing`, `::test_nothing_analyzed_cannot_become_a_clean_result`.

---

## ε — (A) v1.7 개정 (Issue #32)

### (A) 정본 변경 여부
- **변경 있음:** 문서 v1.6 → **v1.7**, 매핑표 v1.5 → **v1.6**. §2 머리 버전 규칙 통합(소비자 우선 2단 분기) / §2.6 공용 타입 신설(MaskedRef 이동·FILLER·Range·BodyPointer·Locator·MaskedSpan) / §2.2 Body `masked_spans`·불변식 1~6·2'·오프셋·base64·마스킹→절단 순서 / §2.3 라벨 규칙(`ref_NN`, 순번, HMAC은 매핑 키) / §2.4 Evidence.pointer = Locator(locus 필드 제거)·중복 키·무결성 문구 / §1.3 ⓕ 해석 주석 / §3 신규 3키.
- `schema_version` 값 변화 없음(Envelope·AnalysisResult 모두 "1.0") — 비가산 변경이 있으나 소비자 0(통합 규칙 첫 적용, 이력 기록).
- 뷰 동기화: `guardrails.yaml` 재파생(44키) + manifest 재생성 / (B) 제목 기준 버전 v1.7 / CLAUDE.md 변경 없음.
- claude.ai 발행본 재발행: merge 후 설계자에게 (A) 전달.

### manifest 상태 변화
- enforced 집합 변화 없음(25키). 신규 not_implemented: `masked_span_integrity`(→ 본문 마스킹 표기 구현 시), `label_consistency`·`masker_independence`(→ fixture 마스커 구현 시).

### 미해결 — 코드가 (A)보다 낡은 지점(의도됨, 이월처 ζ)
- `src/sentinel/output_schema.py` `EvidenceDraft`·`Evidence`: `locus` 필드 + `pointer: str` → (A)는 locus 제거·`pointer: Locator`.
- `src/sentinel/schema.py` `MaskLabel` 정규식(`^[a-z][a-z0-9]{0,23}_[0-9]{2,4}$`) → (A)는 `ref_` + 숫자 2~4자리.
- `src/sentinel/schema.py` `Body`: `masked_spans` 필드·Body 불변식(1~6, 2' 중 `truncated == false`) 없음. FILLER 정의 없음.
- `principal_01` 잔존(src·tests): `src/sentinel/schema.py:8`, `:20`, `tests/test_sanitization.py:173`, `tests/test_schema.py:184`.
- 중복 처리 키 `(transaction_ref, pointer.locus, …)` — 중복 병합 자체가 미구현.
