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
| W1-00 | #2 | #3 | merged |
| W1-01 | #4 | #5 | merged |
| 문서 교정 (A) v1.3 | #6 | #7 | merged |
| W1-02 | #8 | #9 | merged |
| W1-03 | #10 | #11 | merged |
| W1-04 | #12 | (이 PR) | open |

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
- 시크릿 스캐너 `secret_assignment` 패턴은 오탐 가능(예: 비밀 아닌 8자+ 문자열을 `*_password = "..."`에 대입). 허용목록(우회 구멍)은 두지 않고 fail-closed 쪽을 택함.

### 미해결 (명시적으로 남김 — 숨기지 않음)
- **`secret_scan_hook`은 클라이언트 훅이다.** `git commit --no-verify`로 우회 가능. `make verify`가 추적 파일을 전수 재스캔하지만, 서버측 CI(GitHub Actions 등)는 없다 — (A) 목표층위 'CI게이트'의 서버측 강제는 미구현. 훅 실행엔 PATH의 `python` 필요.
- W1-00의 검증 테스트 실재 확인은 **정적**(파일·함수 존재)뿐. 수집·통과 확인은 W1-09(`manifest_selfcheck`·`manifest_honesty`, 계속 not_implemented).
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

### 4번 주제(LLM 전략) 이월
- **사내 승인 LLM 엔드포인트의 분류**: 사내 승인 LLM은 루프백이 아니라 사내 네트워크의 다른 호스트일 수 있어, 현재 `egress_policy`에선 EXTERNAL로 차단된다. "사내 승인 엔드포인트를 어떻게 LOCAL/허용으로 분류하느냐"는 4번 주제에서 확정 — 그때까지 EXTERNAL 유지(W1-02 리뷰 판단).
- W1-02 egress 검사의 본질적 한계(하위 프로세스·C 확장·Proactor·금지목록 밖 패키지)는 (A) 수정 없이 progress-log 이월로 관리(W1-02 리뷰 판단). 운영 실제 차단은 `egress_enforcement_owner`=unverifiable이 커버.

### 해소 (미해결·관찰에서 이동)
- **N3 색인 공백(거짓 색인)** → 해소: N3가 §3의 '없는 행'을 가리키던 공백을 (A) v1.3 §3.2 `java_logic_isolation` 행으로 메움. CLAUDE.md N3 → `(A) §3.2 java_logic_isolation`. (해소된 것은 '정본 공백'이며, 강제 자체는 not_implemented → Java 연결 시.)
- **N7 색인 누락** → 해소: CLAUDE.md N7 → `(A) §1.3 ⓕ + §3.3 secret_scan_hook` (ⓕ=원본 트래픽, secret_scan_hook=비밀값 커밋).

### 추적됨 (미해결이었으나 현황판에 등재 — 해소 아님)
- **뷰 동기화 ②(CLAUDE.md 금지선 색인 ↔ (A) §1.3/§3) 기계 검사** → 추적됨: `claude_md_sync_check`=not_implemented→2주차. 현재는 PR 체크리스트 수동 확인. CLAUDE.md §4의 "전부 기계 강제" 표현을 사실대로 교정함(①·③=`make verify` 기계 강제, ②=수동).

### (A) 정본 변경 여부
- **변경 있음(W1-00 리뷰 교정, PR #3):** §3.1에 `claude_md_sync_check` 행 추가(not_implemented → 2주차) / §3.3 `secret_scan_hook` 상태 칸 범위 명시(값 enforced 유지). 사유: 문서가 사실과 다른 보장을 하던 지점 교정. 뷰 동기화: `guardrails.yaml` 재파생·manifest 재생성·CLAUDE.md §4 교정 — 같은 PR. claude.ai 발행본 재발행: 보류.
- **변경 있음(문서 교정, Issue #6):** 버전 v1.2 → **v1.3**(제목·버전 줄·§3 매핑표 제목, 버전 이력 추가) / §3.2에 `java_logic_isolation` 행 추가(not_implemented → Java 연결 시). 뷰 동기화: `guardrails.yaml` 재파생·manifest 재생성·CLAUDE.md N3·N7 색인·(B) 제목 기준 버전 — 같은 PR. claude.ai 발행본 재발행: merge 후 설계자에게 전문 전달(재발행은 설계자 몫).

### 다음 주차 이월
- W1-01~W1-09 (진행 예정)