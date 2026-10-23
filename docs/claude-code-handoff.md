# Sentinel Harness — Claude Code 인계문서 (B) · 1주차  〔(A) v1.3 기준〕

> **이 문서의 성격**: 건조한 실행 지시서. '왜'는 담지 않는다 — 근거·트레이드오프·기각대안은 전부 **(A) 설계확정서(레포 `docs/design-decision.md`, 정본)**에 있다.
> **정본 관계**: 규칙 '값'의 정본은 (A)의 FROZEN 블록(§1 범위 / §2 데이터계약 / §3 가드레일 매핑표 v1.2)이다. 이 문서는 그것을 **실행 순서로 추출**만 한다. 값이 (A)와 (B)에서 다르면 **(A)가 맞다.**
> **대상**: VSCode의 **Claude Code**. 이 문서를 읽고 **직접 코드·테스트를 작성하고 실행**하는 주체는 Claude Code다.
> **범위**: 1주차 수직 단면 하나. LLM·규칙엔진·평가 하네스 **없음**. "안전 경계만 있는 골격".

---

## 0. 절대 금지선 (어기면 작업 중단)

금지선 N1~N10은 **CLAUDE.md §1**(정본 색인: (A) §1.3 / §3)에 있다. 요청이 이 중 하나를 건드리면 **코드 전에 먼저 멈추고 위험을 설명**한다. 1주차에서 특히:

- **N1 egress 0 / N2 자율 전송 0** — 1주차엔 LLM 호출도, 어떤 외부 송신도 없다. 비활성 코드조차 0.
- **N3 Java에 로직 금지** — 1주차에 Java 뼈대를 두는 범위라면, 분석·판정·프롬프트·취약점 로직을 Java에 두지 않는다(capture / transport / ui만).
- **N4 엔진은 Burp를 모른다** — Python에 `burp`/`montoya` import 0.
- **N5 실데이터 금지** — 테스트는 OWASP Juice Shop + 더미. 토큰·쿠키·키의 '가짜' 더미만.
- **N6 main 직접 병합 금지** — Issue → feature 브랜치 → PR → merge.
- **N7 민감정보 커밋 금지** — 토큰값은 환경변수로만, 커밋·로그·예외에 노출 0.

---

## 1. 1주차 목표 (단 한 문장)

> **"아무것도 분석하지 못하지만, 금지선을 어길 수조차 없는" 골격을 만들고, 그 안전함을 '위조 거부' 테스트로 증명한다.**

1주차 서버가 하는 유일한 일: 입력 받음 → **① 토큰 검증 → ② 스키마 검증 → ③ Sanitization 독립 재검증** → 감사 로그 → **ExecutionResponse(`analysis_status="not_implemented"`)** 반환. ((A) §3.0 파이프라인 순서)

---

## 2. 작업 흐름 규율 (모든 작업에 예외 없이)

```
① Issue 생성(work-item 템플릿, 라벨 부착)
     ↓
② 기능 브랜치 생성(main에서 분기)
     ↓
③ 작업 + 테스트 작성·실행(적대적 테스트 포함)
     ↓
④ PR 생성(pull_request_template; "Closes #<번호>")
     ↓
⑤ make verify 통과 확인 → merge
```

- **한 Issue = 한 수직 작업 = 한 PR.** 아래 §3의 작업 항목 하나가 Issue 하나다.
- Issue 라벨: `week-1` + 건드리는 경계(`guard:A` / `guard:B` / `guard:D` / `guard:meta` / `guard:common`).
- PR 템플릿이 강제하는 것: 적대적 테스트 포함 · `make verify` 통과 · manifest 자기검증 · **뷰 동기화 3종** · N1~N10 금지선.
- **merge 전 `make verify` 통과 필수.** 실패 시 merge 금지.

---

## 3. 1주차 작업 항목 (의존 순서대로 — 각 항목이 Issue 하나)

> **완료 기준은 '테스트가 통과한다'로만 쓴다**(구현했다 아님). 수치·테스트 개수는 결과지 목표가 아니다 — **기대 숫자를 박지 않는다.** 안전 불변식은 **위조 거부**로 증명한다.

### W1-00. 레포 뼈대 + verify 하네스 + guardrails.yaml 발주 (선행)
- **무엇을**:
  - Python 3.11+ 구조, 테스트 러너(pytest), `make verify` 진입점. `.gitignore`(비밀값·캡처물·생성물). pre-commit 시크릿 스캐너.
  - **`guardrails.yaml` 생성** — 손으로 주지 않는다. **(A) §3 매핑표 v1.2(§3.1~§3.5)에서 파생**하라. 아래 **필드 스키마를 반드시 포함**하고, 임의 구조를 만들지 않는다:
    ```
    규칙 1개 =
      · 가드레일 ID        (규칙 식별자; manifest 키와 동일 식별자 사용)
      · 설명               (규칙이 무엇을 강제하는가)
      · 목표층위           (타입 / 스키마·validator / 테스트 / CI게이트 / 아키텍처테스트 / 파생 / 외부)
      · 1주차 상태         (enforced | not_implemented(→N주차) | disabled | unverifiable)
      · 검증 테스트 식별자  (status=enforced면 1개 이상 필수; 그 외는 비움)
      · manifest 키        (= 가드레일 ID)
    ```
  - **manifest 파생기** — `guardrails.yaml`(SSOT) → manifest 생성물. 생성 시 구조 정합을 **fail-closed**로 검증(enforced인데 검증 테스트 없음 → 생성 거부).
- **완료 기준(테스트 성질)**:
  - `make verify`가 실행된다(진입점 존재).
  - pre-commit이 가짜 토큰 커밋 시도를 **차단**한다.
  - `guardrails.yaml`이 위 6필드를 모두 갖는다. manifest가 거기서 파생되고, **생성물 ↔ 정본 재파생이 일치**한다.
- **manifest**: `secret_scan_hook`, `manifest_derivation`.  **의존**: 없음.

### W1-01. 아키텍처 경계 테스트
- **무엇을**: 정적 import 검사 — 분석 엔진이 (a) `burp`/`montoya`, (b) HTTP 송신·소켓 심볼을 import하지 않음.
- **완료 기준**: 금지 import를 심은 더미를 테스트가 **잡아낸다**(위조 거부). 실제 엔진은 통과.
- **manifest**: `engine_burp_isolation`, `no_autonomous_send`.  **의존**: W1-00.

### W1-02. egress 경계 테스트
- **무엇을**: (a) 외부 HTTP 송신 의존성 0 + 허용목록 빔(정적), (b) 테스트 환경에서 외부 호출 **실패** 실증, (c) 로컬 LLM 개념과 외부 egress 분리.
- **완료 기준**: 허용목록 빔 확인 / (테스트환경) 외부 호출 차단 확인 / 차단 실주체는 `unverifiable`로 정직 기록됨.
- **manifest**: `egress_static_check`, `egress_runtime_block`, `local_llm_vs_egress`, `egress_enforcement_owner(unverifiable)`.  **의존**: W1-00.

### W1-03. FastAPI 서버 기동 + 루프백 바인딩
- **무엇을**: 127.0.0.1에만 바인딩. 단일 분석 엔드포인트(내용 없음).
- **완료 기준**: 기동 테스트로 루프백 바인드 확인. 비루프백 시도를 테스트가 잡음.
- **manifest**: `loopback_binding`.  **의존**: W1-00.

### W1-04. 토큰 검증 — 파이프라인 최선두 (★핵심)
- **무엇을**: 요청 최선두에서 공유 시크릿 토큰 검증. **토큰 검증 코드와 본문 파싱 코드를 물리 분리.** 토큰은 환경변수 `SENTINEL_SHARED_TOKEN`에서만(하드코딩 금지). **미설정·빈값이면 서버 기동 거부(기동 시점 fail-closed, 인증 끈 fallback 없음).** 검증 실패 시 본문 touch 전 거부. 인증 실패만 감사, **본문·토큰값 미기록**. 비교는 상수시간. (서버 설정(env) ≠ 클라이언트 전달(header) 분리; Java 연결 시 Extension 토큰 전달은 별도 검토.)
- **완료 기준(적대적)**: 토큰 없음/위조 → 거부 + **파서·분석·저장 함수 미호출**(스파이로 증명). 미설정·빈값 → 기동 거부. 인증실패 감사에 본문·토큰값 **없음**.
- **manifest**: `request_token_validation`, `auth_precedence_noinvoke`, `authfail_log_hygiene`.  **의존**: W1-03.

### W1-05. Envelope 스키마 검증 (토큰 통과 후)
- **무엇을**: Pydantic `Envelope`. `analysis_type=="single" ⟹ len(transactions)==1` validator. MaskedRef 타입(생문자열 표현 불가).
- **완료 기준(적대적)**: 봉투 single+tx 2개 → 거부. 스키마 위반 → 거부+감사. MaskedRef 자리 생문자열 → 타입 레벨 거부.
- **manifest**: `input_schema_gate`, `envelope_arity`, `maskedref_typing`.  **의존**: W1-04.

### W1-06. Sanitization 독립 재검증 + fail-closed (★단일 실패점이었던 지점)
- **무엇을**: (A) §2.3 신뢰 경계 참조. Python이 수신 데이터에 토큰·쿠키·키 생문자열 잔존을 **독립 재스캔** → 발견 시 `applied` 값과 **무관하게** 거부. `applied==false ‖ failed==true ‖ 필드누락/타입오류` → 거부. 코드·문서에 "패턴 검사는 정책 정의 패턴만 탐지, 모든 비밀값 부재를 증명하지 않음" 명시.
- **완료 기준(적대적)**: `applied:true`+토큰 잔존 → 거부 / sanitization 필드만 거짓 → 거부 / `applied:false`·`failed:true` → 거부.
- **manifest**: `sanitization_trust`.  **의존**: W1-05.

### W1-07. 감사 로그 + ExecutionResponse 반환
- **무엇을**: egress 시도·재검증 거부·인증 실패가 감사에 남음(본문·토큰값 제외). 정상 요청은 `ExecutionResponse(analysis_status="not_implemented", skipped_reasons=[...], manifest_snapshot)`.
- **완료 기준**: 각 거부 경로가 감사에 흔적(민감값 없이). 정상 입력도 **빈 findings가 아니라** `analysis_status="not_implemented"`. ("분석 안 함 ≠ 분석 후 깨끗함")
- **manifest**: `audit_log_present`.  **의존**: W1-06.
- **주의**: "감사 기록 **실패** 시 fail-closed"(`audit_write_failure`)는 **2주차**. 1주차는 "남는다"만 보장하고, "못 남기면 거부"는 **미정의**임을 정직 표기.

### W1-08. 영구 제외 '부재 증명' 테스트
- **무엇을**: 아키텍처 테스트로 (a) AI 수정코드 자동반영 경로 부재(ⓓ), (b) 파인튜닝 경로 부재(ⓔ), (c) 원본 트래픽 저장 기능 부재(파일·임시파일·예외/디버그 로그 포함) 증명.
- **완료 기준**: 해당 심볼/경로 없음 확인. 원본 저장 더미를 심으면 테스트가 잡음.
- **manifest**: `no_autopatch_apply`, `no_finetune_path`, `no_raw_persistence`.  **의존**: W1-00.

### W1-09. manifest 자기검증 메타 테스트 (★자기검증 고리 완성 — 마지막)
- **무엇을**: 메타 테스트 — manifest의 `enforced` 항목이 실제 강제 테스트를 가리키고 그게 **수집·통과**함을 확인. `not_implemented`를 `enforced`로 주장하면 빌드 실패. **과대평가 금지**: 등록·수집·통과만 확인(테스트 내용의 실질 검증은 그 테스트의 책임).
- **완료 기준(적대적)**: 거짓 `enforced` 선언(검증 테스트 없음/미수집), `not_implemented`의 enforced 참칭, 중복 ID, 미지 status → 전부 **거부**로 잡힘.
- **manifest**: `manifest_selfcheck`, `manifest_honesty`.  **의존**: W1-01~W1-08.

---

## 4. 1주차 완료 기준 (전체 — 판정)

> **1주차가 끝났는가의 판정 기준은 '테스트 개수'가 아니라 'manifest 정직성'이다.**

`make verify`가 종료코드 0이고, 그 통과가 아래 불변식으로 뒷받침될 때만 1주차 완료:

1. **적대적 케이스 전부 '거부'로 통과** — (A) §3.6의 4케이스 **+ §3 각 작업의 적대적 완료기준 전부**(예: W1-04 함수 미호출, W1-07 로그 위생, W1-08 저장 부재 등 §3.6 밖의 거부 조건). **'4개만'으로 축소 해석하지 않는다.** 정상 통과가 아니라 **위조 거부**로 증명.
2. **manifest 정직성(판정 기준 자체)**:
   - 모든 `enforced` 키가 **실제 통과 테스트를 가리킨다**(enforced 선언 ↔ 통과 테스트 1:1).
   - 어떤 `not_implemented` 키도 `enforced`로 **참칭되지 않는다**. (목표 주차 ≠ 현재 상태)
   - → '일단 다 enforced로 적자'는 유혹이 **빌드 실패로 차단**된다. 이 프로젝트가 가장 피하려는 '거짓 보장'을 막는 선이다.
3. **뷰 동기화 불일치 0**(레포 내부 기계 강제 3종): `guardrails.yaml`↔(A) §3 / CLAUDE.md 금지선↔(A) §1.3·§3 / manifest 생성물↔(A) §3 파생.
4. 정상 입력이 `analysis_status="not_implemented"`를 받는다.
5. 레포에 실데이터·비밀값 커밋 0.

> **수치는 결과지 목표가 아니다.** 통과한 테스트 개수는 위 불변식이 성립한 '결과'일 뿐, (B)에 기대 숫자를 박지 않는다.

---

## 5. 1주차에 하지 않는 것 (범위 이탈 방지)

- LLM 연동·프롬프트·규칙 엔진·분석 로직 — **없음**.
- Java/Montoya Extension — **1주차엔 붙이지 않음**. 적대적 입력은 손으로 주입. (Java 실제 마스킹은 Java 연결 후 통합 테스트로 별도 증명.)
- 2주차 항목(`token_hardening`, `receipt_hmac`, 출력 스키마 불변식군, `audit_write_failure`) — manifest에 `not_implemented`로 정직 표기, 구현 안 함.
- 3주차 이후(`hallucinated_literal_isolation`, `anomaly_aggregation`), 5번 평가(`eval_harness`) — 손대지 않음.

---

## 6. 가정 검증 루프 (1주차 끝에)

- 실패한 가정·구현 중 발견된 문제를 기록.
- **실제로 검증된 통제만** manifest에서 `enforced`로 승격. 해결 못 한 부분은 명시적으로 남김(숨기지 않음).
- (A)에 수정이 필요한 지점이 나오면 → **(A) 정본(`docs/design-decision.md`)을 고치고**, CLAUDE.md·`guardrails.yaml` 뷰를 같은 PR에서 동기화(뷰 동기화 3종). 그 뒤 claude.ai 발행본을 가끔 1회 재발행(스냅샷 갱신).