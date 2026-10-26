# (A) 설계확정서 v1.12 — Sentinel Harness

> **정본 선언:** 이 문서(레포 `docs/design-decision.md`)가 (A) 설계확정서의 **유일 정본**이다.
> 불변식·금지선·스키마의 '결정된 값'은 여기 FROZEN 블록이 정본이고, (B)·CLAUDE.md·`guardrails.yaml`·manifest는 전부 여기서 파생·추출된다. 값 변경은 이 문서 한 곳에서만.
> claude.ai 프로젝트 docs의 「설계확정서」 페이지는 이 정본의 **발행 시점 스냅샷(사람 열람용)**이며, **불일치 시 레포(이 문서)가 정본**이다.
> 정본을 레포에 두는 이유: CI·PR·Claude Code 등 모든 자동 강제가 레포에 닿는다. claude.ai는 파이프라인 밖이라 정본이 될 수 없다(기계가 못 하는 동기화를 기계인 척하지 않는다).
>
> **문서 성격:** 합의기록형. 사람(미래의 민수, 사내 보안 심의관, AI 연구소)이 읽는다. "무엇을 정했나"와 **"왜 그렇게 정했나"**(트레이드오프·기각 대안 포함)를 담는다. 실행용 건조한 사양은 (B) `docs/claude-code-handoff.md`에 있다.
>
> **버전:** v1.12 = {범위 + 데이터계약(+ExecutionResponse, redacted_kinds 명확화, 출력 계약 보정·버전 규칙, 공용 타입 §2.6·본문 마스킹 표기·라벨 규칙, 정규 노드 주소 CNA·중복 처리) + 가드레일 매핑표 v1.11(통합점검 구멍5 반영 + v1.3 교정 + v1.4 이월처 재조정·tools/ 규칙 + v1.5 출력 게이트 4키 승격 + v1.6 마스킹·라벨·마스커 독립성 키 + v1.7 Evidence 위치 해석 승격 + v1.8 정규 주소·path 쿼리 금지 키 + v1.9 path 쿼리 금지 승격 + v1.10 본문 마스킹 표기 승격 + v1.11 평가 키)} + 평가 프로토콜 §6. 4번(LLM 전략)은 이후 증분.
> **버전 이력:** v1.0(범위+데이터계약+가드레일 골격) → **v1.2**(통합점검 구멍5: ① evidence 불변식 1:1 분해, ② manifest SSOT 파생키 `manifest_derivation`, ③ ⓓⓔⓖ 매핑표 추적, ④ `audit_write_failure` 자리, ⑤ `ExecutionResponse` 정식 편입).
> **v1.3:** PR#3(claude_md_sync_check 추가 · secret_scan_hook 범위 명시) + N3 정본 공백 메움(java_logic_isolation 행 추가)
> **v1.4:** redacted_kinds를 종류별 카운트 맵으로 명확화(W1-06) + 본문 내부 마스킹 표기는 Java 연결 시 설계 숙제로 명시(W1-06에서 드러남)
> **v1.5 (매핑표 v1.4):** §2 데이터 계약 버전 규칙 신설 + §2.2 Body 마스킹 표기 정의처를 5번 설계로 변경 + §2.4 출력 계약 보정(analyzed_refs·severity_if_true 서버 부여, corroboration `not_run`, review_required 기본 true, 출력 전체 폐기 규칙) + §2.5 analysis_status 닫힌 enum + §3 이월처 재조정(`token_hardening`·`receipt_hmac` → Java 연결 시, `audit_write_failure` → 수용 요청 감사(B-6) 범위 확정 시) + 신규 키 `masker_no_send`(§3.1)·`engine_tools_isolation`(§3.2) + §3.5 2주차 enforced 범위 각주 + '현재 CI가 검증한다' 사실 주장 교정(서버측 CI 없음, 검증 주체 = `make verify`).
>   - **문서 버전과 매핑표 버전은 별개다.** 문서 버전(제목의 vX.Y)은 (A) 전체 개정마다, 매핑표 버전(§3 제목)은 §3 표가 바뀔 때만 올린다. 두 숫자가 같을 필요는 없다.
>   - 출력 스키마 최초 동결본에 `not_run` 포함 — 소비자 0, §2 버전 규칙에 따라 `schema_version` 유지.
> **v1.6 (매핑표 v1.5):** §3.5 출력 게이트 4키 승격(`evidence_min_one`·`evidence_ref_integrity`·`server_assigned_status`·`category_closed_enum` → enforced(검증 함수 단위), 증명은 같은 PR의 γ) + 목표 재조정 2키(`assertive_token_guard`·`corroboration_check` → 5번 평가 데이터로 기준 확정 시 — 단정 토큰 목록과 '핵심 주장' 추출 기준은 평가 데이터 없이 정하면 추측이다, 2026-10-26 결정) + §3.5 제목 "C·E (출력·검증)" + † 각주 갱신.
>   - `output_schema_gate` 상태 칸 "derived (→2주차) †" → "derived †"(목표 없는 derived). target은 '언제'를 담는 필드인데 derived에는 자기 목표가 없고, "(→2주차)"는 실효 enforced와 모순됐다. 같은 매핑표 버전(v1.5) 안의 정정.
> **v1.7 (매핑표 v1.6):** §2 머리 버전 규칙 통합 + §2.6 공용 타입 신설(MaskedRef 이동, FILLER, Range, BodyPointer, Locator, MaskedSpan) + §2.2 Body `masked_spans`·불변식·마스킹→절단 순서 + §2.3 라벨 규칙(순번 `ref_NN`, HMAC은 매핑 테이블 키로만) + §2.4 Evidence.pointer = Locator(locus 필드 제거) + §1.3 ⓕ 해석 주석 + §3 신규 키 `masked_span_integrity`·`label_consistency`(§3.3)·`masker_independence`(§3.2).
>   - 버전 규칙: v1.5의 '비가산 → 항상 증가'를 소비자 우선 2단 분기로 대체.
>   - AnalysisResult `schema_version` "1.0" 유지 — Evidence.locus 제거·pointer 객체화 = 비가산, 소비자 0이라 유지.
>   - Envelope `schema_version` "1.0" 유지 — 라벨 형식을 `ref_NN`으로 좁힘 = 비가산 / `masked_spans` = 가산. 둘 다 소비자 0이라 유지.
>   - 같은 매핑표 버전(v1.6) 안의 보강: §3.5 `evidence_pointer_resolves` 추가(§2.6 Locator 서버 검증 규칙에 대응하는 키가 없던 공백, `output_schema_gate` 하위 키 아님) + §2.6 Locator에 'range는 값이 문자열일 때만(MaskedRef면 금지), 모든 변형에 적용' 명시.
> **v1.8 (매핑표 v1.7):** §3.5 `evidence_pointer_resolves` 승격(not_implemented → enforced(검증 함수 단위), 증명은 같은 PR의 ζ1). 바꾼 것은 상태 칸과 이력뿐 — §2.6 문구 변경 없음.
> **v1.9 (매핑표 v1.8):** §2.2 Param.location을 query|form으로 축소 + request.path 쿼리 미포함(raw '?'는 ② 거부) + §2.4 중복 처리 규칙 교체((category, Evidence CNA 집합) 정확 일치만 병합) + §2.6 Locator req_param location 축소·CNA(정규 노드 주소)·정규화 함수 신설·BodyPointer `json` = RFC 8259 엄격 파싱 명문화 + §3 신규 키 `path_no_query_string`(§3.2)·`canonical_address`(§3.5).
>   - Param.location에서 json·path 제거 = 비가산, 소비자 0이라 유지. json: 중첩을 표현하지 못하면서 본문 JSON Pointer와 중복되고 정보도 잃는다. path: Java는 구문 파싱만 하므로 경로 파라미터를 판별할 수 없다(path_template은 Python이 내부에서 파생 — A-3/A-4). 계약이 Java에 불가능한 일을 요구하던 것을 교정했다.
>   - request.path 쿼리 미포함 = 비가산(이전에는 '?' 포함 path가 ②·③을 통과했다), 소비자 0이라 유지.
>   - 같은 버전(v1.9) 안의 정정: §2.6 CNA 근거가 레포에 정의 없는 설계 대화 라벨("D4")을 가리키던 거짓 색인을 실제 절(§2.6 e 헤더 이름 정규화)로 교체. (A) 규범 본문의 다른 임시 라벨(D·E·F·G·H·I·J 계열)은 grep으로 0건 확인.
> **v1.10 (매핑표 v1.9):** §3.2 `path_no_query_string` 승격(not_implemented → enforced(검증 함수 단위 — 입력 스키마), 증명은 같은 PR의 ζ2a). 바꾼 것은 상태 칸과 이력뿐 — §2.2·§2.6 문구 변경 없음. Envelope·AnalysisResult `schema_version` 값 변화 없음(축소·쿼리 금지의 비가산 변경은 v1.9 이력에 기재).
> **v1.11 (매핑표 v1.10):** §3.3 `masked_span_integrity` 승격(not_implemented → enforced(검증 함수 단위 — ③, 불변식 5는 같은 kind 안), 증명은 같은 PR의 ζ2b) + §2.2 불변식 5 적용 범위 한 줄(같은 kind 안) + §2.3 값 재스캔 대상 한 줄(선언된 span 위치의 FILLER를 걷어낸 본문). `schema_version` 값 변화 없음(`masked_spans` 가산·라벨 `ref_NN` 축소는 v1.7 이력에 기재).
>   - 근거(§2.3 한 줄): 기존 패턴 3종(`credential_json_field`·`credential_form_field`·`session_cookie_pair`)이 값 자리의 FILLER 자체에 걸려, 올바르게 마스킹한 자격증명·세션 필드가 거부됐다(ζ2b 0단계 실측). '정책 패턴만 탐지'와 충돌하지 않는다 — 면제 대상은 선언된 위치의 문자 그대로의 FILLER뿐이다.
> **v1.12 (매핑표 v1.11):** 5번(평가) 프로토콜 응고 — §6 신설, 평가 키 등재. §6 = 5번 결정점 ①(판정)②(데이터셋)③(지표) 응고. §3.5 `eval_harness` 목표 "5번 주제" → "평가 하네스 구현 시"(상태 그대로) + 신규 `label_isolation`·`dataset_version_freeze`(둘 다 not_implemented). enforced 집합·`schema_version` 값 변화 없음.
>   - 감사 추적: §6.1 매칭·남은 중복·category 대표/보조·advisory 비채점은 설계 대화의 H1~H5, §6.2는 I1~I8, §6.1 판정 단위는 G1~G6의 응고다. 규범 본문에는 이 라벨을 두지 않는다(§6.3의 J1~J9는 그 절 안에서 정의된 항목 ID).
> 확정일: 2026-10-22 (v1.3 개정: 2026-10-23, v1.4 개정: 2026-10-23, v1.5 개정: 2026-10-26, v1.6 개정: 2026-10-26, v1.7 개정: 2026-10-26, v1.8 개정: 2026-10-26, v1.9 개정: 2026-10-26, v1.10 개정: 2026-10-26, v1.11 개정: 2026-10-26, v1.12 개정: 2026-10-27)

---

## 0. 프로젝트 헌장

### 0.1 정의
제1금융권 취약점 점검 업무를 개선하기 위한, **폐쇄망(주요 단말망) 전용 AI 웹 취약점 점검 보조 시스템.** Burp Suite로 수집한 HTTP 요청·응답을 사내 승인 LLM으로 분석하여, 근거가 있는 취약점 가설을 구조화된 형태로 제시하고, 증거를 취합하며, 보고서 초안을 생성한다.

### 0.2 해결하는 문제와 차별점 (왜 만드는가)
현재 점검은 수작업 중심이라 정확하지만 느리다. 시중 AI 보안 솔루션(Astra, XBOW, Horizon3, Burp AI 등)은 전부 데이터를 외부 클라우드로 전송하는 구조라, **외부 egress가 차단된 주요 단말망에서는 구조적으로 사용 불가**다.

> **한 줄 차별점:** 폐쇄망 안에서, 외부 egress 0으로, 사내 승인 모델로만 동작하는 **감사 가능한** AI 취약점 점검 보조 — 상용 솔루션이 구조적으로 들어올 수 없는 자리를 메운다.

이 차별점은 '기능'이 아니라 '**폐쇄망 + egress 0 + 감사 가능성**'이다. Burp AI/Shadow Repeater가 이미 네이티브로 제공하는 변이·분석 기능을 재구현하는 것이 목적이 아니다. (→ 기각 대안 R-6, R-7 참조)

### 0.3 시스템의 본질
자율 공격 에이전트가 **아니다.** **"구조화된 입출력 하네스 + 사람이 게이트(gate)인 분석 루프"**다. AI는 취약점 가설과 다음 점검 후보를 '제안'하고, 실제 테스트 실행과 최종 판정은 사람이 한다.

### 0.4 조건
- **목적:** 현업 취약점 점검 업무 개선
- **개발 형태:** 1인 개발로 시작, 장기적으로 팀 공용 도구 → 사내 AI 연구소 협업 고도화
- **MVP 환경:** 개인 PC의 격리 환경 + 로컬 테스트 앱(OWASP Juice Shop). **실제 사내 데이터는 심의 전까지 1g도 사용하지 않는다.**

---

## 1. 범위 (FROZEN)

### 1.1 P0 탐지 카테고리 — 4종 (정본)
**기준: 단일 트랜잭션(요청+응답 한 쌍) 안에서 신호가 관측 가능한 것만.**

| # | 카테고리 | enum 값 |
|---|---|---|
| ① | 접근통제 / IDOR·BOLA | `access_control` |
| ② | 정보 노출 | `info_exposure` |
| ③ | 보안 오설정 | `security_misconfig` |
| ④ | 반사형 인젝션 '징후' | `reflected_injection_indicator` |

- **④의 경계:** 이미 캡처된 요청+응답 한 쌍 안에서 관측되는 것만(값이 같은 응답에 반사됨 / 응답에 SQL 에러 문자열 등). **가설까지만, 능동 탐침 없음.** 검증은 사람이 Burp에서.

### 1.2 제외 카테고리와 그 처리
블라인드/시간기반 SQLi, 저장형 XSS, CSRF, 비즈니스 로직, 레이스는 **P0 탐지에서 제외.** 사유: "단일 트랜잭션에서 신호 관측 가능" 기준 미달(능동 전송 필요 / 다중요청 흐름 필요 / 동시성 필요).

- 단, 제외 카테고리도 **'탐지'로 주장하지 않는 선에서 `advisory_signals`(수동 점검 권고)로는** 띄울 수 있다.
- CSRF는 정적 신호(상태변경 POST + 쿠키인증 + 토큰/SameSite 부재)가 있어, 추후 ③에 흡수 가능한 후보로만 남겨둔다.

**미래 확장 경로 (지금은 자리만, 구현 아님):**
- CSRF → 흐름 분석 약간(능동 전송 불필요, 가장 먼저 승격 후보)
- 저장형 XSS / 연관 분석 → "트랜잭션 집합 입력 + 데이터 흐름 추적" 모듈 (관문 1)
- 블라인드 SQLi / 레이스 → **능동 전송을 통제된 형태로 여는 정책/승인/감사 엔진** (관문 2, 사내 심의 필수)
- 비즈니스 로직 → 멀티스텝 추론 (관문 3, 완전 자동화는 현 기술 미완)

### 1.3 영구 제외 — NEVER 하는 것 (정본)
| 코드 | 내용 | REJECTED 사유 | 재론 조건 |
|---|---|---|---|
| ⓐ | 도구의 자율 요청 전송(능동 탐침·스파이더링·크롤링 포함) | 금융 비파괴 원칙(계정 잠금·거래 생성 위험) | 관문2 정책엔진 + 보안심의 통과 후 |
| ⓑ | 외부 egress(OpenAI·Anthropic 클라우드·Google·Burp AI 플랫폼 등) | 폐쇄망 데이터 반출 금지 | 없음(프로젝트 존재 이유와 배치) |
| ⓒ | 사내 실데이터(실보고서·실트래픽·인증정보·내부 URL·토큰) | A-5, 데이터 반출 정책 | 사내 심의·모델 승인 후 |
| ⓓ | AI 생성 수정코드의 자동 반영 | 운영 영향, 사람 검토 필수 | 수정 권고 초안까지만 허용 |
| ⓔ | 실데이터 기반 파인튜닝 | ⓒ와 동일 + 모델 거버넌스 | RAG 검증 후 별도 판단 |
| ⓕ | 원본(마스킹 전) 트래픽의 저장·커밋 | A-7 | 없음 |
| ⓖ | 멀티에이전트 / 사내 사례 RAG | 1인 MVP 범위 초과, 디버깅·거버넌스 비용 | MVP 검증 + 데이터 승인 후(P2) |

> **ⓕ 해석:** 사람이 Burp에서 내보낸 원본 파일은 Burp 프로젝트 파일과 같은 시스템 밖 자산이고, 시스템(엔진·tools)은 이를 영속화하지 않는다.

---

## 2. 데이터 계약 v0.1 (FROZEN)

세 스키마로 분리 관리한다. **마스킹 정책 ≠ 입력 스키마** — 분리해야 마스킹 규칙 변경이 분석 계약을 건드리지 않는다.

> **데이터 계약 버전 규칙:** `schema_version` 처리는 1차로 소비자 존재 여부, 2차로 변경 종류로 가른다.
> - 소비자 없음 → 가산·비가산을 가리지 않고 version 유지. 이력에 '<변경 종류>, 소비자 0이라 유지'를 기록한다.
> - 소비자 있음 → 가산 = 부 버전 증가(X.Y → X.Y+1) / 비가산 = 주 버전 증가(X → X+1, 부 버전 0).
>
> 소비자 = 레포 밖 생산자·소비자, 또는 보존 대상 데이터(평가 데이터셋 등). 같은 PR에서 함께 갱신되는 레포 내부 테스트 픽스처는 소비자가 아니다.
> 첫 소비자가 생기는 시점(예: 평가 데이터셋의 첫 동결 커밋)의 형태가 그 버전의 동결 형태가 된다. 그 이후의 변경은 '소비자 있음' 규칙을 따른다.

### 2.1 최상위 봉투 (P0부터 shape 불변)
```
Envelope
├─ schema_version : "1.0"
├─ analysis_type  : "single"            # P1에서 "diff" 추가(가산적)
└─ transactions   : [Transaction]       # P0는 정확히 1개. 0개·2개↑ 거부(validator)
```
> **왜 봉투부터?** P0가 단일 트랜잭션이지만 최상위를 처음부터 얇은 봉투로 두면, P1 batch는 길이>1 + relation 메타 추가만으로 끝난다(순수 가산적, 최상위 shape 불변). → 기각 대안 R-8 참조.

### 2.2 TransactionSchema (Java가 '구문 파싱'까지만 채움)
```
Transaction
├─ meta: { transaction_id(UUID), captured_at(ISO8601+tz), origin_ref(Burp 내부 id, 실호스트 아님),
│          sanitization: SanitizationReceipt }
├─ request:  { method, scheme(http|https), host, port, path(원본, 쿼리 미포함 ↓),
│              query_params:[Param], headers:[Header], body: Body }
└─ response: { status, headers:[Header], body: Body,
               elapsed_ms(int|null) }   # ★시간기반 SQLi 탐지에 사용 금지(제외 카테고리)

Param  = { name, value: str|MaskedRef, location(query|form) }                # MaskedRef → §2.6
Header = { name, value: str|MaskedRef }
Body   = { content_type, size_bytes(원본크기), truncated(bool),
           encoding(utf8|base64|omitted), content(str|null),
           masked_spans: [MaskedSpan] = [] }                                   # MaskedSpan → §2.6
```
- **Java는 구문 파싱만.** `path_template`, 'ID스러운 파라미터' 분류, 반사 표식 등 **해석 필드는 Python이 내부 파생**(A-3/A-4).
- **request.path:** path는 쿼리 문자열을 포함하지 않는다. 쿼리는 query_params(location=query)로만 표현한다.
  - 강제: 디코딩 전 raw path에 리터럴 '?'가 있으면 ② 스키마 검증에서 거부한다. 인코딩된 '%3F'는 경로 세그먼트의 정상 일부일 수 있으므로 거부하지 않는다. 강제 수단은 manifest 키 `path_no_query_string`이 추적한다.
  - 근거: 같은 쿼리 값을 req_line.path와 req_param 두 방식으로 가리킬 수 있는 경로를 막는다(CNA 중복 원천). 계약 문구만 두고 검증하지 않으면 'Java가 분리한다'는 영수증을 믿는 것과 같다(R-11 계열, 단일 실패점). Python이 재검증한다.
- `host` 가명화 여부는 TransactionSchema가 아니라 SanitizationPolicy가 결정(관심사 분리).
- **body truncation 상한:** req 64KB / resp 256KB(config화). 초과 시 `truncated=true` + head+tail 일부 보존(에러·민감필드가 응답 꼬리에 자주 옴). truncated에서 파생된 finding은 자동으로 `limitations`에 "본문 일부만 분석됨" 플래그.
- **multipart/바이너리:** 텍스트 파트(파일명·주장 content-type·동반 JSON)는 구조화 보존, 바이너리 파트만 `omitted`. `omitted = 본문 미전송 + Java 원본 즉시 폐기`.
- **본문 내부 민감값의 마스킹 표기:** §2.6 masked_spans로 정의됨(아래 Body 불변식). tools/ fixture 마스커가 참조 구현이다. (현재 구현: 평문 민감 패턴이면 fail-closed 거부.) 헤더 값·경로의 부분 마스킹은 미정의 — 큐 11. 현재는 fail-closed.
- **Body 불변식 (③이 검증한다):**
  1. `masked_spans ≠ []` ⇒ `encoding == utf8` ∧ `content ≠ null`.
  2. `at.kind == "text"` ⇒ range 필수. 본문 전체를 가려야 하면 span이 아니라 `omitted`로 처리한다.
  2'. `encoding == omitted` ⇒ `content == null` ∧ `masked_spans == []` ∧ `truncated == false`. omitted가 우선한다 — 'omitted인데 content가 있는' 상태는 표현할 수 없게 한다.
  3. span이 가리키는 저장 값은 정확히 FILLER다. range가 있으면 `값[start:end] == FILLER`이고 `end − start == len(FILLER)`. json에 range가 없으면 노드 값 자체가 문자열 FILLER다.
  4. `json`은 content 전체가 JSON으로 파싱될 때만 허용한다.
  5. span끼리 겹치지 않는다. 같은 노드에 '노드 전체 span'과 'range span'이 함께 있을 수 없다.
     - 적용 범위: 겹침은 같은 kind 안에서만 검사한다. 서로 다른 kind는 좌표계가 분리되어(text = content 오프셋, json = 노드 안 오프셋) 서로 비교하지 않는다.
  6. 정규 순서는 (kind, path, start) 오름차순이다. 같은 입력이면 출력이 바이트 단위까지 같아야 한다(Java 차분 테스트의 전제).
- **설계 의도(FILLER ↔ 사이드카 비대칭):** FILLER에는 kind가 없고, kind·라벨은 `masked_spans.ref`에만 있다. 본문은 신뢰할 수 없는 데이터라 정보를 최소화하고, 마스킹 여부의 권위는 사이드카에 둔다. "일관성을 위해 채움값에 kind를 넣자"는 변경은 금지한다.
- **오프셋:** 저장된 content 기준, 유니코드 코드포인트 단위. 마스커는 유니코드 정규화를 하지 않는다. Java의 UTF-16 → 코드포인트 변환은 Java 쪽 책임이다.
- **base64:** span을 두지 않는다. 마스커가 디코드한 바이트에서 비밀값을 발견하면 `omitted`로 처리한다. 바이너리 응답 속 정보 노출을 평가할 수 없는 점은 커버리지 한계로 둔다.
- **마스킹 → 절단 순서(고정):** 절단은 마스킹이 끝난 뒤에 한다. FILLER가 절단 경계에 걸리면 그 FILLER 전체를 절단 영역에 포함해 버린다 — 반쪽 FILLER는 금지한다(온전한 FILLER가 아니면 아예 없어야 한다). 근거: 절단을 먼저 하면 비밀값의 반쪽이 패턴을 피해 ③을 통과할 수 있다. 경계 표기 방식은 큐 10에 남긴다.

### 2.3 SanitizationPolicy + SanitizationReceipt
```
SanitizationPolicy
├─ policy_version
├─ mode            : "strict_redaction"(기본) | "relation_preserving"(IDOR/BOLA 세션 opt-in)
├─ header_rules    : [{name_pattern, action: redact|pseudonymize|keep}]
├─ body_rules      : [{matcher, action}]
└─ object_id_policy: "pseudonymize_if_sensitive"(기본) | "keep"(테스트 가상데이터 확인 시)

SanitizationReceipt   # 각 Transaction.meta에 필수
├─ applied(bool) ├─ failed(bool) ├─ policy_version
├─ redacted_count(int)
└─ redacted_kinds: {token:int, cookie:int, pii:int, host:int}   # 종류별 개수 맵(값은 없음, 감사용)

# MaskedRef → §2.6으로 이동
```
- **라벨 규칙:**
  - 매핑 테이블의 키 = HMAC(배치 키, 원본값). 라벨은 순번으로 할당한다(`ref_01`, `ref_02`, …). 해시를 잘라 라벨로 쓰지 않는다. Python으로는 라벨만 간다. 원본값은 Java 경계를 넘지 않는다.
  - 같은 원본값 ⇔ 같은 라벨(양방향). 동치 기준은 원본값이며 kind와 무관하다. 헤더·파라미터·본문 span에 공통으로 적용한다. 배치 안에서만 유효하다.
  - 이 불변식은 생산자(마스커·Java) 쪽에서만 강제할 수 있다. Python ③은 원본을 모른다.
  - 접두사 `ref`의 근거: 의미 있는 접두사는 LLM이 근거 없이 추론하게 만든다(R-9와 같은 문제). 의미는 `ref.kind`에만 둔다.
- **정책은 데이터 파일로 둔다.** fixture 마스커(참조 구현)와 Java가 같은 정책 파일을 해석한다. fixture 마스커가 픽스처에 대해 Java의 1차 역할을 대신한다. 마스커는 엔진의 `sanitization_check`를 재사용하지 않는다(독립성 — R-11 정신).
- **키·매핑 테이블:** 프로세스 메모리 전용. 디스크·로그·예외 메시지 기록 금지. **일관성 범위 = 분석 배치 단위**(→ 키 영속화 불필요, 평가 재현성과 보안 트레이드오프 해소).
- **기본 모드 = strict_redaction.** relation_preserving은 IDOR/BOLA 세션에서만 opt-in.
- **2단계 적용:** Java(transport 보호 — 고정 화이트리스트 헤더 치환) + Python(정밀 — body PII 스캔, 가명화 일관성, object_id 민감성 판정).

> **신뢰 경계 (★구현 전 반드시):** `applied==true`는 요청자가 쓰는 주장일 뿐이다. **Python은 '마스킹됐다는 주장'을 믿지 말고 '마스킹됐음을 스스로 재검증'한다.** 수신 데이터에 토큰·쿠키·키 생문자열이 남았는지 Python이 독립 재스캔 → 발견 시 `applied` 값과 무관하게 거부(영수증≠데이터면 데이터를 믿고 거부). **전송 전 보호(Java, 1차)와 수신 후 재검증(Python, 2차 방어선)은 다른 보장이며, 재검증은 1차를 대체하지 않는다.** 패턴 검사는 '정책에 정의된 패턴'만 탐지하며 '모든 비밀값 부재'를 증명하지 않는다(불투명 세션 ID는 일반 문자열과 구분 불가).
> - 값 재스캔은 masked_spans가 가리키는 위치의 FILLER를 걷어낸 본문에 대해 수행한다. 이는 선언된 span 위치를 값과 무관하게 건너뛰는 것이 아니다 — span 위치가 정확히 FILLER임은 masked_span_integrity(불변식 3)가 독립으로 검증하며, FILLER가 아니면 거부된다. 두 검사가 함께 성립해야 통과한다.

### 2.4 AnalysisResultSchema (출력 — LLM 환각을 계약으로 차단)
```
AnalysisResult
├─ schema_version : "1.0"
├─ analyzed_refs  : [UUID]            # 서버 부여: LLM에 실제로 넘긴 transaction_id 목록. LLM 초안에는 없음
├─ findings       : [Finding]         # 탐지 4종만. 빈 배열 = 정상(단, ExecutionResponse와 구분 ↓)
├─ advisory_signals: [AdvisorySignal] # 카테고리 밖 조언. ★탐지 아님
└─ analysis_meta  : { model_id, policy_version, prompt_version, ruleset_version,
                      elapsed_ms, token_usage?, pipeline_mode, manifest_snapshot }

Finding
├─ finding_id(UUID)
├─ category   : enum(4종 폐쇄형)       # LLM이 임의 카테고리 생성 불가
├─ hypothesis : str                   # 조건·추정형만("~가능성/~로 보임"). 단정 토큰 금지
├─ evidence   : [Evidence]            # 최소 1개 필수(0개면 거부=환각 차단)
├─ claim_basis: enum(observed|inferred|speculative)   # 근거의 성격(자유숫자 금지)
├─ severity_if_true: enum | null      # 항상 존재. null = 등급 매핑 미정의. 서버가 부여한다(LLM 초안에 없음). 사실이라면의 위험도(사실성과 무관), 확신도 아님 ↓
├─ status     : enum(unverified|verifying|confirmed|false_positive|needs_review)
│               # ★LLM은 생성 불가. 서버가 unverified 부여. 승격은 ReviewEvent로만
├─ produced_by: enum(rule|llm|hybrid) # AI 기여도 분리 측정(평가 테제)
├─ limitations: [str]
└─ next_steps : [{type: "verification", action, rationale}]   # 도구는 실행 안 함

Evidence
├─ transaction_ref(UUID)   # transaction_id로만 참조(host 문자열 금지). analyzed_refs에 포함돼야 함
├─ pointer: Locator        # §2.6. locus는 Locator 안의 판별자다(별도 locus 필드 없음)
├─ observation(str)        # 관측 사실(해석 아님). 가명 라벨 그대로 인용 가능
├─ corroboration: matched|unmatched|not_checkable|not_run   # 서버 생성(LLM 아님). not_run=대조 미실행 / not_checkable=대조 불가
├─ anomaly_flags: [...]    # 서버 재대조 로직이 생성(LLM 아님). 예: hallucinated_literal_suspected
└─ review_required(bool)   # 서버 기본값 true(미대조 상태의 fail-safe)

AdvisorySignal = { type:"out_of_scope_advisory", topic, basis:[Evidence], suggestion }
```
- **analyzed_refs 서버 부여:** 서버가 LLM에 실제로 넘긴 transaction_id 목록을 채운다. LLM 초안에는 없다. 근거: LLM이 analyzed_refs와 evidence.transaction_ref 양쪽을 다 쓰면 `evidence_ref_integrity`가 자기참조가 된다.
- **severity_if_true 서버 부여:** LLM은 채우지 않는다(초안에 없다).
  - 기본값: category별 기본값 표에서 부여한다. 이 표는 미정의다(5번 이후 확정).
  - 보정(adjust): 서버가 관측·판정한 신호 유형으로 기본값을 조정할 수 있다. 보정 규칙(어떤 신호가 severity를 어떻게 바꾸는지)은 미정의다(5번 이후 확정).
  - 기본값 표가 정의되기 전에는 비워 둔다(null). 기본값 표가 정의된 뒤에도, 보정 규칙이 정의되기 전에는 기본값만 부여하고 보정하지 않는다.
  - 근거: 건건이 자유롭게 매기면 같은 취약점이 다른 값을 받아 평가가 오염된다(R-9와 같은 문제). 규칙이 미정의인 상태에서 판정을 허용하면 추측하거나 LLM에 다시 위임하는 뒷문이 된다.
- **corroboration·review_required:** 서버가 생성한다(LLM 아님). `not_run` = 대조 미실행, `not_checkable` = 대조 불가. `review_required`의 서버 기본값은 true — 미대조 상태의 fail-safe.
- **출력 검증 규칙(전체 폐기):** LLM 초안의 어느 한 부분이라도 검증에 실패하면 결과 전체를 폐기한다(부분 수용 금지). 폐기는 조용히 하지 않는다 — 사유 코드를 감사에 남기고, `ExecutionResponse.analysis_status = output_rejected`로 명시한다(§2.5). 근거: 깨끗한 부분만 골라내는 것은 환각을 부분적으로 신뢰하는 것이다. 빈 결과로 위장하면 '분석 실패'와 '분석 후 깨끗함'이 다시 섞인다.
- **status 승격:** ReviewEvent(사람 판정 + 시각 + 사유) append → current_status는 파생·재계산 가능. LLM 응답에서 status **필드 자체를 제외**하고 서버가 unverified 부여.
- **evidence 무결성:** transaction_ref ∈ analyzed_refs + pointer가 마스킹 후 데이터에서 해석됨 + pointer/observation이 **마스킹 후 데이터로 검증 가능** + observation 핵심 주장이 실제 발견되는지 재대조.
- **환각 리터럴 격리:** 재대조 실패 + 민감패턴 의심 → `hallucinated_literal_suspected`(서버 생성, '날조 확정' 아니라 '경계 이상 의심'). 의심 문자열 미저장·미로그·집계 원문 제외. 플래그 달린 evidence는 유효근거 카운트 제외 → 유효 evidence 0이면 finding 자동 needs_review/폐기.
- **중복 처리:** Finding끼리는 (category, Evidence CNA 집합)이 정확히 같을 때만 병합한다(CNA → §2.6). CNA가 일부 겹치는 것만으로는 병합하지 않는다. advisory의 CNA 집합이 어떤 finding과 정확히 같으면 advisory를 버린다(finding 우선). 평가 채점은 이 중복 처리를 거친 출력을 대상으로 한다.
  - 근거: 겹침으로 병합하면 사슬 병합이 생기고, 거친 노드(body_text)가 서로 다른 결함을 끌어모은다. 보안 도구에서 과병합은 결함을 숨기고, 과소병합은 중복을 보여 줄 뿐이다(fail-safe 방향). 남은 중복은 평가에서 측정된다.

### 2.5 ExecutionResponse (분석 실행 상태 — AnalysisResult와 구분)
```
ExecutionResponse = { analysis_status, skipped_reasons: [str], manifest_snapshot }
```
> **왜 분리?** `findings:[]`가 "분석 완료·깨끗함"인지 "아직 분석 안 함"인지 혼동 금지. **분석 안 함 ≠ 분석 후 취약점 없음.** 평가의 '정상 사례 정확도'가 이 구분에 의존한다. 1주차 골격은 이 타입만 반환한다.

- **`analysis_status` = 닫힌 enum:** `not_implemented | completed | output_rejected`.
  - `not_implemented`: 분석 단계가 구현되지 않아 분석하지 않음(현재 동작).
  - `completed`: 분석이 끝나고 결과(AnalysisResult)가 동봉됨. 동봉 형태(필드 위치)는 LLM 결선 시 정의한다. 분석 후 깨끗함 = `completed` + `findings: []`.
  - `output_rejected`: LLM 출력이 검증에 실패해 결과 전체를 폐기함(§2.4 출력 검증 규칙). 입력 거부(HTTP 4xx)와는 다른, **출력** 거부다.
- 세 값은 "분석 안 함 / 분석 후 결과 있음(깨끗함 포함) / 분석 결과 폐기"를 구분하기 위한 것이다.

### 2.6 공용 타입 (§2.2·§2.3·§2.4가 참조 — 의존 방향은 §2.6 → 나머지, 한쪽뿐)
```
MaskedRef   = { masked: true, label: "ref_NN" | null, kind: token|cookie|pii|host }
FILLER      = "[MASKED]"                       # ASCII 고정 리터럴. kind·라벨 없음
Range       = { start: int ≥ 0, end: int > start }
BodyPointer = { kind: "json", path: <RFC 6901 JSON Pointer>, range?: Range }
            | { kind: "text", range?: Range }
Locator     = { locus: req_line, part: method|path, range? }
            | { locus: req_header|resp_header, name, occurrence: int ≥ 0 = 0, range? }
            | { locus: req_param, location: query|form, name, occurrence: int ≥ 0 = 0, range? }
            | { locus: req_body|resp_body, body: BodyPointer }
            | { locus: resp_status }
MaskedSpan  = { at: BodyPointer, ref: MaskedRef }
```
- **MaskedRef:** §2.3에서 이 소절로 옮겼다. `label` 형식은 `ref_` 뒤에 숫자 2~4자리다(타입 강제 = 정규식, 구현은 ζ). 라벨 규칙은 §2.3.
- **FILLER:** 정본 값은 여기 한 곳뿐이다. 구현 규칙: 코드 안의 정의도 한 곳만 두고, (A) 값과의 일치를 테스트한다(구현 PR 몫).
- **Range:** 유니코드 코드포인트, 반열림 [start, end). 대상은 가리킨 '저장 값' 문자열이다.
- **BodyPointer:**
  - `json`은 content 전체가 JSON으로 파싱될 때만 허용한다. 그 외에는 `text`.
  - 'content 전체가 JSON으로 파싱됨' = RFC 8259 엄격 파싱이다. NaN·Infinity, 후행 문자열, 중복 키를 허용하지 않는다(중복 키는 '노드 정확히 1개' 조건을 깨뜨린다). 출력 게이트·③·fixture 마스커는 같은 정의를 쓴다.
  - JSON Pointer의 `-` 토큰은 금지한다. path가 가리키는 노드는 정확히 1개다.
  - range는 가리킨 노드가 문자열일 때만 허용한다.
  - **JSONPath 대신 JSON Pointer를 쓰는 이유:** JSONPath는 질의 언어라 여러 노드를 가리킬 수 있고 표기가 하나로 정해지지 않는다.
- **Locator (= Evidence.pointer, locus로 판별):**
  - 정규화: 헤더 이름은 서버가 소문자로 바꾼다. 파라미터 이름은 대소문자를 유지한다.
  - range는 가리킨 값이 문자열일 때만 허용한다(값이 MaskedRef면 range 금지). req_line·header·param·body 모든 변형에 적용한다.
  - Evidence의 range는 선택(힌트)이다. 근거: LLM은 문자 수를 세는 데 약해서, 필수로 하면 unmatched 잡음이 폭증한다.
  - 서버 검증: Locator는 마스킹 후 데이터에서 실제로 해석돼야 한다(경로 존재, occurrence 범위, range 길이). 실패하면 출력 전체를 폐기한다(§2.4 출력 검증 규칙). 감사에는 사유 코드만 남기고 pointer 내용은 남기지 않는다.
- **MaskedSpan:** masked_spans의 range는 정확해야 하고 ③이 검증한다(§2.2 Body 불변식). Evidence와의 비대칭은 의도된 것이다 — 만드는 주체의 정확도에 따라 요구 수준을 다르게 둔다.
- **CNA (정규 노드 주소):**
  ```
  CNA  = (transaction_ref, node)
  node = req_line.method | req_line.path
       | header(side, 소문자 이름, occurrence)
       | param(query|form, name, occurrence)
       | body_json(side, JSON Pointer)
       | body_text(side)
       | resp_status
  ```
  - range는 CNA에 포함하지 않는다(Evidence range는 힌트).
  - 정규화 함수: 엔진 안의 순수 함수 1개. 서버 중복 처리(§2.4)와 평가기가 함께 쓴다. 평가기(tools)가 엔진을 import하는 것은 허용 방향이다.
  - 정규화 규칙(결정론적, 모두 이 함수 안에 둔다):
    - `req_body{json, path, range?}` → `body_json(path)`
    - `req_body{text, range}`: 폼 본문에서 range가 파라미터 값 하나의 구간 안에 완전히 들어가면 → 그 `param(form, …)` / JSON으로 파싱되는 본문에서 range가 들어가는 가장 깊은 문자열 노드 → 그 `body_json(path)` / 그 밖의 경우 → `body_text`
    - `header{…, range}` → header 노드(range 제거)
    - `req_line{path, range}` → `req_line.path`
  - 근거: 형식이 다르다는 이유로 출력 전체를 거부하지 않는다(§2.6 e의 헤더 이름 정규화와 같은 원칙(형식 차이를 이유로 출력 전체를 거부하지 않는다)). 승격에 실패하면 거친 노드로 떨어지고, 그 결과로 생기는 FN은 평가에서 측정된다.

---

## 3. 가드레일 — 강제 매핑표 v1.11 (FROZEN)

> 이 표가 **가드레일의 단일 출처(SSOT)**다. capability manifest는 이 표에서 기계 파생되며(`manifest_derivation`), 생성물과 정본의 일치를 make verify(로컬 게이트)가 검증한다. 서버측 CI는 없다.
> **manifest 상태 4종:** `enforced`(선언된 필수검증이 실제 실행·통과한 경우만) | `not_implemented`(예정 주차 명시) | `disabled` | `unverifiable`(통제가 외부 의존 — OS격리·레포설정 — 이라 시스템 자가확인 불가. '있는 척' 아니라 '책임 밖임을 정직 표시').
> **파생 상태(derived):** 자체 강제테스트 없이 하위 키들의 AND로 상태가 정해지는 롤업 항목(예: `output_schema_gate`). 독립 강제를 참칭하지 않으며, 하위 키가 모두 enforced일 때만 enforced.
> **목표 층위:** 주된 강제 지점. 실제 보장엔 보조 층위가 추가될 수 있고, enforced는 선언된 필수검증이 실제 실행·통과한 경우에만 부여.
> **강제 4층위:** 타입(최강·공짜) > 스키마/validator > 테스트 > CI게이트.

### 3.0 파이프라인 순서 (그 자체가 가드레일 — 임의 변경 금지)
```
① 토큰 검증 ──실패──▶ 파서·역직렬화·분석·저장 함수 '미호출'로 즉시 거부
   │                  + 인증실패만 감사(본문·토큰값 미기록)
   │통과
② 스키마 검증(Envelope/Pydantic) ──실패──▶ 거부 + 감사
   │통과
③ Sanitization 독립 재검증 ──생문자열 패턴 잔존──▶ applied 무관 거부 + 감사
   │  (+ fail-closed: applied==false ‖ failed==true ‖ 필드누락 ‖ 타입오류 → 거부)
   │통과
④ [1주차] 분석 없음 → ExecutionResponse(analysis_status="not_implemented") 반환
   [이후]  규칙엔진 → LLM → 출력 스키마 검증 → 저장
```
**감사 기록 실패 시에도 fail-closed**(기록 못 하면 통과시키지 말고 거부) — 수용 요청 감사(B-6) 범위 확정 시.

### 3.1 D. 실행경계
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| egress 정적 의존성 0(외부 HTTP 송신 의존성 0 + 허용목록 빔) | 테스트 | enforced | `egress_static_check` |
| egress 런타임 차단 실증 | 테스트 | enforced(테스트환경 한정) | `egress_runtime_block` |
| egress 차단 실주체(OS/네트워크) | — | unverifiable | `egress_enforcement_owner` |
| 로컬 LLM ≠ 외부 egress 분리 | 테스트 | enforced(1주차=허용목록 빔 검사) | `local_llm_vs_egress` |
| 자율 전송 0(송신·소켓 심볼 import 0) | 아키텍처 테스트 | enforced | `no_autonomous_send` |
| 127.0.0.1 바인딩 | 테스트+설정 | enforced | `loopback_binding` |
| 요청자 토큰 검증(공유시크릿) | validator+테스트 | enforced | `request_token_validation` |
| 토큰 강화(회전·수명) | validator | not_implemented → Java 연결 시 | `token_hardening` |
| 자동 수정반영 부재(ⓓ) | 아키텍처 테스트 | enforced | `no_autopatch_apply` |
| 파인튜닝 경로 부재(ⓔ) | 아키텍처 테스트 | enforced | `no_finetune_path` |
| 멀티에이전트/RAG 부재(ⓖ) | 아키텍처 테스트 | not_implemented → P2 | `no_multiagent_rag` |
| manifest 정직성 | 테스트 | enforced | `manifest_honesty` |
| manifest 자기검증 | 테스트 | enforced | `manifest_selfcheck` |
| manifest 정본 파생(SSOT=이 표) + make verify 일치검증 | 테스트 | enforced | `manifest_derivation` |
| CLAUDE.md 금지선 색인 ↔ (A) §1.3/§3 일치를 기계 검사 | 테스트 | not_implemented → 2주차 | `claude_md_sync_check` |
| fixture 마스커에 송신·소켓·egress 의존 0 | 아키텍처 테스트 | not_implemented → fixture 마스커 구현 시 | `masker_no_send` |

### 3.2 A. 입력경계
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| 엔진 Burp/Montoya import 0 | 아키텍처 테스트 | enforced | `engine_burp_isolation` |
| Java에 분석·판정·프롬프트·취약점 로직 금지 (capture / transport / ui만) | 아키텍처 테스트 | not_implemented → Java 연결 시 | `java_logic_isolation` |
| 입력은 스키마 통과분만 | 스키마/validator | enforced | `input_schema_gate` |
| 봉투 len==1(single) | validator | enforced | `envelope_arity` |
| raw path에 리터럴 '?' 없음(쿼리는 query_params로만) | 스키마/validator | enforced(검증 함수 단위 — 입력 스키마) | `path_no_query_string` |
| 인증 선행 — 함수 미호출 + 코드 물리분리 | 테스트 | enforced | `auth_precedence_noinvoke` |
| 엔진(src/sentinel)이 tools/를 import하지 않음 | 아키텍처 테스트 | not_implemented → fixture 마스커 구현 시 | `engine_tools_isolation` |
| 마스커가 sentinel.pipeline.sanitization_check를 import하지 않음 | 아키텍처 테스트 | not_implemented → fixture 마스커 구현 시 | `masker_independence` |

### 3.3 B. 민감정보경계
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| 원본 생문자열 유입 불가(MaskedRef 타입) | 타입 레벨 | enforced | `maskedref_typing` |
| Sanitization 독립 재검증 | 테스트 | enforced(값 재검증) | `sanitization_trust` |
| 영수증 HMAC 서명 | validator | not_implemented → Java 연결 시 | `receipt_hmac` |
| 비밀값 커밋 금지 | CI(pre-commit) | enforced(클라이언트 훅 + make verify 전수스캔; 서버측 CI 강제는 미구현) | `secret_scan_hook` |
| 원본 트래픽 미기록(기능 부재) | 테스트 | enforced | `no_raw_persistence` |
| 감사 로그 존재 | 테스트 | enforced | `audit_log_present` |
| 인증실패 로그 위생 | 테스트 | enforced | `authfail_log_hygiene` |
| 감사 기록 실패 시 fail-closed | 테스트 | not_implemented → 수용 요청 감사(B-6) 범위 확정 시 | `audit_write_failure` |
| Body 불변식 1~6을 ③에서 검증 | validator+테스트 | enforced(검증 함수 단위 — ③, 불변식 5는 같은 kind 안) | `masked_span_integrity` |
| 라벨 양방향 동치 — 생산자 강제, Python 런타임 보장 아님 | 테스트 | not_implemented → fixture 마스커 구현 시 | `label_consistency` |

### 3.4 전 층위 공통
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| main 직접 병합 금지 | CI(branch protection) | unverifiable(레포 설정) | `branch_protection` |

### 3.5 C·E (출력·검증)
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| evidence≥1(0개 거부=환각차단) | 스키마/validator | enforced(검증 함수 단위) | `evidence_min_one` |
| evidence.transaction_ref ∈ analyzed_refs | validator | enforced(검증 함수 단위) | `evidence_ref_integrity` |
| Evidence.pointer(Locator)가 마스킹 후 데이터에서 해석됨(해석 실패 시 전체 폐기) | validator+테스트 | enforced(검증 함수 단위) | `evidence_pointer_resolves` |
| status 서버부여·LLM 생성불가 | validator | enforced(검증 함수 단위) | `server_assigned_status` |
| category 폐쇄형 enum | 스키마 | enforced(검증 함수 단위) | `category_closed_enum` |
| 출력 스키마 전체(파생 롤업) | 파생(하위 4키 AND) | derived † | `output_schema_gate` |
| hypothesis 단정 토큰 차단 | 테스트 | not_implemented → 5번 평가 데이터로 기준 확정 시 | `assertive_token_guard` |
| observation 재대조 | 테스트 | not_implemented → 5번 평가 데이터로 기준 확정 시 | `corroboration_check` |
| 환각 리터럴 격리 | 테스트 | not_implemented → 3주차 | `hallucinated_literal_isolation` |
| 반복 이상 → 세션 신호 | 테스트 | not_implemented → 3주차 | `anomaly_aggregation` |
| 평가 하네스 | 테스트 | not_implemented → 평가 하네스 구현 시 | `eval_harness` |
| 정규화 함수 — 같은 값을 가리키는 서로 다른 Locator가 같은 CNA로 정규화됨 | 테스트 | not_implemented → 정규화 함수 구현 시 | `canonical_address` |
| 엔진(src/sentinel)이 평가 라벨 경로를 읽지 않음(데이터 읽기 금지 — `engine_tools_isolation`의 코드 import 금지와 다른 격리) | 아키텍처 테스트 | not_implemented → 평가 하네스 구현 시 | `label_isolation` |
| 동결 픽스처가 현재 스키마로 검증되지 않으면 버전 증가 없이 실패(큐 12) | 테스트 | not_implemented → 데이터셋 첫 동결 시 | `dataset_version_freeze` |

> **† `output_schema_gate` (파생 롤업):** `evidence_min_one ∧ evidence_ref_integrity ∧ server_assigned_status ∧ category_closed_enum`. 자체 강제테스트 없음 — 하위 4키가 강제한다. 하위 전부 enforced일 때만 enforced다. 하위 4키가 enforced(검증 함수 단위)이므로 파생값도 enforced이며, 범위도 같다(§3.5 각주). `guardrails.yaml` 파생 시 `status=derived` + 하위 키 목록으로 표현한다(상태 칸은 문장이 아니라 기계 파싱 가능한 상태값).

> **2주차 enforced 범위:** 2주차 enforced 범위 = 검증 함수 단위(주입 테스트). 유일 통로 결선은 LLM 연동 PR에서 별도 증명.

### 3.6 1주차 적대적 테스트 (Java 없이 직접 주입 — '위조 거부'로 증명)
| 공격 케이스 | 기대 동작 |
|---|---|
| `applied:true`인데 본문에 토큰 생문자열 잔존 | ③ 재검증이 거부 |
| 토큰 없음 / 토큰 위조 | ① 본문 파싱 전 거부(함수 미호출) |
| 스키마는 맞고 sanitization 필드만 거짓 | ③ 거부 |
| 봉투 single인데 transactions 2개 | ② validator 거부 |

> **원칙:** 안전 불변식은 '정상 통과'가 아니라 **'위조 거부'**로 증명한다. Java가 없으므로 적대적 입력을 손으로 만들어 넣는다. (단, 이 테스트는 Python의 거부만 증명하며, Java의 실제 마스킹은 Java 연결 후 통합 테스트로 별도 증명.)

---

## 4. 기각된 대안 (REJECTED — 닫힌 문, 재론 조건 없이 다시 열지 말 것)

| 코드 | 기각된 대안 | 사유 | 재론 조건 |
|---|---|---|---|
| R-1 | 처음부터 독립 솔루션(프록시 코어부터) 개발 | 1인 범위 초과, 금융 도입 절차 | MVP 성능 검증 후 |
| R-2 | AI가 Intruder 자율 제어·연속 공격 | 금융 비파괴 원칙 위반 | 관문2 정책엔진+심의 후 |
| R-3 | 과거 취약점을 LLM에 파인튜닝/학습 | 데이터 거버넌스, 비용 | RAG 검증 후 별도 판단 |
| R-4 | 사내 실데이터로 MVP 시작 | A-5, 신입 데이터 접근 현실 | 작동 데모 → 심의 통과 후 |
| R-5 | 멀티에이전트 프레임워크(LangChain 등) 초기 도입 | 디버깅·관측성 비용, 1인 부적합 | P4 이후 |
| R-6 | Burp AI / Shadow Repeater 기능 재구현 | 이미 네이티브 존재, 재발명 | 없음 |
| R-7 | Burp AI 플랫폼(외부 전송) 사용 | 폐쇄망 egress 금지 | 없음 |
| R-8 | P0는 단일 tx, P1에서 최상위 wrapper로 shape 변경 | breaking change | 없음(봉투로 대체) |
| R-9 | confidence를 LLM 자유숫자 또는 low/med/high | 검증 안 된 주관적 확신에 가짜 권위 | 등급별 적중률 실측 후 |
| R-10 | `.gitignore`만으로 원본 미기록 보장 | 디스크 쓰기 못 막음 | 없음(기능 부재+검증으로 대체) |
| R-11 | `applied==true` 불리언만 믿고 fail-closed | 위조 가능, 단일 실패점 | 없음(Python 독립 재검증으로 대체) |

---

## 5. 설계 원칙 요약 (불변)
1. **계약은 동결, 구현은 단계별로.** 필드·의미는 고정, 구현 시점은 분리.
2. **안전 불변식은 미룰 수 없다.** 민감정보 보호·참조 무결성·허용 카테고리·서버 상태 제어는 첫 골격부터.
3. **미구현을 안전으로 오인 금지.** not_implemented 기능을 '보장됨'으로 주장하면 빌드 실패(manifest 정직성).
4. **테스트 통과 ≠ 모든 상황에서 차단.** 외부 의존 통제는 unverifiable로 정직 표시.
5. **안전 검토 중단이 아니라, 중심을 문서 → 통과하는 테스트로 이동.**
6. **AI는 가설 제시, 검증 엔진·사람은 근거 확인.** 자율 공격보다 분석 품질·검증 가능성 우선.
7. **정본은 가장 많은 자동 강제가 닿는 곳에 둔다.** 문서 정본도 레포에 두고, 외부 발행본은 스냅샷으로 표시한다(기계가 못 하는 동기화를 기계인 척하지 않는다).

---

## 6. 평가 프로토콜 (FROZEN)
> 평가 하네스(`eval_harness`)가 구현할 판정·데이터셋·지표의 정본. 하네스 구현은 이후 별도 작업이다.

### 6.1 판정 단위
- **TP·중복 처리 단위 = CNA**(§2.6). range는 판정에 넣지 않는다(힌트).
- **서버 중복 처리:** Finding끼리 (category, CNA 집합)이 정확히 같을 때만 병합한다. 겹침 병합은 금지한다. advisory의 CNA 집합이 어떤 finding과 같으면 advisory를 버린다. (= §2.4 중복 처리, 상호 참조)
- **평가 매칭:** 정답 라벨 V = {categories(집합), anchors(CNA 집합)}.
  - 예측 p가 V와 매칭 = `p.category ∈ V.categories` ∧ `p.CNA ∩ V.anchors ≠ ∅`.
  - 1:1 최대 매칭(결정론적 동점 처리). 매칭 안 된 p = FP, 매칭 안 된 V = FN.
  - 채점 대상 = 서버 중복 처리를 거친 출력.
  - 평가기는 엔진의 CNA 정규화 함수(§2.6, `canonical_address`)를 쓴다 — 서버 중복 처리와 같은 함수다(평가기 → 엔진 import는 허용 방향).
  - advisory_signals는 P/R 채점 대상이 아니다(탐지가 아니다 — §2.4). advisory 지표는 따로 정한다.
- **라벨링 지침:** 더 세밀한 노드가 있으면 거친 노드(body_text·req_line.path)를 anchor로 쓰지 않는다(자석 노드가 FP를 TP로 둔갑시킨다).

### 6.2 데이터셋
- **두 집합:** S(자체 더미 API, 라벨 완전) / J(Juice Shop, 라벨 불완전). 지표를 합산하지 않는다.
- **라벨 상태 셋:** labeled_positive / verified_clean / unlabeled.
  - unlabeled 위의 예측은 FP가 아니라 '미판정'으로 따로 집계한다. 정상 FP율은 verified_clean에서만 잰다.
- **S 라벨의 출처:** 더미 API 정의에서 파생한다(SSOT). 라벨마다 source: construction | catalog | adjudication.
- **hard negative:** S는 category마다 hard negative를 둔다.
- **블라인드·버전 동결:** 모델 첫 실행 전에 라벨을 동결한다. 재심은 새 데이터셋 버전으로만 한다(실행 중 수정 금지, 흔적은 source=adjudication). 지표는 데이터셋 버전과 함께 보고한다.
- **dev/test 분리:** 엔드포인트 단위로 분리한다. 튜닝은 dev에서만, test는 회귀 판정에만 쓴다.
- **라벨 격리:** 라벨 파일은 픽스처와 분리하고 평가기만 읽는다. 엔진은 라벨 경로를 읽지 않는다(`label_isolation`).
- **표본 부족 표기:** §6.3 J8을 따른다.
- **동결 = 첫 소비자 발생:** 그 시점의 형태가 schema_version의 동결 형태로 확정된다(버전을 올리는 것이 아니다. 버전은 동결 이후 첫 변경에서 오른다 — §2 버전 규칙). 큐 12(`dataset_version_freeze`) 강제 장치를 동결과 같은 PR에서 만든다.
- **한계 기록:** IDOR 사례는 relation_preserving + 한 배치 안에서 생성한다(라벨 일관성은 배치 안에서만, §2.3). 단일 라벨러(J)라 라벨러 간 일치도는 측정할 수 없다 — 팀 확장 시 이월.

### 6.3 지표
- **J1 P/R:** §6.1 매칭 규칙. Precision 대표값은 S에서만 낸다. J는 알려진 라벨 기준 Recall + 미판정 건수. category별 + 전체 micro. 대표 = S / 현실성 = J, 섞어 보고하지 않는다.
  - 대표 지표 = 엄격 매칭(위치 + category).
  - 보조 지표 = 위치만 일치(category 무관)한 P/R + category 혼동 행렬.
  - category는 맞혔으나 위치가 틀린 예측은 어느 쪽 지표에도 TP로 들어가지 않는다(매칭 불성립).
  - 정당하게 두 category에 걸치는 결함은 V.categories를 집합으로 둔다.
- **중복:** 매칭 후 남은 중복 예측은 FP로 센다(1:1 매칭에서 둘째 예측은 자연히 FP). 이와 별도로 중복률을 진단 지표로 보고한다.
- **J2 output_rejected 트랜잭션:** 그 라벨은 전부 FN이다(제외 금지). 거부율은 별도 보고한다.
- **J3 정상 오탐률** = verified_clean 중 finding ≥ 1인 비율. hard negative 부분집합은 별도 보고한다.
- **J4 검증 가능한 결과 비율** = 중복 처리 후 finding 중 corroboration=matched가 1개 이상인 비율. `corroboration_check` 구현 전에는 not_run으로 표기하고 숫자를 내지 않는다.
- **J5 분석 시간 절감률:** 1인 단계에서는 보류한다(unverifiable 성격). 숫자화하지 않는다.
  - 근거: 정답을 아는 사람이 잰 수동 시간은 거짓 보장이다. 팀 확장 시 결함 목록을 모르는 점검자 대상, 교차 배치, 트랜잭션 풀 분할, 시간은 정확도와 함께 보고 — 프로토콜로 이월.
- **J6 AI 기여도:** 규칙 단독 vs 규칙+LLM ablation(같은 데이터셋, ΔP·ΔR), produced_by별 P/R, LLM만 찾은 TP 수.
- **J7 불확실성:** 비율은 Wilson 95% 구간. 버전 간 비교는 트랜잭션 단위 쌍체 bootstrap. 대표 지표에서 차이 구간이 통째로 0 아래면 회귀이고, 개선 주장도 같은 기준을 쓴다.
- **J8 최소 표본:** Wilson 구간 반폭 ≤ 0.15일 때만 점추정값을 낸다. 그보다 넓으면 "표본 부족(n=k)" + 구간. 0.15는 초기 임계값이다(설정값 — `DEFAULT_PORT`와 같은 성격(실측으로 조정 가능, 정본이되 불변식 아님)).
- **J9 보고 머리:** 데이터셋 버전·집합(S/J)·분할(dev/test)·model_id·prompt_version·ruleset_version.

---

## 부록 — 확정된 기술 스택
- Extension: Java 17+ / Montoya API / Gradle (레거시 Jython/Extender 미사용)
- 분석 서버: Python 3.11+ / FastAPI / Pydantic
- 구조화 출력: instructor 또는 PydanticAI (LangChain 아님)
- RAG(나중): sentence-transformers + sqlite-vec/FAISS (전부 로컬)
- 저장소: SQLite
- 평가: pytest 하네스 + 라벨 데이터셋 (선택적 promptfoo)
- 테스트 환경: Docker + OWASP Juice Shop (+ 정답 아는 자체 더미 API)
- LLM 전략: 개념 검증은 강한 모델(큰 로컬 또는 비민감 한정 승인 API) → 사내 승인 모델로 포팅. 교체 가능 인터페이스 필수. **(4번 주제에서 확정 예정)**