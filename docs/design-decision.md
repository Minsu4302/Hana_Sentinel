# (A) 설계확정서 v1.2 — Sentinel Harness

> **정본 선언:** 이 문서(레포 `docs/design-decision.md`)가 (A) 설계확정서의 **유일 정본**이다.
> 불변식·금지선·스키마의 '결정된 값'은 여기 FROZEN 블록이 정본이고, (B)·CLAUDE.md·`guardrails.yaml`·manifest는 전부 여기서 파생·추출된다. 값 변경은 이 문서 한 곳에서만.
> claude.ai 프로젝트 docs의 「설계확정서」 페이지는 이 정본의 **발행 시점 스냅샷(사람 열람용)**이며, **불일치 시 레포(이 문서)가 정본**이다.
> 정본을 레포에 두는 이유: CI·PR·Claude Code 등 모든 자동 강제가 레포에 닿는다. claude.ai는 파이프라인 밖이라 정본이 될 수 없다(기계가 못 하는 동기화를 기계인 척하지 않는다).
>
> **문서 성격:** 합의기록형. 사람(미래의 민수, 사내 보안 심의관, AI 연구소)이 읽는다. "무엇을 정했나"와 **"왜 그렇게 정했나"**(트레이드오프·기각 대안 포함)를 담는다. 실행용 건조한 사양은 (B) `docs/claude-code-handoff.md`에 있다.
>
> **버전:** v1.2 = {범위 + 데이터계약(+ExecutionResponse) + 가드레일 매핑표 v1.2(통합점검 구멍5 반영)}. 4번(LLM 전략)·5번(평가)은 이후 증분.
> **버전 이력:** v1.0(범위+데이터계약+가드레일 골격) → **v1.2**(통합점검 구멍5: ① evidence 불변식 1:1 분해, ② manifest SSOT 파생키 `manifest_derivation`, ③ ⓓⓔⓖ 매핑표 추적, ④ `audit_write_failure` 자리, ⑤ `ExecutionResponse` 정식 편입).
> 확정일: 2026-10-22

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

---

## 2. 데이터 계약 v0.1 (FROZEN)

세 스키마로 분리 관리한다. **마스킹 정책 ≠ 입력 스키마** — 분리해야 마스킹 규칙 변경이 분석 계약을 건드리지 않는다.

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
├─ request:  { method, scheme(http|https), host, port, path(원본),
│              query_params:[Param], headers:[Header], body: Body }
└─ response: { status, headers:[Header], body: Body,
               elapsed_ms(int|null) }   # ★시간기반 SQLi 탐지에 사용 금지(제외 카테고리)

Param  = { name, value: str|MaskedRef, location(query|form|json|path) }
Header = { name, value: str|MaskedRef }
Body   = { content_type, size_bytes(원본크기), truncated(bool),
           encoding(utf8|base64|omitted), content(str|null) }
```
- **Java는 구문 파싱만.** `path_template`, 'ID스러운 파라미터' 분류, 반사 표식 등 **해석 필드는 Python이 내부 파생**(A-3/A-4).
- `host` 가명화 여부는 TransactionSchema가 아니라 SanitizationPolicy가 결정(관심사 분리).
- **body truncation 상한:** req 64KB / resp 256KB(config화). 초과 시 `truncated=true` + head+tail 일부 보존(에러·민감필드가 응답 꼬리에 자주 옴). truncated에서 파생된 finding은 자동으로 `limitations`에 "본문 일부만 분석됨" 플래그.
- **multipart/바이너리:** 텍스트 파트(파일명·주장 content-type·동반 JSON)는 구조화 보존, 바이너리 파트만 `omitted`. `omitted = 본문 미전송 + Java 원본 즉시 폐기`.

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
└─ redacted_kinds: [token|cookie|pii|host]   # 종류별 카운트(값은 없음, 감사용)

MaskedRef = { masked: true, label: "principal_01"|null, kind: "token|cookie|pii|host" }
```
- **가명화:** HMAC-SHA-256(key, 원본값) → 짧은 라벨. Python으로는 라벨만. 원본값은 Java 경계를 넘지 않음.
- **키·매핑 테이블:** 프로세스 메모리 전용. 디스크·로그·예외 메시지 기록 금지. **일관성 범위 = 분석 배치 단위**(→ 키 영속화 불필요, 평가 재현성과 보안 트레이드오프 해소).
- **기본 모드 = strict_redaction.** relation_preserving은 IDOR/BOLA 세션에서만 opt-in.
- **2단계 적용:** Java(transport 보호 — 고정 화이트리스트 헤더 치환) + Python(정밀 — body PII 스캔, 가명화 일관성, object_id 민감성 판정).

> **신뢰 경계 (★구현 전 반드시):** `applied==true`는 요청자가 쓰는 주장일 뿐이다. **Python은 '마스킹됐다는 주장'을 믿지 말고 '마스킹됐음을 스스로 재검증'한다.** 수신 데이터에 토큰·쿠키·키 생문자열이 남았는지 Python이 독립 재스캔 → 발견 시 `applied` 값과 무관하게 거부(영수증≠데이터면 데이터를 믿고 거부). **전송 전 보호(Java, 1차)와 수신 후 재검증(Python, 2차 방어선)은 다른 보장이며, 재검증은 1차를 대체하지 않는다.** 패턴 검사는 '정책에 정의된 패턴'만 탐지하며 '모든 비밀값 부재'를 증명하지 않는다(불투명 세션 ID는 일반 문자열과 구분 불가).

### 2.4 AnalysisResultSchema (출력 — LLM 환각을 계약으로 차단)
```
AnalysisResult
├─ schema_version : "1.0"
├─ analyzed_refs  : [UUID]            # 이번 분석이 참조한 transaction_id
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
├─ severity_if_true?: enum            # 사실이라면의 위험도(사실성과 무관). 확신도 아님
├─ status     : enum(unverified|verifying|confirmed|false_positive|needs_review)
│               # ★LLM은 생성 불가. 서버가 unverified 부여. 승격은 ReviewEvent로만
├─ produced_by: enum(rule|llm|hybrid) # AI 기여도 분리 측정(평가 테제)
├─ limitations: [str]
└─ next_steps : [{type: "verification", action, rationale}]   # 도구는 실행 안 함

Evidence
├─ transaction_ref(UUID)   # transaction_id로만 참조(host 문자열 금지). analyzed_refs에 포함돼야 함
├─ locus(req_line|req_header|req_param|req_body|resp_status|resp_header|resp_body)
├─ pointer(str)            # locus별 고정 표기(헤더명/param+location/JSONPath/범위)
├─ observation(str)        # 관측 사실(해석 아님). 가명 라벨 그대로 인용 가능
├─ corroboration: matched|unmatched|not_checkable
├─ anomaly_flags: [...]    # 서버 재대조 로직이 생성(LLM 아님). 예: hallucinated_literal_suspected
└─ review_required(bool)

AdvisorySignal = { type:"out_of_scope_advisory", topic, basis:[Evidence], suggestion }
```
- **status 승격:** ReviewEvent(사람 판정 + 시각 + 사유) append → current_status는 파생·재계산 가능. LLM 응답에서 status **필드 자체를 제외**하고 서버가 unverified 부여.
- **evidence 무결성:** transaction_ref ∈ analyzed_refs + locus 유효 + pointer/observation이 **마스킹 후 데이터로 검증 가능** + observation 핵심 주장이 실제 발견되는지 재대조.
- **환각 리터럴 격리:** 재대조 실패 + 민감패턴 의심 → `hallucinated_literal_suspected`(서버 생성, '날조 확정' 아니라 '경계 이상 의심'). 의심 문자열 미저장·미로그·집계 원문 제외. 플래그 달린 evidence는 유효근거 카운트 제외 → 유효 evidence 0이면 finding 자동 needs_review/폐기.
- **중복 처리:** 같은 (transaction_ref, locus, topic/category)는 병합, finding이 advisory보다 우선. 평가 TP/FP 채점 = 중복 제거 후.

### 2.5 ExecutionResponse (분석 실행 상태 — AnalysisResult와 구분)
```
ExecutionResponse = { analysis_status, skipped_reasons: [str], manifest_snapshot }
```
> **왜 분리?** `findings:[]`가 "분석 완료·깨끗함"인지 "아직 분석 안 함"인지 혼동 금지. **분석 안 함 ≠ 분석 후 취약점 없음.** 평가의 '정상 사례 정확도'가 이 구분에 의존한다. 1주차 골격은 이 타입만 반환한다.

---

## 3. 가드레일 — 강제 매핑표 v1.2 (FROZEN)

> 이 표가 **가드레일의 단일 출처(SSOT)**다. capability manifest는 이 표에서 기계 파생되며(`manifest_derivation`), 생성물과 정본의 일치를 CI가 검증한다.
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
**감사 기록 실패 시에도 fail-closed**(기록 못 하면 통과시키지 말고 거부) — 2주차.

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
| 토큰 강화(회전·수명) | validator | not_implemented → 2주차 | `token_hardening` |
| 자동 수정반영 부재(ⓓ) | 아키텍처 테스트 | enforced | `no_autopatch_apply` |
| 파인튜닝 경로 부재(ⓔ) | 아키텍처 테스트 | enforced | `no_finetune_path` |
| 멀티에이전트/RAG 부재(ⓖ) | 아키텍처 테스트 | not_implemented → P2 | `no_multiagent_rag` |
| manifest 정직성 | 테스트 | enforced | `manifest_honesty` |
| manifest 자기검증 | 테스트 | enforced | `manifest_selfcheck` |
| manifest 정본 파생(SSOT=이 표) + CI 일치검증 | 테스트 | enforced | `manifest_derivation` |

### 3.2 A. 입력경계
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| 엔진 Burp/Montoya import 0 | 아키텍처 테스트 | enforced | `engine_burp_isolation` |
| 입력은 스키마 통과분만 | 스키마/validator | enforced | `input_schema_gate` |
| 봉투 len==1(single) | validator | enforced | `envelope_arity` |
| 인증 선행 — 함수 미호출 + 코드 물리분리 | 테스트 | enforced | `auth_precedence_noinvoke` |

### 3.3 B. 민감정보경계
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| 원본 생문자열 유입 불가(MaskedRef 타입) | 타입 레벨 | enforced | `maskedref_typing` |
| Sanitization 독립 재검증 | 테스트 | enforced(값 재검증) | `sanitization_trust` |
| 영수증 HMAC 서명 | validator | not_implemented → 2주차 | `receipt_hmac` |
| 비밀값 커밋 금지 | CI(pre-commit) | enforced | `secret_scan_hook` |
| 원본 트래픽 미기록(기능 부재) | 테스트 | enforced | `no_raw_persistence` |
| 감사 로그 존재 | 테스트 | enforced | `audit_log_present` |
| 인증실패 로그 위생 | 테스트 | enforced | `authfail_log_hygiene` |
| 감사 기록 실패 시 fail-closed | 테스트 | not_implemented → 2주차 | `audit_write_failure` |

### 3.4 전 층위 공통
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| main 직접 병합 금지 | CI(branch protection) | unverifiable(레포 설정) | `branch_protection` |

### 3.5 C·E (출력·검증 — 목표층위 예약, 1주차 미구현)
| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |
|---|---|---|---|
| evidence≥1(0개 거부=환각차단) | 스키마/validator | not_implemented → 2주차 | `evidence_min_one` |
| evidence.transaction_ref ∈ analyzed_refs | validator | not_implemented → 2주차 | `evidence_ref_integrity` |
| status 서버부여·LLM 생성불가 | validator | not_implemented → 2주차 | `server_assigned_status` |
| category 폐쇄형 enum | 스키마 | not_implemented → 2주차 | `category_closed_enum` |
| 출력 스키마 전체(파생 롤업) | 파생(하위 4키 AND) | derived (→2주차) † | `output_schema_gate` |
| hypothesis 단정 토큰 차단 | 테스트 | not_implemented → 2주차 | `assertive_token_guard` |
| observation 재대조 | 테스트 | not_implemented → 2주차 | `corroboration_check` |
| 환각 리터럴 격리 | 테스트 | not_implemented → 3주차 | `hallucinated_literal_isolation` |
| 반복 이상 → 세션 신호 | 테스트 | not_implemented → 3주차 | `anomaly_aggregation` |
| 평가 하네스 | 테스트 | not_implemented → 5번 주제 | `eval_harness` |

> **† `output_schema_gate` (파생 롤업):** `evidence_min_one ∧ evidence_ref_integrity ∧ server_assigned_status ∧ category_closed_enum`. 자체 강제테스트 없음 — 하위 4키가 강제한다. 하위 전부 enforced일 때만 enforced이며, 현재 하위 전부 not_implemented이므로 파생값도 미구현(→2주차). `guardrails.yaml` 파생 시 `status=derived` + 하위 키 목록으로 표현한다(상태 칸은 문장이 아니라 기계 파싱 가능한 상태값).

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

## 부록 — 확정된 기술 스택
- Extension: Java 17+ / Montoya API / Gradle (레거시 Jython/Extender 미사용)
- 분석 서버: Python 3.11+ / FastAPI / Pydantic
- 구조화 출력: instructor 또는 PydanticAI (LangChain 아님)
- RAG(나중): sentence-transformers + sqlite-vec/FAISS (전부 로컬)
- 저장소: SQLite
- 평가: pytest 하네스 + 라벨 데이터셋 (선택적 promptfoo)
- 테스트 환경: Docker + OWASP Juice Shop (+ 정답 아는 자체 더미 API)
- LLM 전략: 개념 검증은 강한 모델(큰 로컬 또는 비민감 한정 승인 API) → 사내 승인 모델로 포팅. 교체 가능 인터페이스 필수. **(4번 주제에서 확정 예정)**