# (A) 설계확정서 v1.42 — Sentinel Harness

> **정본 선언:** 이 문서(레포 `docs/design-decision.md`)가 (A) 설계확정서의 **유일 정본**이다.
> 불변식·금지선·스키마의 '결정된 값'은 여기 FROZEN 블록이 정본이고, (B)·CLAUDE.md·`guardrails.yaml`·manifest는 전부 여기서 파생·추출된다. 값 변경은 이 문서 한 곳에서만.
> claude.ai 프로젝트 docs의 「설계확정서」 페이지는 이 정본의 **발행 시점 스냅샷(사람 열람용)**이며, **불일치 시 레포(이 문서)가 정본**이다.
> 정본을 레포에 두는 이유: CI·PR·Claude Code 등 모든 자동 강제가 레포에 닿는다. claude.ai는 파이프라인 밖이라 정본이 될 수 없다(기계가 못 하는 동기화를 기계인 척하지 않는다).
>
> **문서 성격:** 합의기록형. 사람(미래의 민수, 사내 보안 심의관, AI 연구소)이 읽는다. "무엇을 정했나"와 **"왜 그렇게 정했나"**(트레이드오프·기각 대안 포함)를 담는다. 실행용 건조한 사양은 (B) `docs/claude-code-handoff.md`에 있다.
>
> **버전:** v1.42 = {범위(+ 금지선 강제 매핑 §1.4) + 데이터계약(+ExecutionResponse, redacted_kinds 명확화, 출력 계약 보정·버전 규칙, 공용 타입 §2.6·본문 마스킹 표기·라벨 규칙, 정규 노드 주소 CNA·중복 처리, 마스킹 전 원본 RawTransaction) + 가드레일 매핑표 v1.21(통합점검 구멍5 반영 + v1.3 교정 + v1.4 이월처 재조정·tools/ 규칙 + v1.5 출력 게이트 4키 승격 + v1.6 마스킹·라벨·마스커 독립성 키 + v1.7 Evidence 위치 해석 승격 + v1.8 정규 주소·path 쿼리 금지 키 + v1.9 path 쿼리 금지 승격 + v1.10 본문 마스킹 표기 승격 + v1.11 평가 키 + v1.12 원본 타입 격리 키 + v1.13 마스커 격리 승격 + v1.14 라벨·CNA 승격 + v1.15 데이터셋 동결 키 + v1.16 평가 하네스 승격 + v1.17 tools 송신 기준선 + v1.18 색인 동기화 검사 + v1.19 상태 열 머리 + v1.20 색인 설명 문구 검사 + v1.21 completed 경로 키 + v1.22 completed 경로 승격 + v1.23 completed 경로 불변 범위 노트 + v1.24 층 B 러너 노트 + v1.25 S v2 동결 키 + v1.26 S v2 생성기 승격 + v1.27 어댑터 송신 경로 키 + v1.28 어댑터 승격 + v1.29 결선 키 + v1.30 결선 L1 승격 + v1.31 푸시 게이트 + v1.32 결선 L2 승격 + v1.33 L3 선행 계약 + v1.34 결선 L3 승격)} + 평가 프로토콜 §6. 4번(LLM 전략)은 이후 증분.
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
> **v1.13 (매핑표 v1.12):** §2.7 RawTransaction 신설(§2.2 Transaction의 마스킹 전 쌍 — RawParam·RawHeader·RawBody, 타입은 tools/ 아래에만) + §1.3 ⓕ 해석 두 줄(금지선 문구 불변) + §3.2 신규 키 `engine_no_rawtransaction`(not_implemented).
>   - RawTransaction 1.0 정의 — 소비자 0(첫 소비자 = fixture 마스커, 마스커-A). Envelope·AnalysisResult `schema_version` 값 변화 없음.
> **v1.14 (매핑표 v1.13):** 마스커-A — §3.1 `masker_no_send`, §3.2 `engine_tools_isolation`·`masker_independence`·`engine_no_rawtransaction` 승격(not_implemented → enforced, 증명은 같은 PR). `engine_no_rawtransaction`은 (ㄱ) 독립 enforced로 결정(§3.2 근거 주석). §2.7 배치 문장과 §3.2 근거 주석의 '현재 not_implemented'·'지금 결정 아님' 표현을 승격 결과에 맞게 갱신. RawTransaction 1.0 첫 소비자 발생(fixture 마스커) — 이 시점의 형태가 동결 형태. Envelope·AnalysisResult `schema_version` 값 변화 없음.
> **v1.15 (매핑표 v1.14):** 마스커-B1 — 규칙 명문화(모드가 라벨 유무를 결정: strict_redaction → label=null / relation_preserving → ref_NN 순번) + §2.3 body_rules matcher 문법(json:<키 glob> 모든 깊이 / form:<이름 glob>, 마스커·Java 공유 계약) + §3 `label_consistency`(relation_preserving 출력에만)·`canonical_address`(모드 무관) 승격(not_implemented → enforced, 증명은 같은 PR). §2.3 라벨 규칙 첫 줄에 '(relation_preserving에서)' 한정.
>   - 라벨 모드 규칙은 확인이 아니라 새 규칙이다(이전 (A)에는 모드와 라벨 null의 관계가 없었다 — 마스커-A 이월). MaskedRef `label: "ref_NN" | null`(§2.6)·§6.2 IDOR 사례 = relation_preserving과 정합.
>   - Envelope·AnalysisResult `schema_version` 값 변화 없음.
> **v1.16 (매핑표 v1.15):** 마스커-B3 — 데이터셋 첫 동결(S v1). §6.2 LabelFile·Label 스키마(masking_modes·hard_negative 포함)·라벨 무결성·첫 동결 구성 + §3.5 `dataset_version_freeze` 승격, 신규 `dataset_engine_regression`·`dataset_mode_consistency`(enforced, 증명은 같은 PR).
>   - 첫 소비자 발생: Envelope 1.0·LabelFile 1.0의 동결 형태가 이 시점에 확정된다(버전 숫자를 올리는 것이 아니다 — 이후 변경은 '소비자 있음' 규칙). RawTransaction 1.0의 첫 소비자는 이미 마스커-A(v1.14)에서 생겼다 — 동결 파일은 없고(원본 커밋 0) 버전만 frozen_against에 기록한다.
> **v1.17 (매핑표 v1.16):** 평가 하네스 — §6.1 동점 처리 규칙을 정본 값으로(사전순 최소 최대 매칭, 정렬 키, CNA 전순서, finding_id 한계) + §3.5 `eval_harness`·`label_isolation` 승격(not_implemented → enforced, 범위는 상태 칸 노트, 증명은 같은 PR).
>   - `eval_harness` enforced = 채점기 검증(층 A)까지다. 실제 모델 채점(층 B)은 모델 결선 이후 — 하네스 완성 ≠ 실제 측정 가능.
> **v1.18 (매핑표 v1.17):** 4번 0번 결정 응고 — egress 0 유지. §1.3 ⓑ 해석(목적지 기준, src·tools·tests 강제 매핑, 현 단계 LLM = 루프백 로컬, 품질 수치는 재론 근거 아님 — 금지선 문구·재론 조건 불변) + §3.1 신규 `tools_no_external_send`(enforced) + §3 목표 칸 정리(`hallucinated_literal_isolation`·`anomaly_aggregation` → LLM 결선 시, `claude_md_sync_check` → CLAUDE.md 금지선 색인 다음 개정 시) + §6.2 독립 단위 규칙 (i) + §3.5 신규 `dataset_case_independence`(not_implemented) + 부록 LLM 전략 줄 교체. `schema_version` 값 변화 없음.
>   - 테스트 egress 가드를 tools/에서 tests/support로 옮겼다(로직 변경 0) — 소켓을 바꿔 끼워 '막는' 코드라 tools/ 송신 검사에 걸렸고, ⓑ 강제 매핑상 tests 쪽(`egress_runtime_block`)이 제자리다.
>   - 같은 매핑표 버전(v1.17) 안의 보강: `tools_no_external_send`에 tools → tests 패키지 import 금지를 더했다 — 옮긴 가드를 tools/가 다시 import해 송신 검사를 세탁하는 경로를 막는다(가드 이동과 인과).
> **v1.19 (매핑표 v1.17 유지):** §1.4 금지선 강제 매핑 신설(CLAUDE.md 금지선 색인의 정본 — N1~N10 × 정의처 × 강제 키, N5는 키 없음 명시). §3·CLAUDE.md·`schema_version` 변화 없음. CLAUDE.md 색인 갱신과 `claude_md_sync_check` 구현은 v1.20(같은 PR)에서.
> **v1.20 (매핑표 v1.18):** CLAUDE.md 금지선 색인을 §1.4에 맞춰 갱신(꼬리 형식 `→ 정의처: … · 키: …(§3.x)`, N5 '키: 없음') + §3.1 `claude_md_sync_check` 승격(not_implemented → enforced, 증명은 같은 PR — 이 PR이 그 키의 목표 사건) + §1.4 머리 문장의 구현 상태 갱신. §1.4 표 내용·`schema_version` 변화 없음.
> **v1.21 (매핑표 v1.19):** §3.1~§3.5 표 머리 '1주차 상태' → '상태'(열 머리만 — 다른 열·행 변화 없음, 파서는 옛 머리를 오류로 처리). `guardrails.yaml` 필드 `week1_status` → `status` — 필드명 변경 = 비가산, 레포 밖 소비자 0이라 `schema_version` 유지(§2 규칙 준용). §1.4 머리 문장의 꼬리 형식 예시를 겹백틱으로(렌더 수정, 문구 불변). 그 밖의 낡은 주차 표현(§3.0 '④ [1주차]', §3.5 '2주차 enforced 범위', §3.6 제목 등)은 이번에 바꾸지 않는다.
> **v1.22 (매핑표 v1.20):** 낡은 '주차' 표현 정리(뜻 변경 없음 — §2.5, §3 머리말 상태 4종, §3.0 '④ [현재]', §3.1 `local_llm_vs_egress` 노트, §3.5 각주 제목 '출력 게이트 enforced 범위'(본문 불변), §3.6 제목 '기반 적대적 테스트') + §3.1 `claude_md_sync_check` 범위 확장(설명 문구 속 키 표기 0) + §1.4 머리 문장 한 구절. `schema_version` 값 변화 없음.
> **v1.23 (매핑표 v1.21):** rule-only 결선의 계약·원칙 선행 개정(코드는 다음 PR). §2.4 `produced_by` 서버 부여 사실 서술(규칙 변경 아님) + `analysis_meta.pipeline_mode` 닫힌 enum `rule_only | rule_llm`, rule_only에서 `model_id`·`prompt_version` = null + §2.5 `ExecutionResponse.result`와 불변식(completed ⇔ result ≠ null) + §3.5 각주 본문(유일 통로 → `completed_via_gate`) + §3.5 신규 `completed_via_gate`(not_implemented) + §6.2 블라인드 원칙 확장(생산자 버전 동결 후 test 작성, 1인 단계 한계, S v1 = 규칙에 대해 오염된 스모크 집합) + 출력 계약 서술의 생산자 일반화(규칙·LLM — §2.4·§2.5, §3.5 각주 첫 문장 '게이트 자체의 enforced 범위'). 서술 변경이라 `schema_version` 변화 없음.
>   - `pipeline_mode` 닫힌 enum = 비가산, rule_only의 null 허용 = 비가산, `ExecutionResponse.result` = 비가산(필수 필드). 소비자 0이라 AnalysisResult `schema_version` 유지(ExecutionResponse는 자체 버전 필드가 없다).
> **v1.24 (매핑표 v1.22):** 규칙 엔진 + ④ rule-only 결선(코드 PR — 계약 변경 없음). §3.5 `completed_via_gate` 승격(not_implemented → enforced, 현존 경로 한정, 증명은 같은 PR — 이 PR이 그 키의 목표 사건) + §3.0 ④ '[현재]' 줄과 §2.5 `not_implemented`의 현재 동작 서술을 실제 동작으로 갱신(서술 변경이라 `schema_version` 변화 없음).
> **v1.25 (매핑표 v1.23):** 층 B 러너 선행 문서 개정(코드 0). §6.3 J9 보고 머리에 `pipeline_mode` 추가(rule_only에서 `model_id`·`prompt_version`은 null, 대체 문자열 금지) + §6.3 J6 규칙 단독 기준선 = `pipeline_mode=rule_only` 실행 명시 + §3.5 `completed_via_gate` 노트에 불변 범위 추가. 서술 변경이라 `schema_version` 변화 없음.
> **v1.26 (매핑표 v1.24):** 층 B 러너(코드 PR — 계약 변경 없음). §3.5 `completed_via_gate` 노트(저장 필드 직접 쓰기의 정적 검사가 생겼다)·`eval_harness` 노트(rule_only 층 B 실측 가능)를 실제 상태로 갱신. 서술 변경이라 `schema_version` 변화 없음.
> **v1.27 (매핑표 v1.25):** S v2 계약(코드 0). §6.2 S v2 구성(사례 카탈로그 = 생성기 SSOT, 규모 게이트, 라벨링 지침의 위치·원칙·제1조, CORS 허용 목록 사례 제외, 작성 순서, 채점 단위, 동결 순서) + LabelFile 1.1(`split_scheme`·라벨별 `split`·`frozen_against`의 `ruleset_version`·`ruleset_hash`) + §6.3 J9 '없으면 null' + §3.5 신규 `ruleset_freeze`(enforced, 현재 rule_engine.py 한 파일)·`producer_freeze_order`(not_implemented).
  - LabelFile 1.1 = 가산, 소비자 있음(S v1) → 부 버전 증가. 1.0은 계속 읽힌다. AnalysisResult `schema_version` 변화 없음.
> **v1.28 (매핑표 v1.25 유지):** 라벨 모델과 카테고리 경계(코드 0). §1.1 ①②③ 경계 문장 + §6.2 LabelFile 1.1 결함별 라벨(트랜잭션마다 라벨 ≥ 1) + 규모 게이트의 트랜잭션 단위 세는 법 + 라벨링 원칙 O-4(관측이 같으면 라벨이 같다, positive는 관측 신호) + CORS 허용 목록 문장 교체 + §6.3 J1 결함별 라벨의 1:1 매칭.
  - LabelFile 1.1은 소비자 0(데이터 없음)이라 1.1 안에서 변경하고 버전을 유지한다. 1.0(S v1)은 '트랜잭션마다 정확히 1개' 그대로다. §3 변경 없음.
> **v1.29 (매핑표 v1.26):** S v2 생성기 장치(코드 PR — 계약 변경 없음). §3.5 `dataset_case_independence`·`producer_freeze_order` 승격(not_implemented → enforced, 합성 카탈로그로 증명 — 키가 주장하는 것은 생성기 검사 장치다) + 신규 `guideline_freeze`(enforced) + `ruleset_freeze` 범위 3파일. 서술 변경이라 `schema_version` 변화 없음.
> **v1.30 (매핑표 v1.26 유지):** S v2 동결 기록(§6.2) + 카탈로그 필드 목록을 결함별 라벨에 맞춤 + `dataset_case_independence` 설명에서 'S v2 동결 시' 삭제. §3·계약 변경 없음.
> **v1.31 (매핑표 v1.27):** 어댑터 계약 1부 — 송신 경로(코드 0). src/sentinel에 http.client import를 허용하는 첫 계약이다(금지선 문구 불변). §1.3 ⓐ 해석 신설 + ⓑ 해석 강제 매핑·가중치 반입 + §3.1 `no_autonomous_send` 문구(예외: 어댑터 1파일의 http.client) + 신규 `llm_adapter_loopback_only`·`llm_adapter_no_target_resend`·`llm_input_from_sanitized`·`llm_adapter_bounds`(not_implemented)·`inference_server_binding`(unverifiable) + `egress_enforcement_owner` 노트 + §1.4 N1·N2행 + 부록 구조화 출력·추론 서버 선정 기준.
> **v1.32 (매핑표 v1.28):** 어댑터 구현(코드 PR — 계약 변경 없음, 파이프라인 결선 없음). §3.1 `llm_adapter_loopback_only`·`llm_adapter_no_target_resend`·`llm_input_from_sanitized`·`llm_adapter_bounds` 승격(not_implemented → enforced) + `no_autonomous_send` 노트(실제 예외 반영). ③의 통과 표지 `SanitizedEnvelope` 도입.
> **v1.33 (매핑표 v1.29):** 어댑터 계약 2부 — 파이프라인·출력·감사(코드 0). §2.4 '전체 폐기'를 생산자 초안 단위로(계약 변경 — 부분 수용 금지는 유지) + 인젝션 피해 범위 + 환각 리터럴 재정의 + `analysis_meta.llm_outcome` / §2.5 `skipped_reasons` 구분·깨끗함 정의·실패 사유 닫힌 목록 / §2.8 신설(입력 뷰·프롬프트·구조화 출력·감사·model_id·추론 서버 인증·동시성) / §3.0 / §6.2·§6.3 J2·J3·J6, 프롬프트·모델 동결, test 측정 기록 / §3 신규 키 7개·재목표 3개.
  - `analysis_meta.llm_outcome` = 가산, 소비자 없음(결선 전). `schema_version` 유지.
> **v1.34 (매핑표 v1.30):** 결선 L1 — 게이트·결과 표현(코드 PR, 계약 변경 없음). §3.5 `producer_gate_merge`·`clean_requires_no_failure`·`prompt_model_freeze` 승격 + `completed_via_gate` 노트(생산자별 게이트 경로 재증명). 합성 초안으로 증명했고 어댑터 호출은 없다.
> **v1.35 (매핑표 v1.31):** 도구 — verify 스탬프와 pre-push 훅. §3.4 신규 `push_requires_verify`(enforced, 클라이언트 훅 범위). 사람이 지키던 '실패 시 멈추는 체인' 규칙을 장치로 대체한다.
> **v1.36 (매핑표 v1.32):** 결선 L2 — 어댑터 주변 안전장치(코드 PR, 파이프라인 결선 없음). `llm_concurrency`·`llm_io_audit`·`audit_write_failure` 승격(not_implemented → enforced, 범위는 상태 칸). `llm_adapter_loopback_only` 고정 목록에 메시지 역할·본문 키·response_format·헤더 키·API 키 비노출 추가. §2.8 지문 outcome 정의. `no_raw_persistence` 부재 검사가 감사 저장소 API를 호출 대상으로 판별.
> **v1.37 (매핑표 v1.33):** L3 선행 계약(문서 + 키 등재, 코드 0). §2.8 생산자 설정 동결(`prompt_version` = 템플릿 + 생성 설정 묶음 해시, `prompt_model_freeze` 노트 갱신) + 대기 상한(신규 `llm_queue_bound`, not_implemented → L3)과 Burp 쪽 읽기 타임아웃 요구(Java 연결 시 이월) + 어댑터 사유 대응표. §6.3 FROZEN_PROMPTS 값 명시 + J9 보고 머리에 서빙 조건 추가.
> **v1.38 (매핑표 v1.34):** 결선 L3 — rule_llm 결선(코드 PR, 계약 변경 없음). §3.1 `llm_view_budget`·`llm_queue_bound`, §3.5 `hallucinated_literal_isolation` 승격 + 재증명 노트(`llm_adapter_no_target_resend` 호출 지점 1곳, `completed_via_gate` 어댑터 경로, `llm_input_from_sanitized` 입력 뷰, `llm_concurrency`·`llm_io_audit` 실제 호출 경로, `prompt_model_freeze` 묶음 해시 산출).
> **v1.39 (매핑표 v1.34 유지):** 측정 전 규칙(문서만, 코드 0). §6.1·§6.3 needs_review 채점과 병기 + §6.2 모델 선별 프로토콜(선정 기준 사전 등록 — 실패율·탐지력 관문·순이득·동률·실사용 조건).
> **v1.40 (매핑표 v1.34 유지):** 선별 사전 등록(문서만). §6.2 선별 프로토콜에 예산 도출 규칙 한 줄(값은 progress-log, 실행 전 커밋).
> **v1.41 (매핑표 v1.34 유지):** 선별 무효 처리 규칙과 진단 준비(문서만). §6.2 무효 처리 규칙(측정 장치 결함만, 1회 재실행, 기준 고정) + ② 문구(① 통과 후보 중) / §2.8 LLM 초안 거부 감사에 Pydantic 오류의 위치·종류 코드 / §2.4 elapsed_ms 정의.
> **v1.42 (매핑표 v1.35):** 선별 무효 판정 후 수정(코드 PR). §2.8 초안 계약의 하위 제약 전달 수단(전송 스키마 / 출력 규칙 절 / 정당한 제외) + §3.5 `llm_contract_conveyed` 신규(enforced — 전달만, 지키는지는 게이트). JSON Pointer는 RFC 6901 문법만 pattern.
> 확정일: 2026-10-22 (v1.3 개정: 2026-10-23, v1.4 개정: 2026-10-23, v1.5 개정: 2026-10-26, v1.6 개정: 2026-10-26, v1.7 개정: 2026-10-26, v1.8 개정: 2026-10-26, v1.9 개정: 2026-10-26, v1.10 개정: 2026-10-26, v1.11 개정: 2026-10-26, v1.12 개정: 2026-10-27, v1.13 개정: 2026-10-27, v1.14 개정: 2026-10-27, v1.15 개정: 2026-10-27, v1.16 개정: 2026-10-29, v1.17 개정: 2026-10-29, v1.18 개정: 2026-11-02, v1.19 개정: 2026-11-02, v1.20 개정: 2026-11-03, v1.21 개정: 2026-11-03, v1.22 개정: 2026-11-03, v1.23 개정: 2026-11-03, v1.24 개정: 2026-11-04, v1.25 개정: 2026-11-04, v1.26 개정: 2026-11-04, v1.27 개정: 2026-11-04, v1.28 개정: 2026-11-04, v1.29 개정: 2026-11-04, v1.30 개정: 2026-11-05, v1.31 개정: 2026-11-05, v1.32 개정: 2026-11-05, v1.33 개정: 2026-11-05, v1.34 개정: 2026-11-05, v1.35 개정: 2026-11-05, v1.36 개정: 2026-11-06, v1.37 개정: 2026-11-06, v1.38 개정: 2026-11-06, v1.39 개정: 2026-11-06, v1.40 개정: 2026-11-09, v1.41 개정: 2026-11-10, v1.42 개정: 2026-11-10)

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

- **①의 경계:** 요청 주체와 응답 객체 소유 주체가 관측상 다른 것만(relation_preserving 라벨의 같음·다름). **가설까지만.**
- **②의 경계:** 응답에 서버 내부 정보(스택 트레이스·DB/ORM 오류 메시지·서버 파일시스템 경로)가 관측되는 것만. **가설까지만.**
- **③의 경계:** 응답에서 관측되는 보안 설정 오류만. S의 대상은 라벨링 지침의 닫힌 목록이다(목록 변경 = 지침 버전). **가설까지만.**
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

> **ⓐ 해석:** ⓐ는 대상 시스템으로의 요청 전송을 막는다. 루프백 추론 서버 호출은 대상 전송이 아니며, ⓑ와 어댑터 전용 키로 통제된다(미연결 어댑터도 ⓐ의 '비활성 송신 코드'가 아니다).
>
> **ⓑ 해석:** ⓑ는 코드의 위치가 아니라 목적지를 막는다. src·tools·tests 어디서든 외부 목적지로 송신하지 않는다.
> - 품질 수치(평가 결과 포함)는 ⓑ의 재론 근거가 아니다.
> - 강제 매핑: src → `no_autonomous_send`·`egress_static_check`·`llm_adapter_loopback_only` / tools → `tools_no_external_send` / tests → `egress_runtime_block`(테스트 안의 외부 연결 시도는 가드가 차단하는 의도된 적대 탐침) / 추론 서버 프로세스 → `egress_enforcement_owner`·`inference_server_binding`.
> - 현 단계의 LLM 대상은 루프백 로컬 모델만이다(`local_llm_vs_egress`의 LOCAL 분류). 루프백이 아닌 사내 승인 엔드포인트의 분류는 그것이 생길 때 (A) 개정으로 정하고, 그 전까지는 EXTERNAL이다. 이 분류는 사내망의 승인 대상에만 해당하며, 외부 인터넷 목적지에는 적용되지 않는다(ⓑ).
> - 모델 가중치는 설치 시점에 반입하는 자산이다(pip과 같은 범주). 실행 중 다운로드는 금지한다.
>
> **ⓕ 해석:** 사람이 Burp에서 내보낸 원본 파일은 Burp 프로젝트 파일과 같은 시스템 밖 자산이고, 시스템(엔진·tools)은 이를 영속화하지 않는다.
> - RawTransaction(§2.7)은 원본을 담는 유일한 타입이며, 마스킹 경계(마스커) 안에서만 존재한다. 엔진·저장소·커밋 어디에도 RawTransaction 인스턴스나 실제 트래픽에서 나온 평문이 남지 않는다.
> - '평문 내용'의 범위: ⓕ가 막는 것은 RawTransaction 인스턴스와 실제 트래픽에서 나온 평문이다. N5 더미 규칙을 따르는 가짜 리터럴(faketoken_…·example.test 등)은 실제 트래픽에서 나온 것이 아니므로 '평문 내용'에 해당하지 않는다 — ⓕ의 예외가 아니라 애초에 대상이 아니다. 이에 따라 마스커 테스트는 원본 픽스처를 파일로 커밋하지 않고 실행 중에만 만든다.

### 1.4 금지선 강제 매핑 (CLAUDE.md 금지선 색인의 정본)
- CLAUDE.md 금지선 색인(N1~N10)은 이 표에서 파생된다. 색인과 이 표의 집합 일치(정의처·키·키 옆 소절)는 `claude_md_sync_check`가 `make verify`에서 검사한다. 색인 꼬리 형식은 `` → 정의처: <, 목록> · 키: <없음… | `키`(§3.x), 목록> ``이고, 읽을 수 없는 형식은 통과가 아니라 오류다. 색인 줄의 설명 문구(→ 앞)에 manifest 키를 적는 것도 형식 오류다(상태 주장이 설명으로 다시 들어오는 경로 차단).
- 이 표의 완전성(빠진 강제 키가 없는가)은 사람의 리뷰 몫이다. 기계는 교차 검사만 덮는다(ⓑ행 ⊇ ⓑ 해석 강제 매핑 / §3 규칙 칸에 금지선 코드가 적힌 행의 키 ∈ 그 코드의 행).

| N | 금지선 | (A) 정의처 | 강제 키 | 비고 |
|---|---|---|---|---|
| N1 | 외부 egress | §1.3 ⓑ | `egress_static_check`, `egress_runtime_block`, `egress_enforcement_owner`, `local_llm_vs_egress`, `no_autonomous_send`, `tools_no_external_send`, `masker_no_send`, `llm_adapter_loopback_only`, `inference_server_binding` | ⓑ 해석 강제 매핑 포함. `egress_enforcement_owner`·`inference_server_binding`은 unverifiable |
| N2 | 자율 전송 | §1.3 ⓐ | `no_autonomous_send`, `tools_no_external_send`, `masker_no_send`, `llm_adapter_no_target_resend` | |
| N3 | Java 로직 금지 | §3.2 | `java_logic_isolation` | not_implemented |
| N4 | 엔진은 Burp를 모른다 / 입력은 정규화 JSON만 | §3.2 | `engine_burp_isolation`, `engine_tools_isolation`, `engine_no_rawtransaction`, `input_schema_gate` | 앞 셋 = 엔진이 무엇을 보지 않는가, `input_schema_gate` = 입력이 정규화 통과분만인가 |
| N5 | 실데이터 금지 | §1.3 ⓒ | (없음) | 기계 강제 불가 — 정책·리뷰로 지킨다. N5 더미 표지 검사(`dataset_version_freeze` 내부)는 실데이터 부재를 증명하지 않으므로 넣지 않는다 |
| N6 | main 직접 병합 금지 | §3.4 | `branch_protection` | unverifiable(레포 설정) |
| N7 | 민감정보·원본 커밋·저장 금지 | §1.3 ⓕ, §3.3 | `secret_scan_hook`, `no_raw_persistence`, `sanitization_trust`, `maskedref_typing`, `llm_input_from_sanitized` | `masked_span_integrity`는 마스킹 표기 정합성(보조)이라 제외 |
| N8 | AI 수정코드 자동 반영 금지 | §1.3 ⓓ | `no_autopatch_apply` | |
| N9 | 실데이터 파인튜닝 금지 | §1.3 ⓔ | `no_finetune_path` | |
| N10 | 멀티에이전트/사내 사례 RAG | §1.3 ⓖ | `no_multiagent_rag` | not_implemented → P2 |

- 송신 수단 금지 키(`no_autonomous_send`·`tools_no_external_send`·`masker_no_send`)는 목적지를 가리지 않고 송신 자체를 막으므로 ⓐ·ⓑ를 함께 강제한다. 송신 어댑터의 예외는 이 키들의 범위 문구 변경과 별도로, ⓐ(대상 재전송 불가)·ⓑ(루프백 목적지만) 각각에 대한 어댑터 전용 키로 정한다(어댑터 개정).
- 키 상태(enforced 등)는 이 표에 적지 않는다 — 상태의 정본은 §3이다(비고의 상태 언급은 이해용 메모).

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
  - **모드가 라벨 유무를 결정한다:** strict_redaction → label=null(같은 값이어도 라벨로 연결하지 않는다) / relation_preserving → label=ref_NN(순번 할당). 모드는 원본에 싣지 않고 생산자(마스커·Java)의 실행 옵션으로 받는다.
  - 매핑 테이블의 키 = HMAC(배치 키, 원본값). 라벨은 (relation_preserving에서) 순번으로 할당한다(`ref_01`, `ref_02`, …). 해시를 잘라 라벨로 쓰지 않는다. Python으로는 라벨만 간다. 원본값은 Java 경계를 넘지 않는다.
  - 같은 원본값 ⇔ 같은 라벨(양방향). 동치 기준은 원본값이며 kind와 무관하다. 헤더·파라미터·본문 span에 공통으로 적용한다. 배치 안에서만 유효하다.
  - 이 불변식은 생산자(마스커·Java) 쪽에서만 강제할 수 있다. Python ③은 원본을 모른다.
  - label_consistency(라벨 양방향 동치)는 relation_preserving 모드에서만 강제된다. strict_redaction은 label=null이라 이 불변식의 대상이 아니다.
  - 접두사 `ref`의 근거: 의미 있는 접두사는 LLM이 근거 없이 추론하게 만든다(R-9와 같은 문제). 의미는 `ref.kind`에만 둔다.
- **body_rules matcher 문법(마스커·Java 공유 계약):**
  - `json:<키 glob>` — 모든 깊이에서 이름이 glob과 일치하는 JSON 객체 멤버 중 값이 문자열인 노드 → 그 노드 전체 span(JSON Pointer). 중첩 포함: `{"user":{"password":"x"}}`에서 `json:password`는 중첩된 password도 잡는다. 본문이 엄격 JSON(§2.6)으로 파싱될 때만 적용한다.
  - `form:<이름 glob>` — 이름이 glob과 일치하는 폼 본문 파라미터의 값 구간 → text range span(저장 content 기준 코드포인트 오프셋).
  - glob은 헤더 규칙과 같이 대소문자를 무시한다.
  - action(redact / pseudonymize): 지금은 둘 다 'FILLER + span'으로 같게 처리한다. 차이는 미정(큐).
  - text 본문의 정규식 matcher는 아직 없다. 규칙 값(어떤 이름을 가리나)은 정본이 아닌 설정값이다.
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
├─ analyzed_refs  : [UUID]            # 서버 부여: 분석 단계(규칙·LLM)에 실제로 넘긴 transaction_id 목록. 초안에는 없음
├─ findings       : [Finding]         # 탐지 4종만. 빈 배열 = 정상(단, ExecutionResponse와 구분 ↓)
├─ advisory_signals: [AdvisorySignal] # 카테고리 밖 조언. ★탐지 아님
└─ analysis_meta  : { model_id | null, policy_version, prompt_version | null, ruleset_version,
                      elapsed_ms, token_usage?, pipeline_mode: rule_only | rule_llm,
                      llm_outcome: null | ok | rejected | failed:<사유>, manifest_snapshot }   # rule_only에서 null

Finding
├─ finding_id(UUID)
├─ category   : enum(4종 폐쇄형)       # 생산자(규칙·LLM)가 임의 카테고리 생성 불가
├─ hypothesis : str                   # 조건·추정형만("~가능성/~로 보임"). 단정 토큰 금지
├─ evidence   : [Evidence]            # 최소 1개 필수(0개면 거부=환각 차단)
├─ claim_basis: enum(observed|inferred|speculative)   # 근거의 성격(자유숫자 금지)
├─ severity_if_true: enum | null      # 항상 존재. null = 등급 매핑 미정의. 서버가 부여한다(초안에 없음). 사실이라면의 위험도(사실성과 무관), 확신도 아님 ↓
├─ status     : enum(unverified|verifying|confirmed|false_positive|needs_review)
│               # ★초안(규칙·LLM)은 생성 불가. 서버가 unverified 부여. 승격은 ReviewEvent로만
├─ produced_by: enum(rule|llm|hybrid) # 서버 부여(생산 경로). 초안에 없음. AI 기여도 분리 측정(평가 테제)
├─ limitations: [str]
└─ next_steps : [{type: "verification", action, rationale}]   # 도구는 실행 안 함

Evidence
├─ transaction_ref(UUID)   # transaction_id로만 참조(host 문자열 금지). analyzed_refs에 포함돼야 함
├─ pointer: Locator        # §2.6. locus는 Locator 안의 판별자다(별도 locus 필드 없음)
├─ observation(str)        # 관측 사실(해석 아님). 가명 라벨 그대로 인용 가능
├─ corroboration: matched|unmatched|not_checkable|not_run   # 서버 생성(초안 아님). not_run=대조 미실행 / not_checkable=대조 불가
├─ anomaly_flags: [...]    # 서버가 생성(초안 아님). 값: hallucinated_literal_suspected
└─ review_required(bool)   # 서버 기본값 true(미대조 상태의 fail-safe)

AdvisorySignal = { type:"out_of_scope_advisory", topic, basis:[Evidence], suggestion }
```
- **analyzed_refs 서버 부여:** 서버가 분석 단계(규칙·LLM)에 실제로 넘긴 transaction_id 목록을 채운다. 초안에는 없다. 근거: LLM이 analyzed_refs와 evidence.transaction_ref 양쪽을 다 쓰면 `evidence_ref_integrity`가 자기참조가 된다.
- **severity_if_true 서버 부여:** 초안(규칙·LLM)은 채우지 않는다(초안에 없다).
  - 기본값: category별 기본값 표에서 부여한다. 이 표는 미정의다(5번 이후 확정).
  - 보정(adjust): 서버가 관측·판정한 신호 유형으로 기본값을 조정할 수 있다. 보정 규칙(어떤 신호가 severity를 어떻게 바꾸는지)은 미정의다(5번 이후 확정).
  - 기본값 표가 정의되기 전에는 비워 둔다(null). 기본값 표가 정의된 뒤에도, 보정 규칙이 정의되기 전에는 기본값만 부여하고 보정하지 않는다.
  - 근거: 건건이 자유롭게 매기면 같은 취약점이 다른 값을 받아 평가가 오염된다(R-9와 같은 문제). 규칙이 미정의인 상태에서 판정을 허용하면 추측하거나 LLM에 다시 위임하는 뒷문이 된다.
- **produced_by 서버 부여:** 서버가 생산 경로로 부여한다(초안에 없고, 게이트에는 호출자 인자로만 들어간다). 근거: 초안이 자기 생산자를 쓰면 J6(produced_by별 P/R)가 자기신고가 된다.
- **analysis_meta:** `pipeline_mode`는 닫힌 enum `rule_only | rule_llm`이다. `model_id`·`prompt_version`은 rule_only에서 null이고, 그 외에는 필수다(LLM이 없는 경로에 모델·프롬프트 값을 지어내지 않는다).
- **elapsed_ms:** ③ 통과 직후부터 응답 조립까지다(②·③ 제외, LLM 호출 포함). §6.2 선정 기준 ④가 쓰는 값의 정의다.
- **corroboration·review_required:** 서버가 생성한다(초안 아님). `not_run` = 대조 미실행, `not_checkable` = 대조 불가. `review_required`의 서버 기본값은 true — 미대조 상태의 fail-safe.
- **출력 검증 규칙(전체 폐기 — 생산자 초안 단위):** 한 생산자의 초안 어느 한 부분이라도 검증에 실패하면 그 초안 전체를 폐기한다(부분 수용 금지). 폐기는 조용히 하지 않는다 — 사유 코드를 감사에 남긴다. 근거: 깨끗한 부분만 골라내는 것은 환각을 부분적으로 신뢰하는 것이다. 빈 결과로 위장하면 '분석 실패'와 '분석 후 깨끗함'이 다시 섞인다.
  - 생산자별 초안을 받는 게이트 함수가 각 초안을 검증하고, (category, CNA 집합)이 일치하면 병합한 뒤(문구는 규칙 쪽, `produced_by=hybrid`) `_assign`을 1회 호출한다. 근거: 두 초안을 하나로 묶으면 LLM이 실패할 때마다 결정론적인 규칙 결과까지 사라지고 J6 해석도 흐려진다.
  - 규칙 초안 거부 = `output_rejected`(시스템 버그, fail-closed). LLM 초안 거부·실패 = `completed` + 규칙 결과 + 실패 사유(§2.5).
- **인젝션 피해 범위:** LLM에게는 도구·송신이 없으므로 인젝션의 최대 피해는 틀린 초안이며, 게이트와 사람이 거른다.
- **status 승격:** ReviewEvent(사람 판정 + 시각 + 사유) append → current_status는 파생·재계산 가능. 초안에서 status **필드 자체를 제외**하고 서버가 unverified 부여.
- **evidence 무결성:** transaction_ref ∈ analyzed_refs + pointer가 마스킹 후 데이터에서 해석됨 + pointer/observation이 **마스킹 후 데이터로 검증 가능** + observation 핵심 주장이 실제 발견되는지 재대조.
- **환각 리터럴 격리:** LLM 자유 문자열(observation·hypothesis·limitations·next_steps)에 정책 패턴 리터럴이 있으면, 같은 정책 패턴 집합 안에서 ③이 데이터에 없음을 보장하므로 데이터 밖 값이다. 치환하고 `hallucinated_literal_suspected`를 붙인다(서버 생성, '날조 확정' 아니라 '경계 이상 의심'). 원문은 저장·로그하지 않는다. 플래그 달린 evidence는 유효근거 카운트 제외 → 유효 evidence 0이면 finding 자동 needs_review/폐기.
  - 한계: 정책 패턴에 걸리지 않는 환각(지어낸 이름·값)은 잡지 못한다 — `corroboration_check`(미구현)의 몫이다.
- **중복 처리:** Finding끼리는 (category, Evidence CNA 집합)이 정확히 같을 때만 병합한다(CNA → §2.6). CNA가 일부 겹치는 것만으로는 병합하지 않는다. advisory의 CNA 집합이 어떤 finding과 정확히 같으면 advisory를 버린다(finding 우선). 평가 채점은 이 중복 처리를 거친 출력을 대상으로 한다.
  - 근거: 겹침으로 병합하면 사슬 병합이 생기고, 거친 노드(body_text)가 서로 다른 결함을 끌어모은다. 보안 도구에서 과병합은 결함을 숨기고, 과소병합은 중복을 보여 줄 뿐이다(fail-safe 방향). 남은 중복은 평가에서 측정된다.

### 2.5 ExecutionResponse (분석 실행 상태 — AnalysisResult와 구분)
```
ExecutionResponse = { analysis_status, skipped_reasons: [str], manifest_snapshot, result: AnalysisResult | null }
```
> **왜 분리?** `findings:[]`가 "분석 완료·깨끗함"인지 "아직 분석 안 함"인지 혼동 금지. **분석 안 함 ≠ 분석 후 취약점 없음.** 평가의 '정상 사례 정확도'가 이 구분에 의존한다. 현재 골격은 이 타입만 반환한다.

- **`analysis_status` = 닫힌 enum:** `not_implemented | completed | output_rejected`.
  - `not_implemented`: 분석 단계가 구현되지 않아 분석하지 않음(현재 ④는 이 값을 반환하지 않는다 — 규칙 경로가 `completed`·`output_rejected`를 반환한다).
  - `completed`: 분석이 끝나고 결과(AnalysisResult)가 `result`에 동봉됨.
  - `output_rejected`: 규칙 초안이 검증에 실패해 결과 전체를 폐기함(§2.4 출력 검증 규칙 — 시스템 버그). 입력 거부(HTTP 4xx)와는 다른, **출력** 거부다.
- 세 값은 "분석 안 함 / 분석 후 결과 있음(깨끗함 포함) / 분석 결과 폐기"를 구분하기 위한 것이다.
- **불변식:** `completed` ⇔ `result` ≠ null / `not_implemented`·`output_rejected` ⇒ `result` = null.
- **`skipped_reasons`:** '모드상 미수행'(예: `llm_analysis_not_implemented`)과 '실패'(`llm_rejected`·`llm_failed:<사유>`)를 구분한다. rule_llm 성공 시 빈 목록을 허용한다.
  - 실패 사유 닫힌 목록: `unavailable` · `timeout` · `oversize` · `truncated`(finish_reason=length) · `unparseable` · `audit_write`.
  - `analysis_meta.llm_outcome` = `ok | rejected | failed:<사유>`.
- **깨끗함 = `completed` ∧ `findings: []` ∧ 실패 사유 없음.** LLM 실패 + 빈 findings는 깨끗함이 아니다.

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

### 2.7 RawTransaction — §2.2 Transaction의 마스킹 전 쌍
```
RawEnvelope    = { schema_version: "1.0", transactions: [RawTransaction] }      # 버전 자리는 Envelope(§2.1)와 같다
RawTransaction                                                                  # 구조는 Transaction(§2.2)과 같고 아래만 다르다
├─ meta: { transaction_id(UUID), captured_at(ISO8601+tz), origin_ref }       # sanitization 없음 — 아직 마스킹 전
├─ request:  { method, scheme(http|https), host, port, path(원본, 쿼리 미포함),
│              query_params:[RawParam], headers:[RawHeader], body: RawBody }
└─ response: { status, headers:[RawHeader], body: RawBody, elapsed_ms(int|null) }

RawParam  = { name, value: str, location(query|form) }                         # MaskedRef 없음 — 평문 str만
RawHeader = { name, value: str }
RawBody   = { content_type, encoding(utf8|base64|omitted), content(str|null) } # truncated·size_bytes·masked_spans 없음
```
- **성격:** Transaction(§2.2)의 '마스킹 전' 쌍이다. 사람이 Burp에서 내보낸 원본의 레포 내 형식이며, 미래 Java Extension의 출력 직전 형식이기도 하다(fixture 마스커가 참조 구현).
- **Transaction과의 차이(이것만 다르고 나머지 구조는 같다):**
  - 모든 value가 평문 str이다. MaskedRef가 없다.
  - meta.sanitization(SanitizationReceipt)이 없다(아직 마스킹 전).
  - RawBody는 { content_type, encoding, content }만 갖는다. truncated·size_bytes·masked_spans가 없다 — 셋 다 마스킹 산출물이기 때문이다.
  - 이름(RawParam·RawHeader·RawBody)으로 Transaction 쪽과 구분한다(원본을 엔진에 넘기는 혼동 방지).
- **절단 금지(§2.2 순서와 정합):** RawBody에 truncated 필드가 없으므로 잘린 원본은 타입으로 표현할 수 없다. 절단과 size_bytes는 마스커가 마스킹을 끝낸 뒤에 산출한다(§2.2 "절단은 마스킹 뒤 — 먼저 자르면 비밀값 반쪽이 ③을 통과").
- **분석의 입력이 아니다:** RawTransaction은 '마스킹의 입력'일 뿐, 분석의 입력이 절대 아니다. 엔진(src/sentinel)은 이 타입을 모른다.
- **배치(안전 층위 결정 — 구현 재량 아님):** RawTransaction 타입은 tools/ 아래에만 둔다(마스커·평가기 공용, 둘 다 tools/). src/sentinel은 이 타입을 참조하지 않는다. 엔진 → tools/ import는 `engine_tools_isolation`이 강제하고, 엔진의 RawTransaction 계열 import·정의는 위치와 무관하게 `engine_no_rawtransaction`(§3.2)이 잡는다.
  - 근거: common_types(§2.6)에 두면 엔진이 물리적으로 import할 수 있어 '있는데 안 쓴다'를 따로 지켜야 한다. 코드 응집도를 이유로 common_types를 택하지 않는다.
- **schema_version:** 원본 JSON 최상위에 `schema_version: "1.0"`을 둔다(Envelope가 버전을 지는 것과 같은 자리). 마스커는 이 버전을 읽고, 모르는 버전이면 거부한다. 첫 소비자 = fixture 마스커(마스커-A에서 생긴다). 지금은 정의만이다 — §2 버전 규칙.

### 2.8 LLM 경로 (rule_llm) — 입력 뷰·프롬프트·구조화 출력·감사

- **입력 뷰:** `llm_input` 한 곳에서만 만든다(`llm_input_from_sanitized`). 순서는 헤더 → 파라미터 → 본문이고, 본문은 머리와 꼬리를 보존한다. §2.2의 절단과는 별개다.
  - 뷰가 잘리면 서버가 limitations에 "LLM 입력 뷰가 일부만 포함"을 붙인다(LLM이 쓰지 않는다).
  - Evidence는 뷰가 아니라 마스킹된 Transaction 전체에 대해 해석한다. 게이트는 전체 Transaction을 본다.
  - 예산 관계식: 뷰 토큰 / 프롬프트 처리 속도 + max_tokens / 생성 속도 + 여유 ≤ 전체 기한(`llm_adapter_bounds`). 값은 설정값이다(정본이 아니며 결선 PR에서 실측한다).
- **프롬프트:** 고정 지시문 + 구획된 데이터 블록이다. 트랜잭션은 JSON 문자열로 넣고 신뢰 불가 데이터로 표시한다.
- **생산자 설정 동결:** `prompt_version` = 템플릿 파일 + 생성 설정(temperature·max_tokens·뷰 상한·전체 기한·전송 스키마(평탄화본))의 묶음 해시다. test를 측정한 뒤 생성 설정만 바꿔도 같은 프롬프트 버전으로 기록되는 구멍을 막는다. 기한은 출력 내용이 아니라 timeout 실패 빈도를 바꾸며, timeout이면 규칙 결과만 남으므로 J2·J6에 영향을 준다. FROZEN_PROMPTS는 이 묶음 해시를 기록하고, `prompt_model_freeze`가 이 해시로 판정한다.
- **구조화 출력:** 정의처는 Pydantic FindingDraft 목록이다. 전송은 `$ref`를 풀어 넣은 평탄화 스키마(response_format)다.
  - LLM 초안 스키마에는 Locator의 range가 없다(뷰 오프셋 ≠ 원본 오프셋).
  - 초안 계약의 하위 제약은 셋 중 하나로 전달한다: 전송 스키마에 표현 / 프롬프트의 출력 규칙 절에 열거 / 정당한 제외(초안 금지)(`llm_contract_conveyed`). 복합 검증기는 하위 제약 단위로 판정한다.
    - JSON Pointer는 RFC 6901 문법만 pattern으로 싣는다(계약보다 좁히지 않는다). `-` 토큰 금지와 '가리키는 노드 정확히 1개'는 출력 규칙으로만 전달한다.
    - 근거: pattern 위반은 서버가 HTTP 500으로 끝내 환경 실패(unavailable)로 잘못 분류된다. 출력 규칙만 쓰면 위반은 게이트에서 draft_schema_invalid(모델 행동)로 분류된다.
    - 서버 문법이 키워드를 실제로 강제하는지는 수동 절차다(스키마 변환 경고 0 확인, llama.cpp 버전 변경 시 탐침 — inference-server 문서).
  - 파싱 실패 → `llm_failed:unparseable`. 재시도는 없다(v1 — 다시 생성하면 J2를 가린다).
- **감사(B-6):** LLM 호출마다 입력 뷰·원출력의 SHA-256, 크기, 소요 시간, `llm_outcome`, `prompt_version`, `model_id`를 남긴다. 내용은 남기지 않는다(`llm_io_audit`). 내용 보존은 저장 설계(D5)로 넘긴다.
  - LLM 지문의 outcome = llm_outcome ∪ {rule_rejected}(규칙 초안 거부 시에도 LLM 호출의 지문을 남긴다).
  - LLM 감사 기록에 실패하면 LLM 결과를 폐기하고(`llm_failed:audit_write`) 규칙 결과는 유지한다.
  - LLM 초안이 거부되면 Pydantic 오류의 위치·종류 코드만 기록한다(값·메시지 금지). 위치 조각은 계약에 정의된 이름(필드명·판별 리터럴)과 정수 인덱스만 기록하고, 그 밖의 조각은 `<extra>`로 바꾼다. 종류 코드는 검증 라이브러리의 고정 코드만 쓴다.
    - 근거: 계약 밖 키(extra_forbidden 등)는 위치의 마지막 조각이 LLM이 지어낸 문자열이다 — 출력 게이트의 "입력이 정한 필드명은 남기지 않는다"와 같은 원칙.
- **model_id:** `이름@sha256:<가중치 해시>`다. 기동 절차에서 기록한 값을 설정으로 받는다. 서버가 보고하는 경로와 대조하는 데까지만 가능하다(`llm_model_identity` — unverifiable).
- **추론 서버 인증:** 기동마다 랜덤 API 키를 만들고 환경변수로만 전달한다. 로그·커밋에 남기지 않는다(N7). 어댑터가 헤더로 보낸다. 기동 절차에 `--no-slots`를 둔다. 어댑터 정적 검사가 메시지 역할·요청 본문 키·response_format·인증 헤더를 고정한다(`llm_adapter_loopback_only`).
- **동시성:** LLM 호출은 스레드풀에서 하고 동시 처리는 1건이다. 이벤트 루프를 막지 않는다 — LLM 처리 중에도 토큰 검증이 응답해야 한다(`llm_concurrency`).
  - **대기 상한:** 설정값이다(기본 2). 넘으면 토큰 검증 뒤·스레드풀 진입 전에 즉시 503 + 감사 사유 `busy`로 응답하고 분석하지 않는다(`llm_queue_bound`).
  - **클라이언트 요구(Java 연결 시 이월 — Java 쪽 설정 항목):** Burp 쪽 읽기 타임아웃 ≥ (대기 상한 + 1) × 전체 기한 + 여유. 기본값 기준 360초 + 여유다.
- **사유 대응표:** 어댑터 사유 코드는 아래 표로 `llm_failed:<사유>`(§2.5 닫힌 목록)에 대응한다. `truncated`·`unparseable`·`audit_write`는 어댑터 밖에서 정해진다.

| 어댑터 사유 코드 | `llm_failed:<사유>` |
|---|---|
| `api_key_missing` | `unavailable` |
| `connect_failed` | `unavailable` |
| `bad_status` | `unavailable` |
| `transport_error` | `unavailable` |
| `io_timeout` | `timeout` |
| `deadline_exceeded` | `timeout` |
| `response_too_large` | `oversize` |

---

## 3. 가드레일 — 강제 매핑표 v1.35 (FROZEN)

> 이 표가 **가드레일의 단일 출처(SSOT)**다. capability manifest는 이 표에서 기계 파생되며(`manifest_derivation`), 생성물과 정본의 일치를 make verify(로컬 게이트)가 검증한다. 서버측 CI는 없다.
> **manifest 상태 4종:** `enforced`(선언된 필수검증이 실제 실행·통과한 경우만) | `not_implemented`(예정 시점 명시) | `disabled` | `unverifiable`(통제가 외부 의존 — OS격리·레포설정 — 이라 시스템 자가확인 불가. '있는 척' 아니라 '책임 밖임을 정직 표시').
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
④ [현재] 규칙엔진 → 출력 게이트 → ExecutionResponse(analysis_status="completed" | "output_rejected") 반환(rule_only, 저장 없음)
   [이후]  규칙엔진 + LLM(§2.8) → 생산자별 게이트·병합(§2.4) → 저장
```
**감사 기록 실패 시에도 fail-closed**(기록 못 하면 통과시키지 말고 거부)는 모든 감사 기록의 원칙이다. 현재 강제 범위(`audit_write_failure`)는 LLM 감사이고(§2.8 — LLM 결과 폐기, 규칙 결과 유지), 수용 요청 감사 등 나머지는 미구현이다.

### 3.1 D. 실행경계
| 규칙 | 목표층위 | 상태 | manifest 키 |
|---|---|---|---|
| egress 정적 의존성 0(외부 HTTP 송신 의존성 0 + 허용목록 빔) | 테스트 | enforced | `egress_static_check` |
| egress 런타임 차단 실증 | 테스트 | enforced(테스트환경 한정) | `egress_runtime_block` |
| egress 차단 실주체(OS/네트워크) | — | unverifiable(추론 서버 프로세스의 외부 연결(텔레메트리·업데이트·원격 다운로드) 포함) | `egress_enforcement_owner` |
| 로컬 LLM ≠ 외부 egress 분리 | 테스트 | enforced(허용목록 빔 검사) | `local_llm_vs_egress` |
| 자율 전송 0(송신·소켓 심볼 import 0 — 예외: 어댑터 1파일(sentinel/pipeline 아래)의 http.client만) | 아키텍처 테스트 | enforced(예외 1건 — pipeline/llm_adapter.py의 http.client) | `no_autonomous_send` |
| 어댑터 접속 대상은 루프백 하나(연결 생성자 1개, 인자 형태 고정 — 첫 인자 상수 127.0.0.1, 포트는 설정 정수 / HTTPSConnection·set_tunnel·.host 대입·host= 키워드·상속·별칭 import·getattr·source_address 금지 / 동적: sys.audit의 http.client.connect로 목적지 확인 / 요청 메시지 content는 문자열만 — 이미지·URL 파트 금지, 추론 서버의 원격 가져오기 차단 / 메시지 역할 system·user, 요청 본문 키·response_format·헤더 키 고정 / API 키는 환경변수에서만 읽고 로그·예외에 없음) | 아키텍처 테스트 | enforced(정적 범위 + 루프백 스텁의 동적 확인. 추론 서버 실행은 범위 밖) | `llm_adapter_loopback_only` |
| 어댑터로 대상 요청을 재구성할 수 없음(입력 타입에 URL·host·method·path 필드 없음, 필드 목록 고정 / 요청 경로·메서드 상수 / 호출 지점은 파이프라인 한 곳 / LLM 출력은 게이트로만) | 아키텍처 테스트 | enforced(호출 지점 1곳 — `pipeline/llm_path.py`. 뷰에 host·scheme·port 없음) | `llm_adapter_no_target_resend` |
| 어댑터 입력은 ③을 통과한 Transaction에서만 만들어진다(생성 지점 1곳 정적 고정) | 아키텍처 테스트 | enforced(③ 표지 타입과 불변 스냅샷, 생성 지점 정적 고정. 입력 뷰는 같은 스냅샷에서 만든다) | `llm_input_from_sanitized` |
| 어댑터 상한: 응답 최대 바이트·연결/읽기 타임아웃·전체 기한(단조 시계). 초과하면 사유 코드 | 테스트 | enforced | `llm_adapter_bounds` |
| LLM 입력 뷰는 순서·머리꼬리 보존 규칙을 따르고 예산 관계식 안에 있다. 잘리면 서버가 limitations를 붙인다 | 테스트 | enforced(예산 관계식은 0단계 실측값 기준 — 모델이 바뀌면 재실측) | `llm_view_budget` |
| LLM 호출은 스레드풀, 동시 처리 1건. 처리 중에도 토큰 검증이 응답한다 | 테스트 | enforced(분석 호출 전체 단위 — LLM 호출 포함) | `llm_concurrency` |
| 분석 대기 상한(설정값, 기본 2). 넘으면 토큰 검증 뒤·스레드풀 진입 전에 즉시 503 + 감사 사유 busy, 분석 안 함 | 테스트 | enforced | `llm_queue_bound` |
| model_id가 실제로 올라간 가중치인지는 우리 테스트 밖 — 서버가 보고하는 경로와 대조까지만 가능 | — | unverifiable | `llm_model_identity` |
| 추론 서버의 바인딩 주소, 그리고 루프백 포트에서 듣는 프로세스의 정체성(포워더 여부·포트 선점)은 우리 테스트 밖 — OS·운영 절차가 실주체. 기동 절차 문서로 보완 | — | unverifiable | `inference_server_binding` |
| 127.0.0.1 바인딩 | 테스트+설정 | enforced | `loopback_binding` |
| 요청자 토큰 검증(공유시크릿) | validator+테스트 | enforced | `request_token_validation` |
| 토큰 강화(회전·수명) | validator | not_implemented → Java 연결 시 | `token_hardening` |
| 자동 수정반영 부재(ⓓ) | 아키텍처 테스트 | enforced | `no_autopatch_apply` |
| 파인튜닝 경로 부재(ⓔ) | 아키텍처 테스트 | enforced | `no_finetune_path` |
| 멀티에이전트/RAG 부재(ⓖ) | 아키텍처 테스트 | not_implemented → P2 | `no_multiagent_rag` |
| manifest 정직성 | 테스트 | enforced | `manifest_honesty` |
| manifest 자기검증 | 테스트 | enforced | `manifest_selfcheck` |
| manifest 정본 파생(SSOT=이 표) + make verify 일치검증 | 테스트 | enforced | `manifest_derivation` |
| CLAUDE.md 금지선 색인 ↔ (A) §1.4 일치를 기계 검사 | 테스트 | enforced(색인 ↔ §1.4 집합 일치(정의처·키·소절) + 키 실재 + (A) 내부 교차 + 설명 문구 속 키 표기 0. §1.4 자체의 완전성은 범위 밖 — 리뷰) | `claude_md_sync_check` |
| fixture 마스커에 송신·소켓·egress 의존 0 | 아키텍처 테스트 | enforced | `masker_no_send` |
| tools/ 전체(하위 패키지 자동 열거)에 송신·소켓 import, 동적 import, tests 패키지 import 0(테스트 가드 경유 세탁 금지) | 아키텍처 테스트 | enforced(정적 범위 — tools/ 직접 import. 개발 의존성 내부·하위 프로세스는 범위 밖) | `tools_no_external_send` |

### 3.2 A. 입력경계
| 규칙 | 목표층위 | 상태 | manifest 키 |
|---|---|---|---|
| 엔진 Burp/Montoya import 0 | 아키텍처 테스트 | enforced | `engine_burp_isolation` |
| Java에 분석·판정·프롬프트·취약점 로직 금지 (capture / transport / ui만) | 아키텍처 테스트 | not_implemented → Java 연결 시 | `java_logic_isolation` |
| 입력은 스키마 통과분만 | 스키마/validator | enforced | `input_schema_gate` |
| 봉투 len==1(single) | validator | enforced | `envelope_arity` |
| raw path에 리터럴 '?' 없음(쿼리는 query_params로만) | 스키마/validator | enforced(검증 함수 단위 — 입력 스키마) | `path_no_query_string` |
| 인증 선행 — 함수 미호출 + 코드 물리분리 | 테스트 | enforced | `auth_precedence_noinvoke` |
| 엔진(src/sentinel)이 tools/를 import하지 않음 | 아키텍처 테스트 | enforced | `engine_tools_isolation` |
| 마스커가 sentinel.pipeline.sanitization_check를 import하지 않음 | 아키텍처 테스트 | enforced | `masker_independence` |
| 엔진(src/sentinel)이 RawTransaction을 import하지 않음(엔진은 마스킹 후 Transaction만 다룬다) | 아키텍처 테스트 | enforced | `engine_no_rawtransaction` |

> **`engine_no_rawtransaction` 근거:**
> - RawTransaction을 tools/에 두면(§2.7) `engine_tools_isolation`이 이미 커버한다. 이 키는 그 커버가 RawTransaction에도 적용됨을 추적하는 항목이다.
> - ★ 마스커-A에서 결정함 → **(ㄱ) 독립 enforced.** 근거: tools/ 이탈 경로는 실재하는 위험이다 — §2.7이 '코드 응집도로 common_types를 택하지 말 것'을 따로 경고할 만큼의 유혹이고, 그 이동이 일어나면 `engine_tools_isolation`은 침묵한다. 그래서 원본 타입 이름(import·속성 접근·정의)을 위치와 무관하게 잡는 별도 검사를 둔다.
>   - (결정 전 문구) 마스커-A에서 결정할 것: 이 키를 (ㄱ) 별도 테스트로 독립 enforced 할지 (ㄴ) `engine_tools_isolation` 종속 derived로 둘지. 판단 기준 = 'RawTransaction이 tools/를 벗어나는 변경을 방어할 필요가 있는가'. 별도 테스트는 RawTransaction을 tools/ 밖으로 옮겨도 '엔진 import 0'을 콕 집어 지킨다(위치 이동 경로까지 방어). derived는 tools/ 안에 있는 한 충분하지만 tools/ 이탈 시 `engine_tools_isolation`이 침묵한다. 마스커-A에서 실제 구조를 보고 이 기준으로 답한다.
> - `masker_independence`(마스커 → 엔진 `sanitization_check` import 금지)와는 방향이 반대인 격리다.

### 3.3 B. 민감정보경계
| 규칙 | 목표층위 | 상태 | manifest 키 |
|---|---|---|---|
| 원본 생문자열 유입 불가(MaskedRef 타입) | 타입 레벨 | enforced | `maskedref_typing` |
| Sanitization 독립 재검증 | 테스트 | enforced(값 재검증) | `sanitization_trust` |
| 영수증 HMAC 서명 | validator | not_implemented → Java 연결 시 | `receipt_hmac` |
| 비밀값 커밋 금지 | CI(pre-commit) | enforced(클라이언트 훅 + make verify 전수스캔; 서버측 CI 강제는 미구현) | `secret_scan_hook` |
| 원본 트래픽 미기록(기능 부재) | 테스트 | enforced | `no_raw_persistence` |
| 감사 로그 존재 | 테스트 | enforced | `audit_log_present` |
| 인증실패 로그 위생 | 테스트 | enforced | `authfail_log_hygiene` |
| 감사 기록 실패 시 fail-closed | 테스트 | enforced(범위 — LLM 감사. 수용 요청 감사 등 나머지는 미구현) | `audit_write_failure` |
| LLM 호출마다 입력 뷰·원출력의 SHA-256, 크기, 소요 시간, llm_outcome, prompt_version, model_id를 남긴다. 내용은 남기지 않는다 | 테스트 | enforced(실제 호출 경로 — 스텁 서버로 증명) | `llm_io_audit` |
| Body 불변식 1~6을 ③에서 검증 | validator+테스트 | enforced(검증 함수 단위 — ③, 불변식 5는 같은 kind 안) | `masked_span_integrity` |
| 라벨 양방향 동치 — 생산자 강제, Python 런타임 보장 아님 | 테스트 | enforced(relation_preserving 출력에만 — strict는 label=null이라 대상 아님) | `label_consistency` |

### 3.4 전 층위 공통
| 규칙 | 목표층위 | 상태 | manifest 키 |
|---|---|---|---|
| main 직접 병합 금지 | CI(branch protection) | unverifiable(레포 설정) | `branch_protection` |
| 푸시 대상 커밋이 make verify를 통과한 커밋과 같고 작업 트리가 깨끗할 때만 푸시 | CI(pre-commit) | enforced(클라이언트 훅 — git push --no-verify로 우회 가능. 실수 방지용이며 서버측 강제 아님) | `push_requires_verify` |

### 3.5 C·E (출력·검증)
| 규칙 | 목표층위 | 상태 | manifest 키 |
|---|---|---|---|
| evidence≥1(0개 거부=환각차단) | 스키마/validator | enforced(검증 함수 단위) | `evidence_min_one` |
| evidence.transaction_ref ∈ analyzed_refs | validator | enforced(검증 함수 단위) | `evidence_ref_integrity` |
| Evidence.pointer(Locator)가 마스킹 후 데이터에서 해석됨(해석 실패 시 전체 폐기) | validator+테스트 | enforced(검증 함수 단위) | `evidence_pointer_resolves` |
| status 서버부여·LLM 생성불가 | validator | enforced(검증 함수 단위) | `server_assigned_status` |
| category 폐쇄형 enum | 스키마 | enforced(검증 함수 단위) | `category_closed_enum` |
| 출력 스키마 전체(파생 롤업) | 파생(하위 4키 AND) | derived † | `output_schema_gate` |
| 생산자별 초안을 각각 검증한 뒤 (category, CNA 집합) 일치를 병합하고 _assign 1회로 만든다. 규칙 초안 거부는 output_rejected, LLM 초안 거부·실패는 completed + 규칙 결과 + 실패 사유 | 테스트 | enforced(합성 초안으로 증명 — 어댑터 결선은 L3) | `producer_gate_merge` |
| 깨끗함 = completed ∧ findings [] ∧ 실패 사유 없음. LLM 실패 + 빈 findings는 깨끗함이 아니다 | 테스트 | enforced | `clean_requires_no_failure` |
| rule_llm의 test split은 FROZEN_PROMPTS·FROZEN_MODELS에 있는 버전만 측정(아니면 동결 순서 밖 표기) | 테스트 | enforced(판정 값은 묶음 해시(§2.8). 동결 표는 비어 있다 — 등록은 프롬프트 동결 때) | `prompt_model_freeze` |
| LLM 초안 계약의 모든 하위 제약이 전송 스키마에 표현 / 프롬프트 출력 규칙 절에 열거 / 정당한 제외(초안 금지) 중 하나다. 새 제약·새 검증기는 실패 | 테스트 | enforced(전달은 보장하지만 모델이 지키는지는 게이트가 판정. 범위 — Pydantic 초안 계약과 JSON Pointer 하위 제약. 서버 문법의 키워드 강제는 수동 절차) | `llm_contract_conveyed` |
| ④의 completed 반환 경로가 출력 게이트를 지남(현존 경로 한정) | 테스트 | enforced(현존 경로 한정 — 생산자별 게이트 경로까지 재증명, 어댑터 결선 경로까지 재증명. 게이트 결과의 불변은 공개 API 범위 — `object.__setattr__`·`__dict__` 직접 조작은 런타임 범위 밖(src/sentinel 안의 사용은 정적 검사가 거부한다 — 런타임 조립은 그 범위 밖)) | `completed_via_gate` |
| hypothesis 단정 토큰 차단 | 테스트 | not_implemented → 5번 평가 데이터로 기준 확정 시 | `assertive_token_guard` |
| observation 재대조 | 테스트 | not_implemented → 5번 평가 데이터로 기준 확정 시 | `corroboration_check` |
| 환각 리터럴 격리(LLM 자유 문자열의 정책 패턴 리터럴 치환 + 플래그, 원문 저장·로그 금지, 플래그 달린 evidence는 유효 근거 제외) | 테스트 | enforced(정책 패턴 안 — 패턴 밖 환각은 `corroboration_check` 몫) | `hallucinated_literal_isolation` |
| 반복 이상 → 세션 신호 | 테스트 | not_implemented → 세션 개념 도입 시 | `anomaly_aggregation` |
| 평가 하네스 | 테스트 | enforced(채점기 검증까지 — 정답을 아는 입력에서 정확·최대 매칭·결정론. 층 B 실측 가능(rule_only — 러너 `make eval`). LLM 경로의 층 B는 LLM 결선 이후) | `eval_harness` |
| 정규화 함수 — 같은 값을 가리키는 서로 다른 Locator가 같은 CNA로 정규화됨 | 테스트 | enforced(모드 무관 — 항상 적용) | `canonical_address` |
| 엔진(src/sentinel)이 평가 라벨 경로를 읽지 않음(데이터 읽기 금지 — `engine_tools_isolation`의 코드 import 금지와 다른 격리) | 아키텍처 테스트 | enforced(정적 범위 — 라벨 경로 문자열·라벨 타입 import·이름 0까지. 런타임 조립 경로는 범위 밖) | `label_isolation` |
| 동결 픽스처가 현재 스키마로 검증되지 않으면 버전 증가 없이 실패(큐 12) | 테스트 | enforced | `dataset_version_freeze` |
| 동결 데이터셋의 Envelope가 엔진의 실제 ②③을 계속 통과(동결 자산 회귀 보호, 모드 무관) | 테스트 | enforced | `dataset_engine_regression` |
| 동결 자산이 기록된 마스킹 모드의 라벨 규칙을 따름(strict → label 전부 null / relation → 전부 ref_NN) | 테스트 | enforced | `dataset_mode_consistency` |
| S의 (엔드포인트, 결함 패턴) 조합마다 트랜잭션 1건(독립 단위 — 생성기 SSOT가 조합 중복 검사) | 테스트 | enforced(생성기 장치 — 합성 카탈로그로 증명) | `dataset_case_independence` |
| 동결 표의 ruleset 해시가 규칙 파일과 일치(규칙 내용만 바꾸고 버전을 두면 실패) | 테스트 | enforced(범위 — rule_engine.py·strict_json.py·canonical_address.py 3파일. 타입 파일은 제외) | `ruleset_freeze` |
| 라벨링 지침 파일이 동결 표의 해시와 일치(바뀌면 실패하고 생성기가 거부) | 테스트 | enforced | `guideline_freeze` |
| 현재 규칙 해시가 동결 표에 없으면 생성 거부 + test 보고에서 데이터셋 기록과 다른 ruleset은 '동결 순서 밖 — 측정 아님' 표기 | 테스트 | enforced(생성기 장치 — 합성 카탈로그로 증명) | `producer_freeze_order` |

> **† `output_schema_gate` (파생 롤업):** `evidence_min_one ∧ evidence_ref_integrity ∧ server_assigned_status ∧ category_closed_enum`. 자체 강제테스트 없음 — 하위 4키가 강제한다. 하위 전부 enforced일 때만 enforced다. 하위 4키가 enforced(검증 함수 단위)이므로 파생값도 enforced이며, 범위도 같다(§3.5 각주). `guardrails.yaml` 파생 시 `status=derived` + 하위 키 목록으로 표현한다(상태 칸은 문장이 아니라 기계 파싱 가능한 상태값).

> **출력 게이트 enforced 범위:** 게이트 자체의 enforced 범위 = 검증 함수 단위(주입 테스트). ④가 completed를 반환하는 현존 경로가 게이트를 지나는지는 `completed_via_gate`가 추적한다. 이후에 생기는 경로(LLM 등)는 그 결선 PR에서 같은 키로 다시 증명한다.

### 3.6 기반 적대적 테스트 (Java 없이 직접 주입 — '위조 거부'로 증명)
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
  - 1:1 최대 매칭, 결정론적 — **사전순 최소 최대 매칭**. 매칭 안 된 p = FP, 매칭 안 된 V = FN.
    - 예측을 정렬 순서로 보며, 각 예측에 매칭 가능한 라벨을 정렬 순서로 시도하되, 그 쌍을 확정한 뒤에도 전체 매칭 수가 최대로 유지될 때만 확정한다(어떤 라벨로도 최대가 유지되지 않으면 그 예측은 매칭하지 않는다). 최대성은 최대 매칭 알고리즘(Hopcroft-Karp/증가 경로)으로 크기를 확인하며 보장한다. 탐욕 매칭이 아니다(앞선 선택이 뒤의 유일 매칭을 가로채지 않는다). 이 정의는 유일하다.
    - 정렬 키: 예측 (category, CNA 집합의 최소 CNA, finding_id) / 라벨 (transaction_ref, 정렬한 categories, anchor CNA 집합의 최소 CNA). verified_clean처럼 anchor 없는 라벨은 매칭 대상이 아니라 키가 필요 없다.
    - CNA 전순서(정본): (transaction_ref 문자열, node 튜플) 사전순. node 원소는 문자열이면 코드포인트 순, 정수면 수 순. 이 순서는 `canonical_address` 모듈의 명시적 정렬 키(`cna_sort_key`)로 노출하고 테스트로 고정한다(파이썬 튜플 비교에 암묵적으로 맡기지 않는다 — CNA 구조가 바뀌면 순서가 조용히 바뀌므로).
    - 근거: 같은 입력이면 실행마다 같은 채점(재현성) — 그래서 구현 재량이 아니라 정본 값이다.
    - 한계: finding_id는 서버가 uuid4로 부여하므로 같은 모델 재실행 간 동점 승자가 바뀔 수 있다. 동점에서는 TP 수가 같아 지표 값과 J7 회귀 판정은 바뀌지 않고, '어느 예측이 TP로 표시되는가'만 달라진다.
  - 채점 대상 = 서버 중복 처리를 거친 출력.
  - needs_review finding도 예측으로 센다. 사용자에게 보이는 결과이기 때문이다. 건수는 §6.3에서 병기한다.
  - 평가기는 엔진의 CNA 정규화 함수(§2.6, `canonical_address`)를 쓴다 — 서버 중복 처리와 같은 함수다(평가기 → 엔진 import는 허용 방향).
  - advisory_signals는 P/R 채점 대상이 아니다(탐지가 아니다 — §2.4). advisory 지표는 따로 정한다.
- **라벨링 지침:** 더 세밀한 노드가 있으면 거친 노드(body_text·req_line.path)를 anchor로 쓰지 않는다(자석 노드가 FP를 TP로 둔갑시킨다).

### 6.2 데이터셋
- **두 집합:** S(자체 더미 API, 라벨 완전) / J(Juice Shop, 라벨 불완전). 지표를 합산하지 않는다.
- **라벨 상태 셋:** labeled_positive / verified_clean / unlabeled.
  - unlabeled 위의 예측은 FP가 아니라 '미판정'으로 따로 집계한다. 정상 FP율은 verified_clean에서만 잰다.
- **S 라벨의 출처:** 더미 API 정의에서 파생한다(SSOT). 라벨마다 source: construction | catalog | adjudication.
- **hard negative:** S는 category마다 hard negative를 둔다.
- **블라인드·버전 동결 — 원칙: 측정 대상 생산자와 평가 데이터는 서로를 보고 조정되지 않는다.**
  - (a) 라벨은 생산자 첫 실행 전에 동결한다. 재심은 새 데이터셋 버전으로만 한다(실행 중 수정 금지, 흔적은 source=adjudication). 지표는 데이터셋 버전과 함께 보고한다.
  - (b) test 분할은 그 위에서 주장하는 생산자 버전(ruleset_version·prompt_version·model_id)이 동결된 뒤에 작성한다. 동결 전에 test가 있으면 생산자는 test를 보지 않고 dev로만 조정한다(dev/test 분리와 정합).
  - 1인 단계 한계: 데이터 작성자와 생산자 작성자가 같다. 이 편향은 J6의 두 경로(규칙 단독·규칙+LLM)에 함께 걸린다.
  - S v1: 규칙(반사 판정 기준)을 S v1 사례를 읽고 도출하므로 S v1은 규칙에 대해 오염된 스모크 집합이다. S v1 위의 규칙 결과는 측정이 아니라 동작 확인이다.
- **dev/test 분리:** 엔드포인트 단위로 분리한다. 튜닝은 dev에서만, test는 회귀 판정에만 쓴다.
- **라벨 격리:** 라벨 파일은 픽스처와 분리하고 평가기만 읽는다. 엔진은 라벨 경로를 읽지 않는다(`label_isolation`).
- **표본 부족 표기:** §6.3 J8을 따른다.
- **동결 = 첫 소비자 발생:** 그 시점의 형태가 schema_version의 동결 형태로 확정된다(버전을 올리는 것이 아니다. 버전은 동결 이후 첫 변경에서 오른다 — §2 버전 규칙). 큐 12(`dataset_version_freeze`) 강제 장치를 동결과 같은 PR에서 만든다.
- **한계 기록:** IDOR 사례는 relation_preserving + 한 배치 안에서 생성한다(라벨 일관성은 배치 안에서만, §2.3). 단일 라벨러(J)라 라벨러 간 일치도는 측정할 수 없다 — 팀 확장 시 이월.

- **라벨 파일(LabelFile) — 픽스처와 분리된 파일, 평가기만 읽는다:**
  ```
  LabelFile = { schema_version: "1.0" | "1.1", dataset_id, frozen_at(ISO8601+tz), split_scheme?: "endpoint",
                frozen_against: { envelope_schema, raw_schema, labelfile_schema,
                                  ruleset_version, ruleset_hash,        # 1.1에서 필수, 1.0에는 없음
                                  masking_modes: { transaction_ref → strict_redaction | relation_preserving } },
                labels: [Label] }                         # 1.0: 트랜잭션마다 라벨 정확히 1개 / 1.1: 트랜잭션마다 라벨 ≥ 1. 모드 기록은 정확히 1개
  Label     = { transaction_ref(UUID), label_status: labeled_positive | verified_clean | unlabeled,
                categories: [category 4종], anchors: [Locator(§2.6)], hard_negative: bool,
                source: construction | catalog | adjudication,
                split?: dev | test }                      # split_scheme이 있으면 필수
  ```
  - **1.1(가산, 소비자 있음 → 부 버전 증가):** split_scheme은 선택이다. split_scheme이 있으면 라벨의 split은 필수이고 누락은 오류다(null로 읽지 않는다). 1.0(S v1)은 계속 읽히고 split은 null이다.
    - 라벨 모델(1.1): 트랜잭션마다 라벨 ≥ 1이다. labeled_positive는 결함마다 1개이고 같은 트랜잭션에 여러 개가 있을 수 있다. verified_clean·unlabeled는 그 트랜잭션의 유일한 라벨이다. hard_negative는 verified_clean에만 있다. categories 집합은 단일 결함의 모호 category에만 쓴다. 1.0(S v1)은 트랜잭션마다 정확히 1개 그대로다.
  - 상태 제약: labeled_positive → categories ≥ 1, anchors ≥ 1, hard_negative=false / verified_clean → anchors 0개, hard_negative=true면 categories = 흉내 낸 category(어느 category의 FP 후보인가), 아니면 categories 비움 / unlabeled → 둘 다 비움, hard_negative=false. J3의 'hard negative 부분집합'은 hard_negative로 거른다.
  - anchors는 Locator로 적는다(예측 Evidence와 같은 형식). 평가기는 읽을 때 `canonical_address`로 CNA로 바꾼다(§6.1 매칭).
  - masking_modes는 정답이 아니라 생산 조건이다. 동결 자산이 그 모드의 라벨 규칙(§2.3)을 따르는지 회귀 검사한다(`dataset_mode_consistency`). 엔진 ③은 모드를 모른다 — 모드별 ③ 경로는 없다.
  - **라벨 무결성(동결 전에 막는다):** anchor는 Locator 타입으로만 읽히고(스키마), transaction_ref가 가리키는 마스킹된 Envelope에서 실제로 해석돼야 한다 — 예측 evidence와 같은 판정(출력 게이트의 `resolves`, §2.6 서버 검증)을 쓴다. 없는 위치를 가리키는 라벨은 동결하지 않는다. 라벨링 지침(§6.1, 거친 노드 회피)은 라벨러가 지키는 지침이며 기계 강제가 아니다.
- **독립 단위 — 구성 규칙 (i):** S에는 (엔드포인트, 결함 패턴) 조합마다 트랜잭션을 1건만 둔다. 독립 단위 = 트랜잭션. 규모 게이트는 트랜잭션 수로 센다(category별 게이트 = 그 category 라벨이 있는 트랜잭션 수). 재현율의 n은 라벨 수이고, 같은 트랜잭션의 복수 라벨은 독립이 아니다(근사 — 보고에 복수 라벨 트랜잭션 수를 병기). J7 쌍체 bootstrap은 트랜잭션 단위라 이 근사의 영향을 받지 않는다.
  - 엔드포인트 = 더미 API 정의(SSOT)의 (method, 경로 템플릿). Python 내부 파생 path_template이 아니다.
  - 결함 패턴 = SSOT가 사례에 부여한 패턴 ID. verified_clean·hard negative도 패턴 ID를 갖는다.
  - 근거: 같은 조합의 변형으로 n을 채우면 Wilson의 독립 가정이 깨져 구간이 거짓으로 좁아진다.
  - S v1 = 규칙 이전 데이터셋(S v2부터 적용). 사람이 읽은 조합은 겹치지 않으나 기계 판정 근거 없음(생성기에 패턴 ID·엔드포인트 템플릿 없음). 동결본은 건드리지 않는다.
  - 강제: `dataset_case_independence`(생성기 SSOT가 엔드포인트 템플릿·패턴 ID를 기계 판독 가능하게 갖고 조합 중복을 검사한다. 이 검사를 위한 LabelFile 변경은 없다).
- **첫 동결(S v1):** 마스킹된 Envelope 6건 + 라벨 파일 — category 4종 각 labeled_positive 1건(그중 IDOR 1건은 relation_preserving, anchor가 헤더·본문에 걸침), verified_clean 1건, hard negative 1건. 원본은 커밋하지 않는다(§1.3 ⓕ). 표본 충족(J8)과 'category마다 hard negative'는 첫 동결의 목표가 아니다 — 구조 검증이 목적이고 사례는 평가 하네스 이후 새 데이터셋 버전으로 늘린다.

- **S v2 구성:**
  - **사례 카탈로그 = 생성기 SSOT(선언형):** 머리에 지침 버전·해시를 적고, 사례마다 case_id, 엔드포인트(method, 경로 템플릿), pattern_id, split, masking_mode, source, labels(결함마다 label_status·categories·anchors·hard_negative·clause), tx(트랜잭션 선언)를 둔다. 생성기는 (엔드포인트, 패턴) 조합 중복 0·엔드포인트 단위 split·규모 게이트를 강제한다.
  - **규모 게이트:** test는 labeled_positive 트랜잭션 ≥ 39, verified_clean ≥ 39이고 그중 category마다 positive ≥ 8, hard negative ≥ 4다. dev는 positive ≥ 20, clean ≥ 20이다. hard negative 수는 verified_clean 트랜잭션만 센다(positive 트랜잭션 안의 대조 사례, 예: 입력 무관 DB 오류는 세지 않는다).
    - 한계: 템플릿으로 생성하므로 사례 사이의 유사성이 남는다(Wilson의 독립 가정은 근사). 정밀도의 n은 라벨 수가 아니라 예측 수라 이 게이트로 보장되지 않는다.
  - **라벨링 지침:** 레포 문서 `docs/labeling-guideline.md`에 두고 버전을 붙이며, 카탈로그 작성 전에 동결한다(본문은 지침 PR). §6.1의 anchor 지침은 그대로 적용한다.
    - 원칙: 지침은 §1.1 정의에서만 도출한다. 규칙·생산자를 보고 설계하지 않는다.
    - 제1조: 라벨은 마스킹 후 트랜잭션에서 관측 가능한 근거로 판정 가능해야 한다.
    - O-4: 관측이 같은 두 트랜잭션은 라벨이 같다. positive는 관측 신호이고 악용 가능성이 아니다(한계).
    - hard negative마다 §1.1 근거를 적는다. 규칙을 아는 작성자의 편향은 1인 단계 한계다.
  - **CORS 허용 목록 일치 사례:** 관측상 SM-P2와 같으므로 그렇게 라벨하고, 그 배경의 사례를 따로 구성하지 않는다.
  - **작성 순서:** ruleset 동결(rules-2, 완료) → 지침 동결 → 카탈로그 → 생성·동결 → 생산자 첫 실행. LLM은 dev에서만 조정한다(기계로 증명 불가 — 한계).
  - **채점 단위:** split_scheme이 있는 데이터셋은 split 인자가 필수이고 그 split만 채점한다. 인자가 없으면 거부한다.
  - **rule_llm의 test split:** FROZEN_PROMPTS(묶음 해시 — §2.8)·FROZEN_MODELS에 있는 버전만 측정이다. 아니면 "동결 순서 밖 — 측정 아님"으로 표기한다(`prompt_model_freeze`). test 측정마다 progress-log 커밋이 의무다(대상은 S v2. 억지력이며 증명이 아니다).
  - **동결 순서:** 생성기는 현재 규칙 해시가 FROZEN_RULESETS에 없으면 생성을 거부한다. 하네스는 test split 보고에서 데이터셋 기록과 다른 ruleset이면 "동결 순서 밖 — 측정 아님"으로 표기한다(`producer_freeze_order`). 해시 범위는 rule_engine.py·strict_json.py·canonical_address.py이고, 타입 파일(common_types·output_schema·schema)은 제외한다(한계 — 타입 변경은 잡지 못한다).
- **모델 선별 프로토콜(선정 기준을 실행 전에 등록한다):** 결과를 본 뒤 기준을 바꾸면 선별이 오염되므로, 아래 기준은 선별 실행 뒤 바꾸지 않는다.
  - 범위: dev만 쓴다. 모든 후보에 같은 기본 프롬프트 템플릿을 쓴다. 모델마다 예산 설정값(뷰 상한·max_tokens·기한)을 실측 속도로 다시 도출한다(묶음 해시가 달라지는 것은 정상이다).
  - 예산 도출 규칙: 여유 10%, max_tokens 먼저 고정 후 뷰 도출(값은 progress-log, 실행 전 커밋).
  - 후보 조건: 텍스트 전용 instruct GGUF, 컨텍스트 ≥ 8k(4k 모델 제외 — 8KB 뷰 + 출력이 들어가지 않는다), RAM 16GB 안, 라이선스가 사내 업무 사용을 허용(민수 판정).
  - 선정 기준:
    - ① LLM 실패율(J2: truncated·timeout·unparseable·rejected 합) ≤ 10%. 환경 실패(unavailable·oversize·audit_write) 트랜잭션은 그 건만 1회 재실행하고, 남으면 ① 합에 넣는다.
    - ② 탐지력 관문: ①을 통과한 후보 중 llm_only_tp ≥ 1인 후보가 없으면 "선정 없음"을 보고하고 멈춘다(어떤 모델도 고르지 않는다).
    - ③ 순위: 순이득 = llm_only_tp − (produced_by=llm인 FP)가 최대인 모델. 근거: 규칙 결과는 후보 간 동일하므로 순이득이 LLM의 기여를 직접 잰다. Recall만 보면 많이 뿌리는 모델이 이긴다.
    - ④ 동률: J2가 낮은 쪽 → 중앙 소요 시간이 짧은 쪽.
    - ⑤ 선정 대상은 이 PC 실사용 조건(전체 기한 120초) 안의 후보뿐이다. 7B급은 참고 측정(기한 240초)이고 선정 대상이 아니다.
  - 사실 기록: 기준 확정 전에 1.5B 스모크 값(실패율 2/40)을 보았다.
  - 선별 결과는 측정이 아니다(dev). 선정 뒤 FROZEN_MODELS에 등록하고, 그 모델로 dev 튜닝 → 프롬프트 동결 → test.
  - 무효 처리 규칙: 측정 장치 결함(우리 코드가 계약과 어긋남)일 때만 실행을 무효로 한다 → 실행과 사유를 기록한다 → 결함을 고친다 → 같은 기준으로 1회만 재실행한다. 모델 행동은 무효 사유가 아니다. 기준은 바꾸지 않는다.
    - 사실 기록: 이 규칙은 선별 결과(선정 없음)를 본 뒤에 등록했다 — 그래서 재실행은 1회로 제한하고 기준은 고정한다.
- **S v2 동결:** 마스킹된 Envelope 120건 + 라벨 파일(LabelFile 1.1) + 사례 카탈로그(`datasets/S/catalog-v2.json`). 엔드포인트 30개. test 80건(labeled_positive 40, verified_clean 40 — hard negative 26, 일반 14), dev 40건(labeled_positive 20, verified_clean 20). 복수 라벨 트랜잭션 test 5건, dev 2건. 라벨링 지침 v1, ruleset rules-2, 데이터 커밋 `d85b0fb`. 원본은 커밋하지 않는다(§1.3 ⓕ).
  - 한계: J3 전체 비율은 실제 빈도 추정이 아니다(hard negative 과대 대표 — hard negative·일반 clean 부분집합을 따로 읽는다). 요청 본문 값은 구성하지 않았다. 사례는 템플릿으로 생성되어 유사하고(① 소유자 필드 포함), dev/test는 엔드포인트 단위로만 분리되어 패턴 템플릿을 공유한다 — dev 튜닝 효과가 test로 실제보다 잘 옮겨 갈 수 있다. 경로 사례는 실제 요청에서는 인코딩될 문자를 원문으로 구성했다.

### 6.3 지표
- **J1 P/R:** §6.1 매칭 규칙. Precision 대표값은 S에서만 낸다. J는 알려진 라벨 기준 Recall + 미판정 건수. category별 + 전체 micro. 대표 = S / 현실성 = J, 섞어 보고하지 않는다. 결함별 라벨에도 §6.1의 1:1 매칭을 그대로 쓴다(한 트랜잭션에 라벨이 여러 개면 TP도 여러 개일 수 있다). 보고에 복수 라벨 트랜잭션 수를 병기한다.
  - 대표 지표 = 엄격 매칭(위치 + category).
  - 보조 지표 = 위치만 일치(category 무관)한 P/R + category 혼동 행렬.
  - category는 맞혔으나 위치가 틀린 예측은 어느 쪽 지표에도 TP로 들어가지 않는다(매칭 불성립).
  - 정당하게 두 category에 걸치는 결함은 V.categories를 집합으로 둔다.
- **중복:** 매칭 후 남은 중복 예측은 FP로 센다(1:1 매칭에서 둘째 예측은 자연히 FP). 이와 별도로 중복률을 진단 지표로 보고한다.
- **J2 거부·실패:** `output_rejected`는 규칙 쪽 버그만 뜻하고, 그 라벨은 전부 FN이다(제외 금지). LLM 거부율·실패율(사유별)을 보고한다.
  - rule_llm 보고에 needs_review 건수와 그중 TP·FP, 환각 리터럴 치환 횟수를 병기한다(§6.1).
- **J3 정상 오탐률** = verified_clean 중 finding ≥ 1인 비율. hard negative 부분집합은 별도 보고한다. rule_llm은 전체와 LLM 성공 부분집합을 병기한다.
- **J4 검증 가능한 결과 비율** = 중복 처리 후 finding 중 corroboration=matched가 1개 이상인 비율. `corroboration_check` 구현 전에는 not_run으로 표기하고 숫자를 내지 않는다.
- **J5 분석 시간 절감률:** 1인 단계에서는 보류한다(unverifiable 성격). 숫자화하지 않는다.
  - 근거: 정답을 아는 사람이 잰 수동 시간은 거짓 보장이다. 팀 확장 시 결함 목록을 모르는 점검자 대상, 교차 배치, 트랜잭션 풀 분할, 시간은 정확도와 함께 보고 — 프로토콜로 이월.
- **J6 AI 기여도:** 규칙 단독 vs 규칙+LLM ablation(같은 데이터셋, ΔP·ΔR), produced_by별 P/R, LLM만 찾은 TP 수. 규칙 단독 기준선 = `pipeline_mode=rule_only` 실행이다(같은 데이터셋·같은 `ruleset_version`끼리 비교). rule_llm은 전체와 LLM 성공 부분집합을 병기한다.
- **J7 불확실성:** 비율은 Wilson 95% 구간. 버전 간 비교는 트랜잭션 단위 쌍체 bootstrap. 대표 지표에서 차이 구간이 통째로 0 아래면 회귀이고, 개선 주장도 같은 기준을 쓴다.
- **J8 최소 표본:** Wilson 구간 반폭 ≤ 0.15일 때만 점추정값을 낸다. 그보다 넓으면 "표본 부족(n=k)" + 구간. 0.15는 초기 임계값이다(설정값 — `DEFAULT_PORT`와 같은 성격(실측으로 조정 가능, 정본이되 불변식 아님)).
- **J9 보고 머리:** 데이터셋 버전·집합(S/J)·분할(dev/test, 없으면 null)·pipeline_mode·model_id·prompt_version·ruleset_version. rule_only에서 model_id·prompt_version은 null로 적는다(대체 문자열 금지).
  - **서빙 조건(rule_llm):** 추론 서버 버전·-t·-c·--parallel·CPU 요약을 적는다. 동결 대상이 아니라 측정 조건 기록이다 — 하드웨어에 따라 정해지는 값이라 해시에 묶지 않지만, 속도 차이로 생긴 timeout 차이를 모델 차이로 오독하지 않게 한다.

---

## 부록 — 확정된 기술 스택
- Extension: Java 17+ / Montoya API / Gradle (레거시 Jython/Extender 미사용)
- 분석 서버: Python 3.11+ / FastAPI / Pydantic
- 구조화 출력: LLM 클라이언트 라이브러리 0 — 표준 라이브러리 http.client + 추론 서버의 JSON 스키마 제약 디코딩 + 출력 게이트(유일 검증자). 상세는 2부.
- 추론 서버 선정 기준: 오프라인 반입 가능(단일 실행 파일 또는 wheel) / 실행 중 외부 연결 기능(업데이트 확인·원격 모델 다운로드·텔레메트리)이 없거나 끌 수 있음 / JSON 스키마 제약 디코딩 / CPU 추론 / 127.0.0.1에만 바인딩 가능. 기동 조건: 텍스트 전용 모델(멀티모달 투영 파일 없음), --offline 기동.
- RAG(나중): sentence-transformers + sqlite-vec/FAISS (전부 로컬)
- 저장소: SQLite
- 평가: pytest 하네스 + 라벨 데이터셋 (선택적 promptfoo)
- 테스트 환경: Docker + OWASP Juice Shop (+ 정답 아는 자체 더미 API)
- LLM 전략: 개념 검증 = 개발 PC에서 돌릴 수 있는 로컬 모델(현재 CPU 추론 전제). 결과는 그 모델 계열에 대한 측정이다. 더 큰 모델은 하드웨어 확보 시로 미루고, 외부 API로 대체하지 않는다. 교체 가능 인터페이스 필수. **(인터페이스·송신 경로는 어댑터 개정에서)**