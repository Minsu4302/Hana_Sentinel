# 추론 서버 기동 절차

> 대상: 이 PC에서 추론 서버를 띄우는 사람. 서버는 `llama-server`를 가정한다(민수 판정, 1순위). 예비 후보는 llama-cpp-python이다.
> 정본: (A) `docs/design-decision.md` §1.3 ⓑ 해석, §3.1 `inference_server_binding`, 부록.
> 이 절차는 `inference_server_binding`의 운영 보완이다. 추론 서버의 바인딩과 외부 연결은 우리 테스트가 볼 수 없다 — 지키는 주체는 OS와 이 절차다.

## 1. 반입

- 실행 파일과 가중치는 **설치 시점에 반입**한다(pip과 같은 범주). 실행 중 다운로드는 금지한다.
- 레포에 넣지 않는다.
- 내려받은 파일은 공식 체크섬과 대조하고, 버전·URL·SHA-256을 기록한다.
- 모델은 **텍스트 전용**이어야 한다. 멀티모달 투영 파일(mmproj)을 쓰지 않는다. `llama-server`는 요청의 `image_url`이 원격 URL이면 서버가 직접 가져오기 때문이다.

## 2. 기동 전 — 방화벽

실행 파일 폴더의 **모든 `.exe`** 에 아웃바운드 차단 규칙을 만든다. 규칙이 없으면 기동하지 않는다.

```powershell
Get-ChildItem <bin 폴더> -Filter *.exe | ForEach-Object {
  New-NetFirewallRule -DisplayName "sentinel-inference-block $($_.Name)" -Direction Outbound -Action Block -Program $_.FullName
}
Set-NetFirewallProfile -All -LogBlocked True
```

관리자 권한이 필요하다. 업데이트로 실행 파일이 늘면 규칙도 다시 만든다.

## 3. 기동

```text
llama-server.exe -m <모델.gguf> --host 127.0.0.1 --port <N> --offline --no-webui --no-slots --parallel 1 -c 8192 -t <스레드>
```

- `--host 127.0.0.1`: 다른 값을 쓰지 않는다. `0.0.0.0`이면 마스킹된 트랜잭션이 LAN에 노출된다.
- `--offline`: 모델 다운로드를 막는다.
- `--no-webui`: 웹 UI를 켜지 않는다.
- `--no-slots`: 슬롯 조회 엔드포인트를 끈다(기본 켜짐).
- `-c 8192`·`--parallel 1`: `-c`는 전체 값이고 슬롯 수로 나뉜다 — `--parallel 1`이 필수다. 뷰 8KB(약 3,200토큰) + `max_tokens` 1024를 담는다.
- API 키: 기동마다 랜덤 키를 만들어 환경변수로만 전달한다(`LLAMA_API_KEY`). 로그·커밋에 남기지 않는다(N7). 어댑터는 같은 환경변수를 읽어 헤더로 보낸다.
- `-hf`·`--model-url`을 쓰지 않는다.

서버는 키 없이 기동하면 "API 키 없음, CORS 전체 허용"을 경고한다. 같은 PC의 다른 프로세스와 브라우저 페이지가 이 포트에 닿을 수 있다는 뜻이다. `/health`는 키 없이 공개다.

## 4. 기동 후 확인

1. `netstat -ano`에서 그 포트의 LISTEN이 `127.0.0.1:<N>` 하나인가.
2. LISTEN 프로세스의 PID가 방금 띄운 서버인가. 포트에서 듣는 프로세스의 정체는 어댑터가 확인하지 못한다(포워더·포트 선점).
3. 방화벽 로그 `pfirewall.log`에 아웃바운드 DROP이 없는가. 이 로그에는 프로세스 이름이 없으므로 시간대로 대조한다.
4. 서버 로그에 스키마 변환 경고가 0건인가(`JSON schema conversion was incomplete` 등). 측정 기록에 건수를 적는다.
   서버는 지원하지 않는 키워드를 만나면 경고만 남기고 그 자리에 아무 문자열이나 받는다 — 요청은 200으로 성공한다.

### 문법 강제 탐침 (llama.cpp 버전을 바꿀 때)

전송 스키마의 키워드를 서버 문법이 실제로 강제하는지는 서버 버전마다 다르다. 버전을 바꾸면 `pattern`·`additionalProperties`
탐침을 다시 돌린다(현재 확인한 버전: b12119). 탐침은 합성 지시문만 쓴다 — dev·test 데이터를 넣지 않는다.
일부러 제약을 어기는 답을 유도하고, 출력이 제약을 지키면 '강제됨'이다.

한계(정직 표기): `make verify`는 실서버를 보지 않는다. 이 두 확인은 기계 강제가 아니라 수동 절차다(`llm_contract_conveyed`는
우리 쪽 정의에 전달 수단이 있는지까지만 본다).

## 5. rule_llm으로 돌리기

기본은 rule_only다. 아래 셋이 모두 있어야 rule_llm이고, 모자라면 기동·평가를 거부한다(조용히 rule_only로 내려가지 않는다).

- `SENTINEL_PIPELINE_MODE=rule_llm`
- `SENTINEL_LLM_PORT=<N>`
- `SENTINEL_LLM_MODEL_ID=<이름@sha256:가중치 해시>`
- `LLAMA_API_KEY`: 서버 기동 때 만든 키

모델별 예산은 선택이다(없으면 기본값 — 뷰 8192바이트, max_tokens 1024, 전체 기한 120초). 값은 `prompt_version` 묶음 해시에 들어가고, 출처(실측 속도·도출식)는 progress-log에 남긴다.

- `SENTINEL_LLM_VIEW_BYTES`(512~65536), `SENTINEL_LLM_MAX_TOKENS`(16~8192), `SENTINEL_LLM_DEADLINE_SECONDS`(10~3600, 읽기 타임아웃도 같은 값)

선별 실행은 `--rerun-env-failures`를 붙인다. 환경 실패 건만 1회 다시 돌리고 보고서 `reruns`에 처음·다시 결과를 남긴다.

평가는 `make eval EVAL_ARGS="--dataset datasets/S/v2 --split dev --serving-conditions <파일>"`다. 서빙 조건 파일은 `server_version`·`threads`·`context`·`parallel`·`cpu`를 담은 JSON이고 rule_llm에서 필수다(§6.3 J9). 동결 대상이 아니라 측정 조건 기록이다.

## 6. 끝낸 뒤

서버를 종료한다. 기동 때 기록한 `model_id`(`이름@sha256:<가중치 해시>`)를 설정에 넣는다. 서버 로그에 요청 내용이 남지 않는지는 쓰는 버전에서 확인한다.
