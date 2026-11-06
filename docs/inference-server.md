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

## 5. 끝낸 뒤

서버를 종료한다. 기동 때 기록한 `model_id`(`이름@sha256:<가중치 해시>`)를 설정에 넣는다. 서버 로그에 요청 내용이 남지 않는지는 쓰는 버전에서 확인한다.
