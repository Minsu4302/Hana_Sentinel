# Burp 확장(Java) — 빌드·검증·수동 로드 절차

> 정본은 (A) §2.9(Burp Extension 계약)와 §3.1·§3.2의 `java_no_target_send`·`java_loopback_only`·`java_build_egress`·`java_logic_isolation`이다.
> 이 문서는 운영 절차다. 충돌하면 (A)가 우선한다.

## 1. 무엇인가

- 위치: 레포 `burp-extension/`(Gradle 프로젝트 1개). Java 17 대상, 빌드 JDK 21, Gradle 9.9.1(wrapper).
- 진입점 1개(확장 이름 설정 + Montoya logging으로 로드 사실 한 줄)와 capture / transport / ui 패키지를 둔다.
- 2부 PR-1b-1부터 `transport.masker`에 마스커 코어(순수 Java — Montoya import 0, java.net 0)가 있다. 참조 마스커와의 바이트 동등성은
  `tests/test_java_masker_parity.py`가 make verify마다 확인한다(하네스는 `src/test/java` — 배포 jar 밖).
- 아직 아무것도 전송하지 않는다. 컨텍스트 메뉴·HTTP 클라이언트·소켓 코드는 0이다(전송은 2부 PR-2).
- 의존성: `net.portswigger.burp.extensions:montoya-api:2024.12`(compileOnly — 설치된 Burp Community 2024.12.1과 맞춤),
  `com.google.code.gson:gson:2.15.0`(implementation), `com.google.errorprone:error_prone_annotations:2.50.0`(compileOnly —
  gson이 참조하는 애너테이션. 런타임 불필요를 실측해 런타임 클래스패스와 jar에서 뺀다).
- 정책 파일은 레포의 `src/sentinel/sanitization_policy.json` 하나다. 빌드가 `transport/masker` 리소스로 넣는다(사본을 커밋하지 않는다).
- 배포 jar(`build/libs/sentinel-burp-extension-0.1.0.jar`, 기본 jar 태스크): 우리 main 클래스 + 정책 리소스 + gson의
  `com/google/gson/**` + `META-INF/licenses/gson-LICENSE.txt`(Apache-2.0 원문 — `burp-extension/licenses/`, apache.org와 gson 2.15.0
  태그 LICENSE 두 출처의 바이트가 같음). gson의 META-INF(MANIFEST·pom·proguard·versions/9/module-info)는 넣지 않는다.
  타임스탬프·순서를 고정해 같은 입력이면 같은 jar가 나온다. 검사는 `tests/test_java_jar_contents.py`(`java_jar_contents`).

## 2. 보관 위치(레포 밖, 한 번 준비)

다운로드 원본과 Gradle 캐시는 오래 보관되는 레포 밖 폴더에 둔다. 세션 스크래치패드·임시 폴더에는 두지 않는다(사라질 수 있다).
동기화 대상이 아님은 `docs/inference-server.md` §5 「평가 산출물 보관」의 확인 방법을 그대로 쓴다.

- `%USERPROFILE%\sentinel-java\`
  - `archive\` — 다운로드 원본(아래 체크섬과 대조한 것)
  - `jdk-21.0.13+9\` — JDK zip을 푼 것(시스템 설치·PATH 변경 없음)
  - `gradle-home\` — `GRADLE_USER_HOME`(wrapper 배포판·의존성 캐시)

| 원본 | SHA-256(독립 출처와 대조) |
|---|---|
| `OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.zip`(Temurin) | `a4dbaa05fca4bd89d84584e58c459bd732efebb1722af80ab13c6516832004f9` |
| `gradle-9.9.1-bin.zip`(services.gradle.org) | `d8a18a7a841dd5df825d35a685fad6f2d7f12ac0c280e57b67c27b4a520ba228` |
| `gradle-9.9.1-wrapper.jar`(services.gradle.org) | `621008afc4f5d59357fcf06ffa644dd5aade5e091bdc363742710445f73cdaf8` |
| `montoya-api-2024.12.jar`(Maven Central) | `7e6dffb645188492dfb5f512075c9196250efa18b673dfa270ee22fa20e16c5c` |
| `montoya-api-2024.12.module`(Maven Central) | `5489cf5301cf6f2f204b2a92c00049362002541609622108b05ed0cd5248ec67` |
| `gson-2.15.0.jar`(Maven Central) | `96d3dd843dc2911de01cdabcd50064cb9e860353102a0a78c96fd833d396fc7d` |
| `gson-2.15.0.pom`(Maven Central) | `426bc968a4e521865a58dd17a60389fed6195a1c357e3eb8bcb7cae31387bcae` |
| `gson-parent-2.15.0.pom`(Maven Central) | `337664b30ade9b66e373b6efca1aba7421c1f8ff63643b8aa8b6d05d8efe8e8b` |
| `error_prone_annotations-2.50.0.jar`(Maven Central) | `4667724877f1d37a689202da191e23efa7657c62eef93ccdac406eccfe5cdd0a` |
| `error_prone_annotations-2.50.0.pom`(Maven Central) | `71a0680d277324bab46bec4b00f6f111c1b794a931d0d8cda79bcb9246982f92` |
| `error_prone_parent-2.50.0.pom`(Maven Central) | `abf45a019db125b50ff55134ec2af94ae3519761038adf0a60b9bd7b4b8b6254` |

gson·error_prone_annotations의 `.module`은 Maven Central에 없다(404). 위 6개는 `.sha256`·`.sha1`과 모두 대조했다(2026-11-24).

## 3. 첫 빌드(개발 PC, 네트워크 1회)

```
set JAVA_HOME=%USERPROFILE%\sentinel-java\jdk-21.0.13+9
set GRADLE_USER_HOME=%USERPROFILE%\sentinel-java\gradle-home
cd burp-extension
gradlew.bat --no-daemon build
```

- wrapper가 Gradle 배포판을 받고 `distributionSha256Sum`으로 검증한다.
- Gradle이 montoya-api·gson·error_prone_annotations(와 parent pom)를 받고 `gradle/verification-metadata.xml`의 sha256으로 검증한다. 메타데이터에 없는 아티팩트는 빌드가 거부한다.
- 받는 것은 승인된 좌표뿐이다. 저장소는 `mavenCentral()` 하나, 툴체인 자동 다운로드는 꺼져 있다(`gradle.properties`).

의존성을 바꿀 때는 (A) §3.1 `java_build_egress`의 좌표 허용 목록 안에서만 바꾼다. 그리고 `--write-verification-metadata sha256`으로 다시 만든 뒤,
각 해시를 Maven Central의 `.sha256`과 대조해 리뷰 팩에 표로 남긴다. 생성기가 받은 값을 그대로 믿지 않는다.

## 4. make verify의 Java 단계(네트워크 0)

`make verify`는 `tools/java_build.py`로 `gradlew --offline --no-daemon build`를 돌린다. Gradle을 실행하기 전에 다음을 차례로 확인하고,
하나라도 어긋나면 gradlew를 실행하지 않고 실패로 끝낸다. 조용히 건너뛰거나 내려받지 않는다.

1. wrapper 고정값: distributionUrl, distributionSha256Sum, wrapper jar sha256, `gradlew`·`gradlew.bat` sha256, 그리고 `gradle.properties`의 auto-download 끔.
   변조된 실행 스크립트는 실행되기 전에 걸린다.
2. `JAVA_HOME` — JDK 21(javac 포함)
3. `GRADLE_USER_HOME` — 고정 distributionUrl에서 나온 배포판 캐시 폴더(`wrapper\dists\gradle-9.9.1-bin\<URL 해시>\`)에 풀린 배포판과 `.ok` 표지

금지선 4키와 관대한 Gson API 금지(`java_masker_parity` 정적 하위 검사)는 `tests/test_java_boundary.py`가 Java 소스·빌드 파일 텍스트를
정적으로 검사한다(Montoya를 import하지 않는다). 동등성은 `tests/test_java_masker_parity.py`가 빌드 산출물을 `java -cp`로 실행해 본다 —
클래스패스에는 gson jar 하나만 더하고, `GRADLE_USER_HOME` 캐시의 jar가 verification-metadata의 sha256과 같을 때만 쓴다.
범위는 레포 Java 소스·빌드 파일 텍스트다. Burp 자체와 바이트코드 수준은 범위 밖이다.

## 5. Burp에 수동으로 로드(make verify는 Burp를 띄우지 않는다)

Burp Community 2024.12.1 기준.

1. `make verify`(또는 3절의 빌드)로 `burp-extension\build\libs\sentinel-burp-extension-0.1.0.jar`를 만든다.
2. Burp → **Extensions** 탭 → **Installed** → **Add**.
3. **Extension type: Java**, **Extension file**에 위 jar를 고른다 → **Next**.
4. 확인한다.
   - Installed 목록에 이름 **Sentinel**이 보이고 Loaded가 체크돼 있다.
   - 그 확장의 **Output** 탭에 `Sentinel extension loaded` 한 줄이 있다.
   - **Errors** 탭이 비어 있다.
5. 결과(Burp 버전·에디션, 위 세 가지)를 PR에 남긴다.

Burp 자체의 외부 연결(업데이트 확인 등)은 시스템 밖 도구의 동작이다. OS·운영 통제가 실주체다((A) §3.1 `egress_enforcement_owner`).
확장 코드는 이 연결에 관여하지 않으며, 확장 자체는 1부에서 아무것도 전송하지 않는다.
