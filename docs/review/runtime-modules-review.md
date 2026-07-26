# 런타임·도구 모듈 최종 검토

> **역사적 참고 코퍼스 리뷰:** 2026-07-22 이후 `scan.sh`와 아래 모듈은 제품 구현이 아니라 fixture·탐지 아이디어의 출처다. 최신 plugin/action-gate 계약은 `README.md`와 `../plan/`을 우선한다.

- 검토일: 2026-07-15, 결정 반영 재검증 2026-07-18
- 범위: `apk-reverse`, `mobile-reverse`, `js-reverse`, `binary-diff`, `diagram-generator`, `ida-reverse`, `radare2`의 Markdown 31개와 `docs/draft/scan.sh`
- 기준: 저장소에 실제로 존재하는 자산, 현재 머신의 명령 가용성, 코드 예제의 정적 실행 가능성, 공식·상류 1차 자료

## 결론

최초 검토 당시에는 **방법론 전용 macOS 큐레이션**과 **Windows 실행형 도구 팩**이라는 두 제품 정의가 섞여 있었습니다. 후속 결정은 이 묶음 전체와 `scan.sh`를 제품이 아닌 참고 코퍼스로 고정했고, Secure Onboard 제품은 별도의 설치 전 정적 검사기로 정의했습니다.

명령 하나로 바로 고칠 수 있는 오류는 본 검토에서 수정했습니다. IDA/JSHook 도구 계약과 동적 실행 예제는 Secure Onboard 0.1의 차단 항목이 아니며, 해당 참고 자료를 실제 통합으로 채택할 때 아래 조건을 충족해야 합니다.

## 직접 수정한 오류

### 실행을 깨뜨리는 오류

- Frida 17에서 제거된 정적 `Module.findBaseAddress()`와 `Module.findExportByName()` 사용을 현재 `Process.getModuleByName()` 또는 `Module.findGlobalExportByName()` 형태로 바꿨습니다.
- iOS `fileExistsAtPath:` 예제가 `onLeave`에서 범위를 벗어난 `args`를 읽고 인스턴스 객체에서 메서드 메타데이터를 찾던 오류를, 클래스 메서드 래퍼에 attach하고 `onEnter`에서 경로를 저장하도록 고쳤습니다.
- iOS `ptrace` 예제가 포인터를 JavaScript 함수처럼 호출하던 오류를 `NativeFunction` 래퍼로 고쳤습니다.
- Android 예제의 존재하지 않는 표준 `ClassLoader.getDexFileList()` 호출을 제거하고, 해당 코드는 ClassLoader 열거일 뿐 DEX 덤프가 아님을 명시했습니다.
- Android `Cipher` 예제의 존재하지 않는 공개 `getOpmode()` 호출을 제거하고 공개 `getAlgorithm()`만 사용하도록 고쳤습니다.
- `SslErrorHandler.proceed()`를 후크해 다시 호출하던 WebView no-op 예제를 실제 대상 `WebViewClient.onReceivedSslError(...)` 콜백을 식별해 계측하는 형태로 바꿨습니다.
- JNI `RegisterNatives`를 ARM64 고정 오프셋 `0x35C`로 찾으라는 잘못된 지침을 ABI·헤더 기준 식별로 바꿨습니다.
- `ro.debuggable`과 `ro.secure`를 모두 `"1"`로 위장하던 예제를 각각 `"0"`, `"1"`로 고쳤습니다.
- radare2의 `wq`를 “저장 후 종료”라고 설명한 부분을 `q`로 바꿨습니다. radare2 쓰기 명령은 `-w` 모드에서 즉시 반영됩니다.
- Binary Diff 결과가 참조 명령 주소인 `insn_va`를 함수·전역 이름 변경 대상으로 쓰던 오류를 고쳤습니다. 스키마에 `target_va`를 추가하고 적용 전 피연산자 대조를 요구합니다.
- Diagram Generator의 중첩 코드 펜스를 4중 펜스로 고치고, 존재하지 않는 `render_diagram.py` 대신 각 공식 렌더러 명령을 적었습니다.

### 오래됐거나 과장된 사실

- Objection의 현재 진입 형태에 맞춰 `objection -n <name> start`로 바꿨습니다. 과거 `-g ... explore` 예시는 제거했습니다.
- SafetyNet Attestation이 Play Integrity API로 대체되고 2025년 1월 종료됐음을 반영했습니다.
- Android 11+ scoped storage에서 앱 전용 외부 디렉터리를 “모든 앱이 읽을 수 있다”고 한 설명을 OS·`targetSdk`·저장 위치별 모델로 고쳤습니다.
- `adb backup`을 보편적인 현재 추출법처럼 제시하지 않고 Android 12+ 백업 규칙을 확인하도록 바꿨습니다.
- `EncryptedSharedPreferences`가 AndroidX Security 1.1.0부터 deprecated임을 표시했습니다.
- App Store 바이너리의 FairPlay 암호화와 Mach-O FAT/thin 형식을 동일한 속성으로 설명한 문장을 분리했습니다.
- iOS의 `userDidTakeScreenshotNotification`은 촬영 뒤 전달되는 알림이고 `snapshotView(afterScreenUpdates:)`는 보호 우회 API가 아님을 반영했습니다. 진행 중 화면 캡처는 `UIScreen.isCaptured`와 캡처 상태 변경 알림을 구분했습니다.
- `dsymutil`은 이미 존재하는 오브젝트의 DWARF를 dSYM으로 연결하는 도구이지, 스트립된 바이너리에서 사라진 디버그 심볼을 복원하는 도구가 아님을 명시했습니다.
- Frida Gadget, FridaBypassKit, SSL pinning 우회, Objection을 “완전 자동”, “모든 계층”, “권한 불필요”로 표현한 부분을 재서명·무결성·대상 버전·프레임워크별 제약이 드러나도록 축소했습니다.
- Binary Diff의 고정 비용·속도·정확도와 오래된 모델 추천을 제거했습니다. 모델은 실행 시점 공식 문서와 내부 검증 세트로 선택하도록 바꿨습니다.
- 외부 LLM에 독점 디스어셈블리나 비밀을 보내기 전 승인·최소화·마스킹을 요구하도록 했습니다.

### 저장소와 맞지 않는 계약

- APK, radare2, diagram, JS, IDA 문서가 존재하지 않는 스크립트와 자동 설치를 “포함됨”으로 말하던 부분에 미포함 상태를 명시했습니다.
- 상대 경로 `routing.md`와 존재하지 않는 `reverse-engineering/SKILL.md`를 실제 경로로 바로잡았습니다.
- APK 문서의 “현재 머신에 설치된 정확한 버전” 주장을 제거했습니다. 검토 환경에서는 Java 외 `jadx`, `apktool`, `frida`, `adb`, `r2`, IDA 명령을 찾을 수 없었습니다.
- JS 문서의 `js-reverse_*` 이름을 현재 보장된 도구가 아니라 레거시 클라이언트 별칭으로 표시했습니다.
- JSHookMCP 예시는 검토한 `0.3.3`으로 고정하고 현재 요구사항인 Node.js 22.12+ 또는 24.x를 반영했습니다. npm의 2026-07-15 최신 버전은 `0.3.4`이므로 이 핀을 “최신”으로 부르지 않으며, 업그레이드 시 릴리스·도구 스키마·보안 권고를 다시 확인해야 합니다.

## 참고 자료를 향후 채택할 때의 개선 조건

### 해결됨. 제품 형태를 하나로 결정

현재 결정은 이 디렉터리를 **참고 코퍼스**로만 두고, 제품 엔진과 공용 스킬은 별도로 구현하는 것입니다.

권장안:

1. 각 모듈에서 `scripts/*.ps1`, Winget 자동 설치, 특정 Windows 경로, “현재 설치됨” 계약을 제거합니다.
2. 도구 설치·MCP 연결은 별도 `integrations/` 문서로 분리하고, 운영체제별 검증 날짜와 상류 버전을 기록합니다.
3. 실행 가능한 자동화를 다시 제공하려면 별도 제품으로 취급합니다. 실제 스크립트, 테스트 픽스처, CI의 Windows/macOS 행렬, 버전 잠금, 해시 검증이 함께 들어와야 합니다.

두 방향을 계속 섞으면 에이전트가 없는 파일을 호출하고, 설치되지 않은 도구로 분석했다고 보고하는 문제가 반복됩니다.

### 채택 조건. IDA 모듈을 현재 상류 세션 모델로 재작성

`ida-reverse`는 부분 수정으로 신뢰할 수 있는 상태가 되지 않습니다. 현재 파일은 다음 레거시 가정을 중심으로 작성됐습니다.

- 번들 `start.ps1`·`open.ps1`가 존재함
- 정확히 72개 `idapro_*` 도구가 존재함
- 하나의 암묵적 현재 데이터베이스가 모든 호출에 바인딩됨
- GUI 플러그인과 `127.0.0.1:13337`이 기본 경로임

현재 상류 `main`(`1be78d0`, 2026-07-13)은 GUI MCP 플러그인을 비권장·향후 폐기 대상으로 두고 `idalib-mcp`를 권장합니다. 현재 세션 도구는 `idb_open()`·`idb_list()`·`idb_save()`이며 `idb_close()`는 없습니다. worker는 supervisor보다 오래 유지되고 기본 idle TTL은 1시간입니다. 데이터베이스 분석 도구 호출은 `idb_open()`이 반환한 실제 세션 ID를 `database`에 명시해야 하며, 파일명·입력 경로 또는 암묵적 현재 컨텍스트로 대신할 수 없습니다. `idb_save()`는 그 세션 ID를 `session_id` 인자로 받습니다. 기존 worker나 GUI 세션을 채택하면 `preferred_session_id`와 반환 ID가 다를 수 있습니다. 재작성 시 상류 README에서 실제 도구 스키마를 생성하거나 가져오고, 손으로 작성한 고정 개수와 접두어 목록은 없애야 합니다.

### 채택 조건. JS 모듈을 실제 도구 발견 기반으로 전환

현재 13개 JS 문서의 분석 단계는 대체로 유효하지만 `js-reverse_*` 호출 이름은 현재 JSHookMCP 공개 표면과 검증되지 않았습니다.

권장안:

- 논리 작업명(`list scripts`, `network initiator`, `set breakpoint`)과 실제 MCP 도구명을 분리합니다.
- 실행 시작 시 서버 버전, 도구 목록, 입력 스키마를 캡처한 뒤 어댑터 표를 생성합니다.
- JSHookMCP는 `>=0.3.2` 보안 수정이 포함된 검토 버전만 허용하고, `npx`의 부동 latest 대신 검증한 버전과 무결성을 잠급니다. 현재 문서의 `0.3.3` 핀을 `0.3.4`로 올리는 일도 별도 재검증 변경으로 취급합니다.
- 브라우저 대상·테스트 계정·허용 행위를 기록하는 승인 게이트를 모듈 자체에도 둡니다.

### 채택 조건. Binary Diff 적용기를 “후보 생성”과 “쓰기”로 분리

LLM 출력 YAML을 바로 IDB에 적용하면 잘못된 주소 하나가 분석 데이터베이스를 오염시킵니다.

권장 파이프라인:

1. LLM은 `insn_va`, `target_va`, 이름, 근거, confidence를 포함한 후보만 생성합니다.
2. 결정론적 검증기가 명령 피연산자, 섹션 범위, 함수 시작점, 기존 이름 충돌을 검사합니다.
3. dry-run diff와 거절 사유를 출력합니다.
4. 분석가가 승인한 행만 트랜잭션 로그와 함께 적용합니다.
5. 작은 골든 바이너리 쌍으로 주소·이름 마이그레이션 회귀 테스트를 둡니다.

### 참고 구현 개선. `scan.sh`를 테스트 가능한 보안 경계로 만들기

이번에 다음 문제는 직접 수정했습니다.

- `--out` 심볼릭 링크를 통한 대상 밖 파일 덮어쓰기
- 기존 FIFO를 `--out`으로 열어 스캐너가 멈추거나 다른 프로세스에 보고서를 쓰게 되는 문제 → 같은 디렉터리의 owner-only 임시 파일과 원자적 hard-link 생성으로 기존 파일·링크·FIFO를 모두 거부
- 대상 파일의 외부 하드링크나 검사 뒤 교체된 출력 경로를 통한 기존 파일 덮어쓰기
- 논리 경로의 `pwd`만 비교해 대상의 심볼릭 링크 별칭으로 “출력은 대상 밖” 검사를 우회할 수 있던 문제 → `pwd -P` 물리 경로 비교
- 호출자가 주입한 `PATH`나 shell function에서 파서를 고를 수 있던 문제 → 고정 시스템 PATH와 절대 실행 파일만 허용
- 호출자 `umask`에 따라 민감할 수 있는 로컬 보고서가 다른 사용자에게 읽힐 수 있던 파일 권한
- 적중한 소스 줄·비정상 설치 훅 명령·절대 대상 경로를 보고서에 복사해 비밀값·내부정보·프롬프트 지시가 노출될 수 있던 출력 계약 → 원문을 제거하고 규칙·상대 위치만 보고
- 대상 디렉터리의 `json.py`, `PYTHONPATH`, `sitecustomize`가 패키지 JSON 파싱 전에 실행될 수 있는 Python import 경로
- `NODE_OPTIONS=--require`를 통한 Node 파서 선실행
- 로컬 `.husky` JavaScript를 안전한 수명주기 훅으로 감점하던 allowlist
- 실제 배포 코드가 흔한 `dist/`, `build/`를 소스 스캔에서 제외하던 모순
- 대상 경로의 `#`·정규식 문자가 표본 경로 제거용 `sed` 식을 깨뜨리고, 파일명 개행이 보고서 레코드를
  여러 줄로 분리하던 문제
- 개행이 든 파일명 하나를 여러 파일로 세던 구성 파일 수 집계
- 테스트 후보 100개·난독화 후보 200개 이후 검사가 조용히 중단되던 문제 → 보고서에 명시적 INFO 한계 표시

남은 개선:

- 현재 정규식은 주석·예제·`127.0.0.1`도 raw-IP HIGH로 잡아 저장소 자체를 오탐합니다. 언어별 주석 처리보다 먼저 “실행 코드/구성”과 “문서·예제” 결과를 분리하는 것이 단순합니다.
- `sanitize`는 ASCII C0/DEL·백틱·줄바꿈만 처리해 Unicode 방향 전환·제로폭 문자가 보고서에 남습니다. 정식 엔진은 원문 표시 대신 불투명한 경로 ID를 사용하고, 사람이 보는 별도 문자열은 Unicode 정규화·format-control 가시화 후 출력해야 합니다.
- 최종 이름은 같은 디렉터리의 staging 파일을 원자적 hard link로 새로 만들지만, 검사 중 출력 상위 디렉터리 자체를 바꾸는 로컬 경쟁까지 닫으려면 신뢰한 디렉터리 파일 디스크립터에 상대 경로로 생성하는 정식 엔진 구현이 필요합니다.
- 깨진 `package.json`이나 사용 가능한 JSON 파서가 없는 경우가 현재는 해당 파일의 “훅 없음”과 구분되지 않습니다. 파서 실패·미사용을 INFO 이상으로 보고해야 합니다.
- Bash는 스크립트 본문을 실행하기 전에 호출자 환경의 `BASH_ENV`를 처리할 수 있습니다. 정식 실행 계약은 신뢰한 호출자를 전제로 하거나 `env -u BASH_ENV` 같은 격리된 launcher를 제공해야 합니다. 이는 대상 저장소가 주입하는 경로 문제와는 별도입니다.
- 정상 훅, 체인 우회, 악성 `NODE_OPTIONS`, `dist` 페이로드, 깨진 JSON, 파일명 개행, 출력 경로 공격을 포함한 픽스처를 저장소에 체크인해야 합니다.
- `shellcheck`, `bash -n`, 픽스처 기대 결과를 CI에 연결해야 “모두 통과”를 재현할 수 있습니다.

### P2. 공격·우회 예제를 안전한 테스트 절차로 정리

모바일 문서는 방어 검증과 우회 페이로드가 한 흐름에 섞여 있습니다. 모듈 첫 단계에서 소유권·서면 승인·대상·시간창·속도 제한·데이터 처리 조건을 기록하고, 기본 예제는 관찰 전용으로 두는 편이 안전합니다. 대량 SMS 코드 루프처럼 실서비스 장애를 유발할 수 있는 예제는 이번에 제거했습니다.

### P2. 번역 품질과 용어집 정리

`기능`/`함수`, `역방향`/`리버스 엔지니어링`, `보강`/`환경 패치`가 혼용되고 기계 번역 문장이 많습니다. 실행 계약을 고친 뒤 한 차례의 한국어 편집 패스를 적용하되, 코드·명령·제품 고유명은 번역하지 않는 규칙이 필요합니다.

## 공식 자료 대조표

| 주제 | 확인한 1차 자료 | 반영 내용 |
|---|---|---|
| Frida 17 API | [Frida 17.0.0 release](https://frida.re/news/2025/05/17/frida-17-0-0-released/), [JavaScript API](https://frida.re/docs/javascript-api/) | 정적 `Module.find*` 제거와 대체 API |
| Frida 릴리스 상태 | [Frida releases](https://frida.re/news/releases/) | 외부 버전이 변동 정보임을 확인 |
| Objection CLI | [Objection wiki: Using objection](https://github.com/sensepost/objection/wiki/Using-objection) | `-n ... start` 현재 진입 방식 |
| Android CA 신뢰 | [OWASP MASTG Android user CA test](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0286/) | Android 7+ 사용자 CA 비신뢰 기본값 |
| Android 저장소·백업 | [Android storage use cases](https://developer.android.com/training/data-storage/use-cases), [Auto Backup](https://developer.android.com/identity/data/autobackup) | scoped storage와 Android 12+ 백업 규칙 |
| Android 암호화 저장소 | [EncryptedSharedPreferences reference](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences) | 1.1.0 deprecated 표시 |
| Android Cipher | [javax.crypto.Cipher reference](https://developer.android.com/reference/javax/crypto/Cipher) | 공개 메서드와 예제 호출 대조 |
| 무결성 API | [SafetyNet overview](https://developer.android.com/privacy-and-security/safetynet), [Play Integrity standard requests](https://developer.android.com/google/play/integrity/standard) | SafetyNet 종료와 대체 API |
| iOS 화면 캡처 | [userDidTakeScreenshotNotification](https://developer.apple.com/documentation/uikit/uiapplication/userdidtakescreenshotnotification), [capturedDidChangeNotification](https://developer.apple.com/documentation/uikit/uiscreen/captureddidchangenotification), [snapshotView](https://developer.apple.com/documentation/uikit/uiview/snapshotview%28afterscreenupdates%3A%29) | 사후 스크린샷 알림·진행 중 캡처 상태·뷰 스냅샷 API 구분 |
| JSHookMCP | [공식 npm 패키지](https://www.npmjs.com/package/@jshookmcp/jshook), [Getting Started](https://vmoranv.github.io/jshookmcp/en/guide/getting-started), [GHSA-c5r6-m4mr-8q5j](https://github.com/vmoranv/jshookmcp/security/advisories/GHSA-c5r6-m4mr-8q5j) | 최신 `0.3.4`, Node 요구사항, `0.3.2` 보안 수정과 문서의 검토 핀 구분 |
| IDA MCP | [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), [검토한 상류 커밋](https://github.com/mrexodia/ida-pro-mcp/commit/1be78d04119748066d5e73070302ad62916002ea) | `idalib-mcp`, `idb_open/list/save`, 분석 호출의 명시적 세션 ID, GUI 경로 비권장 |
| radare2 | [Official Book: write](https://book.rada.re/commandline/write.html), [rabin2 symbols](https://book.rada.re/tools/rabin2/symbols.html) | 쓰기 즉시 반영, `q`, `is` |
| dSYM | [LLVM dsymutil](https://llvm.org/docs/CommandGuide/dsymutil.html) | 기존 DWARF 연결 도구의 실제 역할 |
| 다이어그램 CLI | [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli), [Graphviz command line](https://graphviz.org/doc/info/command.html), [PlantUML command line](https://plantuml.com/command-line) | 실제 렌더러 명령 |
| Bash 안전 출력 | [Bash redirections](https://www.gnu.org/s/bash/manual/html_node/Redirections.html), [POSIX link](https://pubs.opengroup.org/onlinepubs/009696699/functions/link.html) | noclobber의 regular-file 한계와 기존 최종 이름을 거부하는 원자적 링크 생성 |
| OpenAI 모델 | [OpenAI Models](https://developers.openai.com/api/docs/models) | 특정 모델명을 영구 기본값으로 고정하지 않음 |

## 파일별 검토 체크리스트

상태의 “수정”은 이 검토에서 파일을 직접 바꿨다는 뜻이고, “검토”는 내용 확인 후 근본 변경 제안만 남겼다는 뜻입니다.

| 파일 | 상태 | 핵심 확인 |
|---|---|---|
| `apk-reverse/methodology.md` | 수정 | 설치 버전·미포함 스크립트·라우팅 |
| `apk-reverse/references/android-advanced.md` | 수정 | JNI, Frida 17, Play Integrity, ClassLoader |
| `apk-reverse/references/apk-security-checklist.md` | 수정 | Objection, 저장소, 백업, 암호화 저장소, 속도 제한, 대화형 명령 fence |
| `apk-reverse/references/frida-bypass-kit.md` | 수정 | 범용성·무설정 보장 제거, 대상별 검증과 최소 계층 적용 |
| `apk-reverse/references/frida-cookbook.md` | 수정 | Frida 17 export lookup, Cipher API, TLS·DEX·루트 예제 경계 |
| `mobile-reverse/methodology.md` | 수정 | 승인 경계, dsymutil, Gadget, CA, 런타임 예제, 혼합 Objection/Frida fence |
| `mobile-reverse/references/anti-detection-bypass.md` | 수정 | SafetyNet, Frida 17, ptrace, Objection, 계층 과장 |
| `mobile-reverse/references/frida-objection-deep.md` | 수정 | Frida 17, Objection 현재 CLI, WebView callback, REPL/SQL fence |
| `mobile-reverse/references/ios-reverse-guide.md` | 수정 | `args` 스코프, ObjC 메서드 hook, Frida 17, FairPlay/FAT, 화면 캡처 API, `swift-demangle` 자리표시자 |
| `js-reverse/methodology.md` | 수정 | BOM, 레거시 별칭, Node 요구사항, 미포함 bootstrap, 검토 핀과 최신 버전 구분 |
| `js-reverse/references/ast-deobfuscation.md` | 검토 | 단계·산출물 일관성 |
| `js-reverse/references/automation-entry.md` | 검토 | 실제 도구 발견 필요 |
| `js-reverse/references/env-patching.md` | 검토 | 최소 패치 원칙 |
| `js-reverse/references/fallbacks.md` | 검토 | 실패 전환 경로 |
| `js-reverse/references/instrumentation.md` | 검토 | 관찰 우선·승인 경계 필요 |
| `js-reverse/references/local-rebuild.md` | 검토 | 재현 산출물 |
| `js-reverse/references/mcp-task-template.md` | 검토 | 레거시 별칭 의존 |
| `js-reverse/references/node-env-rebuild.md` | 검토 | 런타임 버전 계약 |
| `js-reverse/references/output-contract.md` | 검토 | 증거·가정 분리 |
| `js-reverse/references/task-artifacts.md` | 검토 | 산출물 구조 |
| `js-reverse/references/task-input-template.md` | 검토 | 대상·승인 입력 보강 필요 |
| `js-reverse/references/tool-defaults.md` | 검토 | 실제 서버 스키마 우선 필요 |
| `binary-diff/methodology.md` | 수정 | 주소 스키마, 후보/dry-run/승인 경계, 모델·비용, 데이터 전송 |
| `binary-diff/references/prompt-template.md` | 수정 | `target_va`, 후보 계획 명명, prompt 파일 계약, 제공자 API 비호환 |
| `diagram-generator/README.md` | 검토 | 범위와 방법론 연결 |
| `diagram-generator/methodology.md` | 수정 | 펜스, 실제 CLI, 미포함 렌더러, 라우팅 |
| `diagram-generator/references/diagram-patterns.md` | 검토 | 예제 구조와 문법 |
| `ida-reverse/methodology.md` | 수정/재작성 필요 | 레거시 경고, 현재 `idb_open/list/save` 세션 계약, 상류 방향, 경로 |
| `ida-reverse/references/ida-mcp-cheatsheet.md` | 수정/재작성 필요 | 레거시 스키마 경고와 현재 세션 API |
| `radare2/methodology.md` | 수정 | `is`, `q`, JS 라우팅, 미포함 스크립트 |
| `radare2/references/cheatsheet.md` | 수정 | 잘못된 `wq` 제거 |
| `docs/draft/scan.sh` | 수정 | 파서·PATH 격리, 물리 경로, 원자적 출력 생성, 탐색 범위·한계 표시, 훅 allowlist, NUL 안전 파일 수·표본 경로 |

## 검증 한계

- 상용 IDA와 모바일 기기·루팅/탈옥 테스트 환경이 없어 IDA, Frida, Objection 예제를 실제 대상 프로세스에 주입하지는 못했습니다. 따라서 해당 예제는 공식 API와 정적 의미를 검증한 수준입니다.
- 현재 저장소에는 Mermaid/Graphviz/PlantUML 렌더러가 없어 다이어그램 예제의 이미지 렌더링은 수행하지 못했습니다.
- 모델 가격·성능과 외부 도구 버전은 변동 정보이므로 검토일을 명시했고, 실행 시점 재확인을 요구했습니다.
- 외부 URL 자동 점검에서 npm 패키지 페이지와 GNU Bash 매뉴얼은 봇 요청에 HTTP 403을 반환했습니다. npm 레지스트리 메타데이터·공식 Getting Started 및 GNU 공식 매뉴얼의 브라우저 응답으로 내용을 각각 교차 확인했습니다.
