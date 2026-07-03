---
name: apk-reverse
description: CLI 환경에서 Android APK 리버스 엔지니어링을 할 때 사용됩니다. APK 압축 풀기, Java 디컴파일, smali 수정, 재패키징, Frida 동적 후크 및 요청 시 so/native 분석으로 전환에 적합합니다. 이 머신에 설치된 jadx, apktool, frida, adb, ida-reverse, radare2를 사용하는 것이 우선적으로 적용됩니다.
---

# APK 역방향 CLI 작업 사양

## 적용 범위

이 기술은 작업이 다음 시나리오에 해당할 때 먼저 사용됩니다.

- APK의 Java 비즈니스 로직 분석
- 포지셔닝 로그인, 서명, 위험 제어, 인증서 확인, 루트 탐지
- 보기 및 수정 `AndroidManifest.xml`
- smali 보기 및 수정
- 재포장 APK
- Frida를 사용하여 Java/native 동적 후크를 만듭니다.
- APK에 `.so`가 포함된 경우 기본 분석으로 전환

## 현재 기계는 검증된 CLI 도구를 사용할 수 있습니다.

- `jadx` `1.5.5`
- `apktool` `3.0.2`
- `frida-ps` `17.9.6`
- `adb`
- `java`

## 스크립트가 선호되는 시나리오

다음 프로세스는 빈도가 높으며 매개변수에 오류가 발생하기 쉽습니다. 스킬 자체 스크립트를 사용하는 것이 좋습니다.

- 한번에 완료 `jadx + apktool` 주문 및 요약 출력: `scripts/decode.ps1`
- Frida 장치 확인, 프로세스 열거, spawn/attach 주입: `scripts/frida-run.ps1`
- 재구축, 정렬, 서명, 설치 APK: `scripts/rebuild-sign-install.ps1`
- 매니페스트 주요 구성요소 및 권한을 빠르게 추출하세요: `scripts/manifest-summary.ps1`

다음 명령 줄은 직접 호출된 상태로 유지되며 별도로 패키지되지 않습니다.

- `adb devices`
- `adb logcat`
- `frida-ps -U`
- `jadx --version`
- `apktool --version`

## 스크립트와 함께 제공

### `scripts/decode.ps1`

목적:

- `jadx` 및 `apktool`를 동시에 실행
- 기본적으로 작업 출력 디렉터리는 원본과 동일한 디렉터리에 생성됩니다. APK
- `package`, `java_files`, `smali_dirs`, `so_files` 및 기타 요약 출력
- `jadx` 일부 디컴파일 오류와 호환되지만 여전히 사용 가능한 제품

예:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\decode.ps1" -ApkPath "D:\DOWNLOAD\app.apk" -Clean
pwsh -File "<skill-root>\apk-reverse\scripts\decode.ps1" -ApkPath "D:\DOWNLOAD\app.apk" -Name demo -SkipJadx
```

### `scripts/frida-run.ps1`

목적:

- Frida의 장치, 프로세스, spawn/attach 입구 통합
- 필기 매개변수 `-f`, `-n`, `-U` 시 혼동 방지

예:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -ListDevices
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -Usb -ListProcesses
pwsh -File "<skill-root>\apk-reverse\scripts\frida-run.ps1" -Usb -Spawn -Package com.example.app -ScriptPath "D:\hooks\test.js"
```

### `scripts/rebuild-sign-install.ps1`

목적:

- `apktool b` 재구축 APK
- `zipalign` 정렬
- `apksigner` 서명 및 확인
- 선택사항 직접 `adb install`

예:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\rebuild-sign-install.ps1" -ProjectDir "C:\work\apktool_out" -Clean
pwsh -File "<skill-root>\apk-reverse\scripts\rebuild-sign-install.ps1" -ProjectDir "C:\work\apktool_out" -Install -Reinstall -DeviceSerial "127.0.0.1:7555"
```

설명:

- 기본적으로 디버깅 키 저장소 생성 및 재사용
- 기본 출력은 `ProjectDir`와 동일한 디렉터리에 있으며, 이는 원래 패키지 및 압축 풀기 디렉터리와 함께 묶는 데 편리합니다.

### `scripts/manifest-summary.ps1`

목적:

- 패키지 이름 추출
- 열 권한
- 칼럼 activity/service/receiver/provider
- 주요 시작 활동 표시

예:

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\manifest-summary.ps1" -ManifestPath "C:\work\apktool_out\AndroidManifest.xml"
```

`.so`, `lib/arm64-v8a/*.so`, `lib/armeabi-v7a/*.so`를 분석하려면 다음을 결합하세요.

- `ida-reverse`
- `radare2`

## 도구 분업

### `jadx`

용도:

- Java 디컴파일 읽기
- 패키지명, 클래스명, 메소드명 검색
- 먼저 고급 논리부터 이해하세요 APK

일반적으로 사용되는 명령:

```bash
jadx -d jadx_out app.apk
jadx --single-class com.example.LoginActivity -d jadx_out app.apk
jadx --deobf -d jadx_out app.apk
```

### `apktool`

용도:

- 포장 풀기 APK
- 보기 및 수정 `AndroidManifest.xml`
- smali 보기 및 수정
- 재구축 APK

일반적으로 사용되는 명령:

```bash
apktool d app.apk -o apktool_out
apktool b apktool_out -o rebuilt.apk
```

### `frida`

용도:

- Java 메소드 호출의 동적 관찰
- Hook 네이티브 내보내기 기능
- 우회 루트 감지, 인증서 확인, 디버깅 감지

일반적으로 사용되는 명령:

```bash
frida-ps -U
frida -U -f com.example.app -l hook.js
frida-trace -U -f com.example.app -j '*!*certificate*'
```

### `adb`

용도:

- 장치 연결
- 설치 APK
- 로그 보기
- 파일 가져오기

일반적으로 사용되는 명령:

```bash
adb devices
adb install -r app.apk
adb shell pm list packages
adb logcat
adb pull /data/local/tmp/file .
```

## 권장 워크플로우

### 1. Triage

먼저 APK의 대략적인 구성을 파악하고, 패키지나 Hook를 급하게 바꾸지 마세요.

권장 조치:

1. `jadx -d jadx_out app.apk`를 사용하여 Java 코드 내보내기
2. `apktool d app.apk -o apktool_out`를 사용하여 smali 및 리소스 내보내기
3. 먼저 살펴보세요:
   - `AndroidManifest.xml`
   - 메인 `package`
   - `application`、`activity`、`service`、`receiver`
   - `lib/` 디렉토리에 `.so`가 있나요?

### 2. 자바 논리 관찰

`jadx_out`부터 먼저 읽어보세요.

- `MainActivity`
- `Application`
- 로그인, 네트워크, 암호화, 위험관리 관련 카테고리
- 타사 SDK 초기화 클래스

일반적인 키워드:

- `login`
- `sign`
- `encrypt`
- `cipher`
- `token`
- `root`
- `certificate`
- `trust`
- `okhttp`
- `retrofit`
- `webview`

Java 코드를 읽을 수 있는 경우 먼저 여기에서 비즈니스 로직을 찾으세요.

### 3. Smali는 리소스 계층으로 확인합니다.

`jadx`의 결과가 불완전하거나 혼란스럽거나 실제 패치가 필요한 경우 `apktool_out`로 전환하세요.

- 보세요 `smali*/`
- 보세요 `res/values/strings.xml`
- 보세요 `AndroidManifest.xml`

우선 패치:

- `android:exported`
- 디버그 플래그
- 루트 감지 반환 값
- 로그인 확인 로직
- 인증서 검증 지점

### 4. 재구축 및 설치

수정 후:

```bash
apktool b apktool_out -o rebuilt.apk
```

또는 스크립트를 직접 사용하여 루프를 닫습니다.

```powershell
pwsh -File "<skill-root>\apk-reverse\scripts\rebuild-sign-install.ps1" -ProjectDir "apktool_out" -Install -Reinstall -DeviceSerial "127.0.0.1:7555"
```

설명:

- 이 스킬은 `apktool` 링크 재설정만 보장합니다.
- 나중에 기기에 정식으로 설치해야 하는 경우에는 일반적으로 서명 과정이 필요합니다.
- 작업이 서명/정렬에 들어가면 `apksigner` / `zipalign`를 추가하세요.

### 5. 다이나믹 훅

정적 분석이 불충분한 경우 Frida를 사용하세요.

- Hook 로그인 기능
- 후크 `OkHttp` / `Retrofit` / `WebView` 핵심 포인트
- 후크 `javax.crypto`, `MessageDigest`
- 후크 루트 감지 기능
- 후크 SSL 고정 논리

원칙:

- 먼저 Java 계층을 Hook한 뒤, 네이티브 Hook이 필요한지 확인합니다.
- 매개 변수와 반환 값을 먼저 인쇄한 다음 반환 값을 적극적으로 수정할지 여부를 결정합니다.

제안:

- 간단한 일회성 명령을 `frida-*`와 함께 직접 사용할 수 있습니다.
- 주입 흐름을 안정적으로 재사용해야 하면 `scripts/frida-run.ps1`를 우선 사용합니다.

### 6. 네이티브 `.so` 전환

APK에 `.so` 키가 포함된 경우:

- `apktool` 또는 `jadx`로 `lib/**/*.so` 찾기
- 심볼과 문자열을 내보내고 빠르게 분류하는 정도라면 `radare2`를 사용할 수 있습니다.
- 장기적인 심층 분석, 디컴파일, 이름 변경, 타입 복원이 필요하면 `ida-reverse`를 사용합니다.

이러한 신호가 나타나면 가능한 한 빨리 기본으로 전환하세요.

- Java 레이어는 단지 JNI 래퍼일 뿐입니다.
- 핵심 서명 논리는 Java에 없습니다.
- `System.loadLibrary()` 이후에는 키 로직이 사라집니다.
- `.so`의 인증서 확인/위험 관리

## 출력 요구 사항

마지막으로 최소한 설명하십시오.

- 엔트리 구성 요소 및 주요 클래스
- 핵심 논리는 Java, smali 또는 `.so`에 있습니다.
- 확인된 민감사항: 로그인, 서명, 루트, SSL, WebView, JNI
- 패치를 했다면 무엇이 바뀌었는지 설명해주세요.
- 후크를 사용하는 경우 후크된 클래스/메서드/내보낸 함수를 표시하세요.

## 금지 사항

- 처음부터 스마리를 맹목적으로 바꾸지 마세요
- 매니페스트와 메인 항목을 보지 않고 Hook을 작성하지 마세요.
- 불완전한 Java 디컴파일을 "분석할 수 없는 논리"와 직접적으로 동일시하지 마십시오.
- `.so`가 핵심 로직을 전달하는 것이 분명한 경우 Java 레이어를 고수하지 마세요.

## 빠른 명령 메모

```bash
# 자바 디컴파일
jadx -d jadx_out app.apk

# 포장 풀기 APK
apktool d app.apk -o apktool_out

# 재구축 APK
apktool b apktool_out -o rebuilt.apk

# 장비 및 공정
adb devices
frida-ps -U

# 시작 및 주입
frida -U -f com.example.app -l hook.js
```

---

## 라우팅 컨텍스트

**상류 입구**: `../../SKILL.md`(마스터 제어), `routing.md`
**다운스트림 내보내기**:
- 핵심 로직은 `.so` → `ida-reverse/` 또는 `radare2/`에 있습니다.
- 동적 Hook/검증 필요 → `reverse-engineering/tools-dynamic.md` (Frida 장)
- 보편적인 역방향 방법론 → `reverse-engineering/SKILL.md`

**유사한 연결 모듈**: `reverse-engineering/`(.so 분석 및 Frida 고급 사용)

---

## 주문형 부트스트랩

해당 스킬의 진입 스크립트가 통합 부트스트래핑 시스템에 연결되었습니다. 도구가 누락되면 오류를 직접 보고하지 않고 자동으로 설치를 시도합니다.

### 자동화 기능 경계

| 도구| 자동으로 설치 가능| 설치방법| 설명|
|------|-----------|---------|------|
| jadx | ✓ | GitHub 릴리스 ZIP| `%USERPROFILE%\Tools\jadx\`로 자동 다운로드 및 압축 해제|
| apktool | ✓ | GitHub 릴리스 JAR + 래퍼| 자동으로 jar를 다운로드하고 `%USERPROFILE%\Tools\apktool\`에 박쥐를 생성합니다.|
| frida / frida-ps | ✓ | pip 설치 frida-tools| Python이 설치되어 있어야 합니다.|
| adb | ✓ | 윙렛/대체 경로| Android 플랫폼 도구 자동 설치|
| zipalign | ✗ |Android Build-Tools를 수동으로 설치해야 함| `sdkmanager "build-tools;35.0.0"` |
| apksigner | ✗ |Android Build-Tools를 수동으로 설치해야 함| 위와 동일|

### 부트스트랩 트리거 포인트

- `scripts/decode.ps1`: jadx 또는 apktool이 없으면 `bootstrap-reverse.ps1`를 자동 호출합니다.
- `scripts/rebuild-sign-install.ps1`: adb 또는 apktool이 없으면 부트스트랩을 자동 호출합니다.
- `scripts/frida-run.ps1`: 현재는 수동 확인입니다(frida-tools pip 설치).

### 부트스트래핑이 실패하는 경우

일반적인 이유:
- 네트워크 불통(GitHub API / PyPI 접근 불가)
- Winget을 사용할 수 없습니다(Windows 버전이 너무 낮음).
- Java가 설치되지 않았습니다(apktool은 JDK에 따라 다름).
