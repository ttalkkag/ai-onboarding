# APK 보안 테스트 간편 점검

> OWASP MASTG(모바일 애플리케이션 보안 테스트 가이드)를 기반으로 합니다.
> 정적 분석, 동적 분석, 네트워크 통신, 데이터 저장, 인증 및 권한 부여, 코드 보호 등 6가지 차원을 다룹니다.

---

## 정적 분석 체크리스트

### 매니페스트 감사

```text
□ android:debuggable="true" → 디버그 가능(프로덕션 환경에는 표시되지 않아야 함)
□ android:allowBackup="true" → 데이터 백업 및 추출 가능
□ android:exported="true" → 노출된 구성요소 Activity/Service/Receiver/Provider
□ 사용자 정의 권한 보호수준 → 정상 여부(서명이어야 함)
□ 인텐트 필터의 방식 → 딥링크 하이재킹 가능 여부 맞춤설정
□ android:usesCleartextTraffic="true" → 일반 텍스트 허용 HTTP
□ minSdkVersion이 너무 낮음 → 보안 기능이 누락되었을 수 있음
```

### 코드 감사 핵심 사항

```text
□ 하드코딩된 키/토큰("key", "secret", "password", "api_key" 검색)
□ 안전하지 않은 난수(SecureRandom 대신 java.util.Random)
□ 안전하지 않은 암호화(비밀번호는 ECB 모드, DES, MD5)
□ WebView 구성(setJavaScriptEnabled + addJavascriptInterface = RCE 위험)
□ SQL 인젝션(rawQuery 사용자 입력 연결)
□ 경로 순회(ContentProvider의 openFile은 경로를 확인하지 않음)
□ 로그 유출 (Log.d/Log.i 민감한 정보 출력)
□ 클립보드 유출(ClipboardManager는 민감한 데이터를 저장함)
□ 암시적 의도 유출(sendBroadcast는 패키지 이름을 지정하지 않음)
```

### 타사 라이브러리 감사

```text
□ 오래된 OkHttp/Retrofit 버전(알려진 취약점)
□ 오래된 WebView 커널
□ SDK 알려진 취약점이 있음(CVE 확인)
□ 광고 SDK 데이터 수집 범위
□ Push SDK 설정 (토큰 유출 여부)
```

---

## 동적 분석 체크리스트

### Frida 후크 우선 대상

| 목표| 훅 포인트| 목적|
|------|---------|------|
| 로그인 인증| `LoginActivity.login()` | 인증 정보 처리 과정을 관찰하세요|
| 서명 생성| `*Sign*`、`*sign*`、`*encrypt*` | 서명 알고리즘 복원|
| SSL Pinning | `CertificatePinner.check` | 패킷 캡처 우회|
| 루트 감지| `*root*`、`*su*`、`*magisk*` | 우회 감지|
|암호화 작업| `javax.crypto.Cipher` | 키/IV 추출|
| 토큰 저장| `SharedPreferences.getString` | 토큰 읽기 및 쓰기 관찰|
| 네트워크 요청| `OkHttpClient.newCall` | 요청 구성 관찰|

### 일반적으로 사용되는 Frida 한 줄 명령

```bash
# 모든 암호화 작업 추적
frida-trace -U -f com.target.app -j '*Cipher*!*'

# 모든 HTTP 요청 추적
frida-trace -U -f com.target.app -j '*OkHttp*!*'

# SharedPreferences 읽기 및 쓰기 추적
frida-trace -U -f com.target.app -j '*SharedPreferences*!*'

# 모든 네이티브 함수 호출 추적
frida-trace -U -f com.target.app -i 'Java_*'
```

### Objection 빠른 명령

```bash
# 연결하다
objection -g com.target.app explore

# 일반적인 명령
android hooking list activities
android hooking list services
android sslpinning disable
android root disable
android clipboard monitor
env                              # 애플리케이션 디렉터리 보기
sqlite connect <db_path>         # 데이터베이스에 연결
```

---

## 네트워크 통신 보안

### 패킷 캡처 구성

```text
방법 1: 시스템 에이전트 + Burp/mitmproxy
- WiFi 프록시 설정 → Burp 청취 주소
- 장치에 CA 인증서를 설치합니다.
- Android 7+에는 network_security_config 또는 Frida 우회가 필요합니다.

방법 2: VPN 모드(권장)
- HttpCanary/패킷 캡처 사용
- 루트가 필요하지 않으며 프록시 구성이 필요하지 않습니다.
- 하지만 복호화할 수 없음 SSL 트래픽 고정 중

방법 3: Frida + r2frida
- 프로세스 내에서 네트워크 호출을 직접 가로채기
- 프록시/VPN 제한 없음
```

### 확인항목

```text
□ HTTPS 사용 여부(모든 API 호출)
□ SSL 고정(인증서바인딩) 유무
□ 인증서 검증이 올바른지 여부(자체 서명은 인정되지 않음)
□ 인증서 투명성(CT) 검사가 있습니까?
□ API 요청 시 키가 일반 텍스트로 전송되는지 여부
□ 토큰에 만료 메커니즘이 있습니까?
□ 변조 방지를 위한 요청 서명이 있나요?
□ 반복공격 방지 여부(nonce/timestamp)
□ WebSocket은 암호화되어 있나요?
□ URL 매개변수에 민감한 데이터가 있는지 여부(기록됩니다)
```

---

## 데이터 저장 보안

### 위치 확인

| 위치| 위험| 확인 명령|
|------|------|---------|
| SharedPreferences | 토큰/비밀번호를 일반 텍스트로 저장| `adb shell cat /data/data/pkg/shared_prefs/*.xml` |
| SQLite 데이터베이스|암호화되지 않은 민감한 데이터| `adb pull /data/data/pkg/databases/` |
| 외부 저장소| 모든 애플리케이션에서 읽을 수 있음| `adb shell ls /sdcard/Android/data/pkg/` |
| 애플리케이션 로그| 누수 디버깅 정보| `adb 로그캣\| grep pkg` |
| 백업 파일| 허용백업=true| `adb backup -f backup.ab pkg` |
| 키보드 캐시| 기록 입력| `inputType`가 `textPassword`인지 확인하세요.|
| 스크린샷 보호| 민감한 페이지는 스크린샷으로 찍힐 수 있습니다| 확인 `FLAG_SECURE`|

### 암호화된 스토리지 솔루션 비교

| 계획| 보안| 설명|
|------|--------|------|
| SharedPreferences 일반 텍스트| ❌ | 루트 바로 다음에 읽기|
| EncryptedSharedPreferences | ✓ |AndroidX 보안 라이브러리|
| SQLCipher | ✓ | 암호화된 SQLite|
| Android Keystore | ✓✓ | 하드웨어 수준의 키 보호|
| 맞춤형 AES 암호화| ⚠️ | 키 관리에 따라 다름|

---

## 인증 및 승인

### 일반적인 취약점

| 허점| 시험방법|
|------|---------|
| 취약한 비밀번호 정책| 123456, 비밀번호 등을 시도해 보세요.|
| 잠금 장치 없음| 무차별 대입 크래킹 로그인 인터페이스|
| 토큰은 만료되지 않습니다| 로그아웃 후 이전 토큰 재생|
| 무단 액세스| 요청 시 user_id 수정|
| SMS 인증 코드가 폭파될 수 있음|4/6 숫자 제한 없음|
| OAuth 구성 오류| Redirect_uri는 변조될 수 있습니다.|
| 생체인증 우회| Hook BiometricPrompt |
| 장치 바인딩 우회| device_id 수정|

### 테스트 페이로드

```bash
# 울트라바이어스 테스트
curl -H "Authorization: Bearer USER_A_TOKEN" \
     "https://api.target.com/users/USER_B_ID/profile"

# 토큰 재생
# 1. 정상적으로 로그인하여 토큰을 획득하세요
# 2. 로그아웃
# 3. 이전 토큰으로 요청 → 401을 반환해야 함

# SMS 인증코드 폭파
for code in $(seq 0000 9999); do
    curl -X POST "https://api.target.com/verify" \
         -d "phone=13800138000&code=$code"
done
```

---

## 코드 보호 평가

| 보호 조치| 탐지 방법| 우회 난이도|
|---------|---------|---------|
| ProGuard 난독화| jadx는 클래스 이름이 a/b/c인지 확인합니다.| 낮음(이름 바꾸기)|
| 문자열 암호화| 복호화 기능 검색, 일반 텍스트 획득을 위한 Hook| 안으로|
| 디버깅 방지|디버거를 연결해 보세요| 중간(Frida 우회 가능)|
| 루트 감지| 루팅된 기기에서 실행| 중간(일반 스크립트 우회)|
| 에뮬레이터 감지| 에뮬레이터에서 실행| 낮음-중간|
| 무결성 검사| 수정 후 설치 APK| 중간(패치 검증 기능)|
| 보호/패커| 항목 클래스 및.so 보기| 중간-높음(언패킹 필요)|
| 기본 보호| 핵심 논리는.so에 있습니다.| 높음(IDA 분석 필요)|
| VMP 가상화| 코드는 가상으로 실행됩니다.|매우 높음|

---

## 빠른 테스트 과정(30분)

```text
1. [5분] 포장 풀기 + 매니페스트 감사
   apktool d app.apk
   확인 debuggable/allowBackup/exported/cleartext

2. [10분] 빠른 코드 감사
   jadx -d out app.apk
   검색: 비밀번호, 키, 비밀, 토큰, http://

3. [5분] 네트워크 테스트
   에이전트 구성 → APP 실행 → 일반 텍스트/약한 암호화가 있는지 확인

4. [5분] 저장공간 확인
   adb 쉘 → shared_prefs 및 데이터베이스 확인

5. [5분] 동적 검증
   Frida 후크 키 기능 → 발견 확인
```
