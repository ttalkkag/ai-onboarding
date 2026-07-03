# Frida 우회 키트 — Android 범용 보안 우회 프레임워크

> 출처: [FridaBypassKit](https://github.com/okankurtuluss/FridaBypassKit)(2025)
> 적용 가능한 시나리오: APK 동적 분석에는 루트 감지 우회, SSL 고정, 시뮬레이터 감지 및 디버깅 방지가 필요합니다.

## 개요

FridaBypassKit은 네 가지 주요 우회 기능을 통합한 Frida 스크립트입니다. 특정 앱에 맞게 맞춤설정할 필요가 없으며 즉시 사용할 수 있습니다.

## 4가지 주요 우회 기능

### 1. 루트 감지 우회

- 후크 `File.exists()`는 su 바이너리를 숨깁니다.
- `Runtime.exec()`에 대한 루트 확인 호출을 차단합니다.
- PackageManager에서 루트 관련 패키지(Magisk, SuperSU 등) 숨기기
- 장치가 루팅되지 않은 것처럼 보이도록 시스템 속성을 수정합니다.

### 2. SSL 고정 우회

- 후크`TrustManagerImpl.verifyChain()`
- 후크`TrustManagerImpl.checkTrustedRecursive()`
- 인증서 체인 확인 우회
- 확인을 피하기 위해 빈 인증서 체인을 반환합니다.
- OkHttp, Retrofit 및 사용자 정의 구현과 호환 가능

### 3. 에뮬레이터 감지 우회

- 가짜 TelephonyManager 반환 값
- 가짜 전화번호 및 이동통신사 이름 반환
- 빌드 속성 수정

### 4. 안티 디버깅 우회

- 후크`Debug.isDebuggerConnected()`
- 디버거 감지 방지
- 디버깅 방지 검사 우회

## 사용방법

```bash
# 전제 조건
pip install frida-tools
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c /data/local/tmp/frida-server &

# 대상 앱 삽입
frida -U -f com.example.app -l FridaBypassKit.js
```

## 기타 권장사항 Frida 스크립트 우회

| 프로젝트| 특징| 링크|
|------|------|------|
| httptoolkit/frida-interception-and-unpinning | 모든 HTTPS 트래픽 직접 MitM| [GitHub](https://github.com/httptoolkit/frida-interception-and-unpinning)|
| 0xCD4/SSL-bypass | 일반 비맞춤형 SSL 우회| [GitHub](https://github.com/0xCD4/SSL-bypass)|
| incogbyte/ssl-bypass 요지| 일반적인 SSL 고정 방법 우회| [요지](https://gist.github.com/incogbyte/1e0e2f38b5602e72b1380f21ba04b15e)|
| Zero3141/Frida-OkHttp-Bypass | 특히 OkHttp CertificatePinner용| [GitHub](https://github.com/Zero3141/Frida-OkHttp-Bypass)|

## 이 패키지와의 통합

`apk-reverse` 워크플로에서 다음 상황을 만나면 사용합니다.

1. APP가 루트를 감지하고 실행을 거부함 → 루트 감지 우회 활성화
2. 패킷을 캡처할 때 HTTPS 요청은 일반 텍스트를 볼 수 없습니다 → 활성화 SSL 고정 우회
3. 앱에서 에뮬레이터 실행 거부를 감지 → 에뮬레이터 감지 우회 활성화
4. Frida 추가 후 앱이 다운됨 → 디버그 감지 우회 활성화

권장 조합: 먼저 전체 FridaBypassKit을 실행한 다음 대상 조정을 수행합니다.
