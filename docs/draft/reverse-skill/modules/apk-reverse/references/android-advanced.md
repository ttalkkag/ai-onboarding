# Android 고급 역참조

> 네이티브 SO 분석, Frida 고급 사용법, SSL Pinning 우회, Root 탐지 대응, 보호 앱 언패킹, Flutter/React Native 리버싱을 다룹니다.

---

## 네이티브 SO 역방향

### 분석과정

```text
1. APK에서.so 파일을 추출합니다.
   unzip app.apk 'lib/arm64-v8a/*.so' -d extracted/

2. 아키텍처 및 기본정보 확인
   file libxxx.so
   rabin2 -I libxxx.so

3. JNI 입구를 찾으세요
   - JNI_OnLoad 검색(동적 등록)
   - Java_com_xxx_yyy 검색(정적 등록)
   - nm -D libxxx.so | grep -i java

4. IDA/Ghidra 부하해석
   - JNI 헤더 파일 가져오기(jni.h 형식)
   - JNIEnv* 매개변수에 주석 달기
   - RegisterNatives 호출 찾기(동적으로 등록된 함수 테이블)

5. 위치 키 로직
   - Java 레이어 네이티브 메소드 이름에서 추적
   - 문자열(키, URL, 오류 메시지)에서 상호 참조
   - 암호화 라이브러리 함수에서 호출 추적(AES/MD5/SHA)
```

### JNI 기능 등록

```c
// 정적 등록: 함수 이름 = Java_패키지 이름_클래스 이름_메소드 이름
JNIEXPORT jstring JNICALL Java_com_example_app_Security_getSign(
    JNIEnv *env, jobject thiz, jstring input) { ... }

// 동적 등록: JNI_OnLoad에서 RegisterNatives 호출
static JNINativeMethod methods[] = {
    {"getSign", "(Ljava/lang/String;)Ljava/lang/String;", (void*)native_getSign},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    jclass clazz = env->FindClass("com/example/app/Security");
    env->RegisterNatives(clazz, methods, sizeof(methods)/sizeof(methods[0]));
    return JNI_VERSION_1_6;
}
```

### IDA의 JNI 분석 팁

```text
1. JNI 유형 라이브러리 가져오기
   File → Load File → Parse C Header → jni.h

2. 첫 번째 매개변수를 JNIEnv*로 표시합니다.
   매개변수를 마우스 오른쪽 버튼으로 클릭 → 유형 설정 → JNIEnv*
   이런 식으로 env->FindClass / env->GetMethodID 등의 호출이 자동으로 인식됩니다.

3. RegisterNatives 찾기
   대상 ABI와 JNI 헤더의 `JNINativeInterface` 레이아웃을 기준으로 호출 슬롯을 식별
   → 세 번째 매개변수는 JNINativeMethod 배열입니다.
   → 배열에서 모든 네이티브 함수 주소를 추출합니다.
```

---

## Frida 고급 사용법

### 후크 네이티브 기능

```javascript
// Hook libc 함수
Interceptor.attach(Process.getModuleByName("libc.so").findExportByName("open"), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
        console.log("[open] " + this.path);
    },
    onLeave: function(retval) {
        if (this.path.includes("su") || this.path.includes("magisk")) {
            console.log("[open] Blocked root check: " + this.path);
            retval.replace(-1);  // 반품 실패
        }
    }
});

// Hook SO에서 기능 맞춤설정
var base = Process.getModuleByName("libsecurity.so").base;
var targetFunc = base.add(0x1234);  // 오프셋 주소
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("arg0: " + args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log("return: " + retval.readUtf8String());
    }
});
```

### 후크 자바 방식

```javascript
Java.perform(function() {
    // Hook 인스턴스 메소드
    var Security = Java.use("com.example.app.Security");
    Security.getSign.implementation = function(input) {
        console.log("[getSign] input: " + input);
        var result = this.getSign(input);  // 원래 메소드 호출
        console.log("[getSign] output: " + result);
        return result;
    };

    // Hook 생성자
    Security.$init.overload('java.lang.String').implementation = function(key) {
        console.log("[Security.<init>] key: " + key);
        this.$init(key);
    };

    // Hook 오버로드된 메소드
    Security.encrypt.overload('java.lang.String', 'int').implementation = function(data, mode) {
        console.log("[encrypt] data=" + data + " mode=" + mode);
        return this.encrypt(data, mode);
    };
});
```

### 메모리 검색 및 수정

```javascript
// 메모리에서 문자열 검색
Process.enumerateModules().forEach(function(module) {
    if (module.name === "libtarget.so") {
        Memory.scan(module.base, module.size, "48 65 6C 6C 6F", {  // "Hello"
            onMatch: function(address, size) {
                console.log("Found at: " + address);
            },
            onComplete: function() {}
        });
    }
});

// 메모리 수정(패치 명령)
var addr = Process.getModuleByName("libsecurity.so").base.add(0x5678);
Memory.patchCode(addr, 4, function(code) {
    var writer = new Arm64Writer(code, {pc: addr});
    writer.putNop();  // NOP로 교체
    writer.flush();
});
```

---

## SSL 고정 우회

### 출발점 예시(구현별 검증 필요)

```javascript
// 일반적인 Java TLS 검증 지점 예시
// 출처: https://github.com/0xCD4/SSL-bypass
Java.perform(function() {
    // 1. TrustManager 우회
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // 2. SSLContext 교체
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, [TrustManager.$new()], null);

    // 3. OkHttp CertificatePinner 우회
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch(e) {}
});
```

이 코드는 출발점 예시입니다. 새로 초기화한 `SSLContext`가 앱의 기존 연결에 자동 적용되는 것은 아니며, OkHttp 오버로드·커스텀 TrustManager·네이티브 TLS는 앱과 라이브러리 버전에 맞춰 각각 확인해야 합니다.

### 각 프레임은 우회합니다.

| 프레임| 바이패스 방식|
|------|---------|
| OkHttp3 | 후크 `CertificatePinner.check`가 비어 있음을 반환합니다.|
| Retrofit | OkHttp와 동일(하단 레이어는 OkHttp를 사용)|
| Volley | 후크 `HurlStack`의 SSL 공장|
| Flutter | `SecurityContext`의 `dart:io` Hook(전용 스크립트 필요)|
| React Native | `OkHttpClientProvider` Hook |
| WebView | 후크`WebViewClient.onReceivedSslError`|

### Flutter 전문화

```javascript
// Flutter SSL 고정 우회(ssl_verify_peer_cert 함수를 찾아야 함)
var flutterModule = Process.getModuleByName("libflutter.so");
var flutter_lib = flutterModule.base;
// ssl_verify_peer_cert의 서명을 검색하세요.
var pattern = "FF 03 05 D1 FD 7B 0F A9";  // ARM64 기능
Memory.scan(flutter_lib, flutterModule.size, pattern, {
    onMatch: function(address) {
        Interceptor.replace(address, new NativeCallback(function() {
            return 0;  // 반환 성공
        }, 'int', []));
    },
    onComplete: function() {}
});
```

위 바이트열은 특정 빌드의 예시일 뿐 안정적인 함수 식별자가 아닙니다. 대상 `libflutter.so` 버전과 아키텍처에서 디스어셈블리·호출 관계로 검증한 주소만 계측하세요.

---

## 루트 감지 우회

### 일반적인 탐지 방법

| 탐지 방법| 바이패스 방식|
|---------|---------|
| 확인 `/system/app/Superuser.apk`|후크 `File.exists()`는 false를 반환합니다.|
| `su` 명령을 확인하세요| 후크 `Runtime.exec()`는 su 호출을 가로챕니다.|
| 확인 `/proc/self/mounts`| Hook 파일 읽기, magisk 필터링 관련|
| Play Integrity API | 승인된 테스트 빌드에서 서버 판정과 오류 처리 검증(SafetyNet Attestation은 종료됨) |
| Magisk 패키지 이름 확인| Magisk 패키지 이름 무작위화|
| 확인 `/data/adb/`| 후크 `opendir`/`access`|

### Frida 루트 탐지 우회 출발점

```javascript
Java.perform(function() {
    // Hook File.exists
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var name = this.getName().toString().toLowerCase();
        var blacklist = ["su", "superuser.apk", "magisk", "busybox", "xposed"];
        for (var i = 0; i < blacklist.length; i++) {
            if (name === blacklist[i]) {
                return false;
            }
        }
        return this.exists();
    };

    // Hook System.getProperty
    var System = Java.use("java.lang.System");
    System.getProperty.overload('java.lang.String').implementation = function(key) {
        if (key === "ro.debuggable") return "0";
        if (key === "ro.secure") return "1";
        return this.getProperty(key);
    };
});
```

---

## 보호/패커 식별 및 포격

### 일반적인 강화 제조업체

| 보호/패커| 특징 식별| 언패킹 방법|
|------|---------|---------|
| 360 강화| `libjiagu.so`、`com.stub.StubApp` | 방귀 / Frida 덤프 덱스|
| 텐센트 레구| `libshell*.so`、`com.tencent.StubShell` | FART / BlackDex |
|뱅뱅 강화| `libDexHelper.so`、`com.secneo.apkwrapper` | FART |
| 사랑의 암호화| `libexec.so`、`s.h.e.l.l` | Frida dump |
| 넷이즈 이둔| `libnesec.so` | Frida dump |
| 나가| `libnaga.so` | Frida dump |

### 일반적인 포격 방법

```text
방법 1: FART(ART 환경 포장 풀기)
- FART ROM 플래시 또는 Frida 버전 FART 사용
- ClassLoader에 의해 로드된 모든 dex를 자동으로 덤프합니다.

방법 2: Frida DEX 덤프
- frida -U -f com.target.app -l dex_dump.js
- DexFile::OpenMemory를 후크하고 메모리에 dex를 덤프합니다.

방법 3: BlackDex
- 루트 프리 포장 풀기 도구
- BlackDex APK를 직접 설치하고 압축을 풀 대상 애플리케이션을 선택하세요.

방법 4: 수동 덤프
- 모든 ClassLoader를 열거하려면 Frida를 사용하세요.
- 애플리케이션의 ClassLoader 찾기 → DexFile 객체 가져오기
- dex 메모리 영역을 읽어서 저장
```

### ClassLoader 열거 예시(DEX 덤프 아님)

```javascript
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            console.log("ClassLoader: " + loader);
        },
        onComplete: function() {}
    });
});
```

표준 ClassLoader에는 `getDexFileList()` API가 없습니다. 실제 DEX 메모리 덤프는 대상 런타임 버전에 맞는 ART 네이티브 후크나 검증된 전용 도구를 별도로 사용해야 합니다.

---

## React Native / Flutter 리버스 엔지니어링

### React Native

```text
1. APK → assets/index.android.bundle (JS 코드) 압축을 푼다
2. JS 포맷 → 검색 API 주소, 키, 서명 로직
3. Hermes 바이트코드(.hbc 파일)가 있는 경우 → hermes-dec로 디컴파일
4. Hook: Frida를 사용하여 Java 레이어에 ReactBridge를 연결합니다.
```

### Flutter

```text
1. Flutter 코드는 libapp.so(Dart AOT)로 컴파일됩니다.
2. Dart 소스 코드로 직접 디컴파일할 수 없습니다.
3. 분석방법:
   - reFlutter 도구: libflutter.so를 패치하여 스냅샷을 얻습니다.
   - Doldrums: Dart 스냅샷 복구 클래스/기능 정보 구문 분석
   - libflutter.so의 Frida 후크 키 기능
4. 네트워크 분석: Flutter는 시스템 에이전트를 사용하지 않으며 특별한 처리가 필요합니다 SSL
```

---

## 도구 빠른 검토

| 도구| 목적| 설치|
|------|------|------|
| jadx | 자바 디컴파일| 현재 큐레이션에 미포함; 실행 전 확인|
| apktool | 포장 풀기/재포장| 현재 큐레이션에 미포함; 실행 전 확인|
| Frida | 다이나믹 훅| `pip install frida-tools` |
| Objection | Frida 캡슐화(사용하기 더 쉬움)| `pip install objection` |
| MobSF | 자동화된 모바일 보안 분석| 도커 배포|
| BlackDex | 뿌리없는 포격| APK 설치|
| FART |ART 포격| 플래시 ROM 또는 버전 Frida|
| hermes-dec | 헤르메스 바이트코드 역컴파일| npm 설치|
| reFlutter | 플러터 리버스 어시스트| 핍 설치|
| Magisk + Shamiko | 루트 숨김| 플래시 인|

---

## 참고자료

| 자원| 설명| 링크|
|------|------|------|
| OWASP MASTG | 모바일 보안 테스트 가이드| https://mas.owasp.org/ |
| FridaBypassKit | 다층 우회 예제 모음(대상별 검증 필요)| https://github.com/okankurtuluss/FridaBypassKit |
| SSL-bypass | SSL 고정 우회 예제(구현별 검증 필요)| https://github.com/0xCD4/SSL-bypass |
| awesome-frida | Frida 자원 수집| https://github.com/dweinstein/awesome-frida |
| 안드로이드 보안이 훌륭해요| Android 보안 리소스| https://github.com/ashishb/android-security-awesome |
