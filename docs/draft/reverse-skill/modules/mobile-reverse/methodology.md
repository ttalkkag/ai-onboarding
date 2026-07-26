# 모바일 리버스 엔지니어링

> Android + iOS 통합 역방향 방법론
> Frida / Objection / OWASP MASTG / SSL 고정 우회

소유하거나 명시적으로 테스트 승인을 받은 앱과 격리된 테스트 기기에서만 사용합니다.

## 적용 가능한 시나리오

- Android APK 역방향 및 보안 테스트
- iOS IPA 리버스 엔지니어링 및 보안 테스트
- 모바일 애플리케이션 런타임 중 동적 계측
- SSL 고정 / 루트 감지 / 탈옥 감지 우회
- 모바일 암호화 알고리즘 추출(AES/RSA/HMAC 키)
- 모바일 애플리케이션 침투 테스트(OWASP MASTG)
- 루팅·탈옥 여부가 다른 승인된 테스트 환경에서 애플리케이션 동작 비교

## 4단계 워크플로

### 1단계: 정보 수집

```text
Android：
□ APK Get (Google Play / APKMirror / adb pull)
□ Manifest analysis: permissions, exported components, Intent Filter, backup flag
□ androguard: androguard analyze APK → components/permissions/signatures
□ APKLeaks: Hardcoded API Key / Token / Secret scan
□ Reinforcement detection: whether to add shell (360/Tencent/Bangbang/Ai Encryption)

iOS：
□ IPA acquisition (App Store / ipatool / Apple Configurator)
□ Decrypt App Store binaries: frida-ios-dump / Clutch
□ Info.plist analysis: ATS configuration, URL Scheme, Queries Schemes
□ class-dump: export ObjC class structure
□ Reinforcement detection: Whether to use Swift/ObjC confusion
```

### 2단계: 정적 분석

```text
Cross-platform:
□ JADX-GUI: APK → Java source code (Android)
□ Ghidra / Hopper:.so / Mach-O Decompile
□ radare2 / Cutter: CLI Quick Scout

Android Special:
□ apktool d app.apk → smali code + resources
□ dex2jar: DEX → JAR → JD-GUI
□ smali/baksmali: Dalvik bytecode modification

iOS Special:
□ class-dump: Export ObjC header files
□ Swift symbol recovery: swift-demangle
□ dsymutil: 기존 오브젝트 파일의 DWARF를 dSYM 번들로 연결(스트립된 바이너리에서 사라진 심볼을 복구하지는 않음)
□ otool -L: View dynamic library dependencies
□ jtool2: Mach-O Analysis
```

### 3단계: 동적 분석

```text
Frida — Universal dynamic instrumentation:
□ frida-ps -U: List device processes
□ frida-trace -U -i "open*" com.app: Trace function calls
□ Custom Hook script: modify parameters/return values, call private methods

Objection — Frida Enhancement layer (no scripting required):
□ objection -n "com.app" start
□ android root disable / ios jailbreak disable
□ android sslpinning disable / ios sslpinning disable
□ android keystore list / ios keychain dump
□ env / ls / sqlite connect

Frida Gadget (루트/탈옥 없이 앱 재패키징 방식):
□ Inject frida-gadget.so / FridaGadget.dylib into APK/IPA
□ 재서명 → 설치(플랫폼 서명·무결성 검사 및 배포 제한을 충족해야 함)
□ objection patchapk --source app.apk (지원되는 APK에서 재패키징 보조)
```

### 4단계: 네트워크 분석

```text
□ Burp Suite: Intercept HTTP/HTTPS, modify request/response
□ mitmproxy: Scriptable proxy (Python API)
□ Wireshark: PCAP packet capture analysis
□ 인증서 설치: Android 7+ 앱은 기본적으로 사용자 CA를 신뢰하지 않으므로 테스트용 Network Security Configuration 또는 승인된 계측을 사용
□ SSL Pinning Bypass: Frida/Objection/Xposed/SSL Kill Switch 2
□ WebSocket / gRPC traffic analysis
```

## 일반적인 우회 빠른 점검

### SSL Pinning

```bash
# Objection(simplest)
objection -n "com.app" start
android sslpinning disable

# Frida Universal Script
frida -U -l ssl_pinning_bypass.js -f com.app

# Xposed（Android）
TrustMeAlready 모듈 → 인증서 검증을 전역 비활성화
```

### 루트/탈옥 감지

```text
# Objection
android root disable
ios jailbreak disable

# Frida Custom (multi-layer detection)
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() { return false; };
    // Additional bypasses: Magisk su detection, frida-server detection, /proc/self/maps detection
});
```

### 디버깅 방지

```bash
# Android
frida -U -l anti_debug_bypass.js -f com.app
# 우회: ptrace(TracerPid), /proc/self/status, isDebuggerConnected()

# iOS
# Bypass: PT_DENY_ATTACH, sysctl CTL_KERN/KERN_PROC/KERN_PROC_PID
frida -U -l ios_anti_debug.js -f com.app
```

## 모바일 암호화 추출

```javascript
// Android — Hook Cipher.getInstance 키 + 알고리즘 가져오기
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log("[Cipher] Algorithm: " + algo);
        return this.getInstance(algo);
    };
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        console.log("[Cipher] Key: " + bytesToHex(key.getEncoded()));
        return this.init(mode, key);
    };
});

function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(('0' + (bytes[i] & 0xff).toString(16)).slice(-2));
    }
    return hex.join('');
}

// iOS — Hook CCCrypt
Interceptor.attach(Module.findGlobalExportByName("CCCrypt"), {
    onEnter: function(args) {
        console.log("CCCrypt op: " + args[0] + " alg: " + args[1]);
        console.log("Key: " + hexdump(args[3], { length: args[4].toInt32() }));
    }
});
```

## 도구 체인

| 도구| 플랫폼| 목적|
|------|:--:|------|
| JADX-GUI | A | 자바 디컴파일|
| apktool | A | APK 압축 풀기/재구축|
| Ghidra | A+I | 다중 아키텍처 디컴파일|
| Hopper | I | iOS 관련 분해|
| Frida | A+I | 동적 계측|
| Objection | A+I | Frida REPL 개선 사항|
| MobSF | A+I | 자동화 SAST+DAST|
| class-dump | I | ObjC 클래스 내보내기|
| frida-ios-dump | I |IPA 암호 해독|
| jtool2 | I | Mach-O 분석|
| Burp Suite | A+I | HTTP 차단|
| mitmproxy | A+I | 스크립트 에이전트|

> A=안드로이드, I=iOS

## 참고자료

- `references/frida-objection-deep.md` — Frida + Objection 깊이 사용법
- `references/ios-reverse-guide.md` — iOS 리버스 엔지니어링 프로젝트
- `references/anti-detection-bypass.md` — 루트/탈옥/디버깅 방지/SSL 고정 우회
