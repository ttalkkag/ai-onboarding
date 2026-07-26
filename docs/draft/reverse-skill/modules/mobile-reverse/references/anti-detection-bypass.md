# 루트 / 탈옥 / 디버깅 방지 / SSL 고정 우회

## 계층 모델 감지

```
Layer 1: Static detection (installation/startup)
  ├─ Package manager detection (Cydia, apt, Magisk)
  ├─ 파일 감지(su, busybox, frida-server)
  └─ 권한 감지(ro.debuggable, ro.secure)

Layer 2: Runtime detection (continuous)
  ├─ Process detection (frida-server, magiskd)
  ├─ Port detection (27042 frida default)
  ├─ 메모리 감지 (/proc/self/maps 주입 흔적)
  └─ Stack detection (Frida call frame)

계층 3: 환경 감지(요청 시 트리거됨)
  ├─ ptrace detection (TracerPid)
  ├─ /proc/self/status Detection
  ├─ build.prop detection (test-keys)
  └─ syscall direct detection (bypassing libc)
```

## Android 루트 감지 우회

### 일반적인 탐지 라이브러리 및 우회

| 탐지 라이브러리| 탐지 방법| 우회|
|--------|---------|---------|
| RootBeer | 8가지 테스트 조합| Hook 각 탐지 방법이 false를 반환함|
| SafetyNet Attestation(종료됨) | 2025년 1월 종료된 레거시 원격 인증 | 현재 테스트 기준으로 사용하지 않음 |
| Google Play Integrity API | SafetyNet을 대체한 현재 무결성 신호 | 승인된 테스트 앱에서 서버 판정과 오류 처리를 검증 |
| 커스텀 네이티브 감지| syscall 읽기 /proc/self/status| syscall을 후크하거나 /proc 마운트를 수정하세요.|

### Frida 종합 우회

```javascript
Java.perform(function() {
    // RootBeer
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    var methods = ["isRooted", "isRootedWithBusyBox", "checkSuExists",
        "detectRootManagementApps", "detectPotentiallyDangerousApps",
        "detectTestKeys", "checkForDangerousProps", "checkForRWPaths"];
    methods.forEach(function(m) {
        RootBeer[m].implementation = function() { return false; };
    });

    // Generic Build.TAGS detection
    var Build = Java.use("android.os.Build");
    var original = Build.TAGS.value;
    Build.TAGS.value = "release-keys";

    // PackageManager → Hide package name
    var PackageManager = Java.use("android.content.pm.PackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
        if (pkg == "de.robv.android.xposed.installer" ||
            pkg.includes("magisk") || pkg.includes("frida")) {
            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
        }
        return this.getPackageInfo(pkg, flags);
    };
});
```

## iOS 탈옥 감지 우회

### 다층 Frida 후크

```javascript
// 1. File system detection
var NSFileManager = ObjC.classes.NSFileManager;
var paths = [
    "/Applications/Cydia.app", "/var/lib/apt", "/bin/bash",
    "/usr/sbin/sshd", "/etc/apt", "/Library/MobileSubstrate"
];
// Hook fileExistsAtPath returns NO

// 2. Fork detection (forbidden in sandbox)
var fork_ptr = Process.getModuleByName("libSystem.B.dylib").findExportByName("fork");
Interceptor.replace(fork_ptr, new NativeCallback(function() {
    return -1;
}, 'int', []));

// 3. Scheme detection
// Via MobileSubstrate hook
var LSApplicationWorkspace = ObjC.classes.LSApplicationWorkspace;
// Hook defaultWorkspace → canOpenURL → return NO for cydia://

// 4. Signature detection
var MISValidateSignature = Module.findGlobalExportByName("MISValidateSignature");
Interceptor.attach(MISValidateSignature, {
    onLeave: function(retval) { retval.replace(0); }
});
```

## 안티 디버깅 우회

### Android

```javascript
// 1. ptrace itself → prevent attachment
// Native: ptrace(PTRACE_TRACEME, 0, NULL, 0)
// Bypass: Hook ptrace → return 0

// 2. TracerPid detection
// /proc/self/status → TracerPid: 0
var fopen = Module.findGlobalExportByName("fopen");
Interceptor.attach(fopen, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.includes("status")) {
            // Modify the returned FILE* and return fake content
        }
    }
});

// 3. isDebuggerConnected (Java)
var Debug = Java.use("android.os.Debug");
Debug.isDebuggerConnected.implementation = function() { return false; };
```

### iOS

```javascript
// 1. PT_DENY_ATTACH
// ptrace(PT_DENY_ATTACH, 0, NULL, 0) → prevent debugger from attaching
var ptracePtr = Module.findGlobalExportByName("ptrace");
var originalPtrace = new NativeFunction(ptracePtr, 'int', ['int', 'int', 'pointer', 'int']);
Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
    if (request == 31) return 0; // PT_DENY_ATTACH → ignore
    return originalPtrace(request, pid, addr, data);
}, 'int', ['int', 'int', 'pointer', 'int']));

// 2. sysctl detection
var sysctl = Module.findGlobalExportByName("sysctl");
Interceptor.attach(sysctl, {
    onLeave: function(retval) {
        // Modify the p_flag field of kinfo_proc → clear P_TRACED
    }
});

// 3. getppid detection (check whether the parent process is launchd)
// When debugging getppid() != 1
```

## SSL 고정 우회

### Android 레이어 5 우회

```text
Layer 1 — TrustManager: Accept all certificates
레이어 2 — OkHttp CertificatePinner: Hook 핀 목록 지우기
Layer 3 — WebView SSL Error Handler: Ignore certificate errors
Layer 4 — Network Security Config: Modify xml → Trust user certificate
Layer 5 — Native SSL (OpenSSL/BoringSSL): Hook SSL_get_verify_result → X509_V_OK
```

### iOS 레이어 4 우회

```text
레이어 1 — NSURLSession: Hook SecTrustEvaluate → kSecTrustResultProceed
Layer 2 — Alamofire: Hook ServerTrustManager
Layer 3 — AFNetworking: Hook AFSecurityPolicy
Layer 4 — libcurl/네이티브 TLS: 해당 라이브러리의 검증 콜백을 런타임 계측
```

### 일반적인 Objection 명령

```bash
# Android
objection -n "com.app" start
android sslpinning disable
# 지원되는 프레임워크에 대한 우회 명령이며 모든 계층을 보장하지 않음

# iOS
objection -n "com.app" start
ios sslpinning disable
# 지원되는 프레임워크에 대한 우회 명령이며 모든 계층을 보장하지 않음
```

Source: OWASP MASTG, Frida CodeShare, Objection wiki
