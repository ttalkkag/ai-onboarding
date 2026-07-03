# Frida + Objection 깊이 사용법

## Frida 핵심 API

### 자바 런타임(안드로이드)

```javascript
Java.perform(function() {
    // Get class instance
    var String = Java.use("java.lang.String");

    // Hook Static method
    var System = Java.use("java.lang.System");
    System.getProperty.overload('java.lang.String').implementation = function(key) {
        console.log("System.getProperty: " + key);
        return this.getProperty(key);
    };

    // Hook 생성자
    var File = Java.use("java.io.File");
    File.$init.overload('java.lang.String').implementation = function(path) {
        console.log("File opened: " + path);
        return this.$init(path);
    };

    // Enumerate loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) { console.log(className); },
        onComplete: function() {}
    });

    // Modify return value
    var RootDetector = Java.use("com.app.security.RootDetector");
    RootDetector.isDeviceRooted.implementation = function() {
        return false;
    };
});
```

### 네이티브 레이어(Android + iOS)

```javascript
// Hook Export function
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        this.path = Memory.readUtf8String(args[0]);
    },
    onLeave: function(retval) {
        console.log("open(" + this.path + ") = " + retval);
    }
});

// Hook Any address (via offset)
var base = Module.findBaseAddress("libnative.so");
var target = base.add(0x12345);
Interceptor.attach(target, {
    onEnter: function(args) {
        console.log("Function called from: " + Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    }
});

// Modify return value
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onLeave: function(retval) {
        if (retval.toInt32() === 0) return; // strings equal, skip
        // Force match
        retval.replace(0);
    }
});
```

### ObjC 런타임(iOS)

```javascript
// Hook ObjC methods
var hook = ObjC.classes.ViewController["- viewDidLoad"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        console.log("viewDidLoad called");
    }
});

// 모든 클래스 열거
ObjC.enumerateLoadedClasses({
    onMatch: function(className) { console.log(className); },
    onComplete: function() {}
});

// ObjC 메서드 호출
var NSString = ObjC.classes.NSString;
var str = NSString.stringWithString_("Hello from Frida");
```

## Objection 명령 빠른 확인

### 유니버설

```bash
objection -g "com.app" explore           # 시작
objection -g "com.app" explore -q        # 자동 시작(기다리지 않고 주입만 가능)
objection patchapk --source app.apk      # Frida 가젯 자동 삽입
objection signapk --source app.apk       # Signature only

# 파일 시스템
env              # 애플리케이션 데이터 디렉토리
ls               # 파일 나열
file download /path/to/file  # 파일 다운로드
file upload local.txt /remote/path  # 파일 업로드

# SQLite
sqlite connect /path/to/db.sqlite
.tables          # list table
select * from users;  # 쿼리
```

### 안드로이드 전용

```bash
android root disable              # Bypass Root detection
android sslpinning disable        # 우회 SSL 고정
android hooking list classes      # enum class
android hooking list class_methods com.app.Main  # enumeration method
android hooking watch class com.app.Main  # Hook 모든 방법
android intent launch_activity com.app.MainActivity  # 활동 시작
android heap search instances com.app.User  # Heap search
android keystore list             # 키스토어 항목
```

### iOS 전용

```bash
ios jailbreak disable             # 탈옥 감지 우회
ios sslpinning disable            # 우회 SSL 고정
ios keychain dump                 # 키체인 내보내기
ios nsuserdefaults get            # NSUserDefaults
ios nsurlcache dump               # HTTP 캐시
ios cookies get                   # 쿠키 읽기
ios pasteboard monitor            # 클립보드 듣기
ios ui dump                       # UI 계층 구조
ios plist cat Info.plist          # plist 읽기
```

## 루트/탈옥 방지 배포

### Android — Frida 가젯 삽입

```bash
# 1. 포장 풀기 APK
apktool d app.apk -o app_unpacked

# 2. frida-gadget을 다운로드하여 lib 디렉토리에 넣습니다.
cp frida-gadget-17.x.x-android-arm64.so \
   app_unpacked/lib/arm64-v8a/libfrida-gadget.so

# 3. System.loadLibrary("frida-gadget")를 smali에 삽입합니다.
# 기본 활동의 onCreate 또는 attachmentBaseContext 수정

# 4. 재구축 및 서명
apktool b app_unpacked -o app_patched.apk
uber-apk-signer -a app_patched.apk

# 5. Objection 자동화
objection patchapk --source app.apk --skip-resources
```

### iOS — Frida 가젯 삽입

```bash
# 1. 앱스토어 IPA 복호화
python3 frida-ios-dump.py -u -p com.app.target

# 2. FridaGadget.dylib 삽입
# Mach-O 로드 명령을 수정하고 @executable_path/FridaGadget.dylib를 추가합니다.

# 3. 재서명
codesign -f -s "Apple Development" Payload/App.app

# 4. Xcode 사이드로드 또는 AltStore를 통해 설치
```

## SSL 고정 우회 고급

### 다중 계층 우회(Android)

```javascript
// 1. OkHttp CertificatePinner
var CertificatePinner = Java.use("okhttp3.CertificatePinner");
CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};

// 2. TrustManager 사용자 정의
var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
TrustManagerImpl.verifyChain.implementation = function() { return []; };

// 3. WebView SSL Error
var SslErrorHandler = Java.use("android.webkit.SslErrorHandler");
SslErrorHandler.proceed.implementation = function() { return this.proceed(); };

// 4. Network Security Config
// AndroidManifest.xml 수정 필요 → android:networkSecurityConfig="@xml/network_security_config"
// XML에 신뢰할 수 있는 사용자 인증서 추가
```

### 다중 계층 우회(iOS)

```javascript
// 1. NSURLSession
var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
    Memory.writeU32(result, 1); // kSecTrustResultProceed = 1
    return 0; // errSecSuccess
}, 'int', ['pointer', 'pointer']));

// 2. Alamofire
// Hook ServerTrustManager.evaluate → 항상 성공을 반환합니다.
```

Source: Frida 문서, Objection 위키, OWASP MSTG
