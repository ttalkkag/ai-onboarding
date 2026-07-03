# Frida 실용적인 스크립트의 빠른 검토

> [awesome-frida](https://github.com/dweinstein/awesome-frida), [Frida-Mobile-Scripts](https://github.com/m0bilesecurity/Frida-Mobile-Scripts), [frida-codeshare-scripts](https://github.com/zengfr/frida-codeshare-scripts) 등과 같은 오픈 소스 프로젝트에서 선택되었습니다.
> 장면별로 분류하여 직접 복사하여 활용해보세요.

---

## 일반 후크 템플릿

### Java 메소드를 후크하세요.

```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");

    // Hook 매개변수 없음 방법
    TargetClass.methodName.implementation = function() {
        console.log("[*] methodName called");
        var ret = this.methodName();
        console.log("[*] return: " + ret);
        return ret;
    };

    // Hook 매개변수가 있는 메소드
    TargetClass.methodName.overload('java.lang.String', 'int').implementation = function(str, num) {
        console.log("[*] methodName(" + str + ", " + num + ")");
        var ret = this.methodName(str, num);
        console.log("[*] return: " + ret);
        return ret;
    };
});
```

### 후크 생성자

```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");
    TargetClass.$init.overload('java.lang.String').implementation = function(arg) {
        console.log("[*] new ClassName(" + arg + ")");
        this.$init(arg);
    };
});
```

### 모든 메소드 열거

```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");
    var methods = TargetClass.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log(method.toString());
    });
});
```

---

## 암호화/서명 후크

### 후크 AES 암호화 및 복호화

```javascript
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.doFinal.overload('[B').implementation = function(input) {
        var mode = this.getOpmode ? this.getOpmode() : "?";
        console.log("[Cipher.doFinal] mode=" + mode);
        console.log("  input: " + bytesToHex(input));
        var result = this.doFinal(input);
        console.log("  output: " + bytesToHex(result));
        return result;
    };

    // 캡처 키
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log("[SecretKeySpec] algo=" + algo + " key=" + bytesToHex(key));
        this.$init(key, algo);
    };

    // 캡처 IV
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        console.log("[IvParameterSpec] iv=" + bytesToHex(iv));
        this.$init(iv);
    };
});

function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
    }
    return hex.join('');
}
```

### 후크MD5/SHA

```javascript
Java.perform(function() {
    var MessageDigest = Java.use("java.security.MessageDigest");

    MessageDigest.digest.overload('[B').implementation = function(input) {
        console.log("[MessageDigest.digest] algo=" + this.getAlgorithm());
        console.log("  input: " + bytesToHex(input));
        var result = this.digest(input);
        console.log("  hash: " + bytesToHex(result));
        return result;
    };

    MessageDigest.digest.overload().implementation = function() {
        console.log("[MessageDigest.digest] algo=" + this.getAlgorithm());
        var result = this.digest();
        console.log("  hash: " + bytesToHex(result));
        return result;
    };
});
```

### Hook HMAC

```javascript
Java.perform(function() {
    var Mac = Java.use("javax.crypto.Mac");

    Mac.doFinal.overload('[B').implementation = function(input) {
        console.log("[Mac.doFinal] algo=" + this.getAlgorithm());
        console.log("  input: " + bytesToHex(input));
        var result = this.doFinal(input);
        console.log("  mac: " + bytesToHex(result));
        return result;
    };

    Mac.init.overload('java.security.Key').implementation = function(key) {
        var keyBytes = key.getEncoded();
        console.log("[Mac.init] key=" + bytesToHex(keyBytes));
        this.init(key);
    };
});
```

---

## 네트워크 요청 후크

### Hook OkHttp3 요청/응답

```javascript
Java.perform(function() {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Interceptor = Java.use("okhttp3.Interceptor");

    // Hook newCall이 요청 URL을 가져옵니다.
    var RealCall = Java.use("okhttp3.RealCall");
    RealCall.execute.implementation = function() {
        var request = this.request();
        console.log("[OkHttp] " + request.method() + " " + request.url().toString());
        var headers = request.headers();
        for (var i = 0; i < headers.size(); i++) {
            console.log("  " + headers.name(i) + ": " + headers.value(i));
        }
        var response = this.execute();
        console.log("[OkHttp] Response: " + response.code());
        return response;
    };
});
```

### 후크 URL 연결

```javascript
Java.perform(function() {
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("[URL] " + this.toString());
        return this.openConnection();
    };
});
```

### Hook WebView

```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log("[WebView.loadUrl] " + url);
        this.loadUrl(url);
    };

    WebView.evaluateJavascript.implementation = function(script, callback) {
        console.log("[WebView.evaluateJavascript] " + script.substring(0, 200));
        this.evaluateJavascript(script, callback);
    };
});
```

---

## 우회 클래스 Hook

### 범용 SSL 고정 우회

```javascript
Java.perform(function() {
    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log("[*] SSL Pinning bypassed (OkHttp3)");
        };
    } catch(e) {}

    // TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain) {
            console.log("[*] SSL Pinning bypassed (TrustManagerImpl)");
            return untrustedChain;
        };
    } catch(e) {}

    // X509TrustManager
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManager = Java.registerClass({
            name: "com.bypass.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function() {},
                checkServerTrusted: function() {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch(e) {}

    // Network Security Config (Android 7+)
    try {
        var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() { return true; };
    } catch(e) {}
});
```

### 범용 루트 감지 우회

```javascript
Java.perform(function() {
    // File.exists 우회
    var File = Java.use("java.io.File");
    var rootPaths = ["su", "Superuser", "magisk", "busybox", "xposed",
                     "/system/xbin/su", "/system/bin/su", "/sbin/su",
                     "/data/local/xbin/su", "/data/local/bin/su"];

    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.toLowerCase().indexOf(rootPaths[i].toLowerCase()) !== -1) {
                console.log("[Root] Blocked: " + path);
                return false;
            }
        }
        return this.exists();
    };

    // Runtime.exec 우회
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[Root] Blocked exec: " + cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmd);
    };

    // Build.TAGS 우회
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";
});
```

### 안티 디버깅 우회

```javascript
Java.perform(function() {
    // Debug.isDebuggerConnected
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[AntiDebug] isDebuggerConnected → false");
        return false;
    };

    // TracerPid 감지 우회(네이티브 레이어)
    var fopen = Module.findExportByName("libc.so", "fopen");
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function(retval) {
            if (this.path && this.path.indexOf("/proc/") !== -1 && this.path.indexOf("/status") !== -1) {
                // TracerPid를 수정하기 위해 fget을 추가로 연결할 수 있습니다.
            }
        }
    });
});
```

### 에뮬레이터 감지 우회

```javascript
Java.perform(function() {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
    Build.MODEL.value = "Pixel 2";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "walleye";
    Build.PRODUCT.value = "walleye";
    Build.HARDWARE.value = "walleye";

    // TelephonyManager
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getDeviceId.implementation = function() { return "352099001761481"; };
    TelephonyManager.getSubscriberId.implementation = function() { return "310260000000000"; };
    TelephonyManager.getSimSerialNumber.implementation = function() { return "89014103211118510720"; };
});
```

---

## 데이터 저장 후크

### Hook SharedPreferences

```javascript
Java.perform(function() {
    var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

    SharedPreferencesImpl.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("[SP.get] " + key + " = " + value);
        return value;
    };

    var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    Editor.putString.implementation = function(key, value) {
        console.log("[SP.put] " + key + " = " + value);
        return this.putString(key, value);
    };
});
```

### Hook SQLite

```javascript
Java.perform(function() {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

    SQLiteDatabase.rawQuery.implementation = function(sql, args) {
        console.log("[SQL] " + sql);
        if (args) console.log("  args: " + JSON.stringify(args));
        return this.rawQuery(sql, args);
    };

    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
        console.log("[SQL.exec] " + sql);
        this.execSQL(sql);
    };
});
```

---

## 언패킹 후크

### 유니버셜 DEX 덤프

```javascript
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                var pathList = Java.cast(loader, Java.use("dalvik.system.BaseDexClassLoader")).pathList.value;
                var dexElements = pathList.dexElements.value;
                for (var i = 0; i < dexElements.length; i++) {
                    var dexFile = dexElements[i].dexFile.value;
                    if (dexFile) {
                        console.log("[DEX] " + dexFile.getName());
                        // dex 콘텐츠를 추가로 덤프할 수 있습니다.
                    }
                }
            } catch(e) {}
        },
        onComplete: function() {}
    });
});
```

### 후크 ClassLoader.loadClass

```javascript
Java.perform(function() {
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
        if (name.indexOf("com.target") !== -1) {
            console.log("[ClassLoader] " + name);
        }
        return this.loadClass(name);
    };
});
```

---

## 유틸리티 기능

```javascript
// 바이트 배열을 16진수로 변환
function bytesToHex(bytes) {
    if (!bytes) return "null";
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
    }
    return hex.join('');
}

// 호출 스택 인쇄
function printStack() {
    console.log(Java.use("android.util.Log").getStackTraceString(
        Java.use("java.lang.Throwable").$new()));
}

// 개체의 모든 필드 인쇄
function printFields(obj) {
    var fields = obj.class.getDeclaredFields();
    fields.forEach(function(field) {
        field.setAccessible(true);
        try {
            console.log("  " + field.getName() + " = " + field.get(obj));
        } catch(e) {}
    });
}

// 클래스 인스턴스에 대한 메모리 검색
function findInstances(className) {
    Java.choose(className, {
        onMatch: function(instance) {
            console.log("[Instance] " + instance);
            printFields(instance);
        },
        onComplete: function() {}
    });
}
```

---

## 참고자료

| 자원| 설명| 링크|
|------|------|------|
| Frida 공식 문서| API 참고| https://frida.re/docs/ |
| Frida CodeShare | 커뮤니티 스크립트 공유| https://codeshare.frida.re/ |
| awesome-frida | 자원백과사전| https://github.com/dweinstein/awesome-frida |
| frida-codeshare-scripts | 인터넷에서 가장 완벽한 스크립트 모음| https://github.com/zengfr/frida-codeshare-scripts |
| Objection | Frida 포장 도구| https://github.com/sensepost/objection |
| r2frida | radare2 + Frida 통합| https://github.com/nowsecure/r2frida |
