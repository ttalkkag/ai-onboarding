# CTF Reverse - 플랫폼 및 프레임워크별 기술

## 목차
- [Rust serde_json 스키마 복구](#rust-serde_json-schema-recovery)
- [Android JNI RegisterNatives 난독화(HTB WonderSMS)](#android-jni-registernatives-obfuscation-htb-wondersms)
- [/proc/self/maps을 통한 Android DEX 런타임 바이트코드 패치(Google CTF 2017)](#android-dex-runtime-bytecode-patching-via-procselfmaps-google-ctf-2017)
- [새 프로젝트에서 Android 네이티브.so 로딩 우회(Codegate CTF 2018)](#android-native-so-loading-bypass-in-new-project-codegate-ctf-2018)
- [Frida Firebase Cloud Functions 우회(BSidesSF 2026)](#frida-firebase-cloud-functions-bypass-bsidessf-2026)
- [Verilog/Hardware 리버스 엔지니어링(srdnlenCTF 2026)](#veriloghardware-reverse-engineering-srdnlenctf-2026)
- [접두사별 해시 반전(Nullcon 2026)](#prefix-by-prefix-hash-reversal-nullcon-2026)
- [Ruby/Perl 다중 언어 제약 조건 만족도(BearCatCTF 2026)](#rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026)
- [Electron 앱 + 네이티브 바이너리 반전(RootAccess2026)](#electron-app--native-binary-reversing-rootaccess2026)
- [Node.js npm 패키지 런타임 검사(RootAccess2026)](#nodejs-npm-package-runtime-introspection-rootaccess2026)
- [Frida Android 인증서 고정 우회(h1702ctf 2017)](#frida-android-certificate-pinning-bypass-h1702ctf-2017)
- [Android 안티 디버그: TracerPid, su 바이너리, 시스템 속성(h1702ctf 2017)](#android-anti-debug-tracerpid-su-binary-system-properties-h1702ctf-2017)
- [Android 로그 기반 키 추출(HackIT 2017)](#android-log-based-key-extraction-hackit-2017)
- [메모리 덤프 및 Smali 패치를 통한 네이티브 JNI 키 추출(HackIT 2017)](#native-jni-key-extraction-via-memory-dump-and-smali-patching-hackit-2017)
- [IBM AS/400 SAVF 파일 EBCDIC 디코딩(EKOPARTY 2017)](#ibm-as400-savf-file-ebcdic-decoding-ekoparty-2017)
- [Intel SGX Enclave 리버스 엔지니어링(Pwn2Win 2017)](#intel-sgx-enclave-reverse-engineering-pwn2win-2017)

핵심 언어 반전(Python, BF/esolangs, DOS, OPAL)에 대해서는 [languages.md](languages.md)를 참조하세요.
Go 및 Rust 바이너리 리버싱에 대해서는 [languages-compiled.md](languages-compiled.md)를 참조하세요.

---

## Rust serde_json 스키마 복구

**패턴(Curly Crab, PascalCTF 2026):** Rust 바이너리는 stdin에서 JSON를 읽고, serde_json을 통해 역직렬화하고, success/failure 이모티콘을 인쇄합니다.

**Approach:**
1. Serde에서 생성된 `Visitor` 구현을 분해합니다.
2. 각 방문자의 `visit_map` / `visit_seq`는 예상되는 키와 유형을 나타냅니다.
3. 역직렬 변환기 코드에서 문자열 리터럴을 찾습니다(`"pascal"`, `"CTF"`와 같은 필드 이름).
4. 방문자 호출 계층 구조에서 중첩된 JSON 스키마 재구성
5. 방문자 메소드 이름에서 값 유형 식별: `visit_str` = 문자열, `visit_u64` = 숫자, `visit_bool` = 부울, `visit_seq` = 배열

```json
{"pascal":"CTF","CTF":2026,"crab":{"I_":true,"cr4bs":1337,"crabby":{"l0v3_":["rust"],"r3vv1ng_":42}}}
```

**주요 정보:** 플래그는 스키마 순서대로 JSON 키를 연결한 것입니다. 필드 이름을 순서대로 읽으면 플래그가 표시됩니다.

---

## Android JNI RegisterNatives 난독화(HTB WonderSMS)

**패턴:** Android 앱은 `System.loadLibrary()`를 사용하여 기본 라이브러리를 로드하지만 표준 JNI 명명 규칙(`Java_com_pkg_Class_method`) 대신 `JNI_OnLoad`에서 `RegisterNatives`을 사용합니다. 이는 각 Java 기본 메소드를 처리하는 C++ 함수를 숨깁니다.

**Identification:**
```java
// In decompiled Java (jadx):
static { System.loadLibrary("audio"); }
private final native ProcessedMessage processMessage(SmsMessage msg);
```
표준 JNI에는 `Java_com_rloura_wondersms_SmsReceiver_processMessage` 기호가 있습니다. `.so`에 해당 기호가 없으면 `RegisterNatives`가 사용됩니다.

**Ghidra에서 실제 핸들러 찾기:**
1. `JNI_OnLoad`(내보낸 기호, 항상 존재함)을 찾습니다.
2. `RegisterNatives(env, clazz, methods, count)` 호출 추적
3. `methods` 배열에는 `{name, signature, fnPtr}` 구조체가 포함되어 있습니다.
4. 실제 네이티브 함수를 찾으려면 `fnPtr`를 따르세요.

```c
// JNI_OnLoad registers functions manually:
static JNINativeMethod methods[] = {
    {"processMessage", "(Landroid/telephony/SmsMessage;)LProcessedMessage;", (void*)real_handler}
};
(*env)->RegisterNatives(env, clazz, methods, 1);
```

**분석을 위한 아키텍처 선택:**
```bash
# x86_64 gives best Ghidra decompilation (most similar to desktop code)
# Extract from APK:
unzip WonderSMS.apk -d extracted/
ls extracted/lib/x86_64/  # Prefer this over arm64-v8a for static analysis
```

**주요 통찰력:** `RegisterNatives`은 의도적인 난독화 기술입니다. 즉, Java 메서드 이름을 기본 기호 이름에서 분리하여 문자열 검색만으로는 핸들러를 찾을 수 없게 만듭니다. 제거된 기호를 사용하여 Android 네이티브 라이브러리를 되돌릴 때는 항상 `JNI_OnLoad`를 먼저 확인하세요.

**탐지:** Java로 선언된 기본 메소드 + `.so` + `JNI_OnLoad`에 일치하는 JNI 기호가 없습니다. 라이브러리는 일반적으로 제거됩니다(디버그 기호 없음).

---

## /proc/self/maps를 통한 Android DEX 런타임 바이트코드 패치(Google CTF 2017)

네이티브 JNI 라이브러리는 런타임 시 메모리의 Dalvik 바이트코드를 패치합니다. `/proc/self/maps`를 읽어 로드된 DEX을 찾고, `mprotect` 쓰기 가능한 것을 찾은 다음 특정 바이트코드 오프셋을 XOR 패치합니다.

```python
# Reconstruct the patched DEX offline:
# 1. Extract the embedded DEX from the APK
# 2. Find the XOR key and patch offsets in the native .so (IDA/Ghidra)
# 3. Apply the same patches to the static DEX
import struct

with open('classes.dex', 'rb') as f:
    dex = bytearray(f.read())

# Patch 144 bytes starting at offset found in .so
xor_key = 0x5A
for i in range(patch_offset, patch_offset + 144):
    dex[i] ^= xor_key

# 4. Recompute DEX checksum and SHA-1 hash
# 5. Decompile with jadx or baksmali
```

**주요 통찰력:** 네이티브 라이브러리는 `/proc/self/maps` + `mprotect`를 통해 메모리의 DEX 바이트코드를 수정할 수 있으므로 APK만으로는 정적 분석이 불충분합니다. 실제 런타임 DEX를 재구성하려면 네이티브 `.so`에서 XOR 키와 패치 오프셋을 추출해야 합니다. ART가 아닌 Dalvik(API < 21)에서만 작동합니다.

---

### 새 프로젝트에서 Android 네이티브.so 로드 우회(Codegate CTF 2018)

**패턴:** 복잡한 JNI 유효성 검사 논리를 뒤집는 대신 패키지 이름, 클래스 이름 및 네이티브 메서드 서명이 일치하는 새로운 Android Studio 프로젝트를 만듭니다. 원본 `.so` 라이브러리를 로드하고 모든 Java 수준 검사(난수 확인, PIN 입력, 루트 감지 등)를 완전히 우회하여 네이티브 함수를 직접 호출합니다.

```java
// Create new project with same package: com.example.puing.a2018codegate
package com.example.puing.a2018codegate;
public class Main4Activity extends AppCompatActivity {
    static { System.loadLibrary("hello-libs"); }
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String flag = stringFromJNI();  // call native directly, skip all Java validation
        Log.d("FLAG", flag);
    }
    public native String stringFromJNI();
}
```

**주요 통찰력:** JNI 함수 이름은 패키지 경로와 클래스 이름을 인코딩합니다. 일치하는 package/class/method 이름으로 새 Android 프로젝트를 만들고, 원본 `.so`을 포함하고, 네이티브 함수를 직접 호출하세요. 모든 Java 수준 유효성 검사(무작위 검사, PIN 입력, 루트 감지)가 완전히 우회됩니다.

**탐지:** APK 플래그 또는 비밀이 네이티브 코드 내에서 계산되어 Java로 반환되는 네이티브 `.so` 라이브러리를 사용합니다. Java 계층에는 네이티브 메서드를 호출하기 전에 여러 유효성 검사 게이트(EditText 검사, 난수 비교, 장치 검사)가 있습니다.

**참고자료:** Codegate CTF 2018

---

## Frida Firebase Cloud Functions 우회(BSidesSF 2026)

**패턴(비닐 드롭, 도레미):** Android 앱은 Firebase Cloud Functions를 통해 작업(QR 코드, 구매)을 검증합니다. 예상되는 페이로드 형식에는 Firebase UID, 값, 타임스탬프가 포함됩니다. Frida를 사용하여 로그인 후 앱을 연결하고, 유효한 페이로드를 구성하고, Cloud 함수를 직접 호출하세요.

```javascript
// Frida hook to bypass QR validation
Java.perform(function() {
    var FirebaseFunctions = Java.use('com.google.firebase.functions.FirebaseFunctions');
    var FirebaseAuth = Java.use('com.google.firebase.auth.FirebaseAuth');

    // Get current user UID after login
    var auth = FirebaseAuth.getInstance();
    var uid = auth.getCurrentUser().getUid();

    // Construct valid payload: uid + amount + timestamp
    var unixMs = Java.use('java.lang.System').currentTimeMillis();
    var payload = uid + "+100+" + unixMs;

    // Call the Cloud Function directly
    var functions = FirebaseFunctions.getInstance();
    var data = Java.use('java.util.HashMap').$new();
    data.put("payload", payload);
    functions.getHttpsCallable("validateScanPayload").call(data);
});
```

**주요 통찰력:** Firebase AppCheck 및 Cloud Functions는 클라이언트를 사용하여 유효한 페이로드를 구성합니다. 인증 후 Frida는 클라이언트 측 검증(QR 스캔, 결제 처리 등)을 우회하여 임의 매개변수로 Cloud 함수를 호출하도록 앱을 연결할 수 있습니다.

**인식해야 하는 경우:** `google-services.json`가 포함된 Android 앱, `build.gradle`의 Firebase 종속 항목, 디컴파일된 코드의 Cloud 함수 호출.

**참조:** BSidesSF 2026 "비닐 드롭"

---

## Verilog/Hardware 리버스 엔지니어링(srdnlenCTF 2026)

**패턴(Rev Juice):** 특정 동전 삽입 및 선택 순서에 따라 숨겨진 제품이 잠금 해제되는 자동 판매기용 Verilog HDL 소스입니다.

**Approach:**
1. Verilog 모듈을 분석하여 상태 머신 및 기록 추적을 이해합니다.
2. 숨겨진 조건 식별(예: `COINS_HISTORY` 배열이 특정 탭에서 특정 값을 갖는 경우에만 제품 8이 활성화됨)
3. 각 작업 유형에 대한 타이밍 모델 구축(각 작업에 소요되는 클럭 사이클 수)
4. 올바른 입력 시퀀스를 구성하기 위해 필요한 기록 값에서 역방향으로 작업합니다.

**타이밍 모델 구성:**
```python
# Map each action to its cycle count (determined from Verilog state machines)
TIMING = {
    "insert_coin": 3,       # 3 cycles per coin insertion
    "select_success": 7,    # 7 cycles for successful product selection
    "select_fail": 5,       # 5 cycles for failed selection attempt
    "cancel_with_coins": 4, # 4 cycles for cancel when coins > 0
    "cancel_at_zero": 2,    # 2 cycles for cancel when coins = 0
}

# COINS_HISTORY is a shift register updated each cycle
# History tap requirements (from Verilog conditions):
# H[0]=1, H[7]=4, H[28]=H[33]=H[38]=6
# H[63]=H[73]=2, H[80]=9
# (H[19]+H[21]+H[56]+H[69]) mod 32 = 0
```

**주요 통찰력:** 하드웨어 문제를 해결하려면 정확한 타이밍 모델을 이해해야 합니다. 각 작업에는 특정 수의 클록 사이클이 필요하며 시프트 레지스터는 고정 탭 위치에서 기록을 기록합니다. 각 사이클에서 어떤 동작이 발생했는지 확인하려면 필요한 탭 값부터 역방향으로 작업하십시오. 해결책은 종종 특정 시퀀스 표기법(예: `I9C_SP6_CNL_I2C_SP2_I6C_SP6_SP6_SP5_CNL_I4C_SP1`)입니다.

**탐지:** 기록 값에 따라 숨겨진 조건이 포함된 `.v` 또는 `.sv`(Verilog/SystemVerilog) 파일, `always @(posedge clk)` 블록, 시프트 레지스터 패턴 및 상태 머신 `case` 문을 찾습니다.

---

## 접두사별 해시 반전(Nullcon 2026)

전체 기술은 [patterns-ctf-2.md](patterns-ctf-2.md#prefix-hash-brute-force-nullcon-2026)을 참조하세요. 이 섹션에서는 언어별 고려 사항을 다룹니다.

**Language-specific notes:**
- 해시 알고리즘은 일반적이지 않을 수 있습니다(MD2, 사용자 정의). 이를 식별할 필요가 없으며 바이너리를 실행하여 출력을 일치시키기만 하면 됩니다.
- `subprocess.run()`와 `timeout=2`를 사용하여 잘못된 입력에 걸리는 바이너리를 처리합니다.
- 제거된 바이너리의 경우 `ltrace`가 해시 함수 이름(예: `MD2_Update`)을 나타내는지 확인하세요.

---

## Ruby/Perl 다중 언어 제약 조건 만족도(BearCatCTF 2026)

**패턴(Polly's Key):** Ruby와 Perl 모두에서 유효한 단일 파일입니다. 각 언어는 50자 키에 대해 서로 다른 유효성 검사 제약 조건을 적용합니다. 플래그를 해독하려면 두 가지를 동시에 충족하십시오.

**다언어 구조 악용:**
- 루비: `=begin`...`=end`는 블록 댓글입니다
- Perl: `=begin`...`=cut`는 POD(Plain Old Documentation)이고, `=end`는 무시됩니다.
- 주석 블록 경계에 따라 각 언어에서 서로 다른 코드가 실행됩니다.

**Typical constraints:**
- **루비:** 문자 세트는 수학적 속성을 형성해야 합니다(예: `^`를 제외한 모든 50개의 인쇄 가능한 ASCII 문자는 정확히 한 번 사용되며 `XOR(val, (val-16) % 257)`를 만족하는 각 문자는 기본 루트 모드 257입니다)
- **Perl:** 삽입 정렬 반전 횟수를 통한 순서 제약 조건(하드코딩된 반전 테이블이 정확한 순열을 결정함)

**Solution approach:**
1. 유효한 문자 집합 찾기(한 언어의 수학적 제약)
2. 정확한 배열을 결정하려면 (다른 언어의) 순서 제약 조건을 사용하세요.
3. 키 해시(예: MD5) 계산 및 암호 해독

```python
# Determine character ordering from inversion counts
def reconstruct_from_inversions(chars, inv_counts):
    result = []
    remaining = sorted(chars)
    for i in range(len(chars) - 1, -1, -1):
        # inv_counts[i] = number of elements to the left that are greater
        idx = inv_counts[i]
        result.insert(idx, remaining.pop(i))
    return result
```

**주요 통찰력:** 다중 언어 파일은 언어별 comment/block 구문을 활용하여 각 인터프리터에서 서로 다른 코드를 실행합니다. 두 언어의 제약 조건이 교차하여 키를 고유하게 결정합니다. 두 인터프리터를 사용하여 파일을 테스트하고 동작을 비교하여 어떤 코드가 어떤 언어로 실행되는지 식별합니다.

**탐지:** 여러 인터프리터에서 실행되는 파일(`ruby file && perl file`). 챌린지는 "다언어"를 언급하거나 Perl처럼 보이는 `.rb`로 끝나는 파일을 제공합니다.

---

## Electron 앱 + 네이티브 바이너리 반전(RootAccess2026)

**패턴(Rootium 브라우저):** Electron 데스크탑 앱은 민감한 작업(vault, crypto, auth)을 위한 기본 ELF/DLL 바이너리를 번들로 제공합니다. 전자 레이어는 래퍼입니다. 실제 플래그 논리는 기본 바이너리에 있습니다.

**Extraction workflow:**
1. **Electron ASAR 아카이브 압축 풀기:**
```bash
# Install ASAR tool
npm install -g @electron/asar

# Extract the app.asar archive
asar extract resources/app.asar app_extracted/
ls app_extracted/
```

2. **네이티브 바이너리 찾기:** JavaScript에서 호출된 ELF/DLL 파일 검색:
```bash
# Find native binaries
find app_extracted/ -name "*.node" -o -name "*.so" -o -name "*vault*" -o -name "*auth*"

# Check JS for child_process.spawn or ffi-napi calls
grep -r "spawn\|execFile\|ffi\|require.*native" app_extracted/
```

3. **네이티브 바이너리를 뒤집습니다**(XOR + 회전 암호 예):
```python
def decrypt_password(encrypted_bytes, key):
    """Common pattern: XOR with constant + bit rotation + key XOR."""
    result = []
    for i, byte in enumerate(encrypted_bytes):
        decrypted = ((byte ^ 0x42) >> 3) ^ key[i % len(key)]
        result.append(chr(decrypted))
    return ''.join(result)

def decrypt_flag(encrypted_flag, password):
    """Flag uses password as key with position-dependent rotation."""
    result = []
    for i, byte in enumerate(encrypted_flag):
        key_byte = ord(password[i % len(password)])
        decrypted = ((byte ^ 0x7E) >> (i % 8)) ^ key_byte
        result.append(chr(decrypted))
    return ''.join(result)
```

**주요 통찰력:** Electron 앱은 네이티브 코드를 래핑하는 JavaScript입니다. `asar`로 추출한 다음 네이티브 바이너리에 집중하세요. JS 계층에는 종종 일반 텍스트의 비밀번호 확인 흐름이 포함되어 기본 바이너리가 기대하는 것을 드러냅니다. ELF의 `.data` 또는 `.rodata` 섹션에서 암호화된 데이터를 찾으세요.

**탐지:** `resources/` 디렉터리의 `.asar` 파일, Electron 프레임워크 파일, 전자 종속성이 있는 `package.json`.

---

## Node.js npm 패키지 런타임 검사(RootAccess2026)

**패턴(RootAccess CLI):** RC4 인코딩, 제어 흐름 평면화 및 여러 조각에 걸친 플래그 분할을 갖춘 난독화된 npm 패키지입니다. 정적 분석은 비현실적입니다. 대신 런타임 내부 검사를 사용하세요.

**동적 분석 접근 방식:**
```javascript
#!/usr/bin/env node

// 1. Load obfuscated modules
const cryptoMod = require('target-package/dist/lib/crypto.js');
const vaultMod = require('target-package/dist/lib/vault.js');

// 2. Enumerate all exported properties
for (const mod of [cryptoMod, vaultMod]) {
    for (const key of Object.keys(mod)) {
        const obj = mod[key];
        console.log(`Export: ${key}`);
        // List all methods including hidden ones
        const props = Object.getOwnPropertyNames(obj);
        const proto = Object.getOwnPropertyNames(obj.prototype || {});
        console.log('  Own:', props);
        console.log('  Proto:', proto);
    }
}

// 3. Extract flag fragments
const Engine = cryptoMod.CryptoEngine;
const total = Engine.getTotalFragments();
let flag = '';
for (let i = 1; i <= total; i++) {
    flag += Engine.getFragment(i);
}
console.log('Flag:', flag);

// 4. Check for hidden methods (common: __getFullFlag__, _debug, _raw)
const hidden = Object.getOwnPropertyNames(Engine)
    .filter(p => p.startsWith('__') || p.startsWith('_'));
console.log('Hidden methods:', hidden);
```

**주요 통찰력:** 심하게 난독화된 JavaScript(제어 흐름 평면화, RC4 문자열 인코딩, 데드 코드)로 인해 정적 분석이 엄청나게 느려집니다. `Object.getOwnPropertyNames()`를 통한 런타임 검사를 통해 숨겨진 메서드를 포함한 모든 메서드가 드러납니다. 모듈 자체의 암호 해독은 로드될 때 자동으로 실행됩니다. 디코딩된 함수를 직접 호출하기만 하면 됩니다.

**탐지:** minified/obfuscated `dist/` 디렉토리가 있는 npm 패키지, 챌린지에는 "CLI 도구 리버스 엔지니어링", `package.json` 사용자 지정 명령이 포함되어 있습니다.

---

## Frida Android 인증서 고정 우회(h1702ctf 2017)

APK는 SSL 고정을 위해 OkHttp `CertificatePinner`를 사용합니다. MITM 프록시를 설정하거나 APK를 패치하는 대신 Frida를 사용하여 로드된 클래스에서 기본 JNI 메서드를 직접 호출합니다.

```javascript
Java.perform(function() {
    var Requestor = Java.use("com.h1702ctf.ctfone.Requestor");
    console.log("hName: " + Requestor.hName());
    console.log("hVal: " + Requestor.hVal());
});
```

`hName()` 및 `hVal()`를 호출하면 서버 측 검사를 우회하는 데 필요한 HTTP 헤더 이름과 값이 반환됩니다. 비밀이 클래스 메소드 자체에 있기 때문에 인증서 고정 우회가 필요하지 않습니다.

**주요 통찰력:** Frida는 로드된 클래스에서 직접 네이티브 JNI 메서드를 호출할 수 있습니다. 네트워크 계층에서 인증서 고정을 우회하거나 네이티브 바이너리를 완전히 반전할 필요가 없습니다.

**참고자료:** h1702ctf 2017

---

## Android 안티 디버그: TracerPid, su 바이너리, 시스템 속성(h1702ctf 2017)

기본 ARM 코드는 세 가지 순차적 안티분석 검사를 구현합니다.
1. `/proc/self/status`를 읽고 0이 아닌 `TracerPid`를 찾으세요(디버거 첨부)
2. `su` 바이너리가 있는지 확인하세요(루트 감지).
3. `__system_property_get`를 통해 사용자 정의 시스템 속성을 읽습니다.

체크 게이트는 필요한 레지스터 값 계산을 수행합니다. 정적 분석을 통한 우회: IDA의 그래프 보기를 사용하여 제어 흐름을 추적하고 세 가지 검사를 모두 통해 "행복한 경로"를 식별한 다음 각 분기에서 보유해야 하는 레지스터 값을 계산합니다.

**주요 통찰력:** 정적 그래프 분석을 통해 기본 Android 코드(TracerPid, su, 시스템 속성)의 디버그 방지 검사를 우회하여 디버거를 실행하지 않고도 올바른 레지스터 값을 찾을 수 있습니다.

**참고자료:** h1702ctf 2017

---

## Android 로그 기반 키 추출(HackIT 2017)

보안 메신저 앱은 Android의 `Log.d()`를 통해 암호화 자료를 기록합니다.
- Curve25519 기본 계약 값
- 메시지당 임시 공유 키
- 메시지 ID 및 교대근무 카운터

AES-CBC IV는 기록된 ephemeral/shared 값에서 파생됩니다. 키는 기록된 기본 계약과 누적된 교대 카운터에서 파생됩니다. `adb logcat`를 사용하여 모든 로그 항목을 수집한 다음 AES-CBC 매개변수를 재구성하여 가로채는 메시지를 해독합니다.

```bash
adb logcat | grep -E "(agreement|ephemeral|shared|key)" > crypto_log.txt
# Parse log entries to reconstruct: key = f(base_agreement, shift_counter)
#                                   iv  = f(ephemeral_shared)
```

**주요 통찰력:** 보안에 민감한 앱의 지나치게 자세한 로깅은 개인 키에 액세스하지 않고도 암호화 매개변수를 재구성할 수 있을 만큼 충분한 상태를 유출합니다.

**참고 자료:** HackIT CTF 2017

---

## 메모리 덤프 및 Smali 패치를 통한 네이티브 JNI 키 추출(HackIT 2017)

JNI 네이티브 라이브러리는 `.data` 섹션에 저장된 XOR 난독화 키를 사용하여 요청 서명을 처리합니다. 키는 사용 직전 런타임 시 난독화됩니다.

**Workflow:**
1. 루팅된 장치에서 GDB 스텁을 사용하여 IDA에 라이브러리 로드
2. XOR 복호화 루틴 뒤에 중단점 설정
3. 해독된 키가 포함된 메모리 영역을 덤프합니다.
4. `baksmali`를 사용하여 APK의 DEX를 분해하고 서명된 POST 요청을 구성하는 smali 파일을 식별합니다.
5. sali를 패치하여 서명된 매개변수를 변경한 다음 `apktool`로 다시 빌드하고 다시 설치하세요.

```bash
# Decompile APK
apktool d target.apk -o target_decompiled/
# Edit smali: change signed parameter from original to desired value
# Rebuild
apktool b target_decompiled/ -o target_patched.apk
# Sign and install
```

**주요 정보:** JNI 서명의 경우: 실행 중에 해독된 키 영역을 메모리 덤프한 다음 smali를 패치하여 원하는 매개변수에 서명합니다. 기본 서명 알고리즘이 완전히 반전되는 것을 방지합니다.

**참고 자료:** HackIT CTF 2017

---

## IBM AS/400 SAVF 파일 EBCDIC 디코딩(EKOPARTY 2017)

IBM AS/400 SAVF(파일 저장) 바이너리 파일은 ASCII가 아닌 EBCDIC 인코딩을 사용합니다. 플래그는 take-2-skip-2 패턴을 사용하여 더미 텍스트와 인터리브됩니다.

```python
import codecs

with open('savefile.savf', 'rb') as f:
    data = f.read()

# Convert EBCDIC to ASCII
ascii_data = data.decode('cp500')  # cp500 is IBM EBCDIC International

# Filter: keep uppercase letters and underscores (flag charset)
flag_chars = [c for c in ascii_data if c.isupper() or c == '_']
# Or apply take-2-skip-2 pattern after decoding
flag = ''.join(ascii_data[i] for i in range(0, len(ascii_data), 4)
               if ascii_data[i].isupper() or ascii_data[i] == '_')
```

**주요 통찰력:** EBCDIC 인코딩은 IBM 메인프레임 기반입니다. 인터리빙 패턴을 식별하기 위해 디코딩 후 문자 분포를 검사합니다. 대문자와 밑줄 필터링은 CTF 플래그 형식에 대한 효과적인 지름길입니다.

**참고자료:** EKOPARTY CTF 2017

---

## Intel SGX Enclave 리버스 엔지니어링(Pwn2Win 2017)

Intel SGX 엔클레이브 `.so` 파일은 ECALL 디스패치 테이블을 노출합니다. SGX 코드는 표준 x86-64이므로 엔클레이브 논리(키 파생 포함)는 IDA로 완전히 되돌릴 수 있습니다.

**Workflow:**
1. `.so`에서 ECALL 테이블을 찾습니다. ECALL 번호로 인덱스된 함수 포인터 배열입니다.
2. 원격 증명 프로토콜을 식별하기 위해 IDA로 ECALL을 디컴파일합니다.
3. `sgx_crypto_wrapper`를 사용하여 Python에서 수동으로 증명 프로토콜을 구현합니다.
4. 키 파생: P-256을 통한 ECDH와 세션 키(SK) 파생을 위한 CMAC-AES-128
5. 파생된 SK를 사용하여 AES-128-GCM으로 암호화된 플래그 Blob을 해독합니다.

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import cmac, ciphers

# ECDH: derive shared secret from server's P-256 public key
private_key = ec.generate_private_key(ec.SECP256R1())
shared_secret = private_key.exchange(ec.ECDH(), server_pub_key)

# CMAC-AES-128 key derivation (per SGX attestation spec)
c = cmac.CMAC(ciphers.algorithms.AES(b'\x00' * 16))
c.update(shared_secret[:16])
sk = c.finalize()

# Decrypt flag with AES-128-GCM using derived SK
```

**주요 통찰력:** SGX 원격 증명 키 파생은 엔클레이브 측정을 고려하여 결정적입니다. Python에서 프로토콜을 다시 구현하면 동일한 세션 키가 복구됩니다.

**참조:** Pwn2Win CTF 2017
