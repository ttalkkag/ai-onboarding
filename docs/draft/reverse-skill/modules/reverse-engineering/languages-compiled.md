# CTF Reverse - 컴파일된 언어 반전(Go, Rust)

## 목차
- [Go 바이너리 리버싱](#go-바이너리-리버싱)
  - [Recognition](#recognition)
  - [Symbol Recovery](#symbol-recovery)
  - [Go 메모리 레이아웃](#go-메모리-레이아웃)
  - [고루틴 및 동시성 분석](#고루틴-및-동시성-분석)
  - [디컴파일의 일반적인 Go 패턴](#디컴파일의-일반적인-go-패턴)
  - [Go Binary 역전 작업 흐름](#go-binary-역전-작업-흐름)
  - [C2 클라이언트 열거를 위한 Go 바이너리 UUID 패치(BSidesSF 2026)](#c2-클라이언트-열거를-위한-go-바이너리-uuid-패치bsidessf-2026)
- [Rust 바이너리 반전](#rust-바이너리-반전)
  - [Rust Recognition](#rust-recognition)
  - [Symbol Demangling](#symbol-demangling)
  - [디컴파일 시 일반적인 Rust 패턴](#디컴파일-시-일반적인-rust-패턴)
  - [Rust 관련 분석 도구](#rust-관련-분석-도구)
- [Swift 바이너리 리버싱](#swift-바이너리-리버싱)
- [Kotlin/JVM 바이너리 반전](#kotlinjvm-바이너리-반전)
  - [JVM 바이트코드(Android/Server)](#jvm-바이트코드androidserver)
  - [Kotlin/Native](#kotlinnative)
- [D 언어 바이너리 역전(CSAW CTF 2016)](#d-언어-바이너리-역전csaw-ctf-2016)
- [Haskell 바이너리 리버싱](#haskell-바이너리-리버싱)
  - [STG 클로저 및 hsdecomp(hxp CTF 2017, Codegate 2018)](#stg-클로저-및-hsdecomphxp-ctf-2017-codegate-2018)
  - [GHC CMM 중간 언어(N1CTF 2018)](#ghc-cmm-중간-언어n1ctf-2018)
- [C++ 이진 반전(빠른 참조)](#c-이진-반전빠른-참조)
  - [vtable Reconstruction](#vtable-reconstruction)
  - [RTTI(런타임 유형 정보)](#rtti런타임-유형-정보)
  - [표준 라이브러리 패턴](#표준-라이브러리-패턴)

---

## Go 바이너리 리버싱

Go 바이너리는 CLI 도구, 네트워크 서비스 및 악성 코드에 대한 Go의 인기로 인해 CTF 과제에서 점점 더 보편화되고 있습니다.

### Recognition

```bash
# Detect Go binary
file binary | grep -i "go"
strings binary | grep "go.buildid"
strings binary | grep "runtime.gopanic"

# Go version embedded in binary
strings binary | grep "^go1\."
```

**Key indicators:**
- 매우 큰 정적 바이너리("hello world"도 ~2MB)
- 삽입된 `go.buildid` 문자열
- `runtime.*` 기호(제거된 바이너리에서도 일부는 남아 있음)
- `main.main`를 진입점으로 사용(`main` 아님)
- `GOROOT`, `GOPATH`, `/usr/local/go/src/` 같은 문자열

### Symbol Recovery

Go는 스트립된 바이너리에도 풍부한 유형 및 기능 정보를 포함합니다.

```bash
# GoReSym - recovers function names, types, interfaces from Go binaries
# https://github.com/mandiant/GoReSym
./GoReSym -d binary > symbols.json

# Parse output
python3 -c "
import json
with open('symbols.json') as f:
    data = json.load(f)
for fn in data.get('UserFunctions', []):
    print(f\"{fn['Start']:#x}  {fn['FullName']}\")
"
```

**Ghidra golang-loader 사용:**
```bash
# Install: Ghidra → Window → Script Manager → search "golang"
# Or import GoReSym JSON with its maintained Ghidra integration:
# https://github.com/mandiant/GoReSym/tree/master/GhidraPython
```

**수정(이진 분석 이동):**
```bash
# https://github.com/goretk/redress
redress source binary              # Reconstruct source tree
redress packages binary            # List packages
redress types all binary           # List all types
redress types interface binary     # List interfaces
```

### Go 메모리 레이아웃

디컴파일 시 Go의 데이터 구조 이해하기:

```c
// String: {pointer, length} (16 bytes on 64-bit)
// NOT null-terminated! Length field is critical.
struct GoString {
    char *ptr;    // pointer to UTF-8 data
    int64 len;    // byte length
};

// Slice: {pointer, length, capacity} (24 bytes on 64-bit)
struct GoSlice {
    void *ptr;    // pointer to backing array
    int64 len;    // current length
    int64 cap;    // allocated capacity
};

// Interface: {type_descriptor, data_pointer} (16 bytes)
struct GoInterface {
    void *type;   // points to type metadata (itab for non-empty interface)
    void *data;   // points to actual value
};

// Map: pointer to runtime.hmap struct
// Channel: pointer to runtime.hchan struct
```

**Ghidra/IDA:** `(ptr, int64)`을 사용하는 함수를 보면 — Go 문자열일 가능성이 높습니다. 3필드 `(ptr, int64, int64)`는 슬라이스입니다.

### 고루틴 및 동시성 분석

```text
# Identify goroutine spawns in disassembly
strings binary | grep "runtime.newproc"
# newproc1 is the internal goroutine creation function

# In GDB with Go support:
gdb ./binary
(gdb) source /usr/local/go/src/runtime/runtime-gdb.py
(gdb) info goroutines          # List all goroutines
(gdb) goroutine 1 bt          # Backtrace for goroutine 1
```

**분해 시 채널 작업:**
- `runtime.chansend1` → `ch <- value`
- `runtime.chanrecv1` → `value = <-ch`
- `runtime.selectgo` → `select { case ... }`
- `runtime.closechan` → `close(ch)`

### 디컴파일의 일반적인 Go 패턴

**Defer mechanism:**
- `runtime.deferproc` → 지연된 함수 등록
- `runtime.deferreturn` → 함수 종료 시 지연된 함수 실행
- 지연된 호출은 LIFO 순서로 실행됩니다 - cleanup/crypto 키 삭제와 관련됨

**오류 처리(`if err != nil` 패턴):**
```text
# In disassembly, this appears as:
# call some_function        → may return multiple values in registers/stack
# The exact register(s) holding an `error` interface depend on result types,
# architecture, and Go's ABI generation; recover the signature before testing.
```

**String concatenation:**
- `runtime.concatstrings` → `s1 + s2 + s3`
- `fmt.Sprintf` → 형식화된 문자열 작성
- `.rodata`에서 형식 문자열을 찾습니다: `"%s%d"`, `"%x"`

**CTF의 일반적인 stdlib 패턴:**
```go
// Crypto operations → look for these in strings/imports:
// "crypto/aes", "crypto/cipher", "crypto/sha256", "encoding/hex", "encoding/base64"

// Network operations:
// "net/http", "net.Dial", "bufio.NewReader"

// File operations:
// "os.Open", "io.ReadAll", "os.ReadFile"
```

### Go Binary 역전 작업 흐름

```text
1. file binary                          # Confirm Go, get arch
2. GoReSym -d binary > syms.json       # Recover symbols
3. strings binary | grep -i flag        # Quick win check
4. Load in Ghidra with golang-loader    # Apply recovered symbols
5. Find main.main                       # Entry point
6. Identify string comparisons          # GoString {ptr, len} pairs
7. Trace crypto operations              # crypto/* package usage
8. Check for embedded resources         # embed.FS in Go 1.16+
```

**Go embed.FS(Go 1.16+):** 바이너리는 컴파일 타임에 파일을 포함할 수 있습니다.
```bash
# Look for embedded file data
strings binary | grep "embed"
# Embedded files appear as raw data in the binary
# Search for known file signatures (PK for zip, PNG header, etc.)
```

**주요 통찰력:** Go의 런타임은 제거된 바이너리에도 광범위한 메타데이터를 포함합니다. 수동 분석 전에 GoReSym을 사용하면 대상 버전과 손상 정도에 따라 많은 함수 이름을 복구할 수 있습니다. Go 문자열은 null로 끝나지 않은 `{ptr, len}` 튜플입니다. Ghidra의 기본 문자열 분석에서는 golang-loader 플러그인이 없으면 해당 문자열이 누락될 수 있습니다.

**탐지:** 대규모 정적 바이너리(간단한 프로그램의 경우 2MB 이상), `go.buildid`, `runtime.gopanic`, `/home/user/go/src/`와 같은 소스 경로.

### C2 클라이언트 열거를 위한 Go 바이너리 UUID 패치(BSidesSF 2026)

**패턴(2번 참조):** Go로 컴파일된 C2 클라이언트에는 `-ldflags -X`을 통해 내장된 UUID가 있습니다. C2 서버는 인증을 위해 mTLS를 사용합니다. 다른 클라이언트와 해당 파일을 열거하려면 UUID를 패치하여 새 클라이언트로 등록한 다음 C2 API를 사용하여 모든 클라이언트를 나열하고 추출된 파일을 다운로드합니다.

**Approach:**
이 사례 절차는 소유하거나 명시적으로 허가받은 CTF 인프라의 격리된 환경에서만 수행합니다.

1. Go 빌드 메타데이터에서 포함된 UUID 추출: `go version -m client_binary`
2. UUID 바이너리 패치(간단한 바이트 교체 — Go 문자열에는 고정 길이 지원 배열이 있음)
3. 패치된 바이너리를 사용하여 C2 서버에 등록합니다(mTLS 인증서가 내장되어 있거나 distfile에 있음).
4. API: `GET /api/clients`를 통해 클라이언트 열거 또는 알려진 엔드포인트 반복
5. 각 클라이언트의 GCS 버킷 또는 파일 저장소에서 파일 나열 및 다운로드
6. Grep이 플래그용 파일을 다운로드했습니다.

```bash
# Extract Go build info
go version -m ./client_binary | grep ldflags
# Output shows: -X main.clientUUID=<uuid>

# Patch UUID in binary (replace old UUID bytes with new UUID)
python3 -c "
import sys
data = open('client_binary', 'rb').read()
old_uuid = b'original-uuid-value-here'
new_uuid = b'attacker-uuid-value-here'
assert len(old_uuid) == len(new_uuid), "replacement must preserve length"
assert data.count(old_uuid) == 1, "expected exactly one verified UUID occurrence"
patched = data.replace(old_uuid, new_uuid, 1)
open('client_patched', 'wb').write(patched)
"
chmod +x client_patched
./client_patched --register
```

**주요 통찰력:** Go 바이너리는 `-ldflags -X`의 문자열 값을 바이너리 데이터 섹션에 직접 삽입할 수 있습니다. Go 문자열은 지원 바이트 배열을 가리키는 `{ptr, len}` 쌍이므로, 이 사례에서는 정확히 한 번 나타나는 UUID를 같은 길이로 바꿨습니다. mTLS 인증서가 UUID에 바인딩되지 않았다는 관찰은 이 사례의 서버 구현에 한정되며 일반 규칙이 아닙니다.

**참조:** BSidesSF 2026 "see-two"

---

## Rust 바이너리 반전

Rust 바이너리는 현대 CTF, 특히 암호화, 시스템 및 보안 도구 문제에 일반적입니다.

### Rust Recognition

```bash
# Detect Rust binary
strings binary | grep -c "rust"
strings binary | grep "rustc"             # Compiler version
strings binary | grep "/rustc/"           # Source paths
strings binary | grep "core::panicking"   # Panic infrastructure
```

**Key indicators:**
- `core::panicking::panic` 문자열
- Rust legacy mangling의 `_ZN...` 또는 v0 mangling의 `_R...` 기호(legacy 형식은 Itanium풍으로 보이지만 별도 Rust 형식)
- ELF의 `.rustc` 섹션
- `/rustc/<commit_hash>/library/`에 대한 언급
- 큰 바이너리 크기(Rust는 기본적으로 정적으로 링크됨)

### Symbol Demangling

```bash
# Rust uses its own legacy (`_ZN...`) and v0 (`_R...`) mangling schemes;
# these are not the C++ Itanium ABI even when legacy names look similar.
# rustfilt demangles Rust-specific symbols
cargo install rustfilt
nm binary | rustfilt | grep "main"

# c++filt may decode some legacy-looking names, but rustfilt also supports Rust v0
nm binary | c++filt | grep "main"

# In Ghidra: Window → Script Manager → search "Demangler"
# Enable "DemangleAllScript" for automatic demangling
```

### 디컴파일 시 일반적인 Rust 패턴

**Option/Result 열거형:**
```text
# Do not assume a fixed layout: Rust's default representation may use an
# explicit discriminant or a niche value (for example, null for Option<&T>).
# Confirm the concrete type and compiler output before assigning variants.

# In disassembly:
# cmp byte [rbp-0x10], 0    → check if None/Err
# je handle_none_case
```

**Vec<T> (Go 슬라이스와 동일):**
```c
// Common compiler output, not a stable Rust ABI; verify field offsets.
struct RustVec {
    void *ptr;      // heap pointer
    uint64 cap;     // capacity
    uint64 len;     // length
};
```

**문자열 / &str:**
```text
# String (owned): often three machine words, but field order is not a stable ABI
# &str (borrowed): {ptr, length} — 16 bytes, can point anywhere

# In decompilation, look for:
# alloc::string::String::from    → String creation
# core::str::from_utf8           → byte slice to str
```

**Iterator chains:**
```text
# .iter().map().filter().collect() compiles to loop fusion
# In disassembly: tight loop with inlined closures
# Look for: core::iter::adapters::map, filter, etc.
```

**Panic unwinding:**
```bash
# Panic strings reveal source locations and error messages
strings binary | grep "panicked at"
strings binary | grep "called .unwrap().. on"
# These often contain file paths, line numbers, and variable names
```

### Rust 관련 분석 도구

```bash
# cargo-bloat: analyze binary size by function
cargo install cargo-bloat
cargo bloat --release -n 50

# Ghidra's current analyzer plus rustfilt for symbol demangling:
# https://github.com/luser/rustfilt
```

**주요 통찰력:** Rust 패닉 메시지는 금광입니다. 여기에는 릴리스 빌드에서도 소스 파일 경로, 줄 번호 및 설명 오류 문자열이 포함됩니다. 항상 `strings binary | grep "panicked"` 먼저. Rust의 단일화는 일반 함수가 유형별로 중복된다는 것을 의미합니다. 유사해 보이는 함수가 많이 있을 것으로 예상됩니다.

**탐지:** `core::panicking`, `.rustc` 섹션, `/rustc/` 경로, `_ZN` Rust 스타일 모듈 경로가 포함된 잘못된 기호.

---

## Swift 바이너리 리버싱

디맹글링, 런타임 구조 및 Ghidra 통합을 포함한 전체 Swift 반전 가이드는 [platforms.md](platforms.md#swift-바이너리-리버싱)를 참조하세요. 주요 빠른 참조:

```bash
# Detect Swift binary
strings binary | grep "swift"
otool -l binary | grep "swift"

# Demangle Swift symbols
swift demangle '$s14MyApp0A8ClassC10checkInput6resultSbSS_tF'
# → MyApp.MyAppClass.checkInput(result: String) -> Bool

# Key runtime functions: swift_allocObject, swift_release, swift_once
# String representation is an implementation detail; infer it from the target
# Protocol witness tables = dynamic dispatch (like vtables)
```

**탐지:** Mach-O의 `__swift5_*` 섹션, `swift_` 런타임 기호, `$s` 접두사의 mangled symbol.

---

## Kotlin/JVM 바이너리 반전

Kotlin은 JVM 바이트코드 또는 네이티브(Kotlin/Native를 통해)로 컴파일됩니다. Android 및 서버측 CTF에서 일반적입니다.

### JVM 바이트코드(Android/Server)

```bash
# Detect Kotlin
strings classes.dex | grep "kotlin"
# Look for: kotlin.Metadata annotation, kotlin/jvm/internal/*

# Decompile
jadx classes.dex                     # Best for Kotlin bytecode
cfr classes.jar --outputdir output   # Java-like output; reconstruct Kotlin idioms manually
fernflower classes.jar output/       # IntelliJ's decompiler

# Kotlin-specific patterns in decompiled output:
# - Companion objects: ClassName$Companion
# - Data classes: copy(), component1(), component2(), toString()
# - Coroutines: ContinuationImpl, invokeSuspend, state machine
# - Null checks: Intrinsics.checkNotNull() everywhere
# - When expression: compiled as tableswitch/lookupswitch
# - Sealed classes: instanceof checks in chain
```

**디스어셈블리 중인 Kotlin 코루틴:**
```text
# Coroutines compile to state machines:
# invokeSuspend(result) {
#     switch (this.label) {
#         case 0: this.label = 1; return suspendFunction();
#         case 1: processResult(result); return Unit;
#     }
# }
# Each suspend point becomes a state in the switch.
# Follow the state machine to understand async flow.
```

### Kotlin/Native

```bash
# Kotlin/Native produces platform binaries (no JVM)
# Recognize by: konan, kotlin.native strings
strings binary | grep "konan"

# Much harder to reverse — no reflection metadata
# Uses LLVM backend, looks similar to C/C++ in disassembly
# Key functions: InitRuntime, DeinitRuntime, CreateStablePointer
# Modern Kotlin/Native uses a tracing garbage collector; older binaries may
# reflect the legacy memory manager, so identify the compiler generation.
```

**탐지:** `kotlin.Metadata` 주석(JVM), `konan` 문자열(네이티브), `kotlin/` 패키지 경로.

---

## D 언어 바이너리 역전(CSAW CTF 2016)

D 언어 바이너리에는 C++와 다른 고유한 기호 맹글링이 있습니다. 컴파일 타임에 템플릿 인스턴스화는 많은 함수 변형을 생성합니다.

```python
# Recognition: D binaries use different mangling than C++
# Symbols contain "_D" prefix and numeric length-prefixed names
# Example: _D4mainQaFNaNbNfZv

# Symbol demangling:
# GDB: set language d
# Radare2: export names show demangled D symbols
# Online: dlang.org/phobos/core_demangle.html

# Common D binary patterns:
# - Templates instantiated at compile-time: enc!("111"), enc!("222"), ...
# - Garbage collector references (GC.malloc, GC.free)
# - Phobos standard library functions (_D3std...)
# - String processing: std.string, std.conv.to

# Reversing a D cipher (XOR with cycling key):
def reverse_d_cipher(encrypted, num_functions=500):
    """D binaries may chain multiple transformation functions.
    Each function XORs with key character, then XORs with key length.
    Process in reverse order."""
    result = bytearray(encrypted)
    for i in range(num_functions - 1, -1, -1):
        key = str(i) * 3  # e.g., "499499499" for function enc!("499")
        key_len = len(key)
        for j in range(len(result)):
            result[j] ^= key_len
            result[j] ^= ord(key[j % key_len])
    return bytes(result)
```

**주요 통찰력:** D 바이너리는 CTF에서 드물지만 `_D` 기호 접두사 및 Phobos 라이브러리 참조로 식별할 수 있습니다. 컴파일 타임 템플릿 시스템은 D 함수가 다양한 매개변수를 사용하여 수백 번 복제될 수 있음을 의미합니다. N이 달라지는 경우 `enc!("N")`와 같은 패턴을 찾으세요.

---

## Haskell 바이너리 리버싱

### STG 클로저 및 hsdecomp(hxp CTF 2017, Codegate 2018)

GHC로 컴파일된 Haskell 바이너리는 STG(Spineless Tagless G-machine) 실행 모델을 사용하므로 게으른 평가, 클로저 및 썽크로 인해 되돌리기가 매우 어렵습니다. STG 머신은 모든 것을 직접 함수 호출이 아닌 클로저 호출로 전환합니다.

**Recognition:**
- 공유 라이브러리: `libHSbase-*`, `libHSrts-*`
- 항목 기호: `hs_main` (표준 `main` 대체)
- 잘못된 기호는 Z 인코딩을 사용합니다. `z` = 접두사, `Z` = 대문자, `zd` = `.`, `zi` = `$`
- GHC 호출 규칙 레지스터 매핑: `rbx` = R1, `r14` = R2

**Closure structure:**
클로저는 첫 번째 qword가 정보를 가리키는 구조체입니다. table/code. 정보 테이블은 코드 포인터 앞에 있으며 메타데이터(클로저 유형, 레이아웃 정보, SRT)를 포함합니다.

```bash
# Identify dependencies without executing an untrusted artifact
readelf -d ./binary | grep -E 'NEEDED.*libHS'
readelf -s ./binary | grep hs_main

# Decompile with hsdecomp (github.com/gereeter/hsdecomp)
# Historical Python 2 tool: use only in an isolated legacy environment and
# expect compatibility gaps with newer GHC output.
python2 hsdecomp ./binary

# Compile reference for monkey-patching
ghc -O0 reference.hs -o reference
objcopy --dump-section .text=main_code reference
```

**원숭이 패치 기술:**
디컴파일이 실패하거나 클로저가 불투명한 경우 동일한 GHC 버전으로 최소 Haskell 프로그램을 컴파일하고 컴파일된 `Main_main_info` 클로저 코드를 추출한 후 챌린지 바이너리에 패치하세요. 이는 숨겨진 클로저를 강제로 평가하고 기본 진입점을 알려진 평가자로 대체하여 결과를 인쇄합니다.

```haskell
-- reference.hs: minimal program that evaluates and prints the target closure
module Main where
main :: IO ()
main = print targetClosure  -- replace with the closure you want to evaluate
```

**주요 통찰력:** Haskell 바이너리는 게으른 평가, 클로저 및 썽크로 인해 되돌리기가 매우 어렵습니다. STG 머신은 모든 것을 직접 함수 호출이 아닌 클로저 호출로 전환합니다. `hsdecomp` 클로저 구조와 패턴 일치를 복구합니다. 디컴파일이 실패하면 참조 바이너리에서 알려진 `Main_main_info`를 원숭이 패치하여 숨겨진 클로저를 강제로 평가하고 결과를 인쇄합니다.

**탐지:** `libHSbase-*` 공유 라이브러리, `hs_main` 항목, Z로 인코딩된 기호(예: `MainZCmain`), GHC 버전 문자열.

**참고 자료:** hxp CTF 2017, Codegate 2018

---

### GHC CMM 중간 언어(N1CTF 2018)

GHC로 컴파일된 하스켈 바이너리는 STG 실행 모델로 인해 일반 C형 디컴파일 결과를 읽기 어렵습니다. `.cmm`(C-- 중간) 파일이 사용 가능하거나 복구 가능한 경우 해당 파일을 읽고 썽크, 클로저 및 지연 평가 의미를 이해하세요. 기하급수적으로 증가하는 재귀 구조의 경우 메모이제이션을 통해 세그먼트 크기를 계산하고 전체 문자열을 구체화하는 대신 대상 인덱스가 속한 세그먼트를 재귀적으로 따라갑니다.

**패턴:** 바이너리는 `f(n) = s1 + f(n-1) + s2 + f(n-1) + s3`인 재귀적 문자열 구조를 구축합니다. 직접 평가는 시간·공간 모두 `O(2^n)`입니다. 대신 메모이제이션을 사용하여 각 재귀 수준의 크기를 계산한 다음 세그먼트 경계를 따라 대상 문자 인덱스를 내려갑니다.

```python
# Haskell recursive string: f(n) = s1 + f(n-1) + s2 + f(n-1) + s3
# Direct evaluation is O(2^n) -- use size memoization:
from functools import lru_cache

@lru_cache(maxsize=None)
def fsize(n):
    if n == 0: return len(s0)
    return len(s1) + fsize(n-1) + len(s2) + fsize(n-1) + len(s3)

def char_at(n, offset):
    if n == 0: return s0[offset]
    if offset < len(s1): return s1[offset]
    offset -= len(s1)
    if offset < fsize(n-1): return char_at(n-1, offset)
    offset -= fsize(n-1)
    if offset < len(s2): return s2[offset]
    offset -= len(s2)
    if offset < fsize(n-1): return char_at(n-1, offset)
    offset -= fsize(n-1)
    return s3[offset]
```

**주요 통찰력:** GHC의 CMM(C 마이너스 마이너스) 중간 표현은 알고리즘을 식별하기에 충분한 구조를 유지합니다. 각 수준에서 크기가 두 배로 늘어나는 재귀적 문자열 구성의 경우 기하급수적으로 증가하는 문자열을 구체화하는 대신 메모이제이션으로 세그먼트 크기를 계산하고 대상 인덱스가 속한 구간을 따라 내려갑니다.

**탐지:** 챌린지 배포에 `.cmm` 파일이 포함된 Haskell 바이너리(위의 인식 참조). 기하급수적으로 증가하는 문자열과 같은 데이터를 생성하는 재귀적 폐쇄 애플리케이션을 찾으십시오.

**References:** N1CTF 2018

---

## C++ 이진 반전(빠른 참조)

C++ RE는 일반 도구에서 잘 다루어지지만 다음 패턴은 CTF에만 적용됩니다.

### vtable Reconstruction

```text
# Virtual function tables are ABI-specific.
# Itanium ABI: the object's vptr points at an address point; offset-to-top and
# RTTI pointer are at negative indices, and non-negative entries are virtual calls.
# MSVC uses a different complete-object-locator/vftable arrangement.

# Identify polymorphic dispatch:
# mov rax, [rdi]           # Load vtable from this pointer
# call [rax + 0x18]        # Call slot 3 relative to this address point
```

### RTTI(런타임 유형 정보)

```bash
# If not stripped, RTTI reveals class hierarchy
strings binary | grep -E "^[0-9]+[A-Z]"   # Mangled type names
c++filt _ZTI7MyClass                        # → typeinfo for MyClass

# In Ghidra: search for vtable references, follow typeinfo pointer
# typeinfo struct: {vtable_for_typeinfo, name_string, base_class_ptr}
```

### 표준 라이브러리 패턴

```text
std::string (one common libstdc++ layout):
  SSO (Small String Optimization): short strings may use an inline buffer
  Confirm the standard-library version and field offsets in the target.

std::vector<T> (common implementation, not a stable ABI):
  {T* begin, T* end, T* capacity_end}

std::map<K,V>:
  Red-black tree: each node has {left, right, parent, color, key, value}

std::unordered_map<K,V>:
  Hash table: {bucket_array, size, load_factor_max, ...}
```
