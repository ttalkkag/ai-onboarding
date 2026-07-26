# CTF Reverse - 동적 분석 도구

## 목차
- [Frida(동적 계측)](#frida동적-계측)
  - [Installation](#installation)
  - [기본 기능 후킹](#기본-기능-후킹)
  - [Anti-Debug Bypass](#anti-debug-bypass)
  - [메모리 스캐닝 및 패치](#메모리-스캐닝-및-패치)
  - [Function Replacement](#function-replacement)
  - [추적 및 스토커](#추적-및-스토커)
  - [r2frida(Radare2 + Frida 통합)](#r2fridaradare2--frida-통합)
  - [Android/iOS의 경우 Frida](#androidios의-경우-frida)
  - [Frida 재귀 함수 속도 향상을 위한 메모(hxp CTF 2017)](#frida-재귀-함수-속도-향상을-위한-메모hxp-ctf-2017)
- [angr(기호 실행)](#angr기호-실행)
  - [angr Installation](#angr-installation)
  - [기본 경로 탐색](#기본-경로-탐색)
  - [제약 조건이 있는 기호 입력](#제약-조건이-있는-기호-입력)
  - [분석을 단순화하는 후크 기능](#분석을-단순화하는-후크-기능)
  - [특정 주소에서 탐색](#특정-주소에서-탐색)
  - [일반적인 패턴과 팁](#일반적인-패턴과-팁)
  - [경로 폭발 처리](#경로-폭발-처리)
  - [angr CFG 복구](#angr-cfg-복구)
- [lldb(LLVM 디버거)](#lldbllvm-디버거)
  - [Basic Commands](#basic-commands)
  - [Scripting (Python)](#scripting-python)
- [x64dbg(Windows 디버거)](#x64dbgwindows-디버거)
  - [Key Features](#key-features)
  - [Scripting](#scripting)
  - [일반적인 CTF 작업 흐름](#일반적인-ctf-작업-흐름)
- [Qiling 프레임워크(교차 플랫폼 에뮬레이션)](#qiling-프레임워크교차-플랫폼-에뮬레이션)
  - [Qiling Installation](#qiling-installation)
  - [Basic Usage](#basic-usage)
  - [에뮬레이션을 통한 디버그 방지 우회](#에뮬레이션을-통한-디버그-방지-우회)
  - [Qiling을 사용한 입력 퍼징](#qiling을-사용한-입력-퍼징)
- [Triton(동적 기호 실행)](#triton동적-기호-실행)
- [Intel 핀 명령 계산 부채널(Hackover CTF 2015)](#intel-핀-명령-계산-부채널hackover-ctf-2015)
  - [유전 알고리즘을 사용한 인텔 핀 명령어 계산(hxp CTF 2017)](#유전-알고리즘을-사용한-인텔-핀-명령어-계산hxp-ctf-2017)
- [Opcode 전용 추적 재구성(0CTF 2016)](#opcode-전용-추적-재구성0ctf-2016)
- [결정론적 분석을 위한 LD_PRELOAD time() 동결(EKOPARTY 2017)](#결정론적-분석을-위한-ld_preload-time-동결ekoparty-2017)
- [바이트별 Bruteforce를 위한 LD_PRELOAD memcmp 사이드 채널(Blaze CTF 2018)](#바이트별-bruteforce를-위한-ld_preload-memcmp-사이드-채널blaze-ctf-2018)

---

## Frida(동적 계측)

Frida 실시간 후크, 추적 및 수정을 위해 실행 중인 프로세스에 JavaScript를 삽입합니다. 안티 디버그 우회, 런타임 검사 및 모바일 RE에 필수적입니다.

### Installation

```bash
pip install frida-tools frida
# Verify
frida --version
```

### 기본 기능 후킹

```javascript
// hook.js — intercept a function and log arguments/return value
Interceptor.attach(Module.getGlobalExportByName("strcmp"), {
    onEnter: function(args) {
        this.arg0 = args[0].readUtf8String();
        this.arg1 = args[1].readUtf8String();
        console.log(`strcmp("${this.arg0}", "${this.arg1}")`);
    },
    onLeave: function(retval) {
        console.log(`  → ${retval}`);
    }
});
```

```bash
# Attach to running process
frida -p $(pidof binary) -l hook.js

# Spawn and instrument from start
frida -f ./binary -l hook.js

# One-liner: hook strcmp and dump comparisons
frida -f ./binary -e '
Interceptor.attach(Module.getGlobalExportByName("strcmp"), {
    onEnter(args) {
        console.log("strcmp:", args[0].readUtf8String(), args[1].readUtf8String());
    }
});
'
```

### Anti-Debug Bypass

```javascript
// Bypass ptrace(PTRACE_TRACEME) — returns 0 (success) without calling
Interceptor.attach(Module.getGlobalExportByName("ptrace"), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.request === 0) { // PTRACE_TRACEME
            retval.replace(ptr(0));
            console.log("[*] ptrace(TRACEME) bypassed");
        }
    }
});

// Bypass IsDebuggerPresent (Windows)
var isDbg = Process.getModuleByName("kernel32.dll").getExportByName("IsDebuggerPresent");
Interceptor.attach(isDbg, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

// Bypass timing checks — hook clock_gettime to return constant
Interceptor.attach(Module.getGlobalExportByName("clock_gettime"), {
    onEnter: function(args) {
        this.ts = args[1];
    },
    onLeave: function(retval) {
        if (retval.toInt32() === 0) {
            // 64-bit Unix timespec; adjust field widths for a 32-bit target.
            this.ts.writeU64(0);        // tv_sec
            this.ts.add(8).writeU64(0); // tv_nsec
        }
    }
});
```

### 메모리 스캐닝 및 패치

```javascript
// Scan for flag pattern in memory
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, "66 6c 61 67 7b", { // "flag{"
        onMatch: function(address, size) {
            console.log("[FLAG] Found at:", address, address.readUtf8String(64));
        },
        onComplete: function() {}
    });
});

// Patch instruction (NOP out a check)
var addr = Process.getModuleByName("binary").base.add(0x1234);
Memory.patchCode(addr, 2, function(code) {
    var writer = new X86Writer(code, { pc: addr });
    writer.putNop();
    writer.putNop();
    writer.flush();
});
```

### Function Replacement

```javascript
// Replace a validation function to always return true
var checkFlag = Module.getGlobalExportByName("check_flag");
Interceptor.replace(checkFlag, new NativeCallback(function(input) {
    console.log("[*] check_flag called with:", input.readUtf8String());
    return 1; // always valid
}, 'int', ['pointer']));
```

### 추적 및 스토커

```javascript
// Trace all calls in a function (Stalker — instruction-level tracing)
var targetAddr = Module.getGlobalExportByName("main");
Interceptor.attach(targetAddr, {
    onEnter: function() {
        this.threadId = Process.getCurrentThreadId();
        Stalker.follow(this.threadId, {
            transform: function(iterator) {
                var instruction;
                while ((instruction = iterator.next()) !== null) {
                    if (instruction.mnemonic === "call") {
                        const callSite = instruction.address;
                        iterator.putCallout(function() {
                            console.log("CALL at", callSite);
                        });
                    }
                    iterator.keep();
                }
            }
        });
    },
    onLeave: function() {
        Stalker.unfollow(this.threadId);
        Stalker.garbageCollect();
    }
});
```

### r2frida(Radare2 + Frida 통합)

```bash
# Attach radare2 to process via Frida
r2 frida://spawn/./binary

# r2frida commands
\ii                    # List imports
\il                    # List loaded modules
\dt strcmp             # Trace strcmp calls
\dc                    # Continue execution
\dm                    # List memory maps
```

### Android/iOS의 경우 Frida

```bash
# Android (requires rooted device or Frida server)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# Hook Android Java methods
frida -U -f com.example.app -l hook_android.js
```

```javascript
// hook_android.js — hook Java method
Java.perform(function() {
    var MainActivity = Java.use("com.example.app.MainActivity");
    MainActivity.checkPassword.implementation = function(input) {
        console.log("[*] checkPassword called with:", input);
        var result = this.checkPassword(input);
        console.log("[*] Result:", result);
        return result;
    };
});
```

**주요 통찰력:** Frida 난독화된 코드, 압축된 바이너리, 런타임 생성 데이터 등 정적 분석이 실패하는 경우에 탁월합니다. 후크 비교 함수(`strcmp`, `memcmp`, 사용자 정의 유효성 검사기)를 사용하여 알고리즘을 뒤집지 않고 예상 값을 추출합니다. 관찰하려면 `Interceptor.attach`를 사용하고, 수정하려면 `Interceptor.replace`를 사용하세요.

**사용 시기:** 안티 디버깅 우회, 런타임 계산 키 추출, 일반 텍스트 덤프를 위한 암호화 기능 연결, 모바일 앱 분석, 압축된 바이너리 검사.

### Frida 재귀 함수 속도 향상을 위한 메모(hxp CTF 2017)

Frida로 재귀 함수를 연결하고, 결과를 메모하고, 캐시된 값을 재생하여 중복 계산을 건너뜁니다. 기하급수적으로 복잡해지는 피보나치와 같은 반복적 문제는 메모를 통해 즉각적으로 구현됩니다.

```javascript
// memo_hook.js — memoize a recursive function to skip redundant calls
var memo = {};
var funcAddr = ptr("0x400abc");    // Address of the recursive function
var retAddr = ptr("0x400def");     // Address of the function's ret instruction

Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        this.key = args[0].toInt32();
        if (memo[this.key] !== undefined) {
            // Skip computation entirely: set return value and jump to ret
            this.context.rax = memo[this.key];
            this.context.rip = retAddr;
        }
    },
    onLeave: function(retval) {
        // Cache the result for future calls with the same argument
        memo[this.key] = retval.toInt32();
    }
});
```

```bash
# Usage
frida -f ./binary -l memo_hook.js
```

다중 인수 함수의 경우 복합 키를 빌드합니다.
```javascript
Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        this.key = args[0].toInt32() + "," + args[1].toInt32();
        if (memo[this.key] !== undefined) {
            this.context.rax = memo[this.key];
            this.context.rip = retAddr;
        }
    },
    onLeave: function(retval) {
        memo[this.key] = retval.toInt32();
    }
});
```

**주요 통찰력:** Frida의 `Interceptor`는 레지스터 상태를 읽고 수정할 수 있으므로 `rax`(반환 값) 및 `rip`(`ret` 명령어로)를 설정하여 함수 실행을 완전히 건너뛸 수 있습니다. 이는 동일한 인수가 동일한 결과를 생성하는 모든 재귀 함수에서 작동합니다. 지수 시간 재귀 계산(Fibonacci, Ackermann, 트리 순회)은 메모화에 따라 선형이 됩니다.

이 예제는 x86-64의 정수 반환 ABI와 검증한 `ret` 주소를 전제로 합니다. 함수가 순수하고 동일한 전체 인수·전역 상태에서 같은 결과를 내며, 숨겨진 부작용·포인터 출력·예외·thread-local 상태가 없을 때만 적용하세요. 다른 ABI·반환형·재귀 형태에서는 stack/register 상태를 별도로 모델링해야 합니다.

**참고자료:** hxp CTF 2017

---

## angr(기호 실행)

angr은 자동으로 프로그램 경로를 탐색하여 제약 조건을 충족하는 입력을 찾습니다. 수동으로 몇 시간이 걸리는 많은 플래그 확인 바이너리를 몇 분 만에 해결합니다.

### angr Installation

```bash
pip install angr
```

### 기본 경로 탐색

```python
import angr
import claripy

# Load binary
proj = angr.Project('./binary', auto_load_libs=False)

# Find address of "Correct!" print, avoid "Wrong!" print
# Get these from disassembly (objdump -d or Ghidra)
FIND_ADDR = 0x401234    # Address of success path
AVOID_ADDR = 0x401256   # Address of failure path

# Create simulation manager and explore
simgr = proj.factory.simgr()
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    found = simgr.found[0]
    # Get stdin that reaches the target
    print("Flag:", found.posix.dumps(0))  # fd 0 = stdin
```

### 제약 조건이 있는 기호 입력

```python
import angr
import claripy

proj = angr.Project('./binary', auto_load_libs=False)

# Create symbolic input (e.g., 32-byte flag)
flag_len = 32
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# Constrain to printable ASCII
state = proj.factory.entry_state(stdin=flag)
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# Constrain known prefix: "flag{"
state.solver.add(flag_chars[0] == ord('f'))
state.solver.add(flag_chars[1] == ord('l'))
state.solver.add(flag_chars[2] == ord('a'))
state.solver.add(flag_chars[3] == ord('g'))
state.solver.add(flag_chars[4] == ord('{'))
state.solver.add(flag_chars[flag_len-1] == ord('}'))

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401256)

if simgr.found:
    found = simgr.found[0]
    result = found.solver.eval(flag, cast_to=bytes)
    print("Flag:", result.decode())
```

### 분석을 단순화하는 후크 기능

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)

# Hook printf to avoid path explosion in I/O
@proj.hook(0x401100, length=5)  # Address of call to printf
def skip_printf(state):
    pass  # Do nothing, just skip

# Hook sleep/anti-debug functions
@proj.hook(0x401050, length=5)  # Address of call to sleep
def skip_sleep(state):
    pass

# Replace a function with a summary
class AlwaysSucceed(angr.SimProcedure):
    def run(self):
        return 1

proj.hook_symbol('check_license', AlwaysSucceed())
```

### 특정 주소에서 탐색

```python
# Start from middle of function (skip initialization)
state = proj.factory.blank_state(addr=0x401200)

# Set up registers/memory manually
state.regs.rdi = 0x600000  # Pointer to input buffer
state.memory.store(0x600000, b"AAAA" + b"\x00" * 28)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401300, avoid=0x401350)
```

### 일반적인 패턴과 팁

```python
# Pattern 1: argv-based input
state = proj.factory.entry_state(args=['./binary', flag_sym])

# Pattern 2: Multiple find/avoid addresses
simgr.explore(
    find=[0x401234, 0x401300],     # Any success path
    avoid=[0x401256, 0x401400]     # All failure paths
)

# Pattern 3: Find by output string (no address needed)
def is_successful(state):
    stdout = state.posix.dumps(1)  # fd 1 = stdout
    return b"Correct" in stdout

def should_avoid(state):
    stdout = state.posix.dumps(1)
    return b"Wrong" in stdout

simgr.explore(find=is_successful, avoid=should_avoid)

# Pattern 4: Timeout protection
simgr.explore(find=0x401234, avoid=0x401256, num_find=1)
# Or use exploration techniques:
simgr.use_technique(angr.exploration_techniques.DFS())  # Depth-first
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=500))
```

### 경로 폭발 처리

```python
# Use DFS instead of BFS (default) for flag checkers
simgr.use_technique(angr.exploration_techniques.DFS())

# Limit symbolic memory operations
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# Hook expensive functions (crypto, hashing) to avoid explosion
import hashlib
class SHA256Hook(angr.SimProcedure):
    def run(self, data, length, output):
        # Concretize input and compute hash
        concrete_data = self.state.solver.eval(
            self.state.memory.load(data, self.state.solver.eval(length)),
            cast_to=bytes
        )
        h = hashlib.sha256(concrete_data).digest()
        self.state.memory.store(output, h)

proj.hook_symbol('SHA256', SHA256Hook())
```

`ZERO_FILL_UNCONSTRAINED_*`는 미정 값을 0으로 고정해 경로를 잃을 수 있고, 위 SHA-256 summary는 symbolic data와 length에서 임의의 한 모델을 concretize합니다. 둘 다 성능용 근사이며 결과의 soundness를 보장하지 않습니다. concretization이 유일한지 확인하거나 원래 함수로 후보를 재실행하고, 다른 모델에서도 결과가 유지되는지 검증하세요.

### angr CFG 복구

```python
# Control flow graph for understanding structure
cfg = proj.analyses.CFGFast()
print(f"Functions found: {len(cfg.functions)}")

# Find main
for addr, func in cfg.functions.items():
    if func.name == 'main':
        print(f"main at {addr:#x}")
        break

# Cross-references
node = cfg.model.get_any_node(0x401234)
print("Predecessors:", [hex(p.addr) for p in cfg.model.get_predecessors(node)])
```

**주요 통찰력:** angr은 명확한 success/failure 경로가 있는 플래그 검사기 바이너리에서 가장 잘 작동합니다. 복잡한 바이너리의 경우 비용이 많이 드는 기능(crypto, I/O)을 검증된 summary로 연결하고 DFS 탐색을 사용하세요. 제약 조건을 추가하기 전에 가장 간단한 접근 방식(find/avoid 주소)부터 시작하세요. angr이 느린 경우 입력을 인쇄 가능한 ASCII로 제한하고 알려진 접두사를 추가하세요.

**사용 시기:** 분기 논리, maze/path-finding 바이너리, 제약이 많은 검사, 자동화된 바이너리 분석으로 유효성 검사기에 플래그를 지정합니다. 덜 효과적인 경우: 무거운 암호화, 부동 소수점 수학, 복잡한 힙 작업.

---

## lldb(LLVM 디버거)

macOS/iOS.용 기본 디버거는 Linux에서도 작동합니다. Swift/Objective-C 및 Apple 플랫폼 바이너리에 적합합니다.

### Basic Commands

```text
lldb ./binary
(lldb) run                          # Run program
(lldb) b main                       # Breakpoint on main
(lldb) b 0x401234                   # Breakpoint at address
(lldb) breakpoint set -r "check.*"  # Regex breakpoint
(lldb) c                            # Continue
(lldb) si                           # Step instruction
(lldb) ni                           # Next instruction
(lldb) register read                # Show all registers
(lldb) register write rax 0         # Modify register
(lldb) memory read 0x401000 -c 32   # Read 32 bytes
(lldb) x/s $rsi                     # Examine string (GDB-style)
(lldb) dis -n main                  # Disassemble function
(lldb) image list                   # Loaded modules + base addresses
```

### Scripting (Python)

```python
# lldb Python scripting
import lldb

def hook_strcmp(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    arg0 = frame.FindRegister("rdi").GetValueAsUnsigned()
    arg1 = frame.FindRegister("rsi").GetValueAsUnsigned()
    s0 = process.ReadCStringFromMemory(arg0, 256, lldb.SBError())
    s1 = process.ReadCStringFromMemory(arg1, 256, lldb.SBError())
    print(f'strcmp("{s0}", "{s1}")')

# Register in lldb: command script add -f script.hook_strcmp hook_strcmp
```

**주요 통찰력:** macOS 바이너리(Mach-O), iOS 앱 및 GDB를 사용할 수 없는 경우 lldb를 사용하세요. `image list`는 PIE 바이너리용 ASLR 슬라이드를 제공합니다. 스크립팅 API는 GDB보다 더 구조적입니다.

---

## x64dbg(Windows 디버거)

최신 UI를 갖춘 오픈 소스 Windows 디버거입니다. Windows RE 과제에 대한 OllyDbg/WinDbg의 대안입니다.

### Key Features

```bash
# Launch
x64dbg.exe binary.exe         # 64-bit
x32dbg.exe binary.exe         # 32-bit

# Essential shortcuts
F2      → Toggle breakpoint
F7      → Step into
F8      → Step over
F9      → Run
Ctrl+G  → Go to address
Ctrl+F  → Find pattern in memory
```

### Scripting

```bash
# x64dbg command line
bp 0x401234                    # Breakpoint
SetBPX 0x401234, 0, "log {s:utf8@[esp+4]}"  # Log string arg on hit
run                            # Continue
StepOver                       # Step over
```

### 일반적인 CTF 작업 흐름

1. GUI 크래커의 경우 `GetWindowTextA`/`MessageBoxA`에 중단점을 설정합니다.
2. success/failure 메시지에서 역추적
3. 압축된 바이너리에서 IAT 재구성을 위해 **Scylla** 플러그인 사용
4. **Snowman** 빠른 의사-C용 디컴파일러 플러그인

**주요 통찰력:** x64dbg에는 패턴 검색, 하드웨어 중단점 및 조건부 로깅이 내장되어 있습니다. Windows CTF 바이너리의 경우 동적 분석의 경우 IDA/Ghidra보다 빠른 경우가 많습니다. 자동 함수 인수 주석을 작성하려면 **xAnalyzer** 플러그인을 사용하세요.

---

## Qiling 프레임워크(교차 플랫폼 에뮬레이션)

Qiling은 OS 수준 지원(syscall, 파일 시스템, 레지스트리)으로 바이너리를 에뮬레이트합니다. Unicorn을 기반으로 구축되었지만 Unicorn에 부족한 OS 계층을 추가합니다.

### Qiling Installation

```bash
pip install qiling
# Download rootfs for target OS:
git clone https://github.com/qilingframework/rootfs
```

### Basic Usage

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Linux ELF emulation
ql = Qiling(["./binary", "arg1"], "rootfs/x8664_linux",
            verbose=QL_VERBOSE.DEFAULT)
ql.run()

# Windows PE emulation (no Windows needed!)
ql = Qiling(["rootfs/x86_windows/bin/binary.exe"], "rootfs/x86_windows")
ql.run()

# ARM/MIPS emulation (IoT firmware)
ql = Qiling(["rootfs/arm_linux/bin/binary"], "rootfs/arm_linux")
ql.run()
```

### 에뮬레이션을 통한 디버그 방지 우회

```python
from qiling import Qiling
from qiling.const import QL_INTERCEPT

ql = Qiling(["./binary"], "rootfs/x8664_linux")

# Hook ptrace syscall — return 0 (success)
def hook_ptrace(ql, ptrace_request, pid, addr, data):
    ql.log.info("ptrace bypassed")
    return 0

ql.os.set_syscall("ptrace", hook_ptrace, QL_INTERCEPT.CALL)

# Hook specific address (e.g., anti-VM check)
def skip_check(ql):
    ql.arch.regs.rax = 0  # Force success
    ql.log.info(f"Skipped check at {ql.arch.regs.rip:#x}")

ql.hook_address(skip_check, 0x401234)

ql.run()
```

### Qiling을 사용한 입력 퍼징

```python
# Emulate binary with different inputs to find flag
import string
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe

def test_input(candidate):
    ql = Qiling(["./binary"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DISABLED)
    ql.os.stdin = pipe.SimpleInStream(0)
    ql.os.stdout = pipe.SimpleOutStream(1)
    ql.os.stdin.write(candidate.encode())
    ql.run()
    return ql.os.stdout.read()

for ch in string.printable:
    output = test_input("flag{" + ch)
    if b"Correct" in output:
        print(f"Found: {ch}")
```

**GDB/Frida 이상의 장점:**
- 디버거 아티팩트는 적지만 API/syscall 및 안티 분석 검사는 대상별로 후크 필요
- 하드웨어가 없는 크로스 플랫폼(x86 호스트의 ARM, MIPS, RISC-V)
- Python으로 스크립팅 가능(GDB보다 빠른 반복)
- Snapshot/restore 무차별 공격의 경우

**주요 통찰력:** Qiling은 CPU 외에 syscall, 파일 시스템, 레지스트리 같은 OS 계층을 에뮬레이트합니다. 구현되지 않았거나 실제 커널과 다른 API/syscall이 있으며 `ptrace(TRACEME)` 같은 검사도 자동으로 올바른 결과를 낸다고 가정할 수 없습니다. 필요한 동작을 대상별로 후크하고 실제 플랫폼 또는 다른 에뮬레이터와 교차 검증하세요.

**사용 시기:** 외부 아키텍처 바이너리, IoT 펌웨어, 강력한 안티 디버그, 많은 입력에 대한 자동화된 테스트.

---

## Triton(동적 기호 실행)

전체 Triton 참조는 [tools-advanced.md](tools-advanced.md#triton동적-기호-실행)을 참조하세요. 빠른 사용법:

```python
from triton import *

ctx = TritonContext(ARCH.X86_64)

# Symbolize input buffer
input_symbols = []
for i in range(32):
    sym = ctx.symbolizeMemory(MemoryAccess(0x600000 + i, CPUSIZE.BYTE), f"flag_{i}")
    input_symbols.append(sym)

# Process instructions and collect constraints
# At comparison point, solve for flag
model = ctx.getModel(ctx.getPathPredicate())
flag = bytearray()
for sym in input_symbols:
    if sym.getId() not in model:
        raise ValueError(f"unconstrained input symbol: {sym.getName()}")
    flag.append(model[sym.getId()].getValue())
print(bytes(flag))
```

**주요 통찰력:** Triton은 angr의 경로 폭발이 문제가 되는 단일 경로 DSE(동적 기호 실행)에 탁월합니다. 구체적인 실행 추적을 제공하고, 특정 입력을 기호화하고, 비교 지점에서 제약 조건을 해결합니다. 실행 흐름이 알려진 선형 코드 경로의 경우 angr보다 빠릅니다.

**최적의 용도:** 단일 경로 기호 실행, 난독화 해제, 오염 분석. 선형 코드 경로의 경우 angr보다 빠릅니다.

---

## Intel 핀 명령 계산 부채널(Hackover CTF 2015)

**패턴:** Intel Pin의 `inscount0` 도구를 사용하여 바이너리에 대해 문자별로 무차별 입력을 수행합니다. 각각의 올바른 문자는 비교 논리에서 더 깊은 실행(더 많은 명령)을 발생시킵니다.

```python
import string
from subprocess import Popen, PIPE

pin = './pin'
tool = './source/tools/ManualExamples/obj-ia32/inscount0.so'
binary = './target'

key = ''
while True:
    best_count, best_char = 0, ''
    for c in string.printable:
        cmd = [pin, '-injection', 'child', '-t', tool, '--', binary]
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        p.communicate((key + c + '\n').encode())
        with open('inscount.out') as f:
            count = int(f.read().split()[-1])
        if count > best_count:
            best_count, best_char = count, c
    key += best_char
    print(f"Found: {key}")
```

**주요 통찰력:** Movfuscated 바이너리(`movfuscator`로 컴파일)는 모든 명령을 `mov` 작업 시퀀스로 확장하므로 정적 분석이 실용적이지 않습니다. 그러나 문자별 비교에서는 여전히 측정 가능한 명령어 수 차이가 발생합니다. 핀의 `inscount0.so`는 실행된 총 명령어 수를 계산합니다. 각 위치의 올바른 문자는 ~1000개 이상의 명령어를 발생시킵니다(비교에서 계속 진행). 순차 입력 검사를 통해 난독화된 바이너리에도 작동합니다.

---

### 유전 알고리즘을 사용한 인텔 핀 명령어 계산(hxp CTF 2017)

각 문자 검사를 통과한 후에만 다음 청크를 해독하는 자체 수정 코드의 경우 검색 공간이 너무 크고 문자가 상호 작용할 수 있기 때문에 표준 문자별 핀 계산이 실패합니다. 입력 공간을 보다 효율적으로 탐색하려면 대신 유전 알고리즘을 사용하세요.

```python
import subprocess
import random
import string

PIN_PATH = '/tmp/pin-3.5/pin'
TOOL_PATH = 'source/tools/ManualExamples/obj-intel64/inscount0.so'

def fitness(candidate):
    """Run binary under Pin and return instruction count as fitness."""
    proc = subprocess.Popen(
        [PIN_PATH, '-t', TOOL_PATH, '--', './binary'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(candidate.encode())
    # inscount0 writes count to stderr or inscount.out
    try:
        with open('inscount.out') as f:
            return int(f.read().split()[-1])
    except:
        return 0

def mutate(individual, rate=0.1):
    """Randomly mutate characters in the individual."""
    result = list(individual)
    for i in range(len(result)):
        if random.random() < rate:
            result[i] = random.choice(string.printable[:62])
    return result

# Genetic algorithm parameters
FLAG_LEN = 40
POP_SIZE = 100
SURVIVORS = 20

# Initialize random population
population = [random.choices(string.printable[:62], k=FLAG_LEN) for _ in range(POP_SIZE)]

for generation in range(10000):
    # Score each individual by instruction count
    scored = [(fitness(''.join(p)), p) for p in population]
    scored.sort(reverse=True)
    best_score, best_individual = scored[0]
    print(f"Gen {generation}: {best_score} {''.join(best_individual)}")

    # Keep top survivors, mutate to refill population
    survivors = [s[1] for s in scored[:SURVIVORS]]
    population = survivors + [mutate(random.choice(survivors)) for _ in range(POP_SIZE - SURVIVORS)]
```

**Go 바이너리용 수정된 핀(테이블 조회 플래그 확인):**
카운터 증가가 정확성과 상관 관계가 없기 때문에 표준 `inscount`이 실패하는 경우(예: 테이블 조회 비교) Pin의 icount 도구를 수정하여 성공 분기 주소에서만 실행을 계산합니다. 이 대상 카운터를 사용하여 문자별로 무차별 공격을 가할 수 있습니다.
```cpp
// Modified inscount0.cpp — count only executions of a specific address
static ADDRINT target_addr = 0x401234;  // success-branch address
static UINT64 target_count = 0;

VOID CountAtTarget(ADDRINT ip) {
    if (ip == target_addr) target_count++;
}

VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CountAtTarget,
                   IARG_INST_PTR, IARG_END);
}
```

**주요 통찰력:** 각각의 올바른 문자가 새로운 코드 섹션의 잠금을 해제하고 명령 수가 정확성에 따라 단조롭게 증가하는 대상에서만 이 fitness가 유효합니다. 유전 알고리즘의 수렴 시간과 성공 여부는 대상·seed·population·하드웨어에 따라 달라지며 보장되지 않습니다. 총 명령어 수가 상관 관계가 없는 테이블 조회 비교의 경우 검증한 특정 분기 주소를 대상으로 합니다.

**참고자료:** hxp CTF 2017

---

## Opcode 전용 추적 재구성(0CTF 2016)

opcode만 있는 실행 추적(register/memory 값 없음)이 주어지면 프로그램을 재구성합니다. sort/dedup 주소별 추적, 기본 블록으로 분할, 기능에 주석 달기. 정렬 알고리즘은 특히 취약합니다. 분기 결정으로 인해 요소 순서가 누출됩니다.

**Approach:**
1. 추적 항목을 주소별로 정렬하고 중복을 제거하여 코드 레이아웃을 복구합니다.
2. 기본 블록 경계 식별(점프, 콜, 리턴)
3. 지도 분기 taken/not-taken 추적 순서에 따른 결정
4. 정렬 알고리즘의 경우 파티션 비교를 통해 모든 입력 요소의 상대적 순서가 드러납니다.

**주요 통찰력:** 데이터 값이 없는 실행 추적은 여전히 분기 결정을 통해 정보를 유출합니다. Quicksort 파티션 비교를 통해 각 단계에서 어떤 요소가 greater/lesser인지 확인하여 분기 방향에서만 정렬된 입력을 완전히 복구할 수 있습니다.

---

## 결정론적 분석을 위한 LD_PRELOAD time() 동결(EKOPARTY 2017)

LD_PRELOAD를 통해 `time()`를 재정의하여 상수 값을 반환하고 타임스탬프 시드 PRNG를 고정합니다. 바이너리의 암호가 결정적이 되면 VM 또는 암호 내부를 이해하지 않고 각 출력 바이트를 무차별 공격합니다.

```c
// freeze_time.c — compile: gcc -shared -fPIC -o freeze.so freeze_time.c
#include <time.h>

time_t time(time_t *t) {
    if (t) *t = 1234567890;
    return 1234567890;
}
```

```bash
# Build and use:
gcc -shared -fPIC -o freeze.so freeze_time.c
LD_PRELOAD=./freeze.so ./binary

# Byte-at-a-time oracle: run with frozen time, try each candidate byte,
# observe output — correct byte produces expected output character.
for byte in $(seq 0 255); do
    output=$(echo -n "$(printf '\x%02x' $byte)" | LD_PRELOAD=./freeze.so ./binary)
    # Check output against known/expected
done
```

`srand()` 또는 `rand()`도 관련되어 있으면 `rand()`도 재정의하세요.
```c
int rand(void) { return 42; }
```

**주요 통찰력:** LD_PRELOAD 함수 차단은 비결정론적 소스(시간, 랜드)를 고정합니다. 결정적이 되면 복잡한 VM이라도 한 번에 바이트 단위로 다루기 쉬운 오라클이 됩니다.

**참고자료:** EKOPARTY CTF 2017

---

## 바이트별 Bruteforce를 위한 LD_PRELOAD memcmp 사이드 채널(Blaze CTF 2018)

**패턴:** `memcmp`의 원래 음수/0/양수 반환 의미를 보존하면서 공통 접두사 길이를 별도 로그로 기록합니다. 검증 함수가 접두사 비교를 수행하는 이 사례에서는 로그를 바이트 단위 오라클로 사용할 수 있습니다.

```c
// memcmp_hook.c - compile: gcc -shared -fPIC -o hook.so memcmp_hook.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>

int memcmp(const void *p1, const void *p2, size_t n) {
    static int (*real_memcmp)(const void *, const void *, size_t);
    if (!real_memcmp)
        real_memcmp = dlsym(RTLD_NEXT, "memcmp");

    const unsigned char *s1 = p1;
    const unsigned char *s2 = p2;
    size_t prefix = 0;
    while (prefix < n && s1[prefix] == s2[prefix])
        ++prefix;
    fprintf(stderr, "MEMCMP_PREFIX=%zu\n", prefix);
    return real_memcmp(p1, p2, n);
}
```

```bash
# Capture MEMCMP_PREFIX from stderr for each candidate. Verify that the logged
# comparison is the target validation call, not an unrelated library call.
```

**주요 통찰력:** 비교 의미를 바꾸지 않고 접두사 길이를 기록하면 해당 `memcmp` 호출이 순차 검증하는 대상에서만 오라클을 만들 수 있습니다. 모든 `memcmp` 호출이 비밀 비교인 것은 아니며 constant-time 비교·변환된 버퍼·다중 후보 비교에는 그대로 적용되지 않습니다.

**탐지:** 바이너리는 플래그 확인을 위해 `memcmp` 또는 `strcmp`를 사용합니다(`ltrace` 출력 또는 가져오기 테이블에 표시됨). 비교 함수는 사용자 입력과 computed/stored 예상 값을 사용하여 호출됩니다.

**참고자료:** 블레이즈 CTF 2018
