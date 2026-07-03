# CTF 리버스 - 도구 참조

## 목차
- [GDB](#gdb)
  - [기본 명령어](#basic-commands)
  - [PIE 바이너리 디버깅](#pie-binary-debugging)
  - [원 라이너 자동화](#one-liner-automation)
  - [기억검사](#memory-exmination)
- [Radare2](#radare2)
  - [기본 세션](#basic-session)
  - [r2pipe 자동화](#r2pipe-automation)
- [Ghidra](#ghidra)
  - [헤드리스 분석](#headless-analytic)
  - [복호화용 에뮬레이터](#emulator-for-decryption)
  - [MCP 명령](#mcp-commands)
- [유니콘 에뮬레이션](#unicorn-emulation)
  - [기본설정](#basic-setup)
  - [혼합 모드(64~32) 스위치](#mixed-mode-64-to-32-switch)
  - [추적 훅 등록](#register-tracing-hook)
  - [트랙 레지스터 변경 사항](#track-register-changes)
- [파이썬 바이트코드](#python-bytecode)
  - [Disassembly](#disassembly)
  - [상수 추출](#extract-constants)
  - [Pyarmor 정적 언팩(1샷)](#pyarmor-static-unpack-1shot)
- [WASM 분석](#wasm-analyse)
  - [C로 디컴파일](#decompile-to-c)
  - [공통 패턴](#common-patterns)
- [안드로이드 APK](#android-apk)
  - [Extraction](#extraction)
  - [주요 위치](#key-locations)
  - [Search](#search)
  - [Flutter APK (Blutter)](#flutter-apk-blutter)
  - [HarmonyOS HAP/ABC (abc-디컴파일러)](#harmonyos-hapabc-abc-decompiler)
- [.NET 분석](#net-analytic)
  - [Tools](#tools)
  - [2단계 XOR + AES-CBC 디코드 패턴(Codegate 2013)](#two-stage-xor--aes-cbc-decode-pattern-codegate-2013)
  - [NativeAOT](#nativeaot)
- [팩형 바이너리](#packed-binaries)
  - [UPX](#upx)
  - [커스텀 패커](#custom-packers)
  - [PyInstaller](#pyinstaller)
- [LLVM IR](#llvm-ir)
  - [어셈블리로 변환](#convert-to-assemblies)
- [RISC-V 이진 분석(EHAX 2026)](#risc-v-binary-analytic-ehax-2026)
- [바이너리 닌자](#binary-ninja)
- [dogbolt.org와의 디컴파일러 비교](#decompiler-comparison-with-dogboltorg)
- [유용한 명령](#useful-commands)

동적 계측 도구(Frida, angr, lldb, x64dbg)에 대해서는 [tools-dynamic.md](tools-dynamic.md)를 참조하세요.

---

## GDB

### Basic Commands
```bash
gdb ./binary
run                      # Run program
start                    # Run to main
b *0x401234              # Breakpoint at address
b *main+0x100            # Relative breakpoint
c                        # Continue
si                       # Step instruction
ni                       # Next instruction (skip calls)
x/s $rsi                 # Examine string
x/20x $rsp               # Examine stack
info registers           # Show registers
set $eax=0               # Modify register
```

### PIE 바이너리 디버깅
```bash
gdb ./binary
start                    # Forces PIE base resolution
b *main+0xca            # Relative to main
b *main+0x198
run
```

### One-liner Automation
```bash
gdb -ex 'start' -ex 'b *main+0x198' -ex 'run' ./binary
```

### Memory Examination
```bash
x/s $rsi                 # String at RSI
x/38c $rsi               # 38 characters
x/20x $rsp               # 20 hex words from stack
x/10i $rip               # 10 instructions from RIP
```

---

## Radare2

### Basic Session
```bash
r2 -d ./binary           # Open in debug mode
aaa                      # Analyze all
afl                      # List functions
pdf @ main               # Disassemble main
db 0x401234              # Set breakpoint
dc                       # Continue
ood                      # Restart debugging
dr                       # Show registers
dr eax=0                 # Modify register
```

### r2pipe Automation
```python
import r2pipe
r2 = r2pipe.open('./binary', flags=['-d'])
r2.cmd('aaa')
r2.cmd('db 0x401234')

for char in range(256):
    r2.cmd('ood')        # Restart
    r2.cmd(f'dr eax={char}')
    output = r2.cmd('dc')
    if 'correct' in output:
        print(f"Found: {chr(char)}")
```

---

## Ghidra

### Headless Analysis
```bash
analyzeHeadless /path/to/project tmp -import binary -postScript script.py
```

### 복호화용 에뮬레이터
```java
EmulatorHelper emu = new EmulatorHelper(currentProgram);
emu.writeRegister("RSP", 0x2fff0000);
emu.writeRegister("RBP", 0x2fff0000);

// Write encrypted data
emu.writeMemory(dataAddress, encryptedBytes);

// Set function arguments
emu.writeRegister("RDI", arg1);

// Run until return
emu.setBreakpoint(returnAddress);
emu.run(functionEntryAddress);

// Read result
byte[] decrypted = emu.readMemory(outputAddress, length);
```

### MCP Commands
- 정찰: `list_functions`, `list_imports`, `list_strings`
- 분석: `decompile_function`, `get_xrefs_to`
- 주석: `rename_function`, `rename_variable`

---

## Unicorn Emulation

### Basic Setup
```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map code segment
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, code_bytes)

# Map stack
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)

# Run
mu.emu_start(start_addr, end_addr)
```

### 혼합 모드(64~32) 스위치
```python
# When a 64-bit stub jumps into 32-bit code via retf/retfq:
# - retf pops 4-byte EIP + 2-byte CS (6 bytes)
# - retfq pops 8-byte RIP + 8-byte CS (16 bytes)

uc32 = Uc(UC_ARCH_X86, UC_MODE_32)
# Copy memory regions, then GPRs
reg_map = {
    UC_X86_REG_EAX: UC_X86_REG_RAX,
    UC_X86_REG_EBX: UC_X86_REG_RBX,
    UC_X86_REG_ECX: UC_X86_REG_RCX,
    UC_X86_REG_EDX: UC_X86_REG_RDX,
    UC_X86_REG_ESI: UC_X86_REG_RSI,
    UC_X86_REG_EDI: UC_X86_REG_RDI,
    UC_X86_REG_EBP: UC_X86_REG_RBP,
}
for e, r in reg_map.items():
    uc32.reg_write(e, mu.reg_read(r) & 0xffffffff)  # mu = 64-bit emulator from above
uc32.reg_write(UC_X86_REG_EFLAGS, mu.reg_read(UC_X86_REG_RFLAGS) & 0xffffffff)

# SSE-heavy blobs need XMM registers copied
for xr in [UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
           UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7]:
    uc32.reg_write(xr, mu.reg_read(xr))

# Run 32-bit, then copy regs/memory back to 64-bit
```

**팁:** 구현되지 않은 규정에 대한 경고를 무음으로 설정하려면 `UC_IGNORE_REG_BREAK=1`를 설정하세요.

### 추적 후크 등록
```python
def hook_code(uc, address, size, user_data):
    if address == TARGET_ADDR:
        rsi = uc.reg_read(UC_X86_REG_RSI)
        print(f"0x{address:x}: rsi=0x{rsi:016x}")

mu.hook_add(UC_HOOK_CODE, hook_code)
```

### 레지스터 변경 사항 추적
```python
prev_rsi = [None]
def hook_rsi_changes(uc, address, size, user_data):
    rsi = uc.reg_read(UC_X86_REG_RSI)
    if rsi != prev_rsi[0]:
        print(f"0x{address:x}: RSI changed to 0x{rsi:016x}")
        prev_rsi[0] = rsi

mu.hook_add(UC_HOOK_CODE, hook_rsi_changes)
```

---

## Python Bytecode

### Disassembly
```python
import marshal, dis

with open('file.pyc', 'rb') as f:
    f.read(16)  # Skip header (varies by Python version)
    code = marshal.load(f)
    dis.dis(code)
```

### Extract Constants
```python
for ins in dis.get_instructions(code):
    if ins.opname == 'LOAD_CONST':
        print(ins.argval)
```

### Pyarmor 정적 언팩(1샷)

Repository: `https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot`

```bash
# Basic usage (recursive processing)
python /path/to/oneshot/shot.py /path/to/scripts

# Specify pyarmor runtime library explicitly
python /path/to/oneshot/shot.py /path/to/scripts -r /path/to/pyarmor_runtime.so

# Save outputs to another directory
python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output
```

Notes:
- `oneshot/pyarmor-1shot`는 `shot.py`을 실행하기 전에 존재해야 합니다.
- 지원되는 포커스: Pyarmor 8.x-9.x(`PY` + 6자리 헤더 스타일).
- Pyarmor 7 이하(`PYARMOR` 헤더)는 범위를 벗어납니다.
- 분해 결과는 일반적으로 신뢰할 수 있습니다. 디컴파일된 소스는 실험적입니다.

---

## WASM Analysis

### C로 디컴파일
```bash
wasm2c checker.wasm -o checker.c
gcc -O3 checker.c wasm-rt-impl.c -o checker
```

### Common Patterns
- `w2c_memory` - 선형 메모리 배열
- `wasm_rt_trap(N)` - 런타임 오류
- 함수 내보내기: `flagChecker`, `validate`

---

## Android APK

### Extraction
```bash
apktool d app.apk -o decoded/   # Best - decodes XML
jadx app.apk                     # Decompile to Java
unzip app.apk -d extracted/      # Simple extraction
```

### Key Locations
- `res/values/strings.xml` - 문자열 리소스
- `AndroidManifest.xml` - 앱 메타데이터
- `classes.dex` - Dalvik 바이트코드
- `assets/`, `res/raw/` - 리소스

### Search
```bash
grep -r "flag\|CTF" decoded/
strings decoded/classes*.dex | grep -i flag
```

### 펄럭펄럭 APK (펄럭펄럭)

```bash
# Run Blutter on arm64 build
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

### HarmonyOS HAP/ABC (abc-디컴파일러)

Repository: `https://github.com/ohos-decompiler/abc-decompiler`

```bash
# Extract .hap first to obtain .abc files
unzip app.hap -d hap_extracted/
```

중요한 시작 모드:
```bash
# Use CLI entrypoint (avoid java -jar GUI mode)
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI [options] <input>
```

```bash
# Basic decompile
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -d "out" ".abc"

# Recommended for .abc
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple --log-level ERROR -d "out_abc_simple" ".abc"
```

Notes:
- `-m simple --log-level ERROR`로 시작하세요.
- `auto`이 실패하면 먼저 `-m simple`로 다시 시도하세요.
- 오류가 항상 완전한 실패를 의미하는 것은 아닙니다. `out_xxx/sources/`를 확인하세요.
- 실행마다 새로운 출력 디렉터리를 사용합니다.

---

## .NET Analysis

### Tools
- **dnSpy** - 디버깅 + 디컴파일(최상)
- **ILSpy** - Decompiler
- **dotPeek** - JetBrains 디컴파일러

### NativeAOT
- `System.Private.CoreLib` 문자열을 찾으세요
- 유형 메타데이터가 있지만 재구성됨
- 길이 접두사가 붙은 UTF-16 패턴 검색

### 2단계 XOR + AES-CBC 디코드 패턴(Codegate 2013)

**패턴:**.NET 바이너리는 XOR 디코딩 후 AES-256-CBC 암호 해독을 수행하는 암호화된 바이트 배열을 저장합니다. 동일한 키 값이 AES 키와 IV로 사용됩니다.

**Steps:**
1. 바이너리에서 하드코딩된 바이트 배열 및 키 문자열 추출(dnSpy/ILSpy)
2. 각 바이트를 XOR합니다(다중 패스일 수 있음, 예: `0x25`, `0x58`, 단일 `0x7D`와 동일)
3. XOR 결과를 Base64로 디코딩합니다.
4. AES-256-CBC는 추출된 키를 키와 IV로 사용하여 `RijndaelManaged`로 복호화합니다.

```python
from Crypto.Cipher import AES
from base64 import b64decode

# Step 1: XOR decode
data = bytearray(encrypted_bytes)
for i in range(len(data)):
    data[i] ^= 0x7D  # Combined XOR key (0x25 ^ 0x58)

# Step 2: Base64 decode
ct = b64decode(bytes(data))

# Step 3: AES-256-CBC decrypt (same value for key and IV)
key = b"9e2ea73295c7201c5ccd044477228527"  # Padded to 32 bytes
cipher = AES.new(key, AES.MODE_CBC, iv=key)
plaintext = cipher.decrypt(ct)
```

**주요 정보:**.NET 디컴파일에 `RijndaelManaged`가 나타나면 Key와 IV가 동일한 값으로 설정되어 있는지 확인하세요. 이는 일반적인 CTF 패턴입니다. XOR 단계는 실제 암호화 이전에 간단한 난독화 계층 역할을 하는 경우가 많습니다.

---

## Packed Binaries

### UPX
```bash
upx -d packed -o unpacked
strings binary | grep UPX     # Check for UPX signature
```

### Custom Packers
1. 스텁 압축 해제 후 중단점 설정
2. Dump memory
3. PE/ELF 헤더 수정

### PyInstaller
```bash
python pyinstxtractor.py binary.exe
# Look in: binary.exe_extracted/
```

---

## LLVM IR

### 어셈블리로 변환
```bash
llc task.ll --x86-asm-syntax=intel
gcc -c task.s -o file.o
```

---

## RISC-V 이진 분석(EHAX 2026)

**패턴(iguessbro):** 정적으로 연결되고 제거된 RISC-V ELF 바이너리. x86에서는 기본적으로 실행할 수 없습니다.

**캡스톤을 이용한 분해:**
```python
from capstone import *

with open('binary', 'rb') as f:
    code = f.read()

# RISC-V 64-bit with compressed instruction support
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC | CS_MODE_RISCV64)
md.detail = True

# Disassemble from entry point (check ELF header for e_entry)
TEXT_OFFSET = 0x10000  # typical for static RISC-V
for insn in md.disasm(code[TEXT_OFFSET:], TEXT_OFFSET):
    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
```

**일반적인 RISC-V 패턴:**
- `li a0, N` → 즉시 로드(인수 설정)
- `mv a0, s0` → 이동 등록
- `call offset` → 함수 호출(auipc + jalr 쌍)
- `beq/bne a0, zero, label` → 조건 분기
- `sd/ld` → 64비트 store/load
- `addiw` → 32비트 추가(W-접미사 = 단어 연산)

**x86과의 주요 차이점:**
- 플래그 레지스터 없음 — 비교는 분기 명령과 인라인으로 수행됩니다.
- a0-a7의 인수(rdi/rsi/rdx 아님)
- a0의 반환 값
- 저장된 레지스터 s0-s11(호출 수신자 저장)
- 표준(4바이트)과 혼합된 압축 명령어(2바이트) — `CS_MODE_RISCVC` 사용

**RISC-V의 RE 방지 트릭:**
- 문자열 상수로 가짜 플래그(`"n0t_th3_r34l"` 패턴 확인)
- 무차별 대입 타이밍(rdtime 명령어)
- 증분 키를 사용한 XOR 복호화: `decrypted[i] = enc[i] ^ (key & 0xFF) ^ 0xA5; key += 7`

**에뮬레이션:** `qemu-riscv64 -L /usr/riscv64-linux-gnu/./binary` (크로스 툴체인 시스템 루트 필요)

---

## Binary Ninja

커뮤니티가 빠르게 성장하는 대화형 disassembler/decompiler입니다.

**디컴파일 출력:** HLIL(고급 중간 언어), pseudo-C, pseudo-Rust, pseudo-Python.

```bash
# Open binary
binaryninja binary
```

```python
# Headless analysis (Python API)
import binaryninja
bv = binaryninja.open_view("binary")
for func in bv.functions:
    print(func.name, hex(func.start))
    print(func.hlil)  # High-Level IL
```

**커뮤니티 플러그인:** 플러그인 관리자(Ctrl+Shift+P → "플러그인 관리자")를 통해 사용할 수 있습니다.

**무료 버전:** https://binary.ninja/free/(클라우드 기반, 제한된 기능).

**Ghidra의 장점:** 더 빠른 시작, 더 깔끔한 IL 표현, 더 나은 Python API 스크립팅.

---

## dogbolt.org와의 디컴파일러 비교

**dogbolt.org**는 동일한 바이너리에서 여러 디컴파일러를 동시에 실행하고 결과를 나란히 표시합니다.

**지원되는 디컴파일러:** Hex-Rays(IDA), Ghidra, Binary Ninja, angr, RetDec, Snowman, dewolf, Reko, Relyze.

**사용 시기:**
- 디컴파일러 출력이 혼란스럽습니다. 명확성을 위해 대안과 비교하세요.
- 한 디컴파일러가 구문을 잘못 처리함 - 다른 디컴파일러가 올바르게 처리할 수도 있음
- 모든 도구를 로컬에 설치하지 않고도 빠른 분류
- 출력을 상호 참조하여 디컴파일러 정확성을 검증합니다.

```bash
# Upload via web interface: https://dogbolt.org/
# Or use the API:
curl -F "file=@binary" https://dogbolt.org/api/binaries/
```

**주요 통찰력:** 다양한 디컴파일러는 다양한 구성에 탁월합니다. 하나가 읽을 수 없는 출력을 생성하면 다른 하나는 더 명확한 의사 코드를 생성하는 경우가 많습니다. 상호 참조는 디컴파일러 버그를 포착합니다.

---

## Useful Commands

```bash
# File info
file binary
checksec --file=binary
rabin2 -I binary

# String extraction
strings binary | grep -iE "flag|secret"
rabin2 -z binary

# Sections
readelf -S binary
objdump -h binary

# Symbols
nm binary
readelf -s binary

# Disassembly
objdump -d binary
objdump -M intel -d binary
```
