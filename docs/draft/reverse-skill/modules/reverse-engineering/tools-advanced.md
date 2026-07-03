# CTF Reverse - 고급 도구 및 난독화 해제

상업용 packers/protectors, 바이너리 diffing, 난독화 프레임워크, 에뮬레이션 및 angr 이상의 기호 실행을 위한 고급 도구입니다.

## 목차
- [VMProtect 분석](#vmprotect-analytic)
  - [Recognition](#recognition)
  - [Approach](#approach)
  - [Tools](#tools)
  - [CTF 전략](#ctf-strategy)
- [테미다/윈라이센스 분석](#themida--winlicense-analysis)
  - [테미다 인식](#themida-인식)
  - [CTF에 대한 접근 방식](#approach-for-ctf)
- [이진 비교](#binary-diffing)
  - [BinDiff](#bindiff)
  - [Diaphora](#diaphora)
- [난독화 프레임워크](#deobfuscation-frameworks)
  - [D-810 (IDA)](#d-810-이다)
  - [GOOMBA (Ghidra)](#goomba-ghidra)
  - [Miasm](#miasm)
- [Qiling 프레임워크(에뮬레이션)](#qiling-framework-emulation)
- [트리톤(동적 기호 실행)](#triton-dynamic-symbolic-execution)
- [만티코어(기호 실행)](#manticore-symbolic-execution)
- [리진/커터](#리진--cutter)
- [RetDec(리타겟팅 가능 디컴파일러)](#retdec-retargetable-decompiler)
- [LLVM IR로 맞춤 VM 바이트코드 리프팅(Google CTF 2017)](#custom-vm-bytecode-lifting-to-llvm-ir-google-ctf-2017)
- [고급 GDB 기술](#advanced-gdb-techniques)
  - [파이썬 스크립팅](#python-scripting)
  - [GDB 스크립트를 사용한 무차별 대입](#brute-force-with-gdb-script)
  - [조건부 중단점](#conditional-breakpoints)
  - [Watchpoints](#watchpoints)
  - [역방향 디버깅(rr)](#reverse-debugging-rr)
  - [GDB 대시보드 / GEF / pwndbg](#gdb-dashboard--gef--pwndbg)
- [고급 Ghidra 스크립팅](#advanced-ghidra-scripting)
- [패치 전략](#patching-strategies)
  - [바이너리 닌자 패치(Python API)](#binary-ninja-patching-python-api)
  - [LIEF(실행 파일 형식 계측용 라이브러리)](#lief-library-for-instrumenting-executable-formats)
- [ILP/LP 솔버를 사용한 GDB 제약 조건 추출(BackdoorCTF 2017)](#gdb-constraint-extraction-with-ilplp-solver-backdoorctf-2017)
- [제로 플래그 모니터링을 사용한 GDB 위치 인코딩 입력(EKOPARTY 2017)](#gdb-position-encoded-input-with-zero-flag-monitoring-ekoparty-2017)
- [실행 전용 바이너리를 덤프하는 LD_PRELOAD(BackdoorCTF 2017)](#ld_preload-to-dump-execute-only-binary-backdoorctf-2017)

---

## VMProtect Analysis

VMProtect는 x86/x64 코드를 생성된 VM에서 해석되는 사용자 정의 바이트코드로 가상화합니다. CTF에서 가장 까다로운 수호자 중 하나입니다.

### Recognition

```bash
# VMProtect signatures
strings binary | grep -i "vmp\|vmprotect"
# PE sections: .vmp0, .vmp1 (VMProtect adds its own sections)
readelf -S binary | grep ".vmp"
# Large binary with entropy > 7.5 in certain sections
```

**Key indicators:**
- `push` / `pop` 무거운 프롤로그(VM 항목이 모든 레지스터를 스택에 푸시함)
- 대형 스위치 케이스 디스패처(VM 핸들러 루프)
- VM 핸들러에 내장된 디버그 방지 검사
- 돌연변이 엔진: 동일한 opcode에는 빌드마다 다른 핸들러가 있습니다.

### Approach

```text
1. Identify VM entry points — look for pushad/pushaq-like sequences
2. Find the handler table — large indirect jump (jmp [reg + offset])
3. Trace handler execution — each handler ends with jump to next
4. Identify handlers:
   - vAdd, vSub, vMul, vXor, vNot (arithmetic)
   - vPush, vPop (stack operations)
   - vLoad, vStore (memory access)
   - vJmp, vJcc (control flow)
   - vRet (VM exit — restores real registers)
5. Build disassembler for VM bytecode
6. Simplify / deobfuscate the lifted IL
```

### Tools

- **VMPAttack**(IDA 플러그인): VM 핸들러를 자동으로 식별합니다.
- **NoVmp**: VTIL을 통한 탈가상화(오픈 소스)
- **VMProtect devirtualizer 스크립트**: 커뮤니티 IDA/Binary Ninja 스크립트
- **CTF에 대한 접근 방식:** 완전히 탈가상화하는 것보다 특정 작업(암호화, 비교)을 추적하는 것이 더 쉬운 경우가 많습니다.

### CTF Strategy

```python
# Trace VM execution dynamically to extract operations on flag
# Hook VM handler dispatch to log opcode + operands

import frida

script = """
var vm_dispatch = ptr('0x...');  // Address of handler table jump
Interceptor.attach(vm_dispatch, {
    onEnter(args) {
        // Log handler index and stack state
        var handler_idx = this.context.rax;  // or whichever register
        console.log('Handler:', handler_idx, 'RSP:', this.context.rsp);
    }
});
"""
```

**주요 통찰력:** CTF에는 완전한 탈가상화가 거의 필요하지 않습니다. 입력에 대해 어떤 작업이 수행되는지 추적하는 데 집중하세요. VM 내에서 호출되는 후크 comparison/crypto 함수입니다.

---

## Themida / WinLicense 분석

VMProtect와 유사하지만 추가 디버그 방지 레이어가 있습니다.

### Themida Recognition
- 섹션: `.themida`, `.winlice`
- 매우 강력한 안티 디버그(커널 수준 검사, 드라이버 설치)
- 코드 변이 + 가상화 + 패킹 결합

### CTF에 대한 접근 방식
1. **압축 해제된 코드 덤프:** 실행되도록 하고, 압축 해제 후 프로세스 메모리를 덤프합니다.
2. **디버그 방지 우회:** Themida 전용 사전 설정이 있는 x64dbg의 ScyllaHide
3. **가져오기 수정:** IAT 재구성을 위해 Scylla 플러그인 사용
4. **덤프된 코드에 중점:** 압축을 푼 후 일반 바이너리로 분석

```bash
# x64dbg workflow for Themida:
1. Load binary
2. Enable ScyllaHide → Profile: Themida
3. Run to OEP (Original Entry Point) — may need several attempts
4. Dump with Scylla: OEP → IAT Autosearch → Get Imports → Dump
5. Fix dump: Scylla → Fix Dump
6. Analyze fixed dump in Ghidra/IDA
```

---

## Binary Diffing

패치 분석, 1일 익스플로잇 개발, 두 가지 버전의 바이너리를 제공하는 CTF 챌린지에 매우 중요합니다.

### BinDiff

```bash
# Export from IDA/Ghidra first, then diff
# IDA: File → BinExport → Export as BinExport2
# Ghidra: Use BinExport plugin

# Command line diffing
bindiff primary.BinExport secondary.BinExport
# Opens in BinDiff GUI — shows matched/unmatched functions
```

**Key metrics:**
- 함수 쌍당 유사성 점수(0.0-1.0)
- 변경된 지침이 강조표시됨
- 일치하지 않는 기능 = new/removed 코드

### Diaphora

BinDiff의 무료 오픈 소스 대안으로 IDA 플러그인으로 실행됩니다.

```bash
# In IDA:
# File → Script file → diaphora.py
# Export first binary, then open second and diff

# Ghidra version: diaphora_ghidra.py
```

**CTF에 유용함:** 챌린지가 "패치된" 바이너리와 "원본" 바이너리를 제공하는 경우 diff는 취약점이나 숨겨진 기능을 드러냅니다.

---

## Deobfuscation Frameworks

### D-810 (IDA)

IDA Pro용 패턴 기반 난독화 플러그인. OLLVM 난독화 바이너리에 탁월합니다.

```text
Capabilities:
- MBA simplification: (a ^ b) + 2*(a & b) → a + b
- Dead code elimination
- Opaque predicate removal
- Constant folding
- Control flow unflattening (partial)

Installation: Copy to IDA plugins directory
Usage: Edit → Plugins → D-810 → Select rules → Apply
```

### GOOMBA (Ghidra)

```text
GOOMBA (Ghidra-based Obfuscated Object Matching and Bytes Analysis):
- Integrates with Ghidra's P-Code
- Simplifies MBA expressions
- Pattern matching for known obfuscation

Installation: Copy .jar to Ghidra extensions
Usage: Code Browser → Analysis → GOOMBA
```

### Miasm

기호 실행 및 IR 리프팅 기능을 갖춘 강력한 리버스 엔지니어링 프레임워크입니다.

```python
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.expression import *

# Load binary and lift to Miasm IR
cont = Container.from_stream(open("binary", "rb"))
machine = Machine(cont.arch)
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)

# Disassemble function
asmcfg = mdis.dis_multiblock(entry_addr)

# Lift to IR
lifter = machine.lifter_model_call(loc_db=cont.loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

# Symbolic execution
from miasm.ir.symbexec import SymbolicExecutionEngine
sb = SymbolicExecutionEngine(lifter)
# Execute symbolically, then simplify expressions
```

**사용 사례:** 표현식 트리 난독화 해제, 복잡한 산술 단순화, 난독화된 코드를 통한 데이터 흐름 추적.

---

## Qiling 프레임워크(에뮬레이션)

OS 수준 지원(syscalls, 파일 시스템, 레지스트리)을 갖춘 Unicorn 기반의 크로스 플랫폼 에뮬레이션 프레임워크입니다.

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Emulate Linux ELF
ql = Qiling(["./binary"], "rootfs/x8664_linux",
            verbose=QL_VERBOSE.DEBUG)

# Hook specific address
@ql.hook_address
def hook_check(ql, address, size):
    if address == 0x401234:
        ql.arch.regs.rax = 0  # Bypass check
        ql.log.info("Anti-debug bypassed")

# Hook syscall
@ql.hook_syscall(name="ptrace")
def hook_ptrace(ql, request, pid, addr, data):
    return 0  # Always succeed

# Hook API (Windows)
@ql.set_api("IsDebuggerPresent", target=ql.os.user_defined_api)
def hook_isdebug(ql, address, params):
    return 0

ql.run()
```

**유니콘에 비해 장점:**
- OS 에뮬레이션(파일 I/O, 네트워크, 레지스트리)
- 다중 플랫폼(Linux, Windows, macOS, Android, UEFI)
- 내장 디버거 인터페이스
- 라이브러리 로딩을 위한 Rootfs

**CTF 사용 사례:**
- 외부 아키텍처용 바이너리 에뮬레이션(ARM, MIPS, RISC-V)
- 모든 안티 디버그를 한 번에 우회(디버거 아티팩트 없음)
- 하드웨어가 없는 Fuzz embedded/IoT 펌웨어
- 코드 수정 없이 실행 추적

---

## Triton(동적 기호 실행)

기호 실행, 오염 분석 및 AST 단순화 기능을 갖춘 핀 기반 동적 바이너리 분석 프레임워크입니다.

```python
from triton import *

ctx = TritonContext(ARCH.X86_64)

# Load binary sections
with open("binary", "rb") as f:
    binary = f.read()
ctx.setConcreteMemoryAreaValue(0x400000, binary)

# Symbolize input
for i in range(32):
    ctx.symbolizeMemory(MemoryAccess(INPUT_ADDR + i, CPUSIZE.BYTE), f"input_{i}")

# Emulate instructions
pc = ENTRY_POINT
while pc:
    inst = Instruction(pc, ctx.getConcreteMemoryAreaValue(pc, 16))
    ctx.processing(inst)

    # At comparison point, extract path constraint
    if pc == CMP_ADDR:
        ast = ctx.getPathConstraintsAst()
        model = ctx.getModel(ast)
        for k, v in sorted(model.items()):
            print(f"input[{k}] = {chr(v.getValue())}", end="")
        break

    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
```

**트리톤 대 앙그:**
| Feature | Triton | angr |
|---|---|---|
| Execution | 구체적 + 상징적(DSE) | Fully symbolic |
| Speed | Faster (concrete-driven) | 느림(모든 경로 탐색) |
| Path explosion | 덜 경향이 있음(한 가지 경로를 따릅니다) | Major issue |
| API | C++ / Python | Python |
| Best for | 단일 경로 난독화, 오염 추적 | Multi-path exploration |

**주요 용도:** Triton은 난독화에 탁월합니다. 프로그램을 구체적으로 실행하고 기호 상태를 추적한 다음 수집된 제약 조건을 단순화합니다.

---

## 맨티코어(기호 실행)

Trail of Bits의 상징적 실행 도구. angr과 유사하지만 기본 EVM(Ethereum)을 지원합니다.

```python
from manticore.native import Manticore

m = Manticore("./binary")

# Hook success/failure
@m.hook(0x401234)
def success(state):
    buf = state.solve_one_n_batched(state.input_symbols, 32)
    print("Flag:", bytes(buf))
    m.kill()

@m.hook(0x401256)
def fail(state):
    state.abandon()

m.run()
```

**최적의 용도:** EVM/smart 계약 분석, 더 간단한 Linux 바이너리. angr은 일반적으로 복잡한 RE 작업에 더 성숙합니다.

---

## Rizin / Cutter

Rizin은 radare2의 유지 포크입니다. Cutter는 Qt 기반 GUI입니다.

```bash
# Rizin CLI (r2-compatible commands)
rizin -d ./binary
> aaa                    # Analyze all
> afl                    # List functions
> pdf @ main             # Print disassembly
> VV                     # Visual graph mode

# Cutter GUI
cutter binary           # Open in GUI with decompiler
```

**Cutter advantages:**
- 내장 Ghidra 디컴파일러(r2ghidra 플러그인을 통해)
- 하나의 GUI에 그래프 보기, 16진수 편집기, 디버그 패널
- 통합 Python/JavaScript 스크립팅 콘솔
- 무료 및 오픈 소스

---

## RetDec(리타겟팅 가능 디컴파일러)

다양한 아키텍처를 지원하는 LLVM 기반 디컴파일러입니다. 무료이며 오픈 소스입니다.

```bash
# Install
pip install retdec-decompiler
# Or use web: https://retdec.com/decompilation/

# CLI
retdec-decompiler binary
# Outputs: binary.c (decompiled C), binary.dsm (disassembly)

# Specific function
retdec-decompiler --select-ranges 0x401000-0x401100 binary
```

**강점:** 멀티 아키텍처 지원(x86, ARM, MIPS, PowerPC, PIC32), 무료, 컴파일 가능한 C 생성. Ghidra에서 제대로 지원되지 않는 아키텍처에 적합합니다.

---

## LLVM IR로 사용자 정의 VM 바이트코드 리프팅(Google CTF 2017)

복잡한 사용자 지정 VM의 경우 VM 바이트코드를 LLVM IR로 변환하고 LLVM의 최적화 패스를 사용하여 코드를 단순화한 다음 최적화된 IR를 디컴파일합니다.

```python
# Pipeline: VM bytecode → custom disassembler → LLVM IR → optimize → decompile
# 1. Write disassembler for the custom VM opcodes
# 2. Emit LLVM IR for each opcode:
#    INC reg  → %reg = add i32 %reg, 1
#    CDEC reg → conditional decrement
#    CALL fn  → call void @fn()
# 3. Use MCJIT or llc to optimize:
#    opt -O3 -S vm_lifted.ll -o vm_optimized.ll
# 4. Load optimized IR in IDA or decompile with RetDec
# Result: 1300 lines → 150 lines after inlining + constant folding
```

**주요 통찰력:** LLVM의 최적화 패스(인라인, 상수 폴딩, 데드 코드 제거)는 리프트된 VM 바이트코드를 획기적으로 단순화합니다. 1300줄의 IL을 생성하는 26개의 레지스터와 3개의 opcode가 있는 사용자 지정 VM은 `-O3` 이후 최대 150줄로 줄어들어 기본 알고리즘(예: Collatz 시퀀스 계산)을 드러냅니다.

---

## 고급 GDB 기술

### Python Scripting

```python
# ~/.gdbinit or source from GDB
import gdb

class TraceCompare(gdb.Breakpoint):
    """Log all comparison operations."""
    def __init__(self, addr):
        super().__init__(f"*{addr}", gdb.BP_BREAKPOINT)

    def stop(self):
        frame = gdb.selected_frame()
        rdi = int(frame.read_register("rdi"))
        rsi = int(frame.read_register("rsi"))
        rdx = int(frame.read_register("rdx"))
        # Read compared buffers
        inferior = gdb.selected_inferior()
        buf1 = inferior.read_memory(rdi, rdx).tobytes()
        buf2 = inferior.read_memory(rsi, rdx).tobytes()
        print(f"memcmp({buf1!r}, {buf2!r}, {rdx})")
        return False  # Don't stop, just log

# Usage in GDB:
# (gdb) source trace_cmp.py
# (gdb) python TraceCompare(0x401234)
```

### GDB 스크립트를 이용한 무차별 대입

```python
# Byte-by-byte brute force via GDB Python API
import gdb, string

def bruteforce_flag(check_addr, success_addr, fail_addr, flag_len):
    flag = []
    for pos in range(flag_len):
        for ch in string.printable:
            candidate = ''.join(flag) + ch + 'A' * (flag_len - pos - 1)
            gdb.execute('start', to_string=True)
            gdb.execute(f'b *{check_addr}', to_string=True)
            # Write candidate to stdin pipe
            # ... (setup input)
            gdb.execute('continue', to_string=True)
            rip = int(gdb.parse_and_eval('$rip'))
            if rip == success_addr:
                flag.append(ch)
                break
        gdb.execute('delete breakpoints', to_string=True)
    return ''.join(flag)
```

### Conditional Breakpoints

```bash
# Break only when register has specific value
(gdb) b *0x401234 if $rax == 0x41
(gdb) b *0x401234 if *(char*)$rdi == 'f'

# Break on Nth hit
(gdb) b *0x401234
(gdb) ignore 1 99    # Skip first 99 hits, break on 100th

# Log without stopping
(gdb) b *0x401234
(gdb) commands
> silent
> printf "rax=%lx rdi=%lx\n", $rax, $rdi
> continue
> end
```

### Watchpoints

```bash
# Hardware watchpoint — break when memory changes
(gdb) watch *(int*)0x601050        # Break on write to address
(gdb) rwatch *(int*)0x601050       # Break on read
(gdb) awatch *(int*)0x601050       # Break on read or write

# Watch a variable by name (needs debug symbols)
(gdb) watch flag_buffer[0]

# Conditional watchpoint
(gdb) watch *(int*)0x601050 if *(int*)0x601050 == 0x42
```

### 역방향 디버깅(rr)

```bash
# Record execution
rr record ./binary
# Replay with reverse execution support
rr replay

# In rr replay (GDB commands plus):
(gdb) reverse-continue     # Run backward to previous breakpoint
(gdb) reverse-stepi        # Step backward one instruction
(gdb) reverse-next         # Reverse next
(gdb) when                 # Show current event number

# Set checkpoint and return to it
(gdb) checkpoint
(gdb) restart 1           # Return to checkpoint 1
```

**주요 용도:** 중요한 순간을 지나쳤을 때 다시 시작하는 대신 되돌리세요. 상태를 손상시키는 디버그 방지에 매우 유용합니다.

### GDB 대시보드 / GEF / pwndbg

```bash
# pwndbg (most popular for CTF)
# https://github.com/pwndbg/pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Key pwndbg commands:
pwndbg> context           # Show registers, stack, code, backtrace
pwndbg> vmmap             # Memory map (like /proc/self/maps)
pwndbg> search -s "flag{" # Search memory for string
pwndbg> telescope $rsp 20 # Smart stack dump
pwndbg> cyclic 200        # Generate De Bruijn pattern
pwndbg> hexdump $rdi 64   # Pretty hex dump
pwndbg> got               # Show GOT entries
pwndbg> plt               # Show PLT entries

# GEF (alternative)
# https://github.com/hugsy/gef
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Key GEF commands:
gef> xinfo $rdi           # Detailed info about address
gef> checksec             # Binary security features
gef> heap chunks          # Heap chunk listing
gef> pattern create 100   # De Bruijn pattern
```

---

## 고급 Ghidra 스크립팅

```python
# Ghidra Python (Jython) — run via Script Manager or headless

# Batch rename functions matching a pattern
from ghidra.program.model.symbol import SourceType
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.getName().startswith("FUN_"):
        # Check if function contains specific instruction pattern
        body = func.getBody()
        inst_iter = currentProgram.getListing().getInstructions(body, True)
        for inst in inst_iter:
            if inst.getMnemonicString() == "CPUID":
                func.setName("anti_vm_check_" + hex(func.getEntryPoint().getOffset()),
                            SourceType.USER_DEFINED)
                break

# Extract all XOR constants from a function
def extract_xor_constants(func):
    """Find all XOR operations and their immediate operands."""
    constants = []
    body = func.getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    for inst in inst_iter:
        if inst.getMnemonicString() == "XOR":
            for i in range(inst.getNumOperands()):
                op = inst.getOpObjects(i)
                if op and hasattr(op[0], 'getValue'):
                    constants.append(int(op[0].getValue()))
    return constants

# Bulk decompile and search for pattern
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)

for func in fm.getFunctions(True):
    result = decomp.decompileFunction(func, 30, monitor)
    if result.depiledFunction():
        code = result.getDecompiledFunction().getC()
        if "strcmp" in code or "memcmp" in code:
            print(f"Comparison in {func.getName()} at {func.getEntryPoint()}")
```

---

## Patching Strategies

### 바이너리 닌자 패치(Python API)

```python
import binaryninja as bn

bv = bn.open_view("binary")

# NOP out instruction
bv.write(0x401234, b"\x90" * 5)  # 5-byte NOP

# Patch conditional jump (JNZ → JZ)
bv.write(0x401234, b"\x74")  # 0x75 (JNZ) → 0x74 (JZ)

# Insert always-true (mov eax, 1; ret)
bv.write(0x401234, b"\xb8\x01\x00\x00\x00\xc3")

bv.save("patched")
```

### LIEF(실행 파일 형식 계측용 라이브러리)

```python
import lief

# Parse and modify ELF/PE/Mach-O
binary = lief.parse("binary")

# Add a new section
section = lief.ELF.Section(".patch")
section.content = list(b"\xcc" * 0x100)
section.type = lief.ELF.SECTION_TYPES.PROGBITS
section.flags = lief.ELF.SECTION_FLAGS.EXECINSTR | lief.ELF.SECTION_FLAGS.ALLOC
binary.add(section)

# Modify entry point
binary.header.entrypoint = 0x401000

# Hook imported function
binary.patch_pltgot("strcmp", 0x401000)

binary.write("patched")
```

**LIEF 장점:** 교차 형식(ELF, PE, Mach-O), Python API, sections/segments 추가, 헤더 수정, 패치 가져오기 가능.

---

## ILP/LP 솔버를 사용한 GDB 제약 조건 추출(BackdoorCTF 2017)

바이너리가 입력 바이트 간의 선형 산술 관계를 적용하는 경우 GDB를 통해 자동으로 제약 조건을 추출하고 ILP 솔버로 해결합니다.

**기술:** 위치 인코딩 입력(`input[i] = i`)을 보내면 비교가 실행될 때 어떤 위치가 관련되어 있는지, 해당 위치의 sum/difference이 무엇과 같아야 하는지 정확히 알 수 있습니다. 기록된 비교에서 모든 제약 조건을 수집한 다음 PuLP 또는 Gurobi에 제공합니다.

```python
from pulp import *

n = 32  # flag length
prob = LpProblem("crackme", LpMinimize)
x = [LpVariable(f'x{i}', 32, 126, cat='Integer') for i in range(n)]
prob += 0  # dummy objective

# Constraints extracted via GDB automation (input[i]=i, monitor comparisons):
prob += x[3] + x[7] == 0xAB
prob += x[1] - x[5] == 0x0C
# ... add all extracted constraints ...

# Constrain to printable ASCII
for xi in x:
    prob += xi >= 32
    prob += xi <= 126

prob.solve(PULP_CBC_CMD(msg=0))
flag = ''.join(chr(int(value(xi))) for xi in x)
print("Flag:", flag)
```

**제약조건 추출을 위한 GDB 자동화:**
```python
# In GDB Python: set input[i]=i, run, log every CMP instruction result
import gdb

class CmpLogger(gdb.Breakpoint):
    def stop(self):
        frame = gdb.selected_frame()
        # Read compared values, map back to input indices via position encoding
        return False
```

**주요 통찰력:** 바이너리가 입력 바이트 간의 선형 산술 관계를 적용하는 경우 GDB 자동화를 통해 제약 조건이 추출되면 ILP 솔버는 만족스러운 할당을 직접 찾습니다.

**참조:** BackdoorCTF 2017

---

## 제로 플래그 모니터링 기능을 갖춘 GDB 위치 인코딩 입력(EKOPARTY 2017)

`input[i] = i`(위치 인코딩) 위치에 입력을 보냅니다. CPU 제로 플래그(ZF)를 모니터링하는 바이너리를 통해 단일 단계를 수행합니다. 특정 포지션의 값과 관련된 비교에서 ZF가 설정되면 비교가 일치합니다. 해당 포지션에 대한 예상 값을 기록합니다.

```python
import gdb

# Script: single-step binary with position-encoded input, watch ZF
class ZFMonitor(gdb.Breakpoint):
    def stop(self):
        zf = (int(gdb.parse_and_eval('$eflags')) >> 6) & 1
        if zf:
            rip = int(gdb.parse_and_eval('$rip'))
            # Disassemble at rip to find the compared immediate
            disasm = gdb.execute(f'x/1i {rip-5}', to_string=True)
            print(f"ZF set at {rip:#x}: {disasm.strip()}")
        return False

# Run once with input b'\x00\x01\x02\x03...\x1f'
# ZF fires when comparison matches the position's own value -> that IS the key byte
```

수동으로 반전하지 않고 한 번에 각 입력 바이트를 필요한 값으로 매핑합니다.

**주요 정보:** 제로 플래그 모니터링과 결합된 위치 인코딩 입력(`input[i]=i`)은 한 번의 패스로 전체 key/password를 보여줍니다. 제로 플래그는 위치 i에 대한 예상 값이 i 자체와 같을 때 실행됩니다.

**참고자료:** EKOPARTY CTF 2017

---

## 실행 전용 바이너리를 덤프하는 LD_PRELOAD(BackdoorCTF 2017)

바이너리에는 실행 전용 권한(모드 `--x`, 읽기 비트 없음)이 있습니다. 파일을 직접 읽거나 표준 도구를 사용하여 읽을 수는 없지만 커널은 실행 시 파일을 메모리에 매핑합니다.

프로세스 내부에서 실행되고 `/proc/self/mem`를 통해 자체 메모리를 읽는 생성자가 있는 공유 라이브러리를 LD_PRELOAD:

```c
// dump_xo.c — compile: gcc -shared -fPIC -o dump_xo.so dump_xo.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((constructor)) void dump() {
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[256];
    unsigned long base = 0, end = 0;

    // Find the execute-only binary's mapping (r-xp or --xp)
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "binary_name")) {
            sscanf(line, "%lx-%lx", &base, &end);
            break;
        }
    }
    fclose(maps);

    FILE *mem = fopen("/proc/self/mem", "rb");
    fseek(mem, base, SEEK_SET);
    size_t size = end - base;
    void *buf = malloc(size);
    fread(buf, 1, size, mem);
    fclose(mem);

    FILE *out = fopen("/tmp/dumped_binary", "wb");
    fwrite(buf, 1, size, out);
    fclose(out);
}
// Usage: LD_PRELOAD=./dump_xo.so ./binary_xo
```

**주요 통찰력:** 실행 전용은 파일 읽기를 차단하지만 실행은 차단하지 않습니다. LD_PRELOAD 생성자는 `/proc/self/mem`가 파일 권한에 관계없이 매핑된 메모리에 대한 액세스를 제공하는 프로세스 내에서 실행됩니다.

**참조:** BackdoorCTF 2017
