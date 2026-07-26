# CTF 리버스 - 패턴 및 기술

## 목차
- [커스텀 VM 반전](#커스텀-vm-반전)
  - [Analysis Steps](#analysis-steps)
  - [일반적인 VM 패턴](#일반적인-vm-패턴)
  - [RVA 기반 Opcode 디스패칭](#rva-기반-opcode-디스패칭)
  - [상태 머신 VM(90,000개 이상의 상태)](#상태-머신-vm90000개-이상의-상태)
  - [퍼징 및 명령어 세트 검색을 통한 맞춤형 VM 리버스 엔지니어링(hxp CTF 2017)](#퍼징-및-명령어-세트-검색을-통한-맞춤형-vm-리버스-엔지니어링hxp-ctf-2017)
- [Anti-Debugging Techniques](#anti-debugging-techniques)
  - [Common Checks](#common-checks)
  - [Bypass Technique](#bypass-technique)
  - [LD_PRELOAD Hook](#ld_preload-hook)
  - [pwntools 바이너리 패치(Crypto-Cat)](#pwntools-바이너리-패치crypto-cat)
- [Nanomites](#nanomites)
  - [Linux (Signal-Based)](#linux-signal-based)
  - [Windows(디버그 이벤트)](#windows디버그-이벤트)
  - [Analysis](#analysis)
- [Self-Modifying Code](#self-modifying-code)
  - [패턴: XOR 복호화](#패턴-xor-복호화)
- [알려진 일반 텍스트 XOR(플래그 접두사)](#알려진-일반-텍스트-xor플래그-접두사)
  - [변형: 위치 인덱스를 사용한 XOR](#변형-위치-인덱스를-사용한-xor)
- [혼합 모드(x86-64 / x86) 스테이저](#혼합-모드x86-64--x86-스테이저)
- [LLVM(저수준 가상 머신) 난독화(제어 흐름 평면화)](#llvm저수준-가상-머신-난독화제어-흐름-평면화)
  - [Pattern](#pattern)
  - [De-obfuscation](#de-obfuscation)
- [S-Box / 키스트림 생성](#s-box--키스트림-생성)
  - [피셔-예이츠 셔플(Xorshift32)](#피셔-예이츠-셔플xorshift32)
  - [Xorshift64* Keystream](#xorshift64-keystream)
  - [Identifying Patterns](#identifying-patterns)
- [SECCOMP/BPF 필터 분석](#seccompbpf-필터-분석)
  - [BPF Analysis](#bpf-analysis)
- [예외 처리기 난독화](#예외-처리기-난독화)
  - [RtlInstallFunctionTableCallback](#rtlinstallfunctiontablecallback)
  - [VEH(벡터 예외 처리기)](#veh벡터-예외-처리기)
- [메모리 덤프 분석](#메모리-덤프-분석)
  - [바이너리가 메모리를 덤프할 때](#바이너리가-메모리를-덤프할-때)
  - [알려진 일반 텍스트 공격](#알려진-일반-텍스트-공격)
- [바이트별 균일 변환](#바이트별-균일-변환)
- [x86-64 Gotchas](#x86-64-gotchas)
  - [Sign Extension](#sign-extension)
  - [루프 경계 상태 업데이트](#루프-경계-상태-업데이트)
- [사용자 정의 Mangle 기능 반전](#사용자-정의-mangle-기능-반전)
- [위치 기반 변환 반전](#위치-기반-변환-반전)
- [16진수로 인코딩된 문자열 비교](#16진수로-인코딩된-문자열-비교)
- [신호 기반 이진 탐색](#신호-기반-이진-탐색)
- [패치를 통한 악성 코드 방지 분석 우회](#패치를-통한-악성-코드-방지-분석-우회)
- [다단계 쉘코드 로더](#다단계-쉘코드-로더)
- [타이밍 부채널 공격](#타이밍-부채널-공격)
- [미끼 + 신호 처리기 혼합 부울 산술을 사용한 다중 스레드 안티 디버그(ApoorvCTF 2026)](#미끼--신호-처리기-혼합-부울-산술을-사용한-다중-스레드-안티-디버그apoorvctf-2026)
- [INT3 패치 + 코어 덤프 무차별 대입 Oracle(Pwn2Win 2016)](#int3-패치--코어-덤프-무차별-대입-oraclepwn2win-2016)
- [신호 처리기 체인 + LD_PRELOAD Oracle(Nuit du Hack 2016)](#신호-처리기-체인--ld_preload-oraclenuit-du-hack-2016)
- [printf 형식 문자열 VM을 Z3으로 디컴파일(SECCON 2017)](#printf-형식-문자열-vm을-z3으로-디컴파일seccon-2017)

---

## 커스텀 VM 반전

### Analysis Steps
1. VM 구조 식별: 레지스터, 메모리, 명령 포인터
2. Opcode 의미에 대한 역방향 `executeIns`/`runvm` 기능
3. 바이트코드를 파싱하는 디스어셈블러 작성
4. 알고리즘 이해를 위한 디스어셈블리 디컴파일

### 일반적인 VM 패턴
```c
switch (opcode) {
    case 1: *R[op1] *= op2; break;      // MUL
    case 2: *R[op1] -= op2; break;      // SUB
    case 3: *R[op1] = ~*R[op1]; break;  // NOT
    case 4: *R[op1] ^= mem[op2]; break; // XOR
    case 5: *R[op1] = *R[op2]; break;   // MOV
    case 7: if (R0) IP += op1; break;   // JNZ
    case 8: putc(R0); break;            // PRINT
    case 10: R0 = getc(); break;        // INPUT
}
```

### RVA 기반 Opcode 디스패칭
- Opcode는 핸들러 기능을 가리키는 RVA입니다.
- 핸들러가 작업을 수행하고 다음 RVA를 읽고 점프합니다.
- RVA 체인을 따라 모든 핸들러를 매핑합니다.

### 상태 머신 VM(90,000개 이상의 상태)
```java
// BFS for valid path
var agenda = new ArrayDeque<State>();
agenda.add(new State(0, ""));
while (!agenda.isEmpty()) {
    var current = agenda.remove();
    if (current.path.length() == TARGET_LENGTH) {
        println(current.path);
        continue;
    }
    for (var transition : machine.get(current.state).entrySet()) {
        agenda.add(new State(transition.getValue(),
                            current.path + (char)transition.getKey()));
    }
}
```

**주요 통찰력:** 챌린지가 디스패처 루프와 함께 바이트코드 blob을 번들로 묶을 때 커스텀 VM이 나타납니다. 먼저 opcode 스위치 테이블을 뒤집은 다음 알고리즘을 이해하기 전에 바이트코드를 리프트하는 디스어셈블러를 작성합니다.

### 퍼징 및 명령어 세트 검색을 통한 맞춤형 VM 리버스 엔지니어링(hxp CTF 2017)

디스패치 루프의 정적 분석이 너무 복잡한 경우 알 수 없는 VM 바이트코드를 반전시키는 체계적인 블랙박스 접근 방식:

**1단계: 명령어 정렬을 결정합니다.**
명령어 정렬을 식별하기 위해 바이트코드를 다양한 너비(6~11비트)의 비트 문자열로 덤프합니다. Opcode 경계를 제안하는 반복 패턴을 찾으십시오.

**2단계: 임의 바이트를 퍼징합니다.**
단일 명령을 보내고 registers/memory에 대한 효과를 관찰하여 opcode를 매핑합니다. 최소 프로그램으로 줄이기: 관찰 가능한 각 효과를 생성하는 가장 짧은 입력을 찾습니다.

**3단계: 명령어 세트를 구축합니다.**
발견된 ISA의 예(가변 길이 6-11비트):
```text
000 xxxxxxxx  jmpz    001 xxxxxxxx  jmp     010 xxxxxxxx  call
011 xxxxxxxx  label   1000 xxxxxxx  loadram  1001 xxxxxxx  saveram
110 xxxxxxxx  loadi   11100 xxxxxx  shl      11101 xxxxxx  shr
111100 not    111101 and    111110 or    111111 setif
```

**4단계: 빌드 assembler/disassembler.**
발견된 ISA를 조립 및 분해하는 도구를 작성한 다음 챌린지 바이트코드를 분해하여 알고리즘을 이해합니다.

**5단계: 누락된 기본 요소 구현.**
ISA에 예상되는 작업이 부족한 경우 사용 가능한 지침에서 이를 합성합니다. 예: AND/OR/NOT만 사용하여 XTEA 암호 해독 구현(기본 XOR 또는 ADD 없음):
```python
# XOR from AND/OR/NOT:  XOR(a, b) = (a OR b) AND NOT(a AND b)
# ADD via full-adder chains using AND/OR/NOT for carry propagation
def xor_from_primitives(a, b):
    return (a | b) & ~(a & b)

def add_from_primitives(a, b, bits=32):
    carry = 0
    result = 0
    for i in range(bits):
        ai = (a >> i) & 1
        bi = (b >> i) & 1
        sum_bit = xor_from_primitives(xor_from_primitives(ai, bi), carry)
        carry = (ai & bi) | (carry & xor_from_primitives(ai, bi))
        result |= (sum_bit << i)
    return result
```

**주요 통찰력:** VM 디스패치 루프의 정적 분석이 너무 복잡한 경우 블랙박스 퍼징을 통해 ISA를 더 빠르게 매핑할 수 있습니다. 단일 명령을 보내고 상태 변경을 관찰합니다. 가변 길이 명령어 세트는 여러 비트 폭을 테스트해야 합니다. ISA가 알려지면 최소한의 기본 요소(AND/OR/NOT)로도 복잡한 알고리즘(XTEA)을 구현할 수 있습니다.

**참고자료:** hxp CTF 2017

---

## Anti-Debugging Techniques

### Common Checks
- `IsDebuggerPresent()` (윈도우)
- `ptrace(PTRACE_TRACEME)` (리눅스)
- `/proc/self/status` TracerPid
- 타이밍 확인(`rdtsc`, `time()`)
- 레지스트리 확인(Windows)

### Bypass Technique
1. 디버그 검사 후 `test` 명령어 식별
2. `test`에 중단점을 설정합니다.
3. 조건을 우회하도록 레지스터 수정

```bash
# In radare2
db 0x401234          # Break at test
dc                   # Run
dr eax=0             # Clear flag
dc                   # Continue
```

### LD_PRELOAD Hook
```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <sys/ptrace.h>

long int ptrace(enum __ptrace_request req, ...) {
    long int (*orig)(enum __ptrace_request, pid_t, void*, void*);
    orig = dlsym(RTLD_NEXT, "ptrace");
    va_list ap;
    va_start(ap, req);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    // Log or modify behavior
    return orig(req, pid, addr, data);
}
```

Compile: `gcc -shared -fPIC -ldl hook.c -o hook.so`
Run: `LD_PRELOAD=./hook.so ./binary`

**주요 통찰력:** 디버깅 방지 검사는 대부분의 반전 문제에서 첫 번째 장애물입니다. `ptrace`, `IsDebuggerPresent` 또는 `main()` 초기에 타이밍 확인을 찾아 패치하거나 연결한 후 심층 분석을 시도하세요.

### pwntools 바이너리 패치(Crypto-Cat)
pwntools를 사용하여 직접 디버그 방지 호출을 패치합니다. 기능을 `ret` 명령어로 대체합니다.
```python
from pwn import *

elf = ELF('./challenge', checksec=False)
elf.asm(elf.symbols.ptrace, 'xor eax, eax; ret')  # Return success explicitly
elf.save('patched')                   # Save patched binary
```

기타 일반적인 패치:
```python
elf.asm(addr, 'nop')                  # NOP out an instruction
elf.asm(addr, 'xor eax, eax; ret')    # Return 0 (bypass checks)
elf.asm(addr, 'mov eax, 1; ret')      # Return 1 (force success)
```

---

## Nanomites

### Linux (Signal-Based)
- `SIGTRAP` (`int 3`) → 사용자 정의 작업
- `SIGILL` (`ud2`) → 사용자 정의 작업
- `SIGFPE` (`idiv 0`) → 사용자 정의 작업
- `SIGSEGV` (null deref) → 사용자 정의 작업

### Windows(디버그 이벤트)
- `EXCEPTION_DEBUG_EVENT` → 메인 핸들러
- 부모 디버거가 `WriteProcessMemory`/`SetThreadContext` 등 Windows 디버그 API로 자녀 상태를 수정합니다.
- 매직 마커: `0x1337BABE`, `0xDEADC0DE`

### Analysis
1. `fork()` + `ptrace(PTRACE_TRACEME)`를 확인하세요.
2. `WaitForDebugEvent` 루프 찾기
3. EAX 값을 작업에 매핑
4. 알고리즘을 재구성하기 위한 로그 작업

**주요 통찰력:** Nanomite는 디버거 상위에서만 실행되는 signal/exception 핸들러 내부에 실제 계산을 숨깁니다. 바이너리가 분기되고 하위가 `ptrace(TRACEME)`을 호출하면 상위가 실제 CPU입니다. POKE 작업을 기록하여 알고리즘을 재구성합니다.

---

## Self-Modifying Code

### 패턴: XOR 복호화
```asm
lea     rax, next_block
mov     dl, [rcx]        ; Input char
xor_loop:
    xor     [rax+rbx], dl
    inc     rbx
    cmp     rbx, BLOCK_SIZE
    jnz     xor_loop
jmp     rax              ; Execute decrypted
```

**해결책:** 블록 시작 시 알려진 opcode는 XOR 키(플래그 문자)를 나타냅니다.

**주요 통찰력:** 자체 수정 코드는 각 입력 문자를 키로 사용하여 다음 블록을 해독합니다. 해독된 각 블록(예: 함수 프롤로그)의 시작 부분에 있는 양호한 것으로 알려진 opcode는 올바른 키 바이트를 표시하여 한 번에 한 문자씩 플래그를 복구합니다.

---

## 알려진 일반 텍스트 XOR(플래그 접두사)

**패턴:** 암호화된 바이트가 제공됩니다. 플래그 형식이 알려져 있습니다(예: `0xL4ugh{`).

**Approach:**
1. XOR 키를 반복한다고 가정합니다.
2. 키 바이트를 복구하려면 알려진 접두사(및 힌트 문구)를 사용하세요.
3. 작은 키 길이를 시도하고 인쇄 가능한 출력을 검증하십시오.

```python
enc = bytes.fromhex("...")  # ciphertext
known = b"0xL4ugh{say_yes_to_me"
for klen in range(2, 33):
    key = bytearray(klen)
    ok = True
    for i, b in enumerate(known):
        if i >= len(enc):
            break
        ki = i % klen
        v = enc[i] ^ b
        if key[ki] != 0 and key[ki] != v:
            ok = False
            break
        key[ki] = v
    if not ok:
        continue
    pt = bytes(enc[i] ^ key[i % klen] for i in range(len(enc)))
    if all(32 <= c < 127 for c in pt):
        print(klen, key, pt)
```

**참고:** 챌린지 힌트는 플래그 본문에 그대로 표시되는 경우가 많습니다(예: "say_yes_to_me").

### 변형: 위치 인덱스를 사용한 XOR
**패턴:** `cipher[i] = plain[i] ^ key[i % k] ^ i`(또는 `^ (i & 0xff)`).

**Symptoms:**
- 반복 키 XOR은 알려진 접두사에 거의 맞지만 이후 위치에서 끊어집니다.
- 알려진 접두사가 있는 XOR은 인덱스당 +1씩 변경되는 "키"를 생성합니다.

**수정:** 먼저 색인을 제거한 다음 알려진 접두사가 있는 키를 복구하세요.
```python
enc = bytes.fromhex("...")
known = b"0xL4ugh{say_yes_to_me"
for klen in range(2, 33):
    key = bytearray(klen)
    ok = True
    for i, b in enumerate(known):
        if i >= len(enc):
            break
        ki = i % klen
        v = (enc[i] ^ i) ^ b  # strip index XOR
        if key[ki] != 0 and key[ki] != v:
            ok = False
            break
        key[ki] = v
    if not ok:
        continue
    pt = bytes((enc[i] ^ i) ^ key[i % klen] for i in range(len(enc)))
    if all(32 <= c < 127 for c in pt):
        print(klen, key, pt)
```

---

## 혼합 모드(x86-64 / x86) 스테이저

**패턴:** 64비트 ELF는 대개 안티 디버그 이후 원거리 반환(`retf`/`retfq`)을 통해 32비트 blob으로 점프합니다.

**Identification:**
- 바이트 `0xCB`(retf) 또는 `0xCA`(retf imm16), 때로는 `0x48`(retfq)가 앞에옴
- 32비트 disasm은 긴밀한 루프에서 SSE 작업(`psubb`, `pxor`, `paddb`)을 표시합니다.
- 32비트 영역으로 계산된 점프

**Gotchas:**
- `retf` 팝 **6바이트**: 4바이트 EIP + 2바이트 CS(8 아님)
- 32비트 blob은 상속된 **XMM 상태** 및 **EFLAGS**에 의존할 수 있습니다.
- 에뮬레이터를 전환할 때 XMM/flags 전송이 누락되어 잘못된 출력이 발생함

**Bypass/Emulation 팁:**
1. UC_MODE_32 에뮬레이터 생성, 메모리 + GPR, **EFLAGS** 및 **XMM regs** 복사
2. 32비트 블록을 실행한 다음 메모리 + 레지스터를 다시 64비트로 복사합니다.
3. 안티 디버그가 `fork/ptrace` + 패치를 사용하는 경우 상위 항목을 에뮬레이트하여 POKE를 기록하고 하위 항목에 적용합니다.

---

## LLVM(저수준 가상 머신) 난독화(제어 흐름 평면화)

### Pattern
```c
while (1) {
    if (i == 0xA57D3848) { /* block */ }
    if (i != 0xA5AA2438) break;
    i = 0x39ABA8E6;  // Next state
}
```

### De-obfuscation
1. `je` 지침에서 중단되는 GDB 스크립트
2. 상태 변수 값 기록
3. 지도 상태 전환
4. 진정한 제어 흐름 재구성

**주요 통찰력:** 제어 흐름 평탄화는 구조화된 if/else/loops를 단일 디스패처 스위치로 대체합니다. 상태 변수가 핵심입니다. 정적으로 난독화 문제를 해결하지 않고도 런타임 시 해당 값을 추적하여 원래 제어 흐름 그래프를 재구성할 수 있습니다.

---

## S-Box / 키스트림 생성

### 피셔-예이츠 셔플(Xorshift32)
```python
def gen_sbox():
    sbox = list(range(256))
    state = SEED
    for i in range(255, -1, -1):
        state = ((state << 13) ^ state) & 0xffffffff
        state = ((state >> 17) ^ state) & 0xffffffff
        state = ((state << 5) ^ state) & 0xffffffff
        j = state % (i + 1) if i > 0 else 0
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox
```

### Xorshift64* Keystream
```python
def gen_keystream():
    ks = []
    mask = 0xffffffffffffffff
    state = SEED_64 & mask
    mul = 0x2545f4914f6cdd1d
    for _ in range(256):
        state = (state ^ (state >> 12)) & mask
        state = (state ^ (state << 25)) & mask
        state = (state ^ (state >> 27)) & mask
        output = (state * mul) & mask
        ks.append((output >> 56) & 0xff)
    return ks
```

### Identifying Patterns
- Xorshift32: 13, 17, 5 시프트(곱셈 상수 없음)
- Xorshift64*: 12, 25, 27을 시프트한 다음 `0x2545f4914f6cdd1d`를 곱합니다.
- 기타 공통 상수: `0x9e3779b97f4a7c15`(황금비)

**주요 통찰력:** Fisher-Yates 셔플 패턴(255부터 루프 카운트다운, PRNG가 선택한 인덱스로 교체)에 의한 S-box 생성과 xorshift 상수에 의한 키스트림 생성기를 인식합니다. PRNG 계열이 식별되면 알고리즘은 해당 시드에 의해 완전히 결정됩니다.

---

## SECCOMP/BPF 필터 분석

```bash
seccomp-tools dump ./binary
```

### BPF Analysis
- `A = sys_number` 다음에 비교가 옵니다.
- `mem[N] = A`, `A = mem[N]` 메모리 작업용
- 제약 방정식에 매핑하고 z3으로 해결

```python
from z3 import *
flag = [BitVec(f'c{i}', 32) for i in range(14)]
s = Solver()
s.add(flag[0] >= 0x20, flag[0] < 0x7f)
# Add constraints from filter
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[c].as_long()) for c in flag))
```

**주요 통찰력:** SECCOMP(보안 컴퓨팅 모드) 필터는 플래그 유효성 검사를 syscall 인수에서 작동하는 BPF 바이트코드로 인코딩합니다. `seccomp-tools`로 필터를 덤프하고, 비교 및 ​​메모리 작업을 z3 제약 조건으로 변환하고, 바이너리를 실행하지 않고도 플래그를 해결합니다.

---

## 예외 처리기 난독화

### RtlInstallFunctionTableCallback
- 동적으로 생성된 코드 영역의 x64 unwind/function-table 메타데이터를 제공하는 콜백을 등록합니다.
- 이것 자체가 예외 처리기를 등록하는 API는 아니지만, 난독화된 JIT·런타임 코드의 unwind 경계를 늦게 생성하는 데 쓰일 수 있습니다.
- 콜백과 반환된 `RUNTIME_FUNCTION` 범위를 추적한 뒤 실제 SEH/VEH 제어 흐름과 구분합니다.

### VEH(벡터 예외 처리기)
- `AddVectoredExceptionHandler` 핸들러 설치
- 핸들러는 예외 주소의 코드를 해독합니다.
- 단계별로 해독된 코드 덤프

**주요 통찰력:** 예외 핸들러 기반 난독화는 고의적인 오류에 대해 트리거되는 SEH/VEH 핸들러 내부의 실제 제어 흐름을 숨깁니다. 실제 실행 경로를 따르도록 오류가 있는 명령이 아닌 예외 처리기 내부에 중단점을 설정합니다.

---

## 메모리 덤프 분석

### 바이너리가 메모리를 덤프할 때
- `/proc/self/maps` 읽기 확인
- `/proc/self/mem` 읽기 확인
- 덤프에 종종 추가되는 힙 데이터

### 알려진 일반 텍스트 공격
```python
prologue = bytes([0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5])
encrypted = data[func_offset:func_offset+8]
partial_key = bytes(a ^ b for a, b in zip(encrypted, prologue))
```

**주요 통찰력:** `/proc/self/maps` 읽기는 매핑 탐색·안티분석·JIT·덤프 준비 등 여러 목적일 수 있고, 실제 바이트를 읽으려면 `/proc/self/mem`이나 다른 메모리 접근이 추가로 필요합니다. 덤프와 반복 XOR이 확인된 경우에만 대상 빌드에서 관찰한 프롤로그를 known plaintext로 사용하세요. `endbr64`와 frame-pointer 프롤로그는 CET·컴파일 옵션에 따라 없을 수 있습니다.

---

## 바이트별 균일 변환

**패턴:** 출력 버퍼는 각 입력 바이트에 독립적으로 의존합니다(교차 바이트 결합 없음).

**Detection:**
- 하나의 입력 위치 변경 → 하나의 출력 위치만 변경됨
- 단일 바이트로 입력 채우기 → 출력 버퍼가 일정해짐

**Solve:**
1. 각 바이트 값 0..255에 대해 해당 바이트를 반복하여 프로그램을 실행합니다.
2. 출력 바이트 기록 → 빌드 매핑 및 역 매핑
3. 플래그를 복구하려면 정적 대상 바이트에 역 매핑을 적용하세요.

---

## x86-64 Gotchas

### Sign Extension
```python
esi = 0xffffffc7  # 32-bit bit pattern; signed int32 is -57

# For XOR: low byte only
esi_xor = esi & 0xff  # 0xc7

# For addition: full 32-bit with overflow
r12 = (r13 + esi) & 0xffffffff  # a write to ESI zero-extends RSI on x86-64
```

### 루프 경계 상태 업데이트
어셈블리는 종종 루프 경계를 넘어 상태 업데이트를 분할합니다.
```asm
    jmp loop_middle        ; First iteration in middle!

loop_top:                   ; State for iterations 2+
    mov  r13, sbox[a & 0xf]
    ; Uses OLD 'a', not new!

loop_middle:
    ; Main computation
    inc  a
    jne  loop_top
```

**주요 통찰력:** 디컴파일러는 x86-64 기호 확장 및 루프 경계 상태 업데이트를 잘못하는 경우가 많습니다. 항상 `movsx`/`cdqe`와 관련된 작업의 원시 어셈블리에 대해 디컴파일된 출력을 확인하고, 루프 변수가 각 반복에서 사용되기 전후에 업데이트되는지 확인하세요.

---

## 사용자 정의 Mangle 기능 반전

**패턴(플래그 평가):** 바이너리는 중간 상태로 한 번에 2바이트 입력을 변조하며 정적 대상과 비교합니다.

**Approach:**
1. `.rodata` 섹션에서 정적 대상 바이트 추출
2. 맹글 이해: 실행 상태 값을 사용하여 쌍을 처리합니다.
3. 역함수 작성(역방향 처리, 각 작업 실행 취소)
4. 역을 통해 대상 바이트 공급 → 플래그 복구

**주요 통찰력:** 바이너리가 실행 상태와 쌍으로 입력을 조작하고 정적 대상과 비교할 때 `.rodata`에서 대상을 추출하고 역함수를 작성합니다. 원래 입력을 복구하려면 각 작업을 실행 취소하여 대상 바이트를 역순으로 처리합니다.

---

## 위치 기반 변환 반전

**패턴(PascalCTF 2026):** 이진은 입력을 adding/subtracting 위치 인덱스로 변환합니다.

**Reversing:**
```python
expected = [...]  # Extract from .rodata
flag = ''
for i, b in enumerate(expected):
    if i % 2 == 0:
        flag += chr(b - i)   # Even: input = output - i
    else:
        flag += chr(b + i)   # Odd: input = output + i
```

---

## 16진수로 인코딩된 문자열 비교

**패턴(거미의 저주):** 16진수 상수와 비교하여 16진수로 변환된 입력입니다.

**빠른 해결:** strings/Ghidra에서 16진수 상수를 추출하고 디코딩합니다.
```bash
echo "4d65746143..." | xxd -r -p
```

---

## 신호 기반 이진 탐색

**패턴(신호 신호 작은 별):** 바이너리는 UNIX 신호를 바이너리 트리 탐색 메커니즘으로 사용합니다.

**Identification:**
- `SA_SIGINFO`을 사용한 여러 `sigaction()` 호출
- `sigaltstack()` 설정(대체 신호 스택)
- 핸들러는 내장된 페이로드를 디코딩하고 다음 신호 쌍을 설치합니다.
- 두 가지 유형: 노드(하위 항목 설치)와 리프(메시지 인쇄 + 종료)

**Solving approach:**
1. `sigaction`를 통해 `LD_PRELOAD`을 연결하여 신호 설치를 기록합니다.
2. 신호를 보내 이진 트리를 통한 DFS
3. 각 단계에서 어떤 2개의 신호가 설치되어 있는지 관찰하세요.
4. 하나를 보내고 프로그램이 종료되는지 확인하거나(리프) 2개를 더 설치합니다(노드).
5. 리프가 잘못된 경우 뒤로 돌아가서 형제를 사용해 보세요.

```c
// LD_PRELOAD interposer to log sigaction calls
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>

int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact) {
    static int (*real_sigaction)(int, const struct sigaction *,
                                 struct sigaction *);
    if (!real_sigaction)
        real_sigaction = dlsym(RTLD_NEXT, "sigaction");
    if (act && (act->sa_flags & SA_SIGINFO))
        fprintf(stderr, "SET %d SA_SIGINFO=1\n", signum);
    return real_sigaction(signum, act, oldact);
}
```

---

## 패치를 통한 악성 코드 방지 분석 우회

**패턴(당근):** 페이로드를 실행하기 전에 여러 환경을 검사하는 악성코드입니다.

**패치할 일반적인 확인 사항:**
| Check | Technique | Patch |
|-------|-----------|-------|
| `ptrace(PTRACE_TRACEME)` | Anti-debug | 실제 반환값 검사와 실패 분기를 확인한 뒤 그 분기만 패치합니다. |
| `sleep(150)` | Anti-sandbox timing | 수면 값을 1로 변경 |
| `/proc/cpuinfo` "하이퍼바이저" | Anti-VM | `JNZ`에서 `JZ`로 뒤집기 |
| "VMware"/"VirtualBox" 문자열| Anti-VM | `JNZ`에서 `JZ`로 뒤집기 |
|`getpwuid` 사용자 이름 확인 | Environment | Flip comparison |
| `LD_PRELOAD` check | Anti-hook | Skip check |
| 팬 수/하드웨어 점검 | Anti-VM | `JLE`에서 `JGE`로 뒤집기 |
| Hostname check | Environment | `JNZ`에서 `JZ`로 뒤집기 |

**Ghidra 패치 작업 흐름:**
1. 확인 기능 찾기, 조건부 점프 식별
2. 명령어 클릭 → `Ctrl+Shift+G` → opcode 수정
3. `JNZ` (0x75) → `JZ` (0x74) 또는 그 반대의 경우
4. 즉치값의 경우: 피연산자 바이트를 직접 변경합니다.
5. `File → Export Program`에서 원본 형식을 선택해 새 파일로 내보냅니다.
6. `chmod +x` 패치된 바이너리

**서버측 유효성 검사 우회:**
아래 작업은 소유하거나 명시적으로 허가받은 테스트 서버에서만 수행합니다.

- 패치된 바이너리가 시스템 정보를 원격 서버로 보내는 경우 데이터도 패치합니다.
- 데이터 수집 기능에서 문자열 주소 수정
- 올바른 값을 직접 포함하도록 형식 문자열을 변경하세요.

---

## 다단계 쉘코드 로더

**패턴(로더를 좋아한다고 들었습니다):** XOR 디코드 루프와 디버그 방지 기능이 포함된 중첩 쉘코드입니다.

**Debugging workflow:**
1. 런처의 `call rax`에서 중단하고 쉘코드로 들어갑니다.
2. ptrace 안티 디버그 우회: syscall 단계, `set $rax=0`
3. XOR 디코드 루프를 단계별로 진행합니다(또는 숨겨진 경우 `int3`에서 중단).
4. 최종 페이로드까지 각 단계에서 반복합니다.

**`mov` 지침에서 플래그 추출:**
```python
# Final stage loads flag 4 bytes at a time via mov ebx, value
# Extract little-endian 4-byte chunks
values = [0x6174654d, 0x7b465443, ...]  # From disassembly
flag = b''.join(v.to_bytes(4, 'little') for v in values)
```

---

## 타이밍 부채널 공격

**패턴(시계 초과):** 검증 시간은 올바른 캐릭터에 따라 다릅니다(일치 시 더 긴 수면 시간).

**Exploitation:**
허가된 로컬 또는 CTF 서비스에서 요청 빈도 제한을 준수하며 측정하세요.

```python
import string
import time
from pwn import *

flag = ""
for pos in range(flag_length):
    best_char, best_time = '', 0
    for c in string.printable:
        io = remote(host, port)
        start = time.time()
        io.sendline((flag + c).ljust(total_len, 'X'))
        io.recvall()
        elapsed = time.time() - start
        if elapsed > best_time:
            best_time = elapsed
            best_char = c
        io.close()
    flag += best_char
```

---

## 미끼 + 신호 처리기 혼합 부울 산술을 사용한 다중 스레드 안티 디버그(ApoorvCTF 2026)

**패턴(A Golden Experience Requiem):** 계층형 안티 분석 기능이 포함된 멀티 스레드 바이너리: 스레드 1은 미끼 작업(가짜 AES + `ud2`을 통한 고의적 충돌)을 수행하고, 스레드 2는 MBA(혼합 부울 산술)를 사용하여 SIGSEGV 신호 처리기에서 실제 플래그 계산을 수행하고, 스레드 3은 사후 분석을 방지하기 위해 메모리를 지웁니다.

**Thread layout:**
| Thread | Purpose | Trap |
|--------|---------|------|
| Thread 1 | 미끼: AES처럼 보이는 작업 → `ud2` 충돌 | 분석가들은 가짜 암호화폐를 뒤집는 데 시간을 낭비합니다. |
| Thread 2 | 실제 플래그: MBA 변환이 포함된 SIGSEGV 핸들러 | 기본 코드 경로가 아닌 신호 처리기에 숨겨져 있습니다. |
| Thread 3 | 메모리 지우개: 계산 후 플래그 데이터를 0으로 만듭니다. | 메모리 덤핑 방지 |
| Main | rdtsc 기반 안티 디버그 타이밍 확인 | 디버거 연결 실행에 불이익을 줍니다. |

**해결 방법 — MBA 논리의 순수 Python 에뮬레이션:**
```python
# MBA helpers (extracted from assembly)
def mba_add(a, b): return (a + b) & 0xff
def mba_xor(a, b): return (a ^ b) & 0xff

def mba_transform(i):
    """Position-dependent transform from signal handler."""
    val = (i * 7 + 0x3f) & 0xff
    rotated = ((i << 3) | (i >> 5)) & 0xff
    return mba_xor(val, rotated)

# S-box (SHA-256 initial hash values repurposed)
SBOX = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def sbox_lookup(i):
    idx = i & 7
    shift = ((i >> 3) & 3) * 8
    return (SBOX[idx] >> shift) & 0xff

# Two interleaved rodata arrays (even indices → array1, odd → array2)
rodata1 = bytes.fromhex("39407691b717c97879013adf3a2adea11c2b04e0")
rodata2 = bytes.fromhex("bb19b025e37eaa786c4116e7aeea00c9c623940d")

flag = []
for i in range(40):  # flag length
    t = mba_transform(i)
    s = sbox_lookup(i)
    mem = rodata1[i // 2] if i % 2 == 0 else rodata2[i // 2]
    flag.append(chr(t ^ s ^ mem))

print(''.join(flag))
```

**주요 통찰력:** 실제 플래그 로직은 메인 스레드가 아닌 신호 처리기(SIGSEGV/SIGILL)에 있습니다. 스레드 1의 AES 유사 코드와 `ud2` 충돌은 의도적인 잘못된 방향입니다. `rdtsc` 타이밍 검사는 디버거를 감지하고 출력을 손상시킵니다. 어셈블리에서 MBA 로직을 추출하고 Python에서 다시 구현하여 우회합니다. 디버거에서 바이너리를 실행하지 마세요.

**Detection indicators:**
- 다양한 핸들러 기능을 사용한 다중 `pthread_create` 호출
- `signal(SIGSEGV, handler)` 또는 `sigaction` 설정
- `ud2` 지시(고의적인 불법 지시)
- `rdtsc` 타이밍 확인 지침
- 해싱이 아닌 조회 테이블로 사용되는 SHA-256 상수(0x6a09e667...)

---

## INT3 패치 + 코어 덤프 무차별 대입 Oracle(Pwn2Win 2016)

복잡한 변환 논리를 뒤집는 대신 변환 후 바이트를 `0xCC`(INT3)에 패치하고, 코어 덤프를 활성화하고, 바이너리를 실행하고 `strings`를 통해 코어 덤프에서 변환된 결과를 추출하여 각 문자를 무차별 대입합니다.

```bash
# Patch byte at transform output point to 0xCC
printf '\xcc' | dd of=binary bs=1 seek=$((0x400ebb)) conv=notrunc
ulimit -c unlimited
# Brute-force each position:
for c in $(seq 32 126); do
    echo -ne "$(printf '\\x%02x' $c)$known_suffix" | ./binary 2>/dev/null
    strings core | grep -q "$expected" && echo "Found: $c"
done
```

**주요 통찰력:** INT3/SIGTRAP를 중단점 Oracle로 사용합니다. 코어 덤프는 충돌 지점에서 계산된 상태를 캡처합니다. 변환의 전체 리버스 엔지니어링을 방지합니다.

---

## 신호 처리기 체인 + LD_PRELOAD Oracle(Nuit du Hack 2016)

Binary는 흐름 제어를 위해 Unix 신호를 사용합니다. `main()`는 SIGINT를 자신에게 1024번 보내고, 각 핸들러는 하나의 비밀번호 문자를 확인한 후 `signal()`를 호출하여 다음 핸들러를 설치합니다. 우회: 호출될 때(올바른 문자를 나타냄) 기록하는 사용자 정의 `signal()`를 LD_PRELOAD하고 각 위치에 무차별 공격을 가합니다.

```c
// LD_PRELOAD library:
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>

typedef void (*handler_t)(int);
handler_t signal(int sig, handler_t handler) {
    static handler_t (*real_signal)(int, handler_t);
    if (!real_signal)
        real_signal = dlsym(RTLD_NEXT, "signal");
    write(2, "CORRECT\n", 8);  // signal() called = char was correct
    return real_signal(sig, handler);
}
```

**주요 통찰력:** 신호 처리기 체인 반전 방지는 LD_PRELOAD를 통해 `signal()`를 연결하여 무력화할 수 있습니다. `signal()`(다음 핸들러 설치)에 대한 호출은 현재 문자를 확인하는 부채널 역할을 합니다.

---

## printf 형식 문자열 VM을 Z3으로 디컴파일(SECCON 2017)

`%hhn` 형식 문자열을 통해 완전히 구현된 "가상 머신"입니다. 형식 문자열 `%hhn`은 인쇄된 문자 수(mod 256)를 가리키는 바이트에 씁니다. `%Nc%hhn` 명령어 시퀀스는 임의의 바이트-메모리 쓰기를 구현하여 효과적으로 바이트코드 VM을 생성합니다.

**1단계: 지침 유형을 식별합니다.**
명령어 세트를 결정하기 위해 고유한 형식 패턴을 계산합니다.
```bash
# Normalize numbers and count unique patterns
sed -e 's/[[:digit:]]\+/1/g' program.fs | sort | uniq -c | sort -nr
```

**2단계: 디컴파일러 작성.**
형식 패턴을 C 스타일 의사코드로 변환합니다. 각 `%N...%hhn` 쌍은 메모리 쓰기에 매핑됩니다. 쓰기 주소(인수 포인터에서)와 값(문자 수에서)을 추출합니다.

**3단계: 알고리즘 인식.**
의사코드는 일반적으로 바이트에 대한 선형 방정식 시스템을 나타냅니다. 메모리 주소를 기호 변수에 매핑합니다.

**4단계: Z3 제약 조건을 생성하고 해결합니다.**
```python
from z3 import *

flag_len = 32  # adjust based on decompiled output
flag = [BitVec(f'f{i}', 8) for i in range(flag_len)]
s = Solver()

# Constrain to printable ASCII
for f in flag:
    s.add(f >= 0x20, f <= 0x7e)

# Add constraints from decompiled format string operations
# e.g., flag[3] + flag[7] == 0xAB (mod 256)
# These come from the write sequences: each %hhn accumulates
# character counts and writes the result to a target byte
s.add((flag[0] + flag[1]) & 0xFF == 0x9A)  # example constraint
s.add((flag[2] ^ flag[3]) & 0xFF == 0x3F)  # example constraint
# ... (add all constraints from decompilation)

if s.check() == sat:
    m = s.model()
    print(bytes([m[f].as_long() for f in flag]))
```

**디컴파일 방식 세부정보:**
1. 각 `%N...%hhn` 쌍에서 쓰기 주소와 값을 추출합니다.
2. 메모리 주소를 기호 변수(플래그 바이트)에 매핑
3. 쓰기 시퀀스에서 방정식 시스템 구축
4. Z3으로 해결

**주요 정보:** 형식 문자열 `%hhn`는 인쇄된 문자 수(mod 256)를 가리키는 바이트에 씁니다. `%Nc%hhn` 명령어 시퀀스는 임의의 바이트-메모리 쓰기를 구현하여 효과적으로 바이트코드 VM을 생성합니다. 디컴파일 방법: (1) 각 `%N...%hhn` 쌍에서 쓰기 주소와 값을 추출하고, (2) 메모리 주소를 기호 변수에 매핑하고, (3) 쓰기 시퀀스에서 방정식 시스템을 구축하고, (4) Z3으로 해결합니다.

**References:** SECCON 2017
