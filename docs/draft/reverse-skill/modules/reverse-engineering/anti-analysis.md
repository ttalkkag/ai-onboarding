# CTF Reverse - 안티 분석 기술 및 우회

실용적인 우회 방법을 통해 CTF 문제에서 발생하는 디버깅 방지, VM 방지, DBI 방지 및 무결성 검사 기술에 대한 포괄적인 참조 자료입니다.

## 목차
- [Linux 안티 디버그(고급)](#linux-안티-디버그고급)
  - [ptrace-Based](#ptrace-based)
  - [/proc 파일 시스템 검사](#proc-파일-시스템-검사)
  - [Timing-Based Detection](#timing-based-detection)
  - [Signal-Based Anti-Debug](#signal-based-anti-debug)
  - [Syscall-Level Evasion](#syscall-level-evasion)
- [Windows 디버그 방지(고급)](#windows-디버그-방지고급)
  - [PEB(프로세스 환경 블록) 검사](#peb프로세스-환경-블록-검사)
  - [NtQueryInformationProcess](#ntqueryinformationprocess)
  - [Heap Flags](#heap-flags)
  - [TLS Callbacks](#tls-callbacks)
  - [하드웨어 중단점 감지](#하드웨어-중단점-감지)
  - [소프트웨어 중단점 감지(INT3 검색)](#소프트웨어-중단점-감지int3-검색)
  - [Exception-Based Anti-Debug](#exception-based-anti-debug)
  - [NtSetInformationThread(스레드 숨기기)](#ntsetinformationthread스레드-숨기기)
- [Anti-VM / Anti-Sandbox](#anti-vm--anti-sandbox)
  - [CPUID 하이퍼바이저 비트](#cpuid-하이퍼바이저-비트)
  - [MAC 주소/하드웨어 핑거프린팅](#mac-주소하드웨어-핑거프린팅)
  - [타이밍 기반 VM 감지](#타이밍-기반-vm-감지)
  - [파일/레지스트리 아티팩트](#파일레지스트리-아티팩트)
  - [리소스 확인(CPU 수, RAM, 디스크)](#리소스-확인cpu-수-ram-디스크)
- [안티-DBI(동적 바이너리 계측)](#안티-dbi동적-바이너리-계측)
  - [Frida Detection](#frida-detection)
  - [Pin/DynamoRIO 감지](#pindynamorio-감지)
- [코드 무결성/셀프 해싱](#코드-무결성셀프-해싱)
- [Anti-Disassembly Techniques](#anti-disassembly-techniques)
  - [Opaque Predicates](#opaque-predicates)
  - [정크 바이트/중복 지침](#정크-바이트중복-지침)
  - [Jump-in-the-Middle](#jump-in-the-middle)
  - [함수 청킹/분산 코드](#함수-청킹분산-코드)
  - [제어 흐름 평탄화(고급)](#제어-흐름-평탄화고급)
  - [혼합 부울 산술(MBA) 식별 및 단순화](#혼합-부울-산술mba-식별-및-단순화)
- [실행 모드 전환을 위한 SIGILL 핸들러(Hack.lu 2015)](#실행-모드-전환을-위한-sigill-핸들러hacklu-2015)
- [strace 계산을 통한 SIGFPE 신호 처리기 측면 채널(PlaidCTF 2017)](#strace-계산을-통한-sigfpe-신호-처리기-측면-채널plaidctf-2017)
- [Keystone 및 Unicorn을 사용한 명령 추적 반전(MeePwn CTF 2017)](#keystone-및-unicorn을-사용한-명령-추적-반전meepwn-ctf-2017)
  - [스택 프레임 조작을 통한 무호출 함수 체이닝(THC CTF 2018)](#스택-프레임-조작을-통한-무호출-함수-체이닝thc-ctf-2018)
- [포괄적인 우회 전략](#포괄적인-우회-전략)
  - [유니버설 바이패스 체크리스트](#유니버설-바이패스-체크리스트)
  - [계층화된 안티디버그(실제 패턴)](#계층화된-안티디버그실제-패턴)
  - [빠른 참조: 우회 확인](#빠른-참조-우회-확인)

---

## Linux 안티 디버그(고급)

### ptrace-Based

**자체 ptrace(가장 일반적):**
```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) exit(1); // Already traced = debugger attached
```

**Bypasses:**
```text
# 1. LD_PRELOAD (see patterns.md for full hook)
LD_PRELOAD=./hook.so ./binary

# 2. Patch with pwntools
python3 -c "
from pwn import *
elf = ELF('./binary', checksec=False)
elf.asm(elf.symbols.ptrace, 'xor eax, eax; ret')
elf.save('patched')
"

# 3. GDB: catch the syscall
gdb ./binary
(gdb) catch syscall ptrace
(gdb) run
# catch syscall stops on both entry and return. Continue past the entry stop,
# then replace the return value at the second stop:
(gdb) continue
(gdb) set $rax = 0
(gdb) continue
```

`kernel.yama.ptrace_scope`는 프로세스 간 attach 정책을 제한하는 설정이며, 대상 프로세스의 `PTRACE_TRACEME` 호출을 성공으로 바꾸는 우회가 아닙니다.

**Double-ptrace pattern:**
```c
// Fork child to ptrace parent — blocks all other debuggers
pid_t child = fork();
if (child == 0) {
    ptrace(PTRACE_ATTACH, getppid(), 0, 0);
    // Child sits in waitpid loop, keeping parent traced
} else {
    // Parent continues with real logic
}
```
**우회:** 감시 하위 프로세스를 종료한 다음 디버거를 연결합니다.

### /proc 파일 시스템 검사

```c
// TracerPid check
FILE *f = fopen("/proc/self/status", "r");
// Looks for "TracerPid:\t0" — non-zero means debugger

// /proc/self/exe link check (some debuggers change this)
readlink("/proc/self/exe", buf, sizeof(buf));

// /proc/self/maps — check for debugger libraries
grep("frida", "/proc/self/maps");
```

**Bypasses:**
```text
# 1. LD_PRELOAD fopen/fread to fake /proc contents
# 2. Mount namespace isolation
unshare -m bash -c 'mount --bind /dev/null /proc/self/status && ./binary'

# 3. GDB: set breakpoint at fopen, change filename argument
(gdb) b fopen
(gdb) run
(gdb) set {char[20]} $rdi = "/dev/null"
(gdb) continue
```

### Timing-Based Detection

```c
// rdtsc (CPU timestamp counter)
uint64_t start = __rdtsc();
// ... code ...
uint64_t delta = __rdtsc() - start;
if (delta > THRESHOLD) exit(1);  // too slow = debugger

// clock_gettime
struct timespec ts1, ts2;
clock_gettime(CLOCK_MONOTONIC, &ts1);
// ... code ...
clock_gettime(CLOCK_MONOTONIC, &ts2);

// gettimeofday
struct timeval tv1, tv2;
gettimeofday(&tv1, NULL);
```

**Bypasses:**
```text
# 1. Frida hook (see tools-dynamic.md for clock_gettime hook)

# 2. GDB: skip rdtsc by patching with constant
(gdb) set {unsigned char[2]} 0x401234 = {0x90, 0x90}  # NOP the rdtsc

# 3. Pin tool to fix TSC reads
# 4. faketime library
LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="2024-01-01" ./binary
```

### Signal-Based Anti-Debug

```c
// SIGTRAP handler — INT3 under debugger is caught by debugger, not handler
signal(SIGTRAP, handler);
__asm__("int3");
// If handler runs: no debugger. If debugger catches: debugged.

// SIGALRM timeout — kill self if analysis takes too long
signal(SIGALRM, kill_handler);
alarm(5);

// SIGSEGV handler that does real work (see patterns.md for MBA pattern)
signal(SIGSEGV, real_logic_handler);
*(int*)0 = 0;  // deliberate crash → handler runs real code
```

**Bypasses:**
```text
# GDB: pass signals to program instead of handling them
(gdb) handle SIGTRAP nostop pass
(gdb) handle SIGALRM ignore
(gdb) handle SIGSEGV nostop pass

# For alarm-based: patch alarm() to return immediately
```

### Syscall-Level Evasion

```c
// Direct syscall instead of libc — bypasses LD_PRELOAD hooks
long ret;
register long r10 __asm__("r10") = 0;
asm volatile("syscall"
             : "=a"(ret)
             : "a"(101L), "D"(0L), "S"(0L), "d"(0L), "r"(r10)
             : "rcx", "r11", "memory");
// Syscall 101 = ptrace on x86_64
```

**우회:** 바이너리 자체를 패치하거나 ptrace를 사용하여 syscall 수준에서 가로채야 합니다.
```text
# GDB: catch syscall
(gdb) catch syscall 101
(gdb) run
# First stop is syscall entry; second is syscall return.
(gdb) continue
(gdb) set $rax = 0
(gdb) continue
```

---

## Windows 디버그 방지(고급)

### PEB(프로세스 환경 블록) 검사

```c
// BeingDebugged flag (offset 0x2 in PEB)
bool debugged = NtCurrentPeb()->BeingDebugged;

// NtGlobalFlag (offset 0x68/0xBC in PEB)
// When debugger: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS = 0x70
DWORD flags = *(DWORD*)((BYTE*)NtCurrentPeb() + 0xBC); // 64-bit offset
if (flags & 0x70) exit(1);
```

**Bypass (x64dbg):**
```text
# ScyllaHide plugin auto-patches PEB fields
# Manual: dump PEB, zero BeingDebugged and NtGlobalFlag
```

### NtQueryInformationProcess

```c
// ProcessDebugPort (0x7)
DWORD_PTR debugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) exit(1);

// ProcessDebugObjectHandle (0x1E)
HANDLE debugObj = NULL;
NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0x1E, &debugObj, sizeof(debugObj), NULL);
if (status == 0) exit(1); // STATUS_SUCCESS means debugger present

// ProcessDebugFlags (0x1F) — returns inverse: 0 = debugger present
DWORD noDebug = 0;
NtQueryInformationProcess(GetCurrentProcess(), 0x1F, &noDebug, sizeof(noDebug), NULL);
if (noDebug == 0) exit(1);
```

**우회:** `NtQueryInformationProcess`를 연결하여 가짜 값을 반환하거나 ScyllaHide를 사용하세요.

### Heap Flags

```c
// Process heap has debug flags when debugger attached
PHEAP heap = (PHEAP)GetProcessHeap();
// Flags at offset 0x70 (64-bit): should be HEAP_GROWABLE (0x2)
// ForceFlags at offset 0x74: should be 0
if (heap->Flags != 0x2 || heap->ForceFlags != 0) exit(1);
```

### TLS Callbacks

**주요 기술:** TLS(스레드 로컬 저장소) 콜백은 `main()` / 진입점 이전에 실행됩니다.

```c
// Registered in PE header's TLS directory
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent()) {
            ExitProcess(1);  // Kills process before main runs
        }
    }
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK callbacks[] = { TlsCallback, NULL };
```

**IDA/Ghidra에서 감지:** PE TLS 디렉터리 → AddressOfCallBacks를 확인하세요. 여기에 나열된 기능은 EP 이전에 실행됩니다.

**우회:** x64dbg(옵션 → 이벤트 → TLS 콜백)에서 TLS 콜백에 중단점을 설정하거나 TLS 디렉토리 항목을 패치합니다.

### 하드웨어 중단점 감지

```c
// GetThreadContext(GetCurrentThread(), ...) may report success but returns
// an invalid context. Inspect a suspended *different* thread, or inspect the
// CONTEXT supplied to an exception handler.
BOOL debug_registers_set(const CONTEXT *ctx) {
    return ctx->Dr0 || ctx->Dr1 || ctx->Dr2 || ctx->Dr3;
}
```

**Bypass:**
```bash
# x64dbg: use software breakpoints instead, or hook GetThreadContext
# Frida: hook GetThreadContext to zero DR registers
```

### 소프트웨어 중단점 감지(INT3 검색)

```c
// CRC / hash check over code section
unsigned char *code = (unsigned char*)function_addr;
uint32_t checksum = 0;
for (int i = 0; i < code_size; i++) {
    checksum += code[i];
    if (code[i] == 0xCC) exit(1);  // INT3 = software breakpoint
}
if (checksum != EXPECTED_CHECKSUM) exit(1);
```

**우회:** 소프트웨어 중단점 대신 하드웨어 중단점(DR0-DR3)을 사용합니다. 또는 스캔 기능을 연결하십시오.

### Exception-Based Anti-Debug

```c
// A debugger receives the exception first. Whether the process filter later
// runs depends on the debugger's first-/second-chance handling configuration.
SetUnhandledExceptionFilter(handler);
RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);

// INT 2D behavior also varies by Windows version, debugger, and debugger state.
__asm { int 2dh }
```

### NtSetInformationThread(스레드 숨기기)

```c
// Hide thread from debugger — stops all debug events
typedef NTSTATUS(NTAPI *pNtSIT)(HANDLE, ULONG, PVOID, ULONG);
pNtSIT NtSIT = (pNtSIT)GetProcAddress(GetModuleHandle("ntdll"), "NtSetInformationThread");
NtSIT(GetCurrentThread(), 0x11 /*ThreadHideFromDebugger*/, NULL, 0);
// After this, debugger won't see breakpoints or exceptions from this thread
```

**우회:** `NtSetInformationThread`를 연결하여 클래스 0x11을 무시하거나 호출을 패치합니다.

---

## Anti-VM / Anti-Sandbox

### CPUID 하이퍼바이저 비트

```c
int regs[4];
__cpuid(regs, 1);
if (regs[2] & (1 << 31)) {  // ECX bit 31 = hypervisor present
    exit(1);
}

// Hypervisor brand string
__cpuid(regs, 0x40000000);
char brand[13] = {0};
memcpy(brand, &regs[1], 12);
// "VMwareVMware", "Microsoft Hv", "KVMKVMKVM", "XenVMMXenVMM"
```

**우회:** `cpuid` 결과를 패치하거나 `LD_PRELOAD`를 사용하여 래퍼 기능을 연결합니다.

### MAC 주소/하드웨어 핑거프린팅

```text
Known VM MAC prefixes:
  VMware:     00:0C:29, 00:50:56
  VirtualBox: 08:00:27
  Hyper-V:    00:15:5D
  Parallels:  00:1C:42
  QEMU:       52:54:00
```

### 타이밍 기반 VM 감지

```c
// VM exits on privileged instructions are measurably slower
uint64_t start = __rdtsc();
__cpuid(regs, 0);  // Forces VM exit
uint64_t delta = __rdtsc() - start;
if (delta > 500) { /* likely VM */ }
```

### 파일/레지스트리 아티팩트

```text
Files: C:\Windows\System32\drivers\vm*.sys, vbox*.dll, VBoxService.exe
Registry: HKLM\SOFTWARE\VMware, Inc.\VMware Tools
Services: VMTools, VBoxService
Processes: vmtoolsd.exe, VBoxTray.exe, qemu-ga.exe
Linux: /sys/class/dmi/id/product_name contains "VirtualBox"|"VMware"
       dmesg | grep -i "hypervisor detected"
```

### 리소스 확인(CPU 수, RAM, 디스크)

```c
// Sandboxes typically have minimal resources
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) exit(1);

MEMORYSTATUSEX ms;
ms.dwLength = sizeof(ms);
GlobalMemoryStatusEx(&ms);
if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) exit(1); // < 2GB RAM

// Disk size check (< 60GB = sandbox)
GetDiskFreeSpaceEx("C:\\", NULL, &total, NULL);
```

**우회:** 적절한 리소스(4개 이상의 CPU, 8GB+ RAM, 100GB+ 디스크)로 구성된 VM을 사용합니다.

---

## 안티-DBI(동적 바이너리 계측)

### Frida Detection

```c
// 1. Check /proc/self/maps for frida-agent
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
    if (strstr(line, "frida") || strstr(line, "gadget")) exit(1);
}

// 2. Check for Frida's default port (27042)
int sock = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(27042), .sin_addr.s_addr=inet_addr("127.0.0.1")};
if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) exit(1);

// 3. Check for inline hooks (function prologue modification)
// Compare first bytes of libc functions against expected values
unsigned char *strcmp_bytes = (unsigned char *)strcmp;
if (strcmp_bytes[0] == 0xE9 || strcmp_bytes[0] == 0xFF) exit(1); // JMP = hooked

// 4. Thread name check
// Frida creates threads with names like "gmain", "gdbus", "frida-*"
DIR *dir = opendir("/proc/self/task");
while ((entry = readdir(dir))) {
    char comm_path[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", entry->d_name);
    // Read comm and check for "gmain", "gdbus"
}

// 5. Named pipe detection (Windows)
// Frida creates \\.\pipe\frida-* named pipes
```

**Frida 탐지 우회:**
```javascript
// Hook the detection functions themselves
Interceptor.attach(Module.getGlobalExportByName("strstr"), {
    onEnter(args) {
        this.haystack = args[0].readUtf8String();
        this.needle = args[1].readUtf8String();
    },
    onLeave(retval) {
        if (this.needle && (this.needle.includes("frida") || this.needle.includes("gadget"))) {
            retval.replace(ptr(0)); // Not found
        }
    }
});

// Early Frida load (before anti-DBI runs)
// Use frida-gadget as early-init shared library
```

### Pin/DynamoRIO 감지

```c
// Check for instrumentation libraries in /proc/self/maps
// Pin: "pin-", "pinbin", "pinatrace"
// DynamoRIO: "dynamorio", "drcov", "drrun"

// Instruction count timing — DBI adds overhead
// Execute known instruction sequence, compare execution time
```

---

## 코드 무결성/셀프 해싱

```c
// CRC32 over .text section
uint32_t crc = compute_crc32(text_start, text_size);
if (crc != EXPECTED_CRC) exit(1);  // Code was modified (breakpoints, patches)

// MD5/SHA256 of function bodies
unsigned char hash[32];
SHA256(function_addr, function_size, hash);
if (memcmp(hash, expected_hash, 32) != 0) exit(1);
```

**Bypasses:**
1. **하드웨어 중단점**(코드 수정 안 함, DR0-DR3)
2. **비교 패치**를 통해 항상 성공
3. **해시 함수를 연결**하여 예상 값 반환
4. 디버그 대신 **에뮬레이션**(Unicorn/Qiling — 코드 수정 없음)
5. **스냅샷 + 복원:** 이전과 이후의 메모리 덤프, 차이점을 비교하여 확인 항목 찾기

**루프 내 자체 체크섬:**
```c
// Continuous integrity check in separate thread
void *watchdog(void *arg) {
    while (1) {
        if (compute_crc32(text_start, text_end - text_start) != saved_crc) {
            memset(flag_buffer, 0, flag_len);  // Destroy flag
            exit(1);
        }
        usleep(100000);
    }
}
```
**우회:** 감시 스레드를 종료하거나 절전 모드를 무한으로 패치합니다.

---

## Anti-Disassembly Techniques

### Opaque Predicates

```asm
; Condition that always evaluates the same way but looks data-dependent
mov eax, [some_memory]
lea ecx, [eax + 1]
imul eax, ecx          ; x * (x + 1)
and eax, 1             ; consecutive integers' product is always even
jnz fake_branch        ; Never taken, but disassembler doesn't know
; real code here
```

**신원:** Z3/SMT 분기가 always/never 사용되었음을 증명할 수 있습니다.

### 정크 바이트/중복 지침

```asm
jmp real_code
db 0xE8           ; Looks like start of CALL to linear disassembler
real_code:
mov eax, 1        ; Real code — disassembler may misalign here
```

**수정:** 그래프 모드 분해로 전환합니다(Ghidra/IDA 잘 처리하세요). 수동: 올바른 오프셋에서 정의를 해제하고 다시 분석합니다.

### Jump-in-the-Middle

```asm
; Jumps into the middle of a multi-byte instruction
eb 01          ; jmp +1 (skip next byte)
e8             ; fake CALL opcode — disassembler tries to decode as call
90             ; real: NOP (landed here from jmp)
```

### 함수 청킹/분산 코드

무조건 점프로 연결된 비연속적인 청크로 분할된 기능입니다. 선형 함수 경계 감지를 무효화합니다.

**도구:** 각 청크에서 IDA의 "함수 꼬리 추가" 또는 Ghidra의 "함수 생성".

### 제어 흐름 평탄화(고급)

기본 스위치 케이스 이상(patterns.md 참조): 최신 OLLVM 변형은 다음을 사용합니다.
- **가짜 제어 흐름:** 불투명한 술어가 있는 가짜 분기
- **명령 대체:** `a + b` → `a - (-b)`, `a ^ b` → `(a | b) & ~(a & b)`
- **문자열 암호화:** 런타임에 문자열이 해독되고 사용 후 지워집니다.

**Deobfuscation tools:**
- **D-810** (IDA 플러그인): 패턴 기반 난독화, MBA 단순화
- **GOOMBA**(Ghidra): OLLVM에 대한 자동 난독화 해제
- **Miasm**: 난독화를 위한 기호 실행
- **Arybo** / **SiMBA**: MBA 표현 단순화

```bash
# D-810: install in IDA plugins directory, Edit → Plugins → D-810
# Simplifies MBA expressions: (a | b) & ~(a & b) → a ^ b
# Removes opaque predicates via pattern matching
```

### 혼합 부울 산술(MBA) 식별 및 단순화

```python
# Common MBA patterns and their simplified forms:
# (x & y) + (x | y) == x + y
# (x ^ y) + 2*(x & y) == x + y
# (x | y) - (x & ~y) == y
# ~(~x & ~y) == x | y (De Morgan's)
# (x | y) & ~(x & y) == x ^ y

# SiMBA tool for automated simplification:
# pip install simba-simplifier
from simba import simplify_mba
expr = "(a ^ b) + 2*(a & b)"
print(simplify_mba(expr))  # → a + b
```

---

## 실행 모드 전환을 위한 SIGILL 핸들러(Hack.lu 2015)

바이너리는 x86과 x86-64 실행 모드 사이를 전환하거나 사용자 정의 opcode 디스패치를 구현하기 위해 SIGILL(불법 명령어) 핸들러를 설치할 수 있습니다.

1. **신호 등록:** `signal(SIGILL, handler)` 불법 명령 예외에 대한 콜백 설치
2. **모드 전환:** 핸들러는 저장된 명령 포인터 또는 세그먼트 레지스터를 수정하여 32비트와 64비트 코드 사이를 전환합니다.
3. **사용자 정의 opcode:** 잘못된 x86 명령어는 피연산자 바이트를 사용자 정의 VM opcode로 해석하는 핸들러를 트리거합니다.

```c
// Signal handler decodes "illegal" instructions as custom opcodes
void sigill_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *ctx = (ucontext_t *)ucontext;
    unsigned char *pc = (unsigned char *)ctx->uc_mcontext.gregs[REG_RIP];
    // Decode custom opcode from bytes at PC
    // Advance PC past the custom instruction
    ctx->uc_mcontext.gregs[REG_RIP] += opcode_length;
}
```

**주요 통찰력:** 바이너리가 실행 초기에 SIGILL/SIGSEGV/SIGTRAP에 대한 신호 처리기를 설치하는 경우 사용자 지정 명령 전달이 의심됩니다. `strace -e signal`로 신호 전달을 추적하거나 GDB를 가로채지 않도록 설정하세요: `handle SIGILL nostop pass`.

---

## strace 계산을 통한 SIGFPE 신호 처리기 측면 채널(PlaidCTF 2017)

Binary는 제어 흐름을 위해 SIGFPE 신호 처리기를 사용하므로 정적 분석을 신뢰할 수 없습니다. strace를 통해 SIGFPE 신호를 계산하는 무차별 대입 — 올바른 입력 문자는 더 많은 신호를 생성합니다.

```bash
# Count SIGFPE signals per input character guess
for c in {a..z} {A..Z} {0..9}; do
    count=$(echo -n "${c}AAAAAAA" | strace -e signal=SIGFPE ./binary 2>&1 | grep -c SIGFPE)
    echo "$c: $count"
done
# Character producing the most SIGFPEs is correct
# Repeat for each position, extending the known prefix
```

**주요 통찰력:** 신호 처리기(SIGFPE, SIGSEGV, SIGILL)는 정적 분석에 보이지 않는 암시적 제어 흐름을 생성합니다. 제기된 신호의 수는 검증 진행 상황과 관련이 있습니다. `strace -e signal=SIGFPE`를 통해 신호를 계산하면 불투명한 신호 기반 검증이 문자별 무차별 대입을 위한 측정 가능한 부채널로 전환됩니다.

---

## Keystone 및 Unicorn을 사용한 명령 추적 반전(MeePwn CTF 2017)

UPX로 압축된 바이너리는 일련의 산술 전용 변환(sub, add, xor, rol, ror)을 플래그에 적용합니다. 메모리 부작용이 없습니다. 순전히 산술을 등록합니다. IDAPython은 점프하지 않는 명령어를 추적한 다음 플래그를 복구하기 위해 시퀀스를 반전시킵니다.

**Inversion rules:**
- 명령어 순서를 반대로 합니다(마지막 명령어부터)
- 역쌍 교환: `add ↔ sub`, `rol ↔ ror`, `xor`는 자기 역전입니다.

```python
# IDAPython: collect non-jump instructions in the obfuscated routine
import idaapi, idc

def trace_transforms(start_ea, end_ea):
    instructions = []
    ea = start_ea
    while ea < end_ea:
        mnem = idc.print_insn_mnem(ea)
        if mnem not in ('jmp', 'je', 'jne', 'call', 'ret'):
            instructions.append((ea, mnem, idc.print_operands(ea)))
        ea = idc.next_head(ea)
    return instructions

transforms = trace_transforms(0x401000, 0x401200)

# Invert: reverse order, swap add/sub and rol/ror
inverse_map = {'add': 'sub', 'sub': 'add', 'rol': 'ror', 'ror': 'rol', 'xor': 'xor'}
inverted = [(mnem, op) for (_, mnem, op) in reversed(transforms)]
inverted = [(inverse_map.get(m, m), op) for m, op in inverted]
```

```python
# Assemble inverted instructions with Keystone, emulate with Unicorn
from keystone import *
from unicorn import *
from unicorn.x86_const import *

ks = Ks(KS_ARCH_X86, KS_MODE_64)
uc = Uc(UC_ARCH_X86, UC_MODE_64)

asm_src = '\n'.join(f'{mnem} {op}' for mnem, op in inverted)
encoding, _ = ks.asm(asm_src)

CODE_BASE = 0x400000
uc.mem_map(CODE_BASE, 0x10000)
uc.mem_write(CODE_BASE, bytes(encoding))

# Set initial register state to the observed output value
uc.reg_write(UC_X86_REG_RAX, known_output)
uc.emu_start(CODE_BASE, CODE_BASE + len(encoding))
flag_bytes = uc.reg_read(UC_X86_REG_RAX).to_bytes(8, 'little')
```

**PEB 안티 디버그 참고 사항:** 바이너리가 `PEB.BeingDebugged`를 읽고 이를 사용하여 두 비교 대상 값 사이를 선택하는 경우 IDAPython에서 추적된 명령어는 디버그 모드 대상을 사용할 수 있습니다. 추적하기 전에 `BeingDebugged`을 0으로 패치하거나 두 분기를 모두 식별하고 디버그가 아닌 대상 값을 사용하세요.

**주요 통찰력:** 산술 전용 난독화(메모리 쓰기 없음)는 추적, 명령어 순서 반전, 역연산 교환을 통해 완전히 되돌릴 수 있습니다. PEB 안티 디버그는 비교 대상을 자동으로 변경할 수 있습니다. 항상 어떤 분기가 사용되는지 확인하세요.

**참고 자료:** MeePwn CTF 2017

---

### 스택 프레임 조작을 통한 무호출 함수 체이닝(THC CTF 2018)

**패턴:** 바이너리는 스택에 함수 포인터의 연결된 목록을 구축한 다음 저장된 RBP 및 반환 주소를 수정하여 `leave; ret` 명령어가 명시적인 `CALL` 명령어 없이 목록을 통해 연결되도록 하여 함수 호출을 숨깁니다. IDA는 push/pop가 불균형하고 기능 경계를 결정할 수 없기 때문에 디컴파일에 실패합니다.

체인의 각 기능은 다음과 같습니다.
1. 피연산자와 다음 함수의 주소를 스택에 푸시합니다.
2. 다음 스택 프레임을 가리키도록 저장된 RBP를 설정합니다.
3. 반환 주소를 다음 함수로 설정합니다.
4. `leave` RBP에서 RSP를 복원하고(다음 프레임으로 이동), `ret` 다음 기능으로 점프합니다.

```python
# Reversed processing chain (each function applied via leave/ret):
def reverse_processing(byte):
    res = byte | 0x80       # OR 0x80
    res = res ^ 0xCA        # XOR 0xCA
    res = (res + 66) & 0xFF # ADD 66
    res = res ^ 0xCA        # XOR 0xCA (repeated)
    res = (res + 66) & 0xFF
    res = res ^ 0xCA
    res = (res + 66) & 0xFF
    res = res ^ 0xFE        # XOR 0xFE (final)
    return res
# Apply in reverse order, then reverse the character sequence
```

**주요 통찰력:** 다음 스택 프레임을 가리키도록 저장된 RBP를 조작하고 다음 함수에 대해 저장된 RIP를 조작함으로써 `leave; ret`는 `call` 명령 없이 함수를 통해 연결됩니다. call/ret 균형을 추적하는 디스어셈블러는 기능 경계를 식별하지 못합니다. IDA가 처리할 수 있도록 각 함수 본문을 개별적으로 패치합니다.

**탐지:** `leave; ret`로 끝나는 작은 코드 블록이 많이 있지만 해당 `call` 명령어가 없는 바이너리입니다. 스택에는 인터리브된 함수 포인터와 데이터가 포함되어 있습니다. IDA는 "스택 프레임이 너무 큽니다"를 표시하거나 함수 생성에 실패합니다.

**참고자료:** THC CTF 2018

---

## 포괄적인 우회 전략

### 유니버설 바이패스 체크리스트

1. **모든 분석 방지 확인 확인** — 검색: `ptrace`, `IsDebuggerPresent`, `rdtsc`, `cpuid`, `NtQuery`, `GetTickCount`, `CheckRemoteDebuggerPresent`, `/proc/self`, `SIGTRAP`, `alarm`
2. **정적 패치** — NOP/patch 실행 전 pwntools 또는 Ghidra로 확인합니다.
3. **LD_PRELOAD** (Linux) — 가짜 값을 반환하는 후크 libc 함수
4. **ScyllaHide** (Windows x64dbg) — PEB 패치, NT 기능 자동 후크
5. **에뮬레이션**(Unicorn/Qiling) — 일반 디버거와 다른 환경이지만 에뮬레이터 지문과 미구현 API는 대상별 처리 필요
6. **커널 수준 관찰** — 격리된 분석 VM에서만 커널 디버거/추적 도구를 사용

### 계층화된 안티디버그(실제 패턴)

많은 CTF 과제에는 여러 가지 확인 사항이 쌓입니다.
```text
1. TLS callback → IsDebuggerPresent (before main)
2. main() → ptrace(TRACEME)
3. Watchdog thread → timing check + /proc scan
4. Code section → self-CRC32 integrity
5. Signal handler → real logic in SIGSEGV handler
```

**접근 방식:** 패치를 적용하기 전에 모든 확인 사항을 확인하세요. 각각을 체계적으로 패치하거나 연결합니다. 개별적으로 패치하기에는 너무 많으면 에뮬레이터에서 실행하세요.

### 빠른 참조: 우회 확인

| Anti-Debug Check | Platform | Bypass |
|---|---|---|
| `ptrace(TRACEME)` | Linux | `LD_PRELOAD`, `ret 0`, `catch syscall`에 패치 |
| `IsDebuggerPresent` | Windows | ScyllaHide, Frida 후크, PEB 패치 |
| `NtQueryInformationProcess` | Windows | ScyllaHide, 후크 ntdll |
| `rdtsc` timing | Both | NOP rdtsc, Frida 시간 후크, 핀 |
| `/proc/self/status` | Linux | 마운트 네임스페이스, 후크 fopen |
| `alarm(N)` | Linux | `handle SIGALRM ignore` GDB에서 |
| `SIGTRAP` handler | Linux | `handle SIGTRAP nostop pass` |
| `SIGFPE` 핸들러 사이드 채널 | Linux | `strace -e signal=SIGFPE` 입력당 개수 |
| TLS callback | Windows | x64dbg에서 TLS 중단, 패치 |
| DR 레지스터 스캔 | Windows | 소프트웨어 BP를 사용하고 GetThreadContext를 연결합니다. |
| INT3 스캔/CRC| Both |하드웨어 BP, 패치 CRC 비교|
| Frida detection | Both | 초기 로드 가젯, 후크 strstr|
| CPUID hypervisor | Both | 패치 CPUID 결과, 베어메탈|
| Thread hiding | Windows | Hook NtSetInformationThread |
