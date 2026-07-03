---
name: reverse-engineering
description: 리버스 엔지니어링 기술을 제공합니다. 주요 작업이 바이너리, APK, WASM, 펌웨어, 사용자 정의 VM, 바이트코드, 악성 코드와 유사한 로더, ​​디버그 방지 또는 분석 방지 논리를 포함하여 컴파일, 난독화, 압축 또는 가상화된 대상을 악용하거나 해결하기 전에 작동하는 방식을 이해하는 것인 경우에 사용합니다. 취약점이 이미 이해되었고 남은 작업이 악용인 경우에는 사용하지 마십시오. 대신 pwn을 사용하세요. 구현을 뒤집는 것이 실제 방해가 되지 않는 한 순수 웹 워크플로, 로그 또는 디스크 포렌식, 독립형 암호화 문제에는 사용하지 마세요.
license: MIT
compatibility: 도구 설치를 위해서는 파일 시스템 기반 코드 에이전트 또는 셸 액세스가 가능한 CLI, Python 3 및 인터넷 액세스가 필요합니다.
allowed-tools: Bash 읽기 쓰기 편집 Glob Grep 작업 WebFetch WebSearch
metadata:
  user-invocable: "거짓"
---

# Reverse Engineering

RE 과제에 대한 빠른 참조입니다. 자세한 기술은 지원 파일을 참조하세요.

## Prerequisites

**Python 패키지(모든 플랫폼):**
```bash
pip install frida-tools angr qiling uncompyle6 capstone lief z3-solver
# For Python 3.9+ bytecode: build pycdc from source
git clone https://github.com/zrax/pycdc && cd pycdc && cmake . && make
```

**Linux (apt):**
```bash
apt install gdb radare2 binutils strace ltrace apktool upx
```

**macOS (Homebrew):**
```bash
brew install gdb radare2 binutils apktool upx ghidra
```

**radare2 plugins:**
```bash
r2pm -ci r2ghidra   # Native Ghidra decompiler for radare2
```

**Manual install:**
- pwndbg — Linux: [GitHub](https://github.com/pwndbg/pwndbg), macOS: `brew install pwndbg/tap/pwndbg-gdb`

## Additional Resources

- [tools.md](tools.md) - 정적 분석 도구(GDB, Ghidra, radare2, IDA, Binary Ninja, dogbolt.org, Capstone 포함 RISC-V, Unicorn 에뮬레이션, Python 바이트코드, WASM, Android APK,.NET, 압축 바이너리)
- [tools-dynamic.md](tools-dynamic.md) (movfuscated 바이너리용 Intel Pin 명령 계산 사이드 채널, opcode 전용 추적 재구성, 바이트별 무차별 대입을 위한 LD_PRELOAD memcmp 사이드 채널 포함) - 동적 분석 도구: Frida(후킹, 디버그 방지 우회, 메모리 스캐닝, Android/iOS), angr 기호 실행(경로 탐색, 제약 조건, CFG), lldb(macOS/LLVM 디버거), x64dbg(Windows), Qiling(OS 지원이 포함된 크로스 플랫폼 에뮬레이션), Triton(동적 기호 실행)
- [tools-advanced.md](tools-advanced.md) - 고급 도구: VMProtect/Themida 분석, 바이너리 비교(BinDiff, Diaphora), 난독화 프레임워크(D-810, GOOMBA, Miasm), Rizin/Cutter, RetDec, LLVM IR로 맞춤 VM 바이트코드 리프팅, 고급 GDB(Python 스크립팅, 조건부) 중단점, 감시점, rr을 사용한 역방향 디버깅, pwndbg/GEF), 고급 Ghidra 스크립팅, 패치(Binary Ninja API, LIEF)
- [anti-analysis.md](anti-analysis.md) - 포괄적인 안티 분석: Linux 안티 디버그(ptrace, /proc, 타이밍, 신호, 직접 syscall), Windows 안티 디버그(PEB, NtQueryInformationProcess, 힙 플래그, TLS 콜백, HW/SW 중단점 감지, 예외 기반, 스레드 숨기기), anti-VM/sandbox (CPUID, MAC, 타이밍, 아티팩트, 리소스), 안티-DBI(Frida detection/bypass), 코드 integrity/self-hashing, 안티 디스어셈블리(불투명 술어, 정크 바이트), MBA identification/simplification, strace 카운팅을 통한 SIGFPE 신호 처리기 사이드 채널, 스택 프레임 조작을 통한 무콜 함수 연결, 우회 전략
- [patterns.md](patterns.md) - 기본 바이너리 패턴: 맞춤형 VM, 디버깅 방지, 나노마이트, 자체 수정 코드, XOR 암호, 혼합 모드 스테이저, LLVM 난독화, S-box/keystream, SECCOMP/BPF, 예외 처리기, 메모리 덤프, 바이트별 변환, x86-64 문제, 신호 기반 탐색, 악성 코드 안티 분석, 다단계 쉘코드, 타이밍 사이드 채널, 미끼가 포함된 멀티 스레드 안티 디버그 + 신호 처리기 MBA, INT3 패치 + 코어 덤프 무차별 대입 오라클, 신호 처리기 체인 + LD_PRELOAD 오라클
- [patterns-ctf.md](patterns-ctf.md) - 대회별 패턴(1부): 숨겨진 에뮬레이터 opcode, LD_PRELOAD 키 추출, SPN 정적 추출, 이미지 XOR 부드러움, 한 번에 바이트 암호화, 수학적 융합 비트맵, Windows PE XOR 비트맵 OCR, 2단계 RC4+VM 로더, 커널 모듈 미로 해결, 멀티스레드 VM 채널, 문자열 비교를 통한 백도어 공유 라이브러리 감지, RC4 플랫 바이너리가 포함된 사용자 정의 binfmt 커널 모듈, 해시 해결 가져오기/가져오기 안 함 랜섬웨어, 분석 방지를 위한 ELF 섹션 헤더 손상
- [patterns-ctf-2.md](patterns-ctf-2.md) - 대회별 패턴(2부): 다층 자체 복호화 무차별 대입, 내장된 ZIP+XOR 라이센스, 스택 문자열 난독화, 접두사 해시 무차별 대입, 정수 검증을 위한 CVP/LLL 격자, 의사 결정 트리 함수 난독화, GF(2^8) 가우스 제거, ROP 체인 난독화 분석(ROPfuscation)
- [patterns-ctf-3.md](patterns-ctf-3.md) - 대회별 패턴(3부): Z3 단일 라인 Python 회로, 슬라이딩 창 팝카운트, ioctl을 통한 키보드 LED 모스 부호, C++ 소멸자 숨김 검증, syscall 부작용 메모리 손상, MFC 대화 상자 이벤트 핸들러, VM 순차 키 체인 무차별 대입, Burrows-Wheeler 변환 반전, OpenType 글꼴 합자 활용, GLSL 셰이더 VM 자체 수정 코드, 암호화 상태로서의 명령 카운터, objdump를 통한 일괄 crackme 자동화, 포크+파이프+데드 브랜치 방지 분석, 시그모이드 레이어 반전을 통한 TensorFlow DNN 반전, x64 어셈블리에 대한 커널 JIT를 통한 BPF 필터 분석
- [languages.md](languages.md) - 언어별: Python 바이트코드 및 opcode 재매핑, Python 버전별 바이트코드, Pyarmor 정적 압축 풀기, DOS 스텁, HarmonyOS HAP/ABC, Brainfuck/esolangs(+ BF 문자별 정적 분석, BF 사이드 채널 읽기 횟수 oracle, BF 비교 관용구 감지), UEFI, C로의 변환, 코드 적용 범위 부채널, OPAL 기능 반전, 비단사적 대체, FRACTRAN 프로그램 반전
- [languages-platforms.md](languages-platforms.md) - Platform/framework-specific: Rust serde_json 스키마 복구, Android JNI RegisterNatives 난독화, /proc/self/maps를 통한 Android DEX 런타임 바이트코드 패치, 새 프로젝트를 통한 Android 네이티브.so 로드 우회, Frida Firebase Cloud Functions 우회, Verilog/hardware RE, 접두사별 해시 반전, Ruby/Perl 다중 언어 제약 조건 충족, Electron ASAR 추출 + 기본 바이너리 분석, Node.js npm 런타임 내부 검사
- [languages-compiled.md](languages-compiled.md) - Go 바이너리 리버싱(GoReSym, goroutines, 메모리 레이아웃, 채널 ops, embed.FS, C2 열거를 위한 Go 바이너리 UUID 패치), Rust 바이너리 리버싱(demangling, Option/Result, Vec, 패닉 문자열), Swift 바이너리 리버싱(demangling, 프로토콜 감시 테이블), Kotlin/JVM(코루틴 상태 기계), 재귀 구조 분석을 위한 Haskell GHC CMM 중간 언어, C++(vtable 재구성, RTTI, STL 패턴)
- [platforms.md](platforms.md) - 플랫폼별 RE: macOS/iOS(Mach-O, 코드 서명, Objective-C 런타임, Swift, dyld, 탈옥 우회), embedded/IoT 펌웨어(binwalk, UART/JTAG/SPI 추출, ARM/MIPS, RTOS), 커널 드라이버(Linux.ko, eBPF, Windows.sys), 자동차 CAN 버스
- [platforms-hardware.md](platforms-hardware.md) - 하드웨어 및 고급 아키텍처 RE: HD44780 LCD 컨트롤러 GPIO 재구성, RISC-V 고급(사용자 정의 확장, 권한 모드, 디버깅), ARM64/AArch64 반전 및 활용(호출 규칙, ROP 가젯, qemu-aarch64-정적 에뮬레이션)
- [field-notes.md](field-notes.md) - 빠른 참조 노트: 바이너리 유형, 디버깅 방지 우회, 특수 패턴, CTF 케이스 노트

---

## 피벗할 시기

- 이미 바이너리를 이해하고 이제 힙, ROP 또는 커널 활용이 필요한 경우 `/ctf-pwn`로 전환하세요.
- 실제로 삭제된 파일, PCAP 데이터 또는 디스크 아티팩트를 복구하는 것이 문제라면 `/ctf-forensics`로 전환하세요.
- 대상이 웹 앱이고 작은 클라이언트 측 도우미 스크립트만 되돌리는 경우 `/ctf-web`로 전환하세요.
- 바이너리가 기계 학습 모델을 구현하고 문제가 모델 공격이나 적대적 입력에 관한 것이라면 `/ctf-ai-ml`로 전환하세요.
- 역방향 바이너리의 핵심 로직이 암호화 알고리즘이나 수학 문제인 경우 `/ctf-crypto`로 전환하세요.
- 바이너리가 C2, 패킹 또는 회피 동작을 포함하는 실제 악성 코드 샘플인 경우 `/ctf-malware`로 전환하세요.
- 문제가 실제 바이너리가 아닌 장난감 VM, 인코딩 퍼즐 또는 pyjail인 경우 `/ctf-misc`로 전환하세요.

## Problem-Solving Workflow

1. **문자열 추출로 시작** - 많은 쉬운 과제에는 일반 텍스트 플래그가 있습니다.
2. **ltrace/strace** 시도 - 동적 분석에서는 반전 없이 플래그가 표시되는 경우가 많습니다.
3. **Frida 후킹을 시도하세요** - 후킹 strcmp/memcmp을 사용하여 반전 없이 예상 값을 캡처하세요.
4. **angr 사용해 보세요** - 기호 실행으로 많은 플래그 검사기가 자동으로 해결됩니다.
5. **Qiling 사용해 보기** - 외부 아치 바이너리를 에뮬레이트하거나 아티팩트 없이 강력한 안티 디버그를 우회합니다.
6. **맵 제어 흐름** 실행 수정 전
7. 스크립트(r2pipe, Frida, angr, Python)를 통해 **수동 프로세스 자동화**
8. 디컴파일러 출력을 비교하여 **가정 검증**(병렬의 경우 dogbolt.org)

## 빠른 승리(먼저 시도해 보세요!)

```bash
# Plaintext flag extraction
strings binary | grep -E "flag\{|CTF\{|pico"
strings binary | grep -iE "flag|secret|password"
rabin2 -z binary | grep -i "flag"

# Dynamic analysis - often captures flag directly
ltrace ./binary
strace -f -s 500 ./binary

# Hex dump search
xxd binary | grep -i flag

# Run with test inputs
./binary AAAA
echo "test" | ./binary
```

## Initial Analysis

```bash
file binary           # Type, architecture
checksec --file=binary # Security features (for pwn)
chmod +x binary       # Make executable
```

## 메모리 덤핑 전략

**주요 통찰력:** 프로그램이 답을 계산한 후 덤프하도록 합니다. 최종 비교(`b *main+OFFSET`)에서 중단하고 올바른 길이의 입력을 입력한 다음 `x/s $rsi`를 눌러 계산된 플래그를 덤프합니다.

## 미끼 플래그 감지

**패턴:** 실제 확인 전에 여러 개의 가짜 대상이 있습니다. 다양한 성공 메시지가 포함된 여러 비교 대상을 순차적으로 찾습니다. 이전 비교가 아닌 최종 비교에서 중단점을 설정합니다.

## GDB PIE 디버깅

PIE 바이너리는 기본 주소를 무작위로 지정합니다. 상대 중단점을 사용합니다.
```bash
gdb ./binary
start                    # Forces PIE base resolution
b *main+0xca            # Relative to main
run
```

## 비교 방향 (중요!)

두 가지 패턴: (1) `transform(flag) == stored_target` — 변환을 반대로 합니다. (2) `transform(stored_target) == flag` — 플래그는 변환된 데이터입니다. 저장된 대상에 변환을 적용하면 됩니다.

## 일반적인 암호화 패턴

- 단일 바이트를 사용한 XOR - 256개 값 모두 시도
- 알려진 일반 텍스트를 사용한 XOR(`flag{`, `CTF{`)
- 하드코드된 키가 있는 RC4
- 사용자 정의 순열 + XOR
- 반복 키와 계층화된 위치 인덱스(`^ i` 또는 `^ (i & 0xff)`)를 사용한 XOR

## 빠른 도구 참조

```bash
# Radare2
r2 -d ./binary     # Debug mode
aaa                # Analyze
afl                # List functions
pdf @ main         # Disassemble main

# Ghidra (headless)
analyzeHeadless project/ tmp -import binary -postScript script.py

# IDA
ida64 binary       # Open in IDA64
```

## Deep-Dive Notes

어떤 종류의 대상이 있는지 알고 있는 경우 첫 번째 분류 후에 [field-notes.md](field-notes.md)를 사용하세요.

- 대상 형식: Python 바이트코드, WASM, Android, Flutter,.NET, UPX, Tauri
- 기술 노트: 디버그 방지 우회, VM 분석, x86-64 문제, 반복 솔버, Unicorn, 타이밍 사이드 채널
- 플랫폼 노트: macOS/iOS, 임베디드 펌웨어, 커널 드라이버, Swift, Kotlin, Go, Rust, D
- 사례 노트: 최신 CTF 전용 반전 패턴 및 오래된 클래식 챌린지 패턴

---

## 라우팅 컨텍스트

**상류 입구**: `../../SKILL.md`(마스터 제어), `routing.md`
**다운스트림 내보내기**:
- IDA 디컴파일 필요 → `ida-reverse/`
- radare2 CLI 분석 필요 → `radare2/`
- APK 계층 분석 필요 → `apk-reverse/`
- Frida/angr 동적 실행 필요 → `tools-dynamic.md`
- 안티디버깅 우회 필요 → `anti-analysis.md`
- 특정 언어(Go/Rust/Python/WASM)를 만남 → `languages*.md`
- CTF 패턴을 만남 → `patterns*.md`

**동일 유형**: `apk-reverse/`(APK가 `.so`까지 이어지는 것으로 판단되면 이 모듈의 Frida/radare2 분기로 전환할 수 있음)
