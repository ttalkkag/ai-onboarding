# 리버스 엔지니어링 필드 노트

[`SKILL.md`](SKILL.md)를 지원하는 자세한 빠른 메모입니다. 이 파일은 분류 전이 아닌 분류 후에 읽어보세요.

## 목차

- [바이너리 유형](#binary-types)
  - [파이썬.pyc](#python-pyc)
  - [WASM](#wasm)
  - [안드로이드 APK](#android-apk)
  - [Flutter APK (Dart AOT)](#flutter-apk-dart-aot)
  - [.NET](#net)
  - [포장됨(UPX)](#packed-upx)
  - [Tauri 패키지 데스크톱 앱](#tauri-packed-desktop-apps)
- [안티 디버깅 우회](#anti-debugging-bypass)
- [특수 패턴](#specialized-patterns)
  - [S-Box / 키스트림 패턴](#s-box--keystream-patterns)
  - [커스텀 VM 분석](#custom-vm-analytic)
  - [Python 바이트코드 반전](#python-bytecode-reversing)
  - [신호 기반 이진 탐색](#signal-based-binary-exploration)
  - [패칭을 통한 악성코드 차단 우회](#malware-anti-analytic-bypass-via-patching)
  - [예상 값 테이블](#expected-values-tables)
  - [x86-64 문제](#x86-64-문제)
  - [반복 솔버 패턴](#iterative-solver-pattern)
  - [유니콘 에뮬레이션(복잡한 상태)](#unicorn-emulation-complex-state)
  - [다단계 쉘코드 로더](#multi-stage-shellcode-loaders)
  - [타이밍 사이드 채널 공격](#timing-side-channel-attack)
  - [스트립되지 않은 바이너리 정보 유출](#unstripped-binary-information-leaks)
  - [사용자 정의 Mangle 함수 반전](#custom-mangle-function-reversing)
  - [Rust serde_json 스키마 복구](#rust-serde_json-schema-recovery)
  - [위치 기반 변환 반전](#position-based-transformation-reversing)
  - [16진수로 인코딩된 문자열 비교](#hex-encoded-string-comparison)
- [CTF 케이스 메모](#ctf-case-notes)
  - [임베디드 ZIP + XOR 라이선스 복호화](#embedded-zip--xor-license-decryption)
  - [스택 문자열 난독화(.rodata XOR Blob)](#stack-string-deobfuscation-rodata-xor-blob)
  - [접두사 해시 무차별 대입](#prefix-hash-brute-force)
  - [수학적 융합 비트맵](#mathematical-convergence-bitmap)
  - [RISC-V 이진 분석](#risc-v-binary-analytic)
  - [커널 모듈 미로 해결](#kernel-module-maze-solving)
  - [채널이 있는 다중 스레드 VM](#multi-threaded-vm-with-channels)
  - [CVP/LLL 제한된 정수 검증을 위한 격자](#cvplll-lattice-for-constrained-integer-validation)
  - [의사결정 트리 함수 난독화](#decision-tree-function-obfuscation)
  - [Android JNI RegisterNatives 난독화](#android-jni-registernatives-난독화)
  - [다층 자기복호화 바이너리](#multi-layer-self-decrypting-binary)
  - [자체 수정 코드가 포함된 GLSL 셰이더 VM](#glsl-shader-vm-with-self-modifying-code)
  - [플래그 복구를 위한 GF(2^8) 가우스 제거](#gf28-gaussian-elimination-for-flag-recovery)
  - [단일 선 Python 부울 회로용 Z3](#z3-for-single-line-python-boolean-circuit)
  - [슬라이딩 윈도우 팝카운트 차등 전파](#sliding-window-popcount-차등-전파)
  - [Ruby/Perl 다중 언어 제약 조건 만족](#rubyperl-polyglot-constraint-satisfaction)
  - [Verilog/Hardware RE](#veriloghardware-re)
  - [RC4 플랫 바이너리가 포함된 사용자 정의 binfmt 커널 모듈](#custom-binfmt-kernel-module-with-rc4-Flat-binaries)
  - [해시 해결된 가져오기 / 가져오기 불가 랜섬웨어](#hash-resolved-imports--no-import-ransomware)
  - [ELF 분석 방지를 위한 섹션 헤더 손상](#elf-section-header-corruption-for-anti-analytic)
  - [Brainfuck 캐릭터별 정적 분석](#brainfuck-character-by-character-static-analytic)
  - [읽기 횟수 Oracle을 통한 Brainfuck 사이드 채널](#brainfuck-side-channel-via-read-count-oracle)
  - [Brainfuck 비교 관용어 감지](#brainfuck-comparison-idiom-Detection)
  - [백도어 공유 라이브러리 감지](#backdoored-shared-library-Detection)
  - [이진 반전 이동](#go-binary-reversing)
  - [C2 열거를 위한 Go Binary UUID 패치](#go-binary-uuid-patching-for-c2-enumeration)
  - [D 언어 바이너리 반전](#d-언어-binary-reversing)
  - [Rust 바이너리 반전](#rust-binary-reversing)
  - [Frida 동적 계측](#frida-dynamic-instrumentation)
  - [Frida Firebase Cloud Functions 우회](#frida-firebase-cloud-functions-bypass)
  - [angr 기호 실행](#angr-symbolic-execution)
  - [Qiling 에뮬레이션](#qiling-emulation)
  - [VMProtect / 테미다 분석](#vmprotect--themida-analysis)
  - [이진 비교](#binary-diffing)
  - [고급 GDB(pwndbg, rr)](#advanced-gdb-pwndbg-rr)
  - [macOS / iOS 반전](#macos--ios-reversing)
  - [내장형/IoT 펌웨어 RE](#임베디드--iot-firmware-re)
  - [커널 드라이버 반전](#kernel-driver-reversing)
  - [Swift / Kotlin 바이너리 역전](#swift--kotlin-binary-reversing)
  - [INT3 패치 + 코어 덤프 무차별 대입 Oracle](#int3-patch--coredump-brute-force-oracle)
  - [신호 처리기 체인 + LD_PRELOAD Oracle](#signal-handler-chain--ld_preload-oracle)
  - [글꼴 합자 악용](#font-ligature-exploitation)
  - [암호화 상태로서의 명령 카운터](#instruction-counter-as-cryptographic-state)
  - [버로우즈-휠러 변환 반전](#burrows-wheeler-transform-inversion)
  - [FRACTRAN 프로그램 반전](#fractran-program-inversion)
  - [Opcode 전용 추적 재구성](#opcode-only-trace-reconstruction)
  - [스레드 레이스 부호 있는 정수 오버플로](#thread-race-signed-integer-overflow)
  - [ESP32/Xtensa 펌웨어 리버싱](#esp32xtensa-firmware-reversing)
  - [LLVM으로 사용자 정의 VM 바이트코드 리프팅 IR](#custom-vm-bytecode-lifting-to-llvm-ir)
  - [SIGFPE 신호 처리기 측면 채널](#sigfpe-signal-handler-side-channel)
  - [objdump를 통한 일괄 Crackme 자동화](#batch-crackme-automation-via-objdump)
  - [Android DEX 런타임 바이트코드 패치](#android-dex-runtime-bytecode-patching)
  - [포크 + 파이프 + 데드브랜치 안티분석](#fork--pipe--dead-branch-anti-analysis)
- [Web/CTF 인증 우회 사례 참고 사항](#webctf-auth-bypass-case-notes)
  - [서명된 쿠키 키 재사용: admin_session에 대한 액세스 토큰](#signed-cookie-key-reuse-access-token-to-admin_session)
- [웹 피싱 인프라](#web-phishing-infrastructure)
  - [피싱 패널: {domain_a} / {domain_b}](#phishing-panel-domain_a--domain_b)

## Binary Types

### Python .pyc
`marshal.load()` + `dis.dis()`로 분해하세요. 헤더: 8바이트(2.x), 12(3.0-3.6), 16(3.7+). [languages.md](languages.md#python-bytecode-reversing-disdis-output)을 참조하세요.

### WASM
```bash
wasm2c checker.wasm -o checker.c
gcc -O3 checker.c wasm-rt-impl.c -o checker

# WASM patching (challenge binaries):
wasm2wat main.wasm -o main.wat    # Binary → text
# Edit WAT: flip comparisons, change constants
wat2wasm main.wat -o patched.wasm # Text → binary
```

### Android APK
`apktool d app.apk -o decoded/` 자원의 경우; `jadx app.apk` Java 디컴파일용. 플래그는 `decoded/res/values/strings.xml`를 확인하세요. [tools.md](tools.md#android-apk)를 참조하세요.

### 플러터 APK (다트 AOT)
`lib/arm64-v8a/libapp.so` + `libflutter.so`가 있는 경우 [Blutter](https://github.com/worawit/blutter)를 사용하세요: `python3 blutter.py path/to/app/lib/arm64-v8a out_dir`. 재구성된 Dart 기호 + Frida 스크립트를 출력합니다. [tools.md](tools.md#flutter-apk-blutter)를 참조하세요.

### .NET
- dnSpy - 디버깅 + 디컴파일
- ILSpy - decompiler

### Packed (UPX)
```bash
upx -d packed -o unpacked
```
압축 풀기에 실패하면 먼저 UPX 메타데이터를 검사하여 UPX 섹션 이름, 헤더 필드 및 버전 표시가 손상되지 않았는지 확인하세요. 메타데이터가 변조되었거나 불확실해 보이는 경우 GitHub의 UPX 소스를 검토하여 수정 가능성이 있는 지점을 식별하세요.

### Tauri로 가득 찬 데스크톱 앱
Tauri는 Brotli로 압축된 프런트엔드 자산을 실행 파일에 포함합니다. `index.html` 외부 참조를 찾아 자산 인덱스 테이블, 덤프 블롭, Brotli 압축 해제를 찾습니다. 참고: `tauri-codegen/src/embedded_assets.rs`.

## Anti-Debugging Bypass

Common checks:
- `IsDebuggerPresent()` / PEB.BeingDebugged / NtQueryInformationProcess (Windows)
- `ptrace(PTRACE_TRACEME)` / `/proc/self/status` TracerPid (리눅스)
- TLS 콜백(메인 이전에 실행 - PE TLS 디렉토리 확인)
- 타이밍 확인(`rdtsc`, `clock_gettime`, `GetTickCount`)
- 하드웨어 중단점 감지(GetThreadContext를 통한 DR0-DR3)
- INT3 스캐닝/코드 자체 해싱(.text 섹션에 대한 CRC)
- 신호 기반: SIGTRAP 핸들러, SIGALRM 시간 초과, 실제 로직용 SIGSEGV
- Frida/DBI 탐지: `/proc/self/maps` 스캔, 포트 27042, 인라인 후크 검사

Bypass: 검사 시 중단점을 설정하고 조건을 우회하도록 레지스터를 수정합니다. pwntools 패치: `elf.asm(elf.symbols.ptrace, 'ret')` 기능을 즉시 반환으로 대체합니다. [patterns.md](patterns.md#pwntools-binary-patching-crypto-cat)를 참조하세요.

포괄적인 안티 분석 기술 및 우회(코드가 포함된 30개 이상의 방법)에 대해서는 [anti-analysis.md](anti-analysis.md)를 참조하세요.

## Specialized Patterns

### S-Box / 키스트림 패턴
**Xorshift32:** 교대 13, 17, 5
**Xorshift64:** 교대 12, 25, 27
**마법 상수:** `0x2545f4914f6cdd1d`, `0x9e3779b97f4a7c15`

### 맞춤형 VM 분석
1. 구조 식별: 레지스터, 메모리, IP
2. Opcode 의미를 보려면 역방향 `executeIns`
3. 니모닉에 디스어셈블러 매핑 opcode 작성
4. 완전히 뒤집는 것보다 무차별 대입이 더 쉬운 경우가 많습니다.
5. 명령줄 인수를 통해 로드된 바이트코드 파일을 찾습니다.

VM 워크플로, opcode 테이블 및 상태 시스템 BFS는 [patterns.md](patterns.md#custom-vm-reversing)을 참조하세요.

**순차적 키 체인 무차별 공격:** VM이 각 블록의 출력 키가 다음 블록에 공급되는 작은 블록(예: 3바이트 = 2^24 후보)의 입력을 검증할 때 OpenMP 병렬화를 통해 각 블록을 순차적으로 무차별 공격합니다. `gcc -O3 -march=native -fopenmp`로 솔버를 컴파일합니다. [patterns-ctf-3.md](patterns-ctf-3.md#vm-series-key-chain-brute-force-midnight-flag-2026)을 참조하세요.

### Python 바이트코드 반전
인터리브된 even/odd 테이블이 있는 XOR 플래그 검사기가 일반적입니다. 바이트코드 분석 팁과 반전 패턴은 [languages.md](languages.md#python-bytecode-reversing-disdis-output)을 참조하세요.

### 신호 기반 이진 탐색
바이너리는 UNIX 신호를 바이너리 트리 탐색으로 사용합니다. 신호를 보내 `LD_PRELOAD`, DFS를 통해 `sigaction`를 연결합니다. [patterns.md](patterns.md#signal-based-binary-exploration)을 참조하세요.

### 패치를 통한 악성 코드 방지 분석 우회
`JNZ`/`JZ`(0x75/0x74) 뒤집기, 수면 값 변경, Ghidra(`Ctrl+Shift+G`) 패치 환경 확인. [patterns.md](patterns.md#malware-anti-analytic-bypass-via-patching)을 참조하세요.

### 기대값 표
`objdump -s -j.rodata binary | less`로 찾기 - 비교 지침 근처를 보면 크기가 플래그 길이와 일치합니다.

### x86-64 Gotchas
부호 확장 및 32비트 잘림 함정. 자세한 내용과 코드 예시는 [patterns.md](patterns.md#x86-64-gotchas)를 참조하세요.

### 반복 솔버 패턴
위치당 각 바이트(0-255)를 시도하고 예상 출력과 일치시킵니다. **균일 변환 단축키:** 하나의 입력 바이트가 하나의 출력 바이트만 변경하는 경우 0..255 매핑을 빌드한 다음 반전합니다. 전체 구현은 [patterns.md](patterns.md)를 참조하세요.

### 유니콘 에뮬레이션(복잡한 상태)
`from unicorn import *` -- 세그먼트 매핑, 스택 설정, 추적 후크. **혼합 모드 함정:** `retf`을 통해 64비트 스텁을 32비트로 점프하려면 UC_MODE_32로 전환하고 GPR + EFLAGS + XMM reg를 복사해야 합니다. [tools.md](tools.md#unicorn-emulation)을 참조하세요.

### 다단계 쉘코드 로더
XOR 디코드 루프가 포함된 중첩 쉘코드. `call rax`에서 중단하고, `set $rax=0`로 ptrace를 우회하고, `mov` 명령어에서 플래그를 추출합니다. [patterns.md](patterns.md#multi-stage-shellcode-loaders)를 참조하세요.

### 타이밍 부채널 공격
유효성 검사 시간은 올바른 문자에 따라 다릅니다. 플래그를 바이트 단위로 복구하기 위해 후보당 경과 시간을 측정합니다. [patterns.md](patterns.md#timing-side-channel-attack)을 참조하세요.

### 제거되지 않은 바이너리 정보 유출
**패턴:** 디버그 정보 및 파일 경로로 인해 작성자 신원이 유출됩니다. 빠른 확인: `strings binary | grep "/home/"`(홈 디렉토리), `file binary`(제거?), `readelf -S binary | grep debug`(디버그 섹션).

### 사용자 정의 Mangle 기능 반전
바이너리는 실행 상태에서 한 번에 2바이트를 입력합니다. `.rodata`에서 대상을 추출하고 역함수를 작성합니다. [patterns.md](patterns.md#custom-mangle-function-reversing)을 참조하세요.

### Rust serde_json 스키마 복구
예상되는 JSON 스키마를 복구하기 위해 serde `Visitor` 구현을 분해합니다. 필드 이름 순서대로 플래그를 표시합니다. [languages-platforms.md](languages-platforms.md#rust-serdejson-schema-recovery)를 참조하세요.

### 위치 기반 변환 반전
바이너리 adds/subtracts 위치 인덱스; 인덱스별 오프셋을 실행 취소하여 되돌립니다. [patterns.md](patterns.md#위치 기반 변환-반전)을 참조하세요.

### 16진수로 인코딩된 문자열 비교
16진수로 변환된 입력을 상수와 비교합니다. `xxd -r -p`로 디코딩하세요. [patterns.md](patterns.md#hex-encoded-string-comparison)을 참조하세요.

## CTF 케이스 노트

### 임베디드 ZIP + XOR 라이센스 복호화
`.rodata`에 명명된 기호(`EMBEDDED_ZIP`, `ENCRYPTED_MESSAGE`)가 있는 바이너리 → 라이선스가 포함된 ZIP을 추출하고 라이선스 바이트가 포함된 XOR 암호화된 메시지를 복구하여 플래그를 복구합니다. 실행이 필요하지 않습니다. [patterns-ctf-2.md](patterns-ctf-2.md#embedded-zip-xor-license-decryption-metactf-2026)을 참조하세요.

### 스택 문자열 난독화(.rodata XOR Blob)
바이너리 mmap `.rodata` blob, XOR-deobfuscates는 이를 사용하여 입력을 검증합니다. pyelftools를 사용하여 검증 루프를 다시 구현하여 blob을 추출합니다. `0x9E3779B9`, `0x85EBCA6B` 상수 및 `rol32()`를 찾으세요. [patterns-ctf-2.md](patterns-ctf-2.md#stack-string-deobfuscation-from-rodata-xor-blob-nullcon-2026)을 참조하세요.

### 접두사 해시 무차별 대입
바이너리는 모든 접두사를 독립적으로 해시합니다. 접두사 해시를 일치시켜 한 번에 한 문자씩 복구합니다. [patterns-ctf-2.md](patterns-ctf-2.md#prefix-hash-brute-force-nullcon-2026)을 참조하세요.

### 수학적 융합 비트맵
**패턴:** Binary는 뉴턴 방법 수렴에 따라 좌표 쌍을 분류합니다(예: z^3-1=0). pass/fail 결과의 그리드는 ASCII 아트 플래그를 렌더링합니다. 핵심: 바이너리는 검사기가 아니라 분류기입니다. 수학을 뒤집어서 시각화하세요. [patterns-ctf.md](patterns-ctf.md#mathematical-convergence-bitmap-ehax-2026)을 참조하세요.

### RISC-V 바이너리 분석
정적으로 연결되고 제거된 RISC-V ELF. 혼합 압축 명령어의 경우 `CS_MODE_RISCVC | CS_MODE_RISCV64`와 함께 Capstone을 사용하세요. `qemu-riscv64`로 에뮬레이트합니다. 증분 키를 사용한 가짜 플래그와 XOR 복호화를 주의하세요. [tools.md](tools.md#risc-v-binary-analytic-ehax-2026)을 참조하세요.

### 커널 모듈 미로 해결
Rust 커널 모듈은 장치 ioctl을 통해 미로를 구현합니다. 명령을 동적으로 열거하고, 미끼 방지 기능을 갖춘 DFS 솔버를 구축하고, 최소 정적 바이너리(원시 syscall, libc 없음)로 배포합니다. [patterns-ctf.md](patterns-ctf.md#kernel-module-maze-solving-dicectf-2026)을 참조하세요.

### 채널이 있는 다중 스레드 VM
futex 채널을 통해 통신하는 16개 이상의 스레드가 있는 사용자 지정 VM입니다. 스레드 경계를 넘어 데이터 흐름을 추적하고, GDB에서 상수를 추출하고, 반전된 유효성 논리를 관찰하고, BFS 상태 공간 검색을 통해 해결합니다. [patterns-ctf.md](patterns-ctf.md#multi-threaded-vm-with-channel-synchronization-dicectf-2026)을 참조하세요.

### CVP/LLL 제한된 정수 검증을 위한 격자
바이너리는 64비트 계수를 사용한 행렬 곱셈을 통해 플래그를 검증합니다. 솔루션은 인쇄 가능한 ASCII여야 합니다. 제한된 범위에서 가장 가까운 격자점을 찾으려면 SageMath에서 LLL 감소 + CVP를 사용하세요. 2단계 패턴: 1단계에서는 AES 키를 복구하고, 2단계에서는 다른 선형 시스템(mod 2^32)을 사용하여 사용자 지정 VM 바이트 코드를 해독합니다. [patterns-ctf-2.md](patterns-ctf-2.md#cvplll-lattice-for-constrained-integer-validation-htb-shadowlabyrinth)를 참조하세요.

### 의사결정 트리 함수 난독화
다항식 비교를 통해 입력을 라우팅하는 ~200개 이상의 자동 생성 함수. 각 기능을 수동으로 반전하는 대신 Ghidra 헤드리스를 통해 스크립트를 추출합니다. 산술 제약을 통해 알려진 출력 형식 계단식에서 제약 전파. [patterns-ctf-2.md](patterns-ctf-2.md#decision-tree-function-obfuscation-htb-wondersms)를 참조하세요.

### Android JNI RegisterNatives 난독화
`JNI_OnLoad`의 `RegisterNatives`는 각 Java 기본 메소드를 처리하는 C++ 함수를 숨깁니다(표준 `Java_com_pkg_Class_method` 기호 없음). `JNI_OnLoad` → `RegisterNatives` → `fnPtr`를 추적하여 실제 핸들러를 찾으세요. 최상의 Ghidra 디컴파일을 위해서는 APK의 x86_64 `.so`를 사용하세요. [languages-platforms.md](languages-platforms.md#android-jni-registernatives-obfuscation-htb-wondersms)를 참조하세요.

### 다층 자체 복호화 바이너리
각 계층이 사용자 제공 키 바이트 + SHA-NI를 사용하여 다음 계층을 해독하는 N 계층 바이너리입니다. oracle을 사용하십시오(올바른 키 → 예상 패턴이 있는 유효한 코드). 속도를 위해 후보별 포크 COW 격리를 통한 JIT 실행. [patterns-ctf-2.md](patterns-ctf-2.md#multi-layer-self-decrypting-binary-dicectf-2026)을 참조하세요.

### 자체 수정 코드가 포함된 GLSL 셰이더 VM
**패턴:** WebGL2 조각 셰이더는 256x256 RGBA 텍스처(프로그램 메모리 + VRAM)에서 Turing-complete VM을 구현합니다. 자체 수정 코드(STORE opcode)는 그리기 지침을 패치합니다. GPU 병렬 처리로 인해 쓰기 충돌이 발생합니다. 전체 출력을 복구하려면 Python에서 순차적으로 에뮬레이트하세요. [patterns-ctf-3.md](patterns-ctf-3.md#glsl-shader-vm-with-self-modifying-code-apoorvctf-2026)을 참조하세요.

### 플래그 복구를 위한 GF(2^8) 가우스 제거
**패턴:** 바이너리는 AES 다항식(0x11b)을 사용하여 GF(2^8)에 대해 가우스 제거를 수행합니다. `.rodata`의 행렬 + 증가 벡터; 솔루션 벡터는 플래그입니다. 디스어셈블리에서 상수 `0x1b`를 찾으세요. 덧셈은 XOR이고, 곱셈은 다항식 감소를 사용합니다. [patterns-ctf-2.md](patterns-ctf-2.md#gf28-gaussian-elimination-for-flag-recovery-apoorvctf-2026)을 참조하세요.

### 단일 라인 Python 부울 회로용 Z3
**패턴:** 바다코끼리 연산자 체인이 있는 한 줄 Python(2000개 이상의 세미콜론)은 부울 회로를 통해 플래그를 빅엔디안 정수로 검증합니다. 난독화된 XOR `(a | b) & ~(a & b)`. 세미콜론으로 나누고, 기호적으로 Z3으로 변환하고, 1초 안에 해결하세요. [patterns-ctf-3.md](patterns-ctf-3.md#z3-for-single-line-python-boolean-circuit-bearcatctf-2026)을 참조하세요.

### 슬라이딩 윈도우 팝카운트 차등 전파
**패턴:** 바이너리는 16비트 슬라이딩 창의 각 위치에 대한 예상 팝카운트를 통해 입력의 유효성을 검사합니다. 인구수 차이로 인해 재발이 발생합니다: `bit[i+16] = bit[i] + (data[i+1] - data[i])`. 무차별 대입 ~4000-8000 유효한 초기 16비트 창; 각각은 전체 비트 시퀀스를 결정합니다. [patterns-ctf-3.md](patterns-ctf-3.md#sliding-window-popcount- Differential-propagation-bearcatctf-2026)을 참조하세요.

### Ruby/Perl 다중 언어 제약 조건 만족
**패턴:** Ruby와 Perl 모두에서 유효한 단일 파일로, 각각 키에 서로 다른 제약 조건을 적용합니다. `=begin`/`=end`(Ruby 블록 주석)과 `=begin`/`=cut`(Perl POD)를 악용하여 인터프리터마다 다른 코드를 실행합니다. 고유 키를 복구하려면 두 언어의 제약 조건을 교차하세요. [languages-platforms.md](languages-platforms.md#rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026)을 참조하세요.

### Verilog/Hardware RE
**패턴:** 시프트 레지스터 기록에 숨겨진 조건이 포함된 상태 머신용 Verilog HDL 소스. `always @(posedge clk)` 블록과 `case` 문을 분석하여 올바른 입력 시퀀스를 찾습니다. [languages-platforms.md](languages-platforms.md#veriloghardware-reverse-engineering-srdnlenctf-2026)를 참조하세요.

### RC4 플랫 바이너리가 포함된 사용자 정의 binfmt 커널 모듈
**패턴:** 커널 모듈은 암호화된 플랫 바이너리에 대한 binfmt 핸들러를 등록합니다. `.ko`를 뒤집어서 RC4 키(`movabs` 즉시)를 찾고, 플랫 바이너리를 해독하고, 모듈의 `vm_mmap` 호출에서 고정된 가상 주소로 가져옵니다. [patterns-ctf.md](patterns-ctf.md#custom-binfmt-kernel-module-with-rc4-plat-binaries-bsidessf-2026)을 참조하세요.

### 해시 해결된 가져오기 / 가져오기 불가 랜섬웨어
**패턴:** 표시되는 가져오기가 없는 바이너리는 런타임 시 기호 이름 해싱을 통해 API를 확인합니다. 해시 역전을 건너뛰세요. Docker에서 `LD_PRELOAD`를 통해 OpenSSL 기능을 연결하여 AES 키를 직접 캡처하세요. [patterns-ctf.md](patterns-ctf.md#hash-resolved-imports-no-import-ransomware-bsidessf-2026)을 참조하세요.

### ELF 분석 방지를 위한 섹션 헤더 손상
**패턴:** 손상된 섹션 헤더 충돌 분석 도구가 있지만 프로그램 헤더는 손상되지 않아 바이너리가 정상적으로 실행됩니다. `e_shoff`를 0으로 패치하거나 `readelf -l`를 사용합니다(프로그램 헤더에만 해당). 매직 마커 + XOR을 사용하여 손상된 섹션 뒤에 숨겨진 플래그입니다. [patterns-ctf.md](patterns-ctf.md#elf-section-header-corruption-for-anti-analytic-bsidessf-2026)을 참조하세요.

### Brainfuck 문자별 정적 분석
**패턴:** 입력 유효성을 검사하는 BF 프로그램에는 `,`(문자 읽기) 뒤에 `+` 연산이 있으며 그 개수는 예상 ASCII 값입니다. 실행 없이 예상 입력을 복구하기 위해 입력 위치별 증분 카운트를 추출합니다. [languages.md](languages.md#brainfuck-character-by-character-static-analytic-bsidessf-2026)을 참조하세요.

### 읽기 횟수 Oracle을 통한 Brainfuck 사이드 채널
**패턴:** BF 입력 유효성 검사기는 문자가 정확하면 더 많은 바이트를 읽습니다. 후보당 `,` 작업 수 — 최고 읽기 수 = 올바른 바이트. 문자별 복구. [languages.md](languages.md#brainfuck-side-channel-via-read-count-oracle-bsidessf-2026)을 참조하세요.

### Brainfuck 비교 관용구 감지
**패턴:** 컴파일된 BF는 동등성 확인을 위해 고정된 관용구를 사용합니다(`<[-<->] +<[>-<[-]]>[-<+>]`). 패턴을 감지하고 비교 피연산자(예상 플래그 바이트)를 추출하는 계측기 해석기입니다. [languages.md](languages.md#brainfuck-comparison-idiom-Detection-bsidessf-2026)을 참조하세요.

### 백도어 공유 라이브러리 탐지
바이너리는 GDB에서 작동하지만 정상적으로 실행되면 실패합니까(suid)? `ldd`에서 비표준 libc 경로를 확인한 다음 `strings | diff` 의심스러운 라이브러리와 시스템 라이브러리를 비교하여 주입된 항목을 찾습니다. code/passwords. [patterns-ctf.md](patterns-ctf.md#backdoored-shared-library-Detection-via-string-diffing-hacklu-ctf-2012)를 참조하세요.

### 이진 반전으로 이동
`go.buildid`를 사용하는 대규모 정적 바이너리? GoReSym을 사용하여 함수 이름을 복구하세요(제거된 바이너리에서도 작동함). Go 문자열은 `{ptr, len}` 쌍이며 null로 끝나지 않습니다. `main.main`, `runtime.gopanic`, 채널 작전(`runtime.chansend1`/`chanrecv1`)을 찾으세요. 최상의 결과를 얻으려면 Ghidra golang-loader 플러그인을 사용하세요. [languages-compiled.md](languages-compiled.md#go-binary-reversing)을 참조하세요.

### C2 열거를 위한 Go Binary UUID 패치
**패턴:** `-ldflags -X`의 UUID를 사용하는 Go C2 클라이언트. 바이너리 패치 UUID 바이트(동일한 길이), C2에 등록, API를 통해 clients/files을 열거합니다. [languages-compiled.md](languages-compiled.md#go-binary-uuid-patching-for-c2-client-enumeration-bsidessf-2026)을 참조하세요.

### D 언어 바이너리 반전
D 언어 바이너리에는 고유한 기호 맹글링(C++ 스타일 아님)이 있습니다. 템플릿이 많고 다양한 기능 변형이 있습니다. 기호에서 `_D` 접두사를 찾으세요. [languages-compiled.md](languages-compiled.md#d-언어-binary-reversing-csaw-ctf-2016)을 참조하세요.

### Rust 바이너리 반전
`core::panicking` 문자열과 `_ZN` 잘못된 기호가 있는 바이너리인가요? 분해하려면 `rustfilt`를 사용하세요. 패닉 메시지에는 소스 경로와 줄 번호가 포함됩니다. `strings binary | grep "panicked"`이 가장 빠른 접근 방식입니다. Option/Result 열거형은 판별 바이트(0=None/Err, 1=Some/Ok)를 사용합니다. [languages-compiled.md](languages-compiled.md#rust-binary-reversing)을 참조하세요.

### Frida 동적 계측
바이너리를 수정하지 않고 런타임 기능을 후크합니다. `frida -f./binary -l hook.js` 계측을 사용하여 생성합니다. `strcmp`/`memcmp`를 후크하여 예상 값을 캡처하고, `ptrace` 반환 값을 대체하여 안티 디버그를 우회하고, 메모리에서 플래그 패턴을 검색하고, 유효성 검사 기능을 대체합니다. [tools-dynamic.md](tools-dynamic.md#frida-dynamic-instrumentation)를 참조하세요.

### Frida Firebase Cloud Functions 우회
**패턴:** Android 앱은 Firebase Cloud Functions를 통해 유효성을 검사합니다. 로그인 후 Frida 후크는 유효한 페이로드(UID + 값 + 타임스탬프)를 구성하고 QR/payment 검증을 우회하여 Cloud Function을 직접 호출합니다. [languages-platforms.md](languages-platforms.md#frida-firebase-cloud-functions-bypass-bsidessf-2026)를 참조하세요.

### angr 상징적 실행
제약 조건을 충족하는 입력을 찾기 위한 자동 경로 탐색입니다. `angr.Project`로 바이너리를 로드하고, find/avoid 주소를 설정하고, `simgr.explore()`를 호출하세요. 더 빠른 해결을 위해 인쇄 가능한 ASCII 및 알려진 접두사로 입력을 제한합니다. 경로 폭발을 방지하기 위해 값비싼 기능(crypto, I/O)을 연결합니다. [tools-dynamic.md](tools-dynamic.md#angr-symbolic-execution)을 참조하세요.

### Qiling Emulation
OS 수준 지원(syscalls, 파일 시스템)을 갖춘 크로스 플랫폼 바이너리 에뮬레이션입니다. 모든 호스트에서 Linux/Windows/ARM/MIPS 바이너리를 에뮬레이트합니다. 디버거 아티팩트 없음 - 기본적으로 모든 안티 디버그를 우회합니다. Python API를 사용하여 시스템 호출과 주소를 연결합니다. [tools-dynamic.md](tools-dynamic.md#qiling-framework-cross-platform-emulation)을 참조하세요.

### VMProtect / 테미다 분석
VMProtect는 코드를 사용자 정의 바이트코드로 가상화합니다. VM 항목 식별(pushad와 유사), 핸들러 테이블 찾기(대규모 간접 점프), 동적으로 핸들러 추적. CTF의 경우 완전한 역가상화보다는 입력에 대한 작업 추적에 중점을 둡니다. Themida: ScyllaHide + Scylla를 사용하여 OEP에 덤프합니다. [tools-advanced.md](tools-advanced.md#vmprotect-분석)을 참조하세요.

### Binary Diffing
BinDiff와 Diaphora는 두 바이너리를 비교하여 변경 사항을 강조합니다. 챌린지가 patched/original 버전을 제공하는 경우 필수입니다. IDA/Ghidra에서 내보내고, 차이점을 비교하여 취약점이나 숨겨진 기능을 찾아보세요. [tools-advanced.md](tools-advanced.md#binary-diffing)을 참조하세요.

### 고급 GDB(pwndbg, rr)
pwndbg: `context`, `vmmap`, `search -s "flag{"`, `telescope $rsp`. GEF 대안. `rr record`/`rr replay`를 사용한 역방향 디버깅 — 실행을 통해 뒤로 단계를 진행합니다. 무차별 대입 및 자동화된 추적을 위한 Python 스크립팅. [tools-advanced.md](tools-advanced.md#advanced-gdb-techniques)를 참조하세요.

### macOS / iOS 반전
Mach-O 바이너리: 로드 명령의 경우 `otool -l`, Objective-C 헤더의 경우 `class-dump`. Swift: 기호의 경우 `swift demangle`입니다. iOS 앱: frida-ios-dump로 FairPlay DRM을 해독하고 Frida 후크로 탈옥 감지를 우회합니다. `codesign -f -s -`를 사용하여 패치된 바이너리에 다시 서명합니다. [platforms.md](platforms.md#macos-ios-reversing)을 참조하세요.

### 임베디드/IoT 펌웨어 RE
`binwalk -Me firmware.bin` 재귀 추출의 경우. 하드웨어: UART/JTAG/SPI 펌웨어 덤프용 플래시. 파일 시스템: SquashFS(`unsquashfs`), JFFS2, UBI. QEMU로 에뮬레이션: `qemu-arm -L /usr/arm-linux-gnueabihf/./binary`. [platforms.md](platforms.md#embedded-iot-firmware-re)를 참조하세요.

### 커널 드라이버 반전
Linux `.ko`: `file_operations` 구조체, 추적 `copy_from_user`/`copy_to_user`을 통해 ioctl 핸들러를 찾습니다. QEMU+GDB로 디버그합니다(`-s -S`). eBPF: `bpftool prog dump xlated`. Windows `.sys`: `DriverEntry` → `IoCreateDevice` → IRP 핸들러를 찾습니다. [platforms.md](platforms.md#kernel-driver-reversing)을 참조하세요.

### Swift/Kotlin 바이너리 반전
Swift: `swift demangle` 기호, 디스패치를 위한 프로토콜 감시 테이블, `__swift5_*` 섹션. Kotlin/JVM: 코루틴은 최상의 디컴파일을 위해 Kotlin 모드를 사용하여 `invokeSuspend`, `jadx`의 상태 머신으로 컴파일됩니다. Kotlin/Native: LLVM 백엔드, 디스어셈블리에서 C++처럼 보입니다. [languages-compiled.md](languages-compiled.md#swift-binary-reversing)을 참조하세요.

### INT3 패치 + 코어 덤프 무차별 대입 Oracle
출력 변환 후 패치 `0xCC`(INT3), 코어 덤프 활성화, `strings`를 통해 코어 덤프에서 계산된 상태를 추출하여 각 입력 문자에 무차별 공격을 가합니다. 변환의 완전한 역전을 방지합니다. [patterns.md](patterns.md#int3-patch-coredump-brute-force-oracle-pwn2win-2016)을 참조하세요.

### 신호 처리기 체인 + LD_PRELOAD Oracle
바이너리는 문자별 비밀번호 확인을 위해 신호 처리기 체인을 사용합니다. LD_PRELOAD를 통한 후크 `signal()` - 다음 핸들러를 설치하기 위한 호출은 현재 문자가 올바른지 확인합니다. [patterns.md](patterns.md#signal-handler-chain-ldpreload-oracle-nuit-du-hack-2016)을 참조하세요.

### 글꼴 합자 악용
사용자 정의 OpenType 글꼴은 다중 문자 합자 시퀀스를 단일 문자 모양으로 매핑합니다. GSUB 테이블을 반전하여 숨겨진 메시지를 디코딩합니다. [patterns-ctf-3.md](patterns-ctf-3.md#opentype-font-ligature-exploitation-for-hidden-messages-hack-the-vote-2016)을 참조하세요.

### 암호화 상태로서의 명령어 카운터
**패턴:** 손으로 작성한 어셈블리는 거의 모든 명령어 후에 증가하는 명령어 카운터로 전용 레지스터(예: `r12`)를 사용합니다. 카운터는 입력 바이트에 대한 XOR/ROL/multiply 변환을 제공하여 변환 경로에 따라 달라집니다. Unicorn 에뮬레이션을 사용한 바이트 단위의 무차별 대입으로 플래그를 복구합니다. [patterns-ctf-3.md](patterns-ctf-3.md#instruction-counter-as-cryptographic-state-metactf-flash-2026)을 참조하세요.

### Burrows-Wheeler 변환 반전
가능한 모든 행 인덱스를 시도하여 종료 문자 없이 BWT를 반전합니다. 표준 `bwtool` 또는 수동 열 정렬 재구성. [patterns-ctf-3.md](patterns-ctf-3.md#burrows-wheeler-transform-inversion-without-terminator-asis-ctf-finals-2016)을 참조하세요.

### FRACTRAN 프로그램 반전
반복적인 분수 곱셈을 사용하는 난해한 언어. 분수표에서 numerator/denominator를 바꿔서 반전하고 출력을 거꾸로 실행합니다. I/O 소인수분해 지수로 인코딩됩니다. [languages.md](languages.md#fractran-program-inversion-boston-key-party-2016)을 참조하세요.

### Opcode 전용 추적 재구성
Opcode만 있는 실행 추적(데이터 없음)은 여전히 분기 결정을 통해 정보를 유출합니다. 정렬 알고리즘 비교를 통해 요소 순서가 드러납니다. 추적을 중복 제거하고 기본 블록으로 분할하여 재구성합니다. [tools-dynamic.md](tools-dynamic.md#opcode-only-trace-reconstruction-0ctf-2016)을 참조하세요.

### 스레드 경쟁 부호 있는 정수 오버플로
스레드가 안전하지 않은 기술 잠금을 사용하는 전투 시뮬레이션 바이너리입니다. 스킬 선택과 데미지 계산 사이의 경쟁; `cdqe` 부호 확장 0xFFFFFFFF를 -1(부호 있음)로 확장하여 빼기 시 HP 오버플로를 발생시킵니다. [patterns-ctf-3.md](patterns-ctf-3.md#thread-race-condition-with-signed-integer-overflow-codegate-2017)을 참조하세요.

### ESP32/Xtensa 펌웨어 반전
IDA 지원 없음 - 기호 확인을 위해 radare2 + ESP-IDF ROM 링커 스크립트(`esp32.rom.ld`)를 사용합니다. 공개 ESP-IDF HTTP 서버 예시를 상호 참조하여 앱 로직을 식별합니다. [patterns-ctf-3.md](patterns-ctf-3.md#esp32xtensa-firmware-reversing-with-rom-symbol-map-insomnihack-2017)을 참조하세요.

### LLVM으로 사용자 정의 VM 바이트코드 리프팅 IR
커스텀 VM 바이트코드를 LLVM IR로 변환한 다음 `opt -O3`를 사용하여 단순화합니다(인라인, 상수 폴딩, 데드 코드 제거). 1300줄을 ~150줄로 줄여 기본 알고리즘을 공개합니다. [tools-advanced.md](tools-advanced.md#custom-vm-bytecode-lifting-to-llvm-ir-google-ctf-2017)을 참조하세요.

### SIGFPE 신호 처리기 측면 채널
SIGFPE 신호 처리기는 정적 분석에 보이지 않는 암시적 제어 흐름을 생성합니다. 후보 문자당 `strace -e signal=SIGFPE`를 통해 SIGFPE 신호를 계산합니다. 올바른 문자는 더 많은 신호를 생성합니다. [anti-analysis.md](anti-analysis.md#sigfpe-signal-handler-side-channel-via-strace-counting-plaidctf-2017)을 참조하세요.

### objdump를 통한 일괄 Crackme 자동화
동일한 구조의 대규모 크랙미 챌린지(100개 바이너리): 스크립트 `objdump`를 사용하여 CMP 즉시 및 add/sub 산술 시퀀스를 추출한 다음 실행 없이 대수적으로 키를 역계산합니다. [patterns-ctf-3.md](patterns-ctf-3.md#batch-crackme-automation-via-objdump-pattern-extraction-def-con-2017)을 참조하세요.

### Android DEX 런타임 바이트코드 패치
네이티브 JNI 라이브러리는 `/proc/self/maps` + `mprotect` + XOR을 통해 메모리의 Dalvik 바이트코드를 패치합니다. 정적 APK 분석만으로는 충분하지 않습니다. 네이티브 `.so`에서 XOR 키와 오프셋을 추출하여 런타임 DEX을 재구성합니다. [languages-platforms.md](languages-platforms.md#android-dex-runtime-bytecode-patching-via-procselfmaps-google-ctf-2017)을 참조하세요.

### 포크 + 파이프 + 데드 브랜치 안티 분석
Fork/pipe 부모가 데이터를 쓰고 종료하고, 자식이 읽고 계속하는 IPC입니다. 데드 브랜치에 숨겨진 실제 검증(항상 거짓 비교). `strace`는 fork/pipe 패턴을 나타냅니다. 숨겨진 코드에 도달하려면 비교 상수를 패치하세요. [patterns-ctf-3.md](patterns-ctf-3.md#fork-pipe-dead-branch-anti-analytic-rctf-2017)을 참조하세요.

## Web/CTF 인증 우회 사례 참고사항

### 서명된 쿠키 키 재사용: admin_session에 대한 액세스 토큰

**사례:** `class.pangbaoba.me` CTF 숙제 시스템. 공개 `/access/<token>` 경로는 서명된 `student_gate`로 설정됩니다. 동일한 액세스 토큰은 `admin_session`의 HMAC 키로도 작동하여 정확한 세션 페이로드 형태를 위조하여 직접 관리자 API 액세스를 허용했습니다.

**핵심 패턴:** 표시되는 invite/access 토큰은 서버측 서명 비밀로 재사용됩니다. 하나의 서명된 쿠키를 오프라인으로 확인할 수 있는 경우 형제 인증 쿠키가 동일한 서명 체계와 키를 사용하는지 테스트하세요.

**Triage workflow:**
1. 출입 통제 경로에서 `Set-Cookie`, 특히 `<base64url-json>.<base64url-signature>` 모양의 쿠키를 캡처하세요.
2. 첫 번째 세그먼트를 디코딩합니다. `{"access":"student"}`와 같은 소형 JSON 페이로드를 식별합니다.
3. 표시되는 경로 토큰, 초대 코드, 재설정 토큰 또는 프런트엔드 상수를 후보 키로 사용하여 `HMAC-SHA256(payload_b64, candidate_key)`를 다시 계산합니다.
4. 서명이 일치하면 비밀번호가 아닌 *페이로드 형태*를 열거하세요. 올바른 쿠키 이름(`admin_session`, `session`, `auth` 등)에 대해 가능한 인증 요청을 시도해 보세요.
5. 쓰기 작업을 수행하기 전에 먼저 읽기 전용 엔드포인트(`/api/admin/me`, settings/status/list 경로)를 확인하세요.

**중요 교훈:** 첫 번째 명백한 페이로드가 실패할 수 있습니다. 이 경우 `{"access":"admin"}`, `{"role":"admin"}` 및 `{"access":"student","isAdmin":true}`는 실패했지만 백엔드는 실제로 다음을 확인했습니다.

```json
{"admin":true}
```

**최소 PoC 형태:**

```python
import base64, hashlib, hmac, json

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

access_token = "<token from /access/<token>>"
payload_b64 = b64u(json.dumps({"admin": True}, separators=(",", ":")).encode())
sig_b64 = b64u(hmac.new(access_token.encode(), payload_b64.encode(), hashlib.sha256).digest())
print(f"admin_session={payload_b64}.{sig_b64}")
```

**Validation signals:**
- `GET /api/admin/me`가 `401 {"error":"unauthorized"}`에서 `200 {"admin":true}`로 변경됩니다.
- 다른 읽기 전용 관리 엔드포인트는 위조된 쿠키를 사용하여 실제 데이터를 반환합니다.
- `admin_session=j:{}`와 같은 JSON-쿠키 값은 `500`를 유발하며 Express/cookie-parser 유형 혼란을 암시하고 깨지기 쉬운 쿠키 구문 분석을 확인합니다. 우회에는 필요하지 않지만 스택 및 구문 분석 가정을 식별하는 데 도움이 됩니다.

**피해야 할 사항:** 서명된 쿠키 구조가 표시될 때 관리자 비밀번호를 무차별 대입하거나 관련 없는 사용자 ID를 열거하지 마세요. 서명에 대해 오프라인으로 작업하고 빈도가 낮은 읽기 전용 확인을 사용합니다.

**수정 지침:** 공개 route/access 토큰을 HMAC 비밀로 사용하지 마세요. 서버 전용 쿠키 서명 비밀, 별도의 student/admin 비밀, 관리자 신원을 위한 서버측 세션, 엄격한 쿠키 유형 검사를 사용하고 parse/verify 실패 시 `500` 대신 `401`를 반환합니다.

## 웹 피싱 인프라

### 피싱 패널: {target_domain_a} / {target_domain_b}
**전체 분석**: [phishing-case-study.md](phishing-case-study.md)

정부 기관을 사칭하는 2서버 피싱 인프라입니다. 서버 기반 상태 코드 리디렉션을 갖춘 완전한 피해자 제어 시스템.

**Architecture:**
- `{target_domain_a}` — 프리젠테이션 레이어(피싱 페이지, JS 폴링 클라이언트)
- `{target_domain_b}` — 데이터 계층(PHP+MySQL 백엔드, 관리 패널)
- 둘 다 NAT 뒤({internal_ip} 내부), nginx, SSL 전용
- 웹 루트: `/www/wwwroot/{target_domain_b}/`

**피해자 흐름:** 랜딩 페이지(가짜 보조금 할당량) → 1.html(ID/bank 카드 양식 → `submit.php`) → 4.html(PIN → `get-ayment.php`) → 1초 `status_check.php` 폴링을 통해 서버가 제어하는 단계적 페이지(9-16).

**Key Findings:**
- `register.php` → `qichuang.php`(로그인 양식), `list.php`(대시보드 템플릿)의 관리자 패널
- PHP 세션을 통한 인증(`PHPSESSID`); `login.php` 및 `check_login_ajax.php` 삭제됨(404)
- **데이터 유출**: `db.php`는 인증 없이 피해자 이름 목록을 반환합니다(49개 이상의 기록, **은행 세부 정보 없음** — id/username/note/description 필드만)
- **인증 없음 쓰기**: `save_note.php` 인증 없이 데이터를 허용합니다.
- `backend.php` 관리자 등록 끝점을 제안하는 SQL 오류 발생(손상됨)
- `submit.php`(다중 요인)에 대한 속도 제한, SQLi 또는 세션 우회가 발견되지 않음
- 상태 코드 시스템: 관리자는 1-16을 설정하고, 피해자 브라우저는 `N.html`로 자동 리디렉션됩니다.

**Infrastructure:**
| Domain | Public IP | Role |
|--------|-----------|------|
| {target_domain_1}| {target_ip_1}| Backend + Admin |
| {target_domain_2}| {target_ip_2}| 프런트엔드(피싱 페이지)|



---

## 분석 전 예상: 문서 위장 및 이름 스푸핑

### 파일 접미사를 신뢰할 수 없습니다.

**핵심 원칙: 항상 `file` 명령이나 매직 바이트를 사용하여 파일 형식을 결정하고 접미사 이름을 신뢰하지 마십시오. **

일반적인 위장 기술:

| 변장 접미사| 실제 유형| 목적|
|---------|---------|------|
| `.sh` | ELF 바이너리| 사람들이 그것이 대본이라고 생각하게 만들고 경계심을 낮추십시오.|
| `.txt` | PE/ELF | 단순 파일 형식 필터링 우회|
| `.jpg`/`.png` | 실행 파일 또는 압축 패키지| 그림 속에 숨겨진|
| `.dll` | 실제로.NET 어셈블리|분석 방향의 혼란|
| `.so` | 실제로는 암호화된 페이로드입니다.| 먼저 암호를 해독해야 합니다.|
| 접미사 없음| 모든 유형| Linux에서 일반적|

```bash
# 올바른 접근 방식: file 명령 사용
file suspicious_file.sh
# 출력: ELF 64비트 LSB 실행 파일, ARM aarch64...

# xxd를 사용하여 매직 바이트 보기
xxd suspicious_file.sh | head -1
# 7f454c46 = ELF magic
```

### 파일 이름을 신뢰할 수 없습니다.

**"DriverLoader"는 드라이버를 로드하지 못할 수 있으며 "업데이터"는 드라이버를 업데이트하지 못할 수 있습니다. **

일반 이름 스푸핑:

| 파일 이름 힌트| 실제 행동|
|-----------|---------|
| `DriverLoader` | 아마도 ptrace 인젝터/프로세스 후크일 것입니다.|
| `SystemService` | 백도어/C2 에이전트일 가능성이 있음|
| `Updater` / `Update` | 아마도 드로퍼/다운로더일 것입니다.|
| `Helper` / `Assistant` | 권한 상승 도구일 가능성이 있음|
| `lib*.so` | 페이로드 주입 가능성|

**분석 시 다음을 수행해야 합니다.**
- 파일 이름 힌트를 무시하고 실제 코드 동작으로 판단
- `mmap`, `ptrace`, `/proc/self/mem` 등과 같은 시스템 호출에 주의하세요.
- "Load Driver"가 표시되지만 `insmod`/`init_module` 호출이 없으면 이름이 이름에 걸맞지 않다는 의미입니다.

### 정적 분석만으로는 충분하지 않은 경우 동적 보완

순수한 정적 분석은 코드의 뼈대만 볼 수 있습니다. 다음 시나리오는 동적 분석과 협력해야 합니다.

| 장면| 권장되는 동적 방법|
|------|-------------|
| 코드에는 암호 해독/압축 해제 논리가 있습니다.| 복호화 후 중단점을 설정하고 일반 텍스트를 덤프합니다.|
| 많은 간접 호출(함수 포인터 표)| strace/ltrace 실제 호출 추적|
| 안티 디버깅이 의심됨| ptrace 호출을 보기 위한 첫 번째 strace|
| 삽입됨 shellcode/payload| QEMU 사용자 모드 시뮬레이션 실행|
| 네트워크 통신 프로토콜을 알 수 없음| tcpdump/Wireshark 패킷 캡처|

```bash
# strace 추적 시스템 호출(포커스)
strace -f -e trace=open,mmap,ptrace,execve,connect ./binary

# ltrace는 라이브러리 함수 호출을 추적합니다.
ltrace -f ./binary

# QEMU 사용자 모드 시뮬레이션(실제 장치가 필요하지 않음)
qemu-aarch64 -strace ./binary_arm64

# 디버깅 방지 확인: ptrace가 자체 추적되는지 확인
strace ./binary 2>&1 | grep ptrace
# ptrace(PTRACE_TRACEME,...)가 표시되면 디버깅 방지가 있음을 의미합니다.
```

### 프로세스 주입/보호된 쉘 샘플의 일반적인 패턴

이러한 샘플(예: `LinYuDriverLoader`)은 일반적으로 다음과 같습니다.

1. **커널 드라이버를 실제로 로드하지 않음**(대부분의 시나리오에서는 사용할 수 없는 루트 권한이 필요함)
2. **실제 동작은 프로세스 주입입니다**:
   - `ptrace` 대상 프로세스에 연결
   - `/proc/<pid>/mem`를 통해 대상 메모리 읽기 및 쓰기
   - `mmap` 쉘코드를 대상 프로세스 공간에 매핑
3. **내장된 암호화 페이로드**:
   - 런타임에 쉘코드 조각을 해독합니다.
   - 해독된 페이로드는 실제 후크 코드입니다.
4. **디버깅 방지 보호**:
   - `ptrace(PTRACE_TRACEME)` 자체 추적
   - 시간 감지(`clock_gettime` 전후 비교)
   - `/proc/self/status` TracerPid 확인

**분석 전략**:
```text
1. file 명령은 실제 유형을 확인합니다.
2. 명백한 경로/라이브러리 이름/오류 메시지가 있는지 확인하기 위한 문자열
3. rabin2 -I 아키텍처/컴파일러/보호를 확인합니다.
4. 정적 검색 mmap/ptrace/open 호출
5. 복호화 로직이 있는 경우 → 동적으로 실행하여 복호화 후 덤프
6. 디버깅 방지가 있는 경우 → 먼저 패치하거나 LD_PRELOAD를 사용하여 우회합니다.
```
