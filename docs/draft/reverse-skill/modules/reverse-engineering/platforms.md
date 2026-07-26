# CTF 리버스 - 플랫폼별 리버싱

macOS/iOS, embedded/IoT 펌웨어, 커널 드라이버 및 자동차 리버스 엔지니어링.

## 목차
- [macOS / iOS 반전](#macos--ios-반전)
  - [Mach-O 바이너리 형식](#mach-o-바이너리-형식)
  - [코드 서명 및 권한](#코드-서명-및-권한)
  - [Objective-C 런타임 RE](#objective-c-런타임-re)
  - [Swift 바이너리 리버싱](#swift-바이너리-리버싱)
  - [iOS 앱 분석](#ios-앱-분석)
  - [dyld / 동적 연결](#dyld--동적-연결)
- [임베디드/IoT 펌웨어 RE](#임베디드iot-펌웨어-re)
  - [Firmware Extraction](#firmware-extraction)
  - [Firmware Unpacking](#firmware-unpacking)
  - [Architecture-Specific Notes](#architecture-specific-notes)
  - [RTOS Analysis](#rtos-analysis)
- [커널 드라이버 반전](#커널-드라이버-반전)
  - [Linux 커널 모듈](#linux-커널-모듈)
  - [eBPF Programs](#ebpf-programs)
  - [Windows 커널 드라이버](#windows-커널-드라이버)
- [자동차/CAN 버스 RE](#자동차can-버스-re)

---

## macOS / iOS 반전

### Mach-O 바이너리 형식

```bash
# File identification
file binary                    # "Mach-O 64-bit executable arm64" or "x86_64"
otool -l binary               # Load commands (segments, dylibs, entry point)
otool -L binary               # Linked dynamic libraries

# Universal (fat) binaries — multiple architectures in one file
lipo -info universal_binary    # List architectures
lipo universal_binary -thin arm64 -output binary_arm64  # Extract one arch

# Segments and sections
otool -l binary | grep -A5 "segment\|section"
# Key segments: __TEXT (code), __DATA (globals), __LINKEDIT (symbols)
# Key sections: __text (instructions), __cstring (C strings), __objc_methname
```

**핵심 Mach-O 개념:**
- 로드 명령은 동적 링커를 구동합니다(`dyld`).
- `LC_MAIN` → 진입점(`LC_UNIXTHREAD` 대체)
- `LC_LOAD_DYLIB` → 공유 라이브러리 종속성
- `LC_CODE_SIGNATURE` → 코드 서명 blob
- `__DATA_CONST.__got` → 전역 오프셋 테이블
- `__DATA.__la_symbol_ptr` → 게으른 기호 포인터(PLT와 같은)

### 코드 서명 및 권한

```bash
# Check code signature
codesign -dvvv binary
codesign --verify binary

# Extract entitlements (capability permissions)
codesign -d --entitlements - binary
# Key entitlements: com.apple.security.app-sandbox, com.apple.security.network.client

# Remove code signature (for patching)
codesign --remove-signature binary

# Re-sign (ad-hoc, for testing)
codesign -f -s - binary
```

**CTF 관련성:** 패치된 바이너리를 macOS에서 실행하려면 다시 서명해야 합니다. 임시 서명(`-s -`)은 로컬 테스트에 적합합니다.

### Objective-C 런타임 RE

```text
# Dump Objective-C class info
class-dump binary > classes.h
# Shows: @interface, @protocol, method signatures with types

# Runtime inspection with lldb
(lldb) expression -l objc -O -- [NSClassFromString(@"ClassName") new]
(lldb) expression -l objc -O -- [[ClassName alloc] init]

# Method swizzling detection (anti-tamper)
# Look for: method_exchangeImplementations, class_replaceMethod
```

**분해된 Objective-C:**
```text
# objc_msgSend(receiver, selector, ...) is THE dispatch mechanism
# x86-64: RDI=self, RSI=_cmd. arm64: x0=self, x1=_cmd.
# The selector is a SEL token, not a C string pointer, though its name is
# represented in Objective-C metadata.

# In Ghidra/IDA, look for:
objc_msgSend(obj, "checkPassword:", input)
# Selector strings are in __objc_methname section
# Cross-reference selectors to find implementations
```

**class-dump alternatives:**
- `dsdump` — 더 빠르고 Swift + Objective-C 지원
- `otool -oV binary` — Objective-C 세그먼트 덤프
- Ghidra: 분석 옵션에서 "Objective-C" 분석기를 활성화합니다.

### Swift 바이너리 리버싱

```bash
# Detect Swift
strings binary | grep "swift"
otool -l binary | grep "swift"   # __swift5_* sections

# Swift demangling
swift demangle '$s14MyApp0A8ClassC10checkInput6resultSbSS_tF'
# → MyApp.MyAppClass.checkInput(result: String) -> Bool

# xcrun swift-demangle < mangled_names.txt
```

**Swift 분해:**
```text
# Swift uses value witness tables (VWT) for type operations
# Protocol witness tables (PWT) for dynamic dispatch (like vtables)

# Key runtime functions to watch:
swift_allocObject          → heap allocation
swift_release             → reference count decrement
swift_bridgeObjectRetain  → bridged (ObjC ↔ Swift) retain
swift_once                → lazy initialization (like dispatch_once)

# String/Array/Dictionary representations are implementation details that can
# change across Swift runtime versions. Use metadata, witness operations, and
# observed accesses instead of imposing a fixed field layout.
```

**Ghidra Swift의 경우:** "Swift" 언어 모듈을 활성화합니다. Swift 메타데이터 섹션(`__swift5_types`, `__swift5_proto`)에는 Ghidra가 구문 분석할 수 있는 유형 설명자가 포함되어 있습니다.

### iOS 앱 분석

```bash
# Extract IPA (iOS app package)
unzip app.ipa -d extracted/
ls extracted/Payload/*.app/

# Check if encrypted (App Store encryption / FairPlay DRM)
otool -l extracted/Payload/*.app/binary | grep -A4 "LC_ENCRYPTION_INFO"
# cryptid = 1 means encrypted, 0 means decrypted

# Decrypt with frida-ios-dump (requires jailbroken device)
# Or use Clutch / bfdecrypt on device
frida-ios-dump -H jailbroken_ip -p 22 "App Name"

# Analyze decrypted binary
class-dump decrypted_binary > headers.h
```

**탈옥 감지 및 우회:**
```javascript
// Common jailbreak checks:
// 1. Check for Cydia/Sileo
// 2. Check /private/var/lib/apt
// 3. fork() succeeds (sandboxed apps can't fork)
// 4. Open /etc/apt, /bin/sh with write
// 5. Check for substrate/substitute libraries

// Frida bypass:
var paths = ["/Applications/Cydia.app", "/bin/sh", "/etc/apt",
             "/private/var/lib/apt", "/usr/bin/ssh"];
Interceptor.attach(Module.getGlobalExportByName("access"), {
    onEnter(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave(retval) {
        if (paths.some(p => this.path && this.path.includes(p))) {
            retval.replace(-1);  // File not found
        }
    }
});
```

### dyld / 동적 연결

```bash
# DYLD environment variables (for analysis, blocked in hardened runtime)
DYLD_PRINT_LIBRARIES=1 ./binary       # Print loaded dylibs
DYLD_INSERT_LIBRARIES=hook.dylib ./binary  # Inject dylib (like LD_PRELOAD)
# Note: SIP (System Integrity Protection) blocks this for system binaries

# Inspect dyld shared cache (contains all system frameworks)
dyld_shared_cache_util -list /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

---

## 임베디드/IoT 펌웨어 RE

### Firmware Extraction

```bash
# binwalk — firmware analysis and extraction
binwalk firmware.bin                        # Identify embedded filesystems, compressed data
binwalk -e firmware.bin                     # Extract all identified components
binwalk -Me firmware.bin                    # Recursive extraction (matryoshka)
binwalk --dd='.*' firmware.bin              # Extract everything raw

# Manual extraction by signature
strings firmware.bin | head -50             # Look for version strings, filesystem markers
hexdump -C firmware.bin | grep "hsqs"       # SquashFS magic
hexdump -C firmware.bin | grep "UBI#"       # UBI magic
```

**하드웨어 추출 방법(물리적 접근):**
먼저 보드 전원을 분리하고 핀 전압·logic level·ground를 측정하세요. 어댑터의 VCC를 무작정 연결하지 말고, 가능한 경우 read-only·저속 캡처로 시작하며 원본 flash의 검증된 복사본을 보존하세요. 실제 장치 작업은 소유·허가 범위와 전기 안전 절차 안에서 수행합니다.

```text
UART:  Serial console — often gives root shell or bootloader access
       Tools: USB-UART adapter, baudrate detection (usually 115200)
       Identify: 4 pins (GND, TX, RX, VCC), use multimeter

JTAG:  Direct CPU debug — read/write flash, halt CPU, set breakpoints
       Tools: OpenOCD, J-Link, Bus Pirate
       Identify: 10/14/20-pin header, use JTAGulator for auto-detection

SPI Flash: Direct chip read — dump entire firmware
           Tools: flashrom, CH341A programmer
           Identify: 8-pin SOIC chip (Winbond, Macronix, etc.)

eMMC:  Embedded MMC — common in routers, phones
       Tools: eMMC reader, direct solder to test pads
```

### Firmware Unpacking

```bash
# SquashFS (most common in routers)
unsquashfs -d output/ squashfs-root.sqfs
# If custom compression: try different compressors (-comp xz|lzma|lzo|gzip)

# JFFS2
jefferson -d output/ jffs2.img

# UBI/UBIFS
ubireader_extract_images firmware.ubi
ubireader_extract_files ubifs.img

# CPIO (initramfs)
cpio -idv < initramfs.cpio

# Device tree blob
dtc -I dtb -O dts -o output.dts device_tree.dtb

# Kernel extraction
binwalk -e firmware.bin
# Look for: zImage, uImage, vmlinux
# Extract vmlinux from compressed: vmlinux-to-elf tool
```

### Architecture-Specific Notes

**ARM(IoT에서 가장 일반적임):**
```bash
# Cross-toolchain
apt install gcc-arm-linux-gnueabihf gdb-multiarch

# QEMU emulation
qemu-arm -L /usr/arm-linux-gnueabihf/ ./arm_binary
qemu-arm -g 1234 ./arm_binary    # Start GDB server on port 1234
gdb-multiarch -ex 'target remote :1234' ./arm_binary

# ARM instructions are 4 bytes; Thumb instructions may be 16 or 32 bits
# LSB of function pointer indicates mode: 0=ARM, 1=Thumb
# Ghidra: Right-click → Processor Options → ARM/Thumb mode
```

**ARM64/AArch64:** AArch64 호출 규칙, ROP 가젯 및 qemu-aarch64-static 에뮬레이션은 [platforms-hardware.md](platforms-hardware.md#arm64aarch64-반전-및-착취)을 참조하세요.

**MIPS(라우터, 내장형):**
```bash
# Big-endian vs little-endian — check ELF header or file command
file binary    # "MIPS, MIPS32 rel2 (MIPS-II), big-endian" or "little-endian"

# Emulation
qemu-mips -L /usr/mips-linux-gnu/ ./mips_binary         # Big-endian
qemu-mipsel -L /usr/mipsel-linux-gnu/ ./mipsel_binary   # Little-endian

# Key MIPS patterns:
# Pre-Release-6 MIPS commonly has a delay-slot instruction; branch-likely and
# annul semantics need separate handling, and MIPS Release 6 removed delay slots.
# $gp (global pointer) — used for PIC, points to .got
# lui + addiu pair — loads 32-bit constant (upper 16 + lower 16)
```

**RISC-V:** 캡스톤 분해에 대해서는 메인 [tools.md](tools.md#risc-v-이진-분석ehax-2026)을 참조하고 고급 확장 및 디버깅에 대해서는 [platforms-hardware.md](platforms-hardware.md#risc-v-advanced)를 참조하세요.

### RTOS Analysis

```text
FreeRTOS:
  - Tasks (like threads): xTaskCreate → function pointer + stack
  - Strings: "IDLE", "Tmr Svc", task names
  - xQueueSend/xQueueReceive → inter-task communication
  - Look for vTaskDelay() for timing, xSemaphoreTake() for sync

Zephyr:
  - k_thread_create → kernel thread creation
  - k_msgq_put/k_msgq_get → message queues
  - CONFIG_* symbols reveal kernel configuration

Bare metal (no OS):
  - Interrupt vector table at address 0x0 or 0x08000000 (STM32)
  - main loop pattern: while(1) { read_input(); process(); output(); }
  - Peripheral registers at memory-mapped addresses (check datasheet)
```

---

## 커널 드라이버 반전

### Linux 커널 모듈

```bash
# Identify kernel module
file module.ko                      # "ELF 64-bit LSB relocatable"
modinfo module.ko                   # Module info (description, author, license)

# List module symbols
nm module.ko | grep -v " U "       # Symbols defined in the module (not all exported)

# Strings for quick recon
strings module.ko | grep -i "flag\|secret\|ioctl\|device"

# Find ioctl handler
# Key pattern: .unlocked_ioctl = my_ioctl_handler in file_operations struct
# In Ghidra: find struct with function pointers, identify by position

# Load in Ghidra
# Language: x86:LE:64:default
# Choose a consistent analysis base; runtime addresses require applying the
# module's relocations and actual load base.
# Look for init_module / cleanup_module entry points
```

**공통 커널 모듈 CTF 패턴:**
```c
// Device creation (creates /dev/challenge)
alloc_chrdev_region(&dev, 0, 1, "challenge");
cdev_init(&cdev, &fops);

// ioctl handler (main interface)
long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case CUSTOM_CMD_1: /* operation */ break;
        case CUSTOM_CMD_2: /* operation */ break;
    }
}

// copy_from_user / copy_to_user — data transfer with userspace
copy_from_user(kernel_buf, (void __user *)arg, size);
copy_to_user((void __user *)arg, kernel_buf, size);
```

**커널 모듈 디버깅:**
```text
# QEMU + GDB for kernel debugging
qemu-system-x86_64 -kernel bzImage -initrd initrd.cpio -s -S \
  -append "console=ttyS0 nokaslr" -nographic

# In another terminal
gdb vmlinux
(gdb) target remote :1234
(gdb) lx-symbols           # Load module symbols (requires scripts)
(gdb) add-symbol-file module.ko 0x<loaded_address>
```

### eBPF Programs

```bash
# Dump eBPF programs from running system
bpftool prog list
PROGRAM_ID=42  # 검토할 실제 프로그램 ID로 교체
bpftool prog dump xlated id "$PROGRAM_ID"    # Disassemble
bpftool prog dump jited id "$PROGRAM_ID"     # JIT'd machine code

# eBPF bytecode analysis
# eBPF has 11 registers (r0-r10), 64-bit
# r0 = return value, r1-r5 = arguments, r10 = frame pointer
# Most eBPF instructions are 8 bytes; LDDW (64-bit immediate load) occupies 16.

# Disassemble .o file containing eBPF
llvm-objdump -d ebpf_prog.o

# Key eBPF patterns:
# bpf_map_lookup_elem → read from map
# bpf_map_update_elem → write to map
# bpf_probe_read → read kernel memory
# bpf_trace_printk → debug output
```

### Windows 커널 드라이버

```bash
# .sys files are PE format — load in IDA/Ghidra as normal PE
# Entry point: DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)

# Key patterns:
# IoCreateDevice → creates device object
# IRP_MJ_DEVICE_CONTROL → ioctl handler
# MmMapIoSpace → memory-mapped I/O
# ObReferenceObjectByHandle → get kernel object from handle
# ZwCreateFile/ZwReadFile → kernel-mode file operations
```

---

## 자동차/CAN 버스 RE

실제 차량/산업용 버스에서는 아래 송신·재생 명령을 사용하지 말고, 소유하거나 명시적으로 허가받은 전원 제한 격리 벤치와 virtual CAN에서 먼저 검증하세요. 잘못된 프레임은 물리 장치 동작과 안전에 영향을 줄 수 있습니다.

```bash
# CAN bus interface setup
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# Capture CAN traffic
candump can0                               # Live capture
candump -l can0                            # Log to file
cansniffer can0                            # Filter/highlight changes

# Replay CAN messages
canplayer -I logfile.log can0
cansend can0 7DF#0201000000000000          # Send single frame (OBD-II request)

# UDS (Unified Diagnostic Services) — common in automotive CTF
# Service 0x27: Security Access (seed-key authentication)
# Service 0x2E: Write Data By Identifier
# Service 0x31: Routine Control

# Decode CAN frames
# ID: 11-bit or 29-bit identifier
# Classic CAN: DLC encodes 0-8 payload bytes.
# CAN FD supports payloads up to 64 bytes with a nonlinear DLC mapping above 8.
```

**CTF 자동차 패턴:**

- 시드 키 바이패스: ECU 펌웨어에서 키 파생 알고리즘을 역전시킵니다.
- CAN 메시지 재생: 합법적인 명령 캡처, 재생을 통해 기능 잠금 해제
- UDS/KWP2000를 통해 ECU에서 펌웨어 추출
