# CTF 리버스 - 하드웨어 및 고급 아키텍처 리버싱

HD44780 LCD GPIO 재구성, RISC-V 고급 확장 및 디버깅, ARM64/AArch64 반전 및 활용.

## 목차
- [HD44780 LCD 컨트롤러 GPIO 재구성(32C3 2015)](#hd44780-lcd-controller-gpio-reconstruction-32c3-2015)
- [RISC-V(고급)](#risc-v-advanced)
  - [사용자 정의 확장](#custom-extensions)
  - [권한 모드](#privileged-modes)
  - [RISC-V 디버깅](#risc-v-debugging)
- [ARM64/AArch64 반전 및 악용](#arm64aarch64-reversing-and-exploitation)
- [MIPS64 Cavium OCTEON 보조 프로세서 2 암호화(SEC-T CTF 2017)](#mips64-cavium-octeon-coprocessor-2-crypto-sec-t-ctf-2017)
- [EFM32 ARM 마이크로컨트롤러 MMIO AES(SEC-T CTF 2017)](#efm32-arm-microcontroller-mmio-aes-sec-t-ctf-2017)
- [MBR/Bootloader QEMU + GDB로 반전(Square CTF 2017)](#mbrbootloader-reversing-with-qemu--gdb-square-ctf-2017)

---

## HD44780 LCD 컨트롤러 GPIO 재구성(32C3 2015)

원시 Raspberry Pi GPIO 녹음에서 HD44780 LCD에 표시된 텍스트를 복구합니다.

1. **신호 라인 식별:** GPIO 핀을 HD44780 신호(4비트 모드의 경우 RS, CLK, D4-D7)에 매핑
2. **클럭 에지 감지:** 하강 클록 에지의 샘플 데이터 라인(1->0 전환)
3. **니블 어셈블리:** 두 개의 4비트 샘플을 하나의 8비트 command/data 바이트로 결합합니다.
4. **DRAM 주소 매핑:** HD44780은 다중 라인 디스플레이에 비연속 주소 지정을 사용합니다.
   - Line 0: 0x00-0x27
   - Line 1: 0x40-0x67
   - Line 2: 0x14-0x3B
   - Line 3: 0x54-0x7B

```python
display = [' '] * 80  # 4 lines x 20 chars
cursor = 0

for timestamp, gpio_state in sorted(gpio_log):
    if falling_edge(gpio_state, CLK_PIN):
        nibble = extract_data_bits(gpio_state)
        byte = assemble_nibble(nibble)  # Two nibbles per byte
        if rs_high(gpio_state):  # RS=1: data write
            display[dram_to_position(cursor)] = chr(byte)
            cursor += 1
        else:  # RS=0: command (set cursor, clear, etc.)
            cursor = parse_command(byte)
```

**주요 통찰력:** GPIO 핀-신호 매핑은 거의 문서화되지 않습니다. 가장 많은 전환이 있는 핀을 찾아서 CLK를 식별하고, RS는 데이터 패턴(command/data 위상 교대)과의 상관 관계를 통해 식별합니다.

---

## RISC-V (Advanced)

기본적인 분해를 넘어([tools.md](tools.md#risc-v-binary-analytic-ehax-2026) 참조):

### Custom Extensions

```text
Bitmanip extensions (Zbb, Zbc, Zbs):
  clz, ctz, cpop         -> count leading/trailing zeros, popcount
  orc.b, rev8            -> byte-level bit manipulation
  andn, orn, xnor        -> negated logic operations
  clmul, clmulh, clmulr  -> carry-less multiplication (crypto)
  bset, bclr, binv, bext -> single-bit operations

Crypto extensions (Zk*):
  aes32esi, aes32dsmi     -> AES round operations
  sha256sig0, sha512sum0  -> SHA hash acceleration
  sm3p0, sm4ed            -> Chinese crypto standards
```

### Privileged Modes

```text
Machine mode (M):  Highest privilege, firmware/bootloader
Supervisor mode (S): OS kernel
User mode (U):      Applications

CSR registers to watch:
  mstatus/sstatus    -> privilege level, interrupt enable
  mtvec/stvec       -> trap handler address
  mepc/sepc         -> exception return address
  mcause/scause     -> trap cause
  satp              -> page table root (virtual memory)
```

### RISC-V Debugging

```bash
# OpenOCD + GDB for hardware debugging
openocd -f interface/jlink.cfg -f target/riscv.cfg

# GDB for RISC-V
riscv64-unknown-elf-gdb binary
(gdb) target remote :3333

# QEMU with GDB server
qemu-riscv64 -g 1234 -L /usr/riscv64-linux-gnu/ ./binary
riscv64-linux-gnu-gdb -ex 'target remote :1234' ./binary
```

---

## ARM64/AArch64 반전 및 착취

AArch64(ARM 64비트)는 모바일 앱, 클라우드 서버(AWS Graviton), Apple Silicon 및 CTF 챌린지에 나타납니다. x86-64와의 주요 차이점은 반전과 활용 모두에 영향을 미칩니다.

**설정 및 에뮬레이션:**

```bash
# Install cross-toolchain and emulator
apt install gcc-aarch64-linux-gnu gdb-multiarch qemu-user-static

# Run AArch64 binary on x86 host
qemu-aarch64-static -L /usr/aarch64-linux-gnu/ ./arm64_binary

# Debug with GDB
qemu-aarch64-static -g 12345 -L /usr/aarch64-linux-gnu/ ./arm64_binary &
gdb-multiarch -ex 'set arch aarch64' -ex 'target remote :1234' ./arm64_binary

# With library preloading (for challenges that ship libc)
qemu-aarch64-static -g 12345 -E LD_PRELOAD=./libc.so.6 -L ./lib ./arm64_binary
```

**AArch64 호출 규칙(x86-64와의 주요 차이점):**

```text
Registers:
  x0-x7    -- function arguments AND return values (x0 = first arg / return)
  x8       -- indirect result location (struct returns)
  x9-x15   -- caller-saved temporaries
  x19-x28  -- callee-saved (preserved across calls)
  x29 (fp) -- frame pointer
  x30 (lr) -- link register (return address, NOT on stack by default)
  sp       -- stack pointer (must be 16-byte aligned)
  xzr      -- zero register (reads as 0, writes discarded)

Key exploitation differences:
  - Return address in LR (x30), not on stack -- pushed only if function calls others
  - No RIP-relative addressing like x86 -- uses ADRP+ADD pairs for PC-relative loads
  - Fixed 4-byte instruction width -- no variable-length gadget tricks
  - NOP = 0xD503201F (not 0x90)
  - BLR x8 / BR x30 -- indirect calls/jumps use register operands
```

**Ghidra/IDA의 일반적인 AArch64 패턴:**

```text
# PC-relative address loading (equivalent to x86 LEA):
ADRP  x0, #0x411000      ; Load page address (4KB aligned)
ADD   x0, x0, #0x8       ; Add page offset -> x0 = 0x411008

# Function prologue:
STP   x29, x30, [sp, #-0x30]!  ; Push fp + lr, decrement sp
MOV   x29, sp                   ; Set frame pointer

# Function epilogue:
LDP   x29, x30, [sp], #0x30    ; Pop fp + lr, increment sp
RET                              ; Branch to x30 (lr)

# Switch/jump table:
ADR   x1, jump_table
LDRB  w2, [x1, x0]       ; Load offset byte
ADD   x1, x1, w2, SXTB   ; Sign-extend and add
BR    x1                   ; Indirect branch
```

**AArch64의 ROP:**

```python
from pwn import *

# AArch64 gadgets differ from x86:
# - "pop {x0}; ret" equivalent: LDP x0, x1, [sp], #0x10; RET
# - Prologue gadgets: LDP x29, x30, [sp, #0x20]; ... RET
# - system() call: x0 = pointer to "/bin/sh", BLR to system

context.arch = 'aarch64'
elf = ELF('./arm64_binary')

# Common gadget pattern in AArch64 libc:
# LDP X19, X20, [SP,#var_s10]
# LDP X29, X30, [SP+var_s0],#0x20
# RET
# Controls x19, x20, x29, x30 and advances sp by 0x20
```

**주요 통찰력:** AArch64의 고정 명령어 너비와 레지스터 기반 반환 주소(`lr`/`x30`)는 ROP 가젯을 x86보다 더 제한적으로 만듭니다. 스택에서 여러 레지스터를 팝하는 `LDP`(로드 쌍) 가젯을 찾으세요. save/restore 호출 수신자가 함수 prologues/epilogues에 저장한 `STP`/`LDP` 명령어 쌍이 기본 가젯 소스입니다.

**인식해야 하는 경우:** `file`는 "ELF 64비트 LSB... ARM aarch64"를 표시합니다. Ghidra 자동 감지하지만 원시 바이너리의 경우 수동 프로세서 선택이 필요할 수 있습니다. x86 호스트에서 에뮬레이션하려면 `qemu-aarch64-static`를 사용하세요.

**도구:** radare2 (`r2 -AA -a arm -b 64`), Ghidra (자동 감지), `aarch64-linux-gnu-objdump -d`, Unicorn Engine (`UC_ARCH_ARM64`)

**참고 자료:** Google CTF 2016 "Forced Puns", Insomni'hack 2018 "onecall"

---

## MIPS64 Cavium OCTEON 보조 프로세서 2 암호화(SEC-T CTF 2017)

Cavium OCTEON 네트워크 프로세서는 `dmtc2`(CP2로 이동) 및 `dmfc2`(CP2에서 이동) 명령을 사용하여 MIPS Coprocessor 2(CP2)를 통해 하드웨어 AES 및 SHA256을 구현합니다. 이는 일반 레지스터가 디스어셈블러로 이동하는 것처럼 보이지만 하드웨어 암호화 엔진을 구동합니다.

**주요 CP2 레지스터 레이아웃(OCTEON):**
```text
AES key registers:
  0x0104 – AES key quadword 0
  0x0105 – AES key quadword 1
  0x0106 – AES key quadword 2
  0x0107 – AES key quadword 3

SHA256 hash registers:
  0x400E–0x4012 – SHA256 intermediate hash words
  0x404F        – SHA256 control/result

dmtc2  rN, 0x0104   ; load 64 bits of AES key into CP2 register 0x104
dmtc2  rN, 0x0105   ; ...next quadword
```

**Approach:**
1. IDA/Ghidra에서 분해 — 0x100-0x40FF 범위의 선택기를 사용하여 `dmtc2`/`dmfc2`는 OCTEON CP2를 나타냅니다.
2. 레지스터 의미론에 대해서는 Cavium OCTEON 하드웨어 참조 매뉴얼을 상호 참조하십시오.
3. AES 또는 HMAC 키 자료를 복구하기 위해 키 로딩 순서를 추적합니다.

**주요 통찰력:** MIPS의 하드웨어 암호화 가속기는 CP2 레지스터 쓰기(`dmtc2`/`dmfc2`)로 나타납니다. 기본 레지스터 주소와 상호 참조 공급업체 문서를 식별합니다.

**참고 자료:** SEC-T CTF 2017

---

## EFM32 ARM 마이크로컨트롤러 MMIO AES(SEC-T CTF 2017)

Silicon Labs EFM32 Cortex-M 바이너리 — Thumb 모드에서 0x1000에 로드되는 플랫 바이너리입니다.

**IDA setup:**
```text
Processor: ARM Little-endian (ARMv7-M)
Load address: 0x1000
Set T register = 1 (force Thumb mode decoding)
```

**AES 가속기 MMIO 레이아웃(0x400E0000의 EFM32 AES 주변 장치):**
```text
0x400E0000 + 0x000  CTRL   – enable, decrypt mode
0x400E0000 + 0x004  CMD    – start/stop
0x400E0000 + 0x010  KEYLA  – key low word 0
0x400E0000 + 0x014  KEYLB  – key low word 1
0x400E0000 + 0x018  KEYLC  – key low word 2
0x400E0000 + 0x01C  KEYLD  – key low word 3
```

바이너리는 두 개의 개별 값을 로드하고 XOR한 다음 결과를 AES 키로 기록합니다. ECB 모드에서 구성된 키를 사용하여 포함된 암호문 블록을 해독합니다.

```python
from Crypto.Cipher import AES

key_part_a = bytes.fromhex("...")  # extracted from IDA .data section
key_part_b = bytes.fromhex("...")  # second value
key = bytes(a ^ b for a, b in zip(key_part_a, key_part_b))

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
```

**주요 통찰력:** 마이크로 컨트롤러의 하드웨어 AES 가속기는 특정 기본 주소에 MMIO 레지스터 쓰기로 나타납니다. 공급업체 참조 매뉴얼(Silicon Labs 주변 장치에 대한 EFM32 참조 매뉴얼)을 상호 참조하세요.

**참고 자료:** SEC-T CTF 2017

---

## MBR/Bootloader QEMU + GDB로 반전(Square CTF 2017)

GDB 스텁이 활성화된 QEMU에서 floppy/disk 이미지를 부팅한 다음 16비트 리얼 모드 또는 32비트 보호 모드 부트로더 코드의 전체 소스 레벨 디버깅을 위해 GDB를 연결합니다.

```bash
# Boot with GDB stub on port 1234; -S pauses execution at start
qemu-system-x86_64 -fda disk.img -s -S

# In another terminal, attach GDB
gdb -ex "set architecture i8086" \
    -ex "target remote :1234" \
    -ex "break *0x7c00" \
    -ex "continue"

# Common MBR entry point is 0x7c00 (BIOS loads MBR here)
# Step through bootloader, inspect registers and memory:
(gdb) x/20i $pc
(gdb) info registers
(gdb) x/16xb 0x7c00
```

비밀번호 확인을 우회하려면 비교 후 조건부 점프를 식별하고 이미지 파일에서 NOP을 적용하거나 항상 성공하도록 비교를 패치합니다.

```bash
# Find the comparison offset in the image and patch it
python3 -c "
data = open('disk.img', 'rb').read()
# Replace JNZ (0x75) with JMP-short-always or NOP
data = data[:offset] + b'\x90\x90' + data[offset+2:]
open('disk_patched.img', 'wb').write(data)
"
```

**주요 통찰력:** QEMU의 `-s` 플래그는 MBR/bootloader 코드의 전체 디버깅을 위해 포트 1234에 GDB 스텁을 노출합니다. 워크플로는 사용자 영역 디버깅과 동일합니다.

**참고자료:** Square CTF 2017

---
