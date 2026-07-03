# CTF 리버스 - 경쟁별 패턴(3부)

## 목차
- [단일 선 Python 부울 회로용 Z3(BearCatCTF 2026)](#z3-for-single-line-python-boolean-circuit-bearcatctf-2026)
- [슬라이딩 윈도우 팝카운트 차등 전파(BearCatCTF 2026)](#sliding-window-popcount- Differential-propagation-bearcatctf-2026)
- [ioctl을 통한 키보드 LED의 모스 부호(PlaidCTF 2013)](#morse-code-from-keyboard-leds-via-ioctl-plaidctf-2013)
- [C++ 소멸자 숨겨진 유효성 검사(Defcamp 2015)](#c-destructor-hidden-validation-defcamp-2015)
- [Syscall 부작용 메모리 손상(Hack.lu 2015)](#syscall-side- effect-memory-corruption-hacklu-2015)
- [MFC 대화 상자 이벤트 처리기 위치(WhiteHat 2015)](#mfc-dialog-event-handler-location-whitehat-2015)
- [VM 순차 키 체인 Brute-Force(Midnight Flag 2026)](#vm-serial-key-chain-brute-force-midnight-flag-2026)
- [터미네이터가 없는 Burrows-Wheeler 변환 반전(ASIS CTF Finals 2016)](#burrows-wheeler-transform-inversion-without-terminator-asis-ctf-finals-2016)
- [숨겨진 메시지에 대한 OpenType 글꼴 합자 악용(Hack The Vote 2016)](#opentype-font-ligature-exploitation-for-hidden-messages-hack-the-vote-2016)
- [자체 수정 코드가 포함된 GLSL 셰이더 VM(ApoorvCTF 2026)](#glsl-shader-vm-with-self-modifying-code-apoorvctf-2026)
- [암호화 상태로서의 명령 카운터(MetaCTF Flash 2026)](#instruction-counter-as-cryptographic-state-metactf-flash-2026)
- [부호 있는 정수 오버플로가 있는 스레드 경쟁 조건(Codegate 2017)](#thread-race-condition-with-signed-integer-overflow-codegate-2017)
- [ESP32/Xtensa ROM 기호 맵을 사용한 펌웨어 반전(Insomni'hack 2017)](#esp32xtensa-firmware-reversing-with-rom-symbol-map-insomnihack-2017)
- [objdump 패턴 추출을 통한 일괄 Crackme 자동화(DEF CON 2017)](#batch-crackme-automation-via-objdump-pattern-extraction-def-con-2017)
- [포크 + 파이프 + 데드브랜치 안티분석(RCTF 2017)](#fork--pipe--dead-branch-anti-analysis-rctf-2017)
- [날짜 기반 키가 있는 시간 잠금 바이너리(Hack.lu 2017)](#time-locked-binary-with-date-based-key-hacklu-2017)
- [UnicornJS를 통한 이미지 픽셀의 ARM 코드(Hack.lu 2017)](#arm-code-in-image-pixels-via-unicornjs-hacklu-2017)
- [x86 16비트 MBR psadbw 제약 조건 해결(CSAW 2017)](#x86-16-bit-mbr-psadbw-constraint-solving-csaw-2017)
- [시그모이드 레이어 반전을 통한 TensorFlow DNN 반전(N1CTF 2018)](#tensorflow-dnn-inversion-by-inverting-sigmoid-layers-n1ctf-2018)
- [x64 어셈블리에 대한 JIT 컴파일을 통한 BPF 필터 분석(Midnight Sun CTF 2018)](#bpf-filter-analytic-via-jit-compilation-to-x64-assemblies-midnight-sun-ctf-2018)

---

## 단선 Python 부울 회로용 Z3(BearCatCTF 2026)

**패턴(모건 선장):** 한 줄 Python(2000+ 세미콜론)은 부울 회로를 생성하는 비트 연산을 사용하여 입력을 빅 엔디안 정수로 분해하는 바다코끼리 연산자 체인을 통해 플래그를 검증합니다.

**Identification:**
- 명령문을 구분하는 세미콜론이 있는 한 줄 Python
- 바다코끼리 연산자 `:=` 체인: `(x:= expr)`
- 난독화된 XOR: `x ^ i` 대신 `(x | i) & ~(x & i)`
- 입력은 하나의 큰 정수로 처리되며 비트 이동을 통해 분해됩니다.

**Z3 solution:**
```python
from z3 import *

n_bytes = 29  # Flag length
ari = BitVec('ari', n_bytes * 8)

# Parse semicolon-separated statements
# Model walrus chains as LShR(ari, shift_amount)
# Evaluate boolean expressions symbolically
# Final assertion: result_var == 0

s = Solver()
s.add(bfu == 0)  # Final validation variable
if s.check() == sat:
    m = s.model()
    val = m[ari].as_long()
    flag = val.to_bytes(n_bytes, 'big').decode('ascii')
```

**주요 통찰력:** 단일 행 Python 난독화는 입력 비트에 대해 부울 회로를 생성합니다. 바다코끼리 연산자 체인은 단지 변수 할당일 뿐입니다. 세미콜론으로 분할하고 각각을 기호적으로 Z3으로 변환합니다. 난독화된 XOR `(a | b) & ~(a & b)`은 단지 `a ^ b`입니다. Z3는 이러한 회로를 1초 안에 해결합니다. `__builtins__` 액세스 또는 `ord()`/`chr()` 호출을 찾아 입력→정수 변환을 식별합니다.

**탐지:** 1000개 이상의 세미콜론, 해마 연산자, 비트 연산 및 0 또는 True에 대한 최종 비교를 포함하는 한 줄 Python.

---

## 슬라이딩 윈도우 팝카운트 차등 전파(BearCatCTF 2026)

**패턴(보물 찾기 4):** 바이너리는 입력 비트에 대한 16비트 슬라이딩 창의 각 위치에 대해 예상 팝카운트(설정 비트 수)를 통해 입력을 검증합니다.

**차등 전파:**
창이 1비트씩 미끄러지는 경우:
```text
popcount(window[i+1]) - popcount(window[i]) = bit[i+16] - bit[i]
```
So: `bit[i+16] = bit[i] + (data[i+1] - data[i])`

```python
expected = [...]  # 337 expected popcount values
total_bits = 337 + 15  # = 352

# Brute-force the initial 16-bit window (must have popcount = expected[0])
for start_val in range(0x10000):
    if bin(start_val).count('1') != expected[0]:
        continue

    bits = [0] * total_bits
    for j in range(16):
        bits[j] = (start_val >> (15 - j)) & 1

    valid = True
    for i in range(len(expected) - 1):
        new_bit = bits[i] + (expected[i + 1] - expected[i])
        if new_bit not in (0, 1):
            valid = False
            break
        bits[i + 16] = new_bit

    if valid:
        # Convert bits to bytes
        flag_bytes = bytes(int(''.join(map(str, bits[i:i+8])), 2)
                          for i in range(0, total_bits, 8))
        if b'BCCTF' in flag_bytes or flag_bytes[:5].isascii():
            print(flag_bytes.decode(errors='replace'))
            break
```

**주요 통찰력:** 슬라이딩 윈도우 팝카운트 차이는 반복 관계를 만듭니다. 각각의 새로운 비트는 비트 16 위치와 팝카운트 델타에 의해 결정됩니다. 처음 16비트만 사용 가능합니다(초기 팝 카운트에 의해 제한됨). ~4000-8000개의 유효한 초기 창을 무차별 대입하여 각각에 대해 전체 비트 시퀀스가 ​​결정적입니다. 1초 안에 실행됩니다.

**탐지:** 고정 크기 창에서 바이너리 컴퓨팅 popcount/hamming 가중치. 길이 ≒ input_bits - window_size + 1의 예상 값 배열입니다. 배열의 값은 작은 정수(0 ~ window_size)입니다.

---

---

## ioctl을 통한 키보드 LED의 모스 부호(PlaidCTF 2013)

**패턴:** 바이너리는 `ioctl(fd, KDSETLED, value)`를 사용하여 키보드 LED를 깜박입니다(Num/Caps/Scroll 잠금). 타이밍 패턴은 모스 부호를 인코딩합니다.

```bash
# Step 1: Bypass ptrace anti-debug
# Patch ptrace call at offset with NOP (0x90)
python3 -c "
data = open('binary','rb').read()
data = data[:0x72b] + b'\x90'*5 + data[:0x730]  # NOP the ptrace call
open('patched','wb').write(data)
"

# Step 2: Run under strace, capture ioctl calls
strace -e ioctl ./patched 2>&1 | grep KDSETLED > leds.txt

# Step 3: Decode timing patterns
# Short blink (250ms) = dit (.), long blink (750ms) = dah (-)
# Inter-character pause = 3x, inter-word pause = 7x
```

```python
# Parse strace output to extract Morse
import re
morse_map = {'.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
             '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
             '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
             '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
             '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
             '--..':'Z', '-----':'0', '.----':'1'}
# Map LED on-durations to dots/dashes, group by pauses
```

**주요 정보:** `KDSETLED`는 Linux에서 물리적 키보드 LED를 제어합니다(`/dev/console`). 바이너리는 콘솔 액세스로 실행되어야 합니다. `strace -e ioctl`를 사용하면 물리적으로 관찰할 필요 없이 모든 LED 상태 변화를 캡처할 수 있습니다. 호출 사이의 타이밍에 따라 점과 대시가 결정됩니다.

---

## C++ 소멸자 숨겨진 유효성 검사(Defcamp 2015)

유효성 검사 논리는 `main()` 반환 후에 실행되는 C++ 소멸자에 숨겨질 수 있습니다. `__cxa_atexit` 메커니즘은 소멸자 콜백을 등록합니다.

1. **소멸자 찾기:** `.init_array`/constructor 섹션에서 `__cxa_atexit` 호출을 검색하세요.
2. **정적 분석:** 소멸자가 플래그 확인을 수행하는 전역 개체를 식별합니다.
3. **동적 검증:** `__cxa_finalize`에 중단점을 설정하여 사후 기본 실행 추적

```asm
# In IDA/Ghidra: look for atexit registrations
__cxa_atexit(destructor_func, object_ptr, dso_handle);

# Destructor contains actual validation:
# - Regex pattern matching on 4-byte blocks (8 sequential checks)
# - Arithmetic: v2 += -3 * s[i] + 36 + (s[i] ^ 0x2FCFBA)
# - Modular verification of accumulated sum
```

**주요 정보:** `main()`가 사소하거나 불완전해 보일 경우 global/static C++ 개체의 소멸자를 확인하세요. `.fini_array` 섹션과 `__cxa_atexit` 등록은 숨겨진 포스트 메인 로직을 드러냅니다.

---

## Syscall 부작용 메모리 손상(Hack.lu 2015)

`rt_sigprocmask` 시스템 호출은 출력 포인터에 `sigset_t` 구조를 씁니다. 입력 구문 분석이 보안에 중요한 변수 근처의 포인터를 전달하는 경우:

1. 특정 입력 문자(예: `:` ~ `@` 범위, 값 0x3A-0x40)는 부작용으로 `rt_sigprocmask`를 트리거합니다.
2. syscall은 인접한 변수와 겹칠 수 있는 출력 주소의 바이트를 0으로 만듭니다.
3. 리틀 엔디안 레이아웃에서는 인접한 정수 변수의 MSB를 0으로 설정하면 효과적으로 작은 값으로 설정됩니다.

```c
// Memory layout (no ASLR):
// 0x603390: input_buffer[4]
// 0x603394: security_check_var

// Input ':' triggers: rt_sigprocmask(SIG_BLOCK, NULL, (sigset_t*)0x603397, ...)
// This zeros bytes at 0x603397+, corrupting security_check_var's high bytes
```

**주요 통찰력:** 입력 유효성 검사 기능이 syscall과 상호 작용하는 방식을 감사합니다. 16진수 변환 루틴의 문자-시스템 호출 매핑은 커널 공간 작업을 통해 의도하지 않은 메모리 쓰기를 생성할 수 있습니다.

---

## MFC 대화 상자 이벤트 처리기 위치(WhiteHat 2015)

MFC(Microsoft Foundation Class) 애플리케이션에서 이벤트 처리기를 찾으려면 다음을 수행합니다.

1. **SendMessageW에서 중단:** 대화 메시지를 가로채기 위해 `user32!SendMessageW`에 중단점을 설정합니다.
2. **WM_COMMAND에 대한 필터:** 메시지 ID 0x111은 버튼 클릭 및 제어 이벤트를 나타냅니다.
3. **추적 메시지 맵:** `CWnd::OnWndMsg` → `CCmdTarget::OnCmdMsg` → 핸들러 함수에서 MFC 메시지 디스패치를 따릅니다.
4. **OnInitDialog:** 종종 암호 해독 또는 유효성 검사 설정이 포함됩니다. WM_INITDIALOG(0x110)에 의해 트리거됨

```asm
# WinDbg/x64dbg:
bp user32!SendMessageW ".if (poi(@esp+8)==0x111) {} .else {gc}"
# Or in IDA: find cross-references to AFX_MSGMAP_ENTRY structures
```

**주요 통찰력:** MFC 애플리케이션은 디스패치 테이블을 통해 메시지를 라우팅합니다. 런타임 분석 없이 처리된 모든 메시지를 열거하는 `AFX_MSGMAP` 구조를 식별합니다.

---

## VM 순차 키 체인 무차별 공격(Midnight Flag 2026)

**패턴 (67):** 사용자 지정 VM은 N바이트 블록의 입력을 확인합니다. 각 블록의 출력 키는 다음 블록에 입력으로 제공되어 병렬 해결을 방지합니다. 블록당 검색 공간은 무차별 대입(3바이트 블록의 경우 2^24)할 만큼 작습니다.

**Recognition signs:**
- XOR 난독화된 opcode가 포함된 바이트코드(모든 바이트는 상수로 XOR되어 ASCII 모양의 바이트코드 생성)
- 대수적 반전을 실용적이지 않게 만드는 반복 변환 루프(xorshift + 곱셈, 1000회 이상 반복)
- 누적된 상태를 내장된 상수와 비교하는 opcode를 확인하세요.
- 반복적인 바이트코드 패턴이 있는 큰 `.data` 섹션

**Solving approach:**
1. 바이트코드를 구문 분석하여 CHECK 값 추출(각 블록 다음에 예상되는 키)
2. 각 블록에 대해 순차적으로 예상 키를 생성하는 입력 바이트를 무차별 공격합니다.
3. CHECK 값을 다음 블록의 키로 사용

```c
// OpenMP-parallelized per-block brute-force
uint32_t process(uint32_t val) {
    for (int i = 0; i < 1000; i++) {
        val ^= (val << 13);
        val ^= (val >> 17);
        val ^= (val << 5);
        val *= 0x2545f491;
    }
    return val;
}

int solve_block(uint32_t old_key, uint32_t expected_key, unsigned char *out) {
    int found = 0;
    #pragma omp parallel for shared(found)
    for (int v = 0; v < 0x1000000; v++) {
        if (found) continue;
        uint32_t input_val = ((v >> 16) << 16) | (v & 0xFF) | ((v >> 8 & 0xFF) << 8);
        uint32_t saved = input_val ^ old_key;
        uint32_t final_val = process(saved);
        if ((final_val ^ saved) == expected_key) {
            #pragma omp critical
            { if (!found) { out[0]=v>>16; out[1]=(v>>8)&0xFF; out[2]=v&0xFF; found=1; } }
        }
    }
    return found;
}
// Compile: gcc -O3 -march=native -fopenmp -o solve solve.c
```

**주요 통찰력:** 변환이 의도적으로 되돌릴 수 없는 경우(반복 해시와 같은 함수) 무차별 공격이 의도된 솔루션입니다. OpenMP 병렬화는 매우 중요합니다. 287개 블록 x 1670만 개의 후보가 각각 병렬화되는 데는 몇 분이 소요되지만 단일 스레드에서는 몇 시간이 걸립니다. 순차 키 종속성은 블록을 순서대로 풀어야 하지만 각 개별 블록 검색이 당황스러울 정도로 병렬임을 의미합니다.

---

## 터미네이터가 없는 Burrows-Wheeler 변환 반전(ASIS CTF Finals 2016)

표준 종료 문자 없이 이진 표현에 적용되는 BWT입니다. 가능한 모든 원본 문자열을 시도하여 무차별 반전이 필요합니다.

```python
def bwt_inverse_bruteforce(bwt_string):
    """Invert BWT when no terminating character is present.
    Standard BWT inverse needs the terminator position.
    Without it, try all n possible rotations."""
    n = len(bwt_string)

    # Standard BWT inverse produces a table
    table = [''] * n
    for _ in range(n):
        table = sorted([bwt_string[i] + table[i] for i in range(n)])

    # Without terminator, all n rows are valid candidates
    # Filter by known constraints (e.g., starts with '1' for binary, matches XOR pattern)
    candidates = []
    for row in table:
        # Apply challenge-specific validation
        if is_valid_plaintext(row):
            candidates.append(row)

    return candidates

def bwt_with_xor_rounds(encrypted_hex, num_rounds):
    """Multi-round BWT with XOR key derived from round index"""
    data = bytes.fromhex(encrypted_hex)
    for round_idx in range(num_rounds - 1, -1, -1):
        # Each round: BWT on binary representation, then XOR with round-based key
        binary_str = ''.join(format(b, '08b') for b in data)
        candidates = bwt_inverse_bruteforce(binary_str)
        # Select candidate matching constraints (leading '1', trailing bit rule)
        data = select_valid_candidate(candidates, round_idx)
    return data
```

**주요 통찰력:** 표준 BWT는 종료 문자(예: '$')를 사용하여 원래 문자열의 위치를 ​​표시합니다. 이것이 없으면 BWT 반전은 n개의 후보(회전당 하나)를 생성합니다. 도메인별 제약 조건(바이너리 형식, XOR 라운드 구조, 플래그 접두사)을 사용하여 올바른 후보를 식별합니다.

---

## 숨겨진 메시지에 대한 OpenType 글꼴 합자 활용(Hack The Vote 2016)

사용자 정의 OpenType 합자가 포함된 글꼴 파일은 보이는 문자를 숨겨진 글리프에 매핑합니다. GSUB(Glyph Substitution) 테이블은 이러한 매핑을 정의합니다.

```python
from fontTools.ttLib import TTFont

def decode_font_ligatures(font_path, encoded_text):
    """Extract ligature substitution table and decode message"""
    font = TTFont(font_path)

    # Extract GSUB table for ligature substitutions
    gsub = font['GSUB']

    # Navigate to ligature lookup
    ligature_map = {}
    for lookup in gsub.table.LookupList.Lookup:
        for subtable in lookup.SubTable:
            if hasattr(subtable, 'ligatures'):
                for glyph_name, ligatures in subtable.ligatures.items():
                    for lig in ligatures:
                        # Map: input sequence -> output glyph
                        input_seq = [glyph_name] + lig.Component
                        output = lig.LigGlyph
                        ligature_map[tuple(input_seq)] = output

    print("Ligature mappings found:")
    for inp, out in ligature_map.items():
        print(f"  {inp} -> {out}")

    # Alternative: convert TTF to XML for manual analysis
    # font.saveXML('font_dump.xml')
    # Search for <LigatureSubst> entries

# Command-line approach:
# pip install fonttools
# ttx font.otf  # converts to XML
# grep -A5 'LigatureSubst' font.ttx
```

**주요 통찰력:** GSUB 합자 테이블이 있는 맞춤 글꼴은 표시되는 문자가 글리프 매핑과 다른 암호를 생성합니다. `fonttools` 라이브러리의 `ttx` 명령은 글꼴을 XML로 덤프하여 합자 대체 테이블을 쉽게 읽을 수 있게 만듭니다. 각 합자는 입력 문자 시퀀스를 다른 출력 문자 모양으로 매핑합니다.

---

## 자체 수정 코드가 포함된 GLSL 셰이더 VM(ApoorvCTF 2026)

**패턴(Draw Me):** WebGL2 조각 셰이더는 256x256 RGBA 텍스처에서 Turing-complete VM을 구현합니다. 텍스처는 프로그램 메모리이자 디스플레이 출력입니다.

**Texture layout:**
- **행 0:** 레지스터(픽셀 0 = 명령 포인터, 픽셀 1-32 = 범용)
- **행 1-127:** 프로그램 메모리(RGBA = opcode, arg1, arg2, arg3)
- **128~255행:** VRAM(디스플레이 출력)

**오퍼코드:** NOP(0), SET(1), ADD(2), SUB(3), XOR(4), JMP(5), JNZ(6), VRAM-write(7), STORE(8), LOAD(9). 프레임당 16단계.

**자체 수정 코드:** 1단계(암호 해독)에서는 STORE opcode를 사용하여 2단계(그리기)에서 실행되는 XOR 패치 프로그램 메모리에 대해 설명합니다. 해독은 그리기 코드가 실행되기 전에 올바른 픽셀 색상 값으로 SET 명령을 덮어씁니다.

**GPU 렌더링이 실패하는 이유:** GPU는 프레임당 모든 픽셀을 병렬로 실행하지만 셰이더는 프레임당 픽셀당 하나의 쓰기 대상만 추적합니다. 프레임당 여러 VRAM 쓰기를 사용하면 마지막 것만 살아남아 픽셀이 75% 이상 손실됩니다. 마찬가지로 STORE 패치는 병렬 암호 해독 중에 충돌합니다.

**순차 에뮬레이션을 통해 해결:**
```python
from PIL import Image
import numpy as np

img = Image.open('program.png').convert('RGBA')
state = np.array(img, dtype=np.int32).copy()
regs = [0] * 33

# Phase 1: Trace decryption — apply all STORE patches sequentially
x, y = start_x, start_y
while True:
    r, g, b, a = state[y][x]
    opcode = int(r)
    if opcode == 1: regs[g] = b & 255           # SET
    elif opcode == 4: regs[g] = regs[b] ^ regs[a]  # XOR
    elif opcode == 8:                              # STORE — patches program memory
        tx, ty = regs[g], regs[b]
        state[ty][tx] = [regs[a], regs[a+1], regs[a+2], regs[a+3]]
    elif opcode == 5: break                        # JMP to drawing phase
    x += 1
    if x > 255: x, y = 0, y + 1

# Phase 2: Execute drawing code — all VRAM writes preserved
vram = np.zeros((128, 256), dtype=np.uint8)
# ... trace with opcode 7 writing to vram[ty][tx] = color
Image.fromarray(vram, mode='L').save('output.png')
```

**주요 통찰력:** GLSL 셰이더는 Turing-complete이지만 GPU 병렬 처리로 인해 쓰기 충돌이 발생합니다. 자체 수정 코드(STORE 패치)는 문제를 더욱 복잡하게 만듭니다. 즉, 병렬 실행의 패치가 서로를 덮어쓰게 됩니다. Python의 순차 에뮬레이션은 전체 출력을 복구합니다. program.png 파일은 바이트코드입니다.

**탐지:** WebGL/shader PNG "프로그램" 파일을 사용한 챌린지, 챌린지에서 "아무 것도 렌더링되지 않습니다"라고 나오거나 출력이 깨졌습니다. GLSL 소스에서 사용자 정의 opcode 테이블을 찾으십시오.

---

## 암호화 상태로서의 명령어 카운터(MetaCTF Flash 2026)

**패턴(누가 계산합니까?):** 손으로 작성한 어셈블리 바이너리는 거의 모든 명령어 이후에 증가하는 명령어 카운터로 전용 레지스터(예: `r12`)를 사용합니다. 카운터 값은 각 입력 바이트의 XOR, ROL 및 곱셈 변환에 공급되어 전체 변환 경로가 각 바이트에 도달하기 전에 실행되는 명령 수에 따라 달라집니다.

**Identification:**
- 직접 작성한 어셈블리(컴파일러 패턴 없음, 비정상적인 레지스터 사용)
- 대부분의 명령 뒤에 나타나는 증가분(`inc r12` 또는 `add r12, 1`)만 나타나는 레지스터
- 이 카운터 레지스터를 참조하는 변환(`xor rax, r12`, `rol al, cl`, 여기서 `cl`은 카운터에서 파생됨)
- 상태가 전달되는 순차 바이트 처리 루프

**Solving approach:**
```python
# Byte-by-byte brute force with emulation
# Since each byte's transformation depends on the counter (which depends
# on all prior instructions), state is path-dependent.

from unicorn import *
from unicorn.x86_const import *

def try_byte(known_prefix, candidate_byte):
    """Emulate binary with known prefix + candidate, check output."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # Map code, stack, data segments
    uc.mem_map(CODE_BASE, 0x10000)
    uc.mem_write(CODE_BASE, binary_code)
    uc.mem_map(STACK_BASE, 0x10000)
    uc.mem_map(DATA_BASE, 0x10000)

    # Write input: known_prefix + candidate
    test_input = known_prefix + bytes([candidate_byte])
    uc.mem_write(DATA_BASE, test_input + b'\x00' * (64 - len(test_input)))

    # Set up registers (rsp, rdi pointing to input, r12 = 0)
    uc.reg_write(UC_X86_REG_RSP, STACK_BASE + 0x8000)
    uc.reg_write(UC_X86_REG_R12, 0)  # instruction counter starts at 0

    try:
        uc.emu_start(CODE_BASE + ENTRY_OFFSET, CODE_BASE + EXIT_OFFSET)
        # Read transformed output, compare against expected
        output = uc.mem_read(OUTPUT_ADDR, len(test_input))
        return output[:len(test_input)] == expected[:len(test_input)]
    except:
        return False

# Recover flag byte by byte
flag = b''
for pos in range(FLAG_LEN):
    for b in range(256):
        if try_byte(flag, b):
            flag += bytes([b])
            print(f"Position {pos}: {chr(b)} -> {flag}")
            break
```

**주요 통찰력:** 레지스터가 바이트 변환에 대한 명령 카운터 역할을 할 때 바이트 N의 변환은 바이트 0부터 N-1까지 처리하는 동안 실행된 명령의 정확한 수에 따라 달라집니다. 이는 각 바이트 위치의 카운터 값이 모든 이전 바이트의 실행 경로에 따라 달라지기 때문에 분석적 반전을 비현실적으로 만듭니다. 전체 에뮬레이션(Unicorn 또는 GDB 스크립팅)을 사용하는 바이트별 무차별 공격이 가장 신뢰할 수 있는 접근 방식입니다. 올바른 접두사에서 상태를 유지하면서 각 위치에 대해 256개 값을 모두 시도해 보세요.

**인식해야 하는 경우:** 바이너리에는 표준 라이브러리 호출이 없고 특이한 레지스터를 일관되게 사용하며 증가만 하는 레지스터를 표시합니다. 바이트당 변환에는 이 카운터를 참조하는 작업(XOR, 회전, 곱하기)이 포함됩니다. 챌린지 이름은 "계산" 또는 "지침"을 암시합니다.

**Alternative approaches:**
- GDB 스크립팅: 각 바이트 변환 후 중단점 설정, 출력 비교
- 정적 분석: 카운터 값을 계산하기 위해 수동으로 명령을 계산한 다음 대수적으로 변환을 반전합니다(카운터 누적으로 인해 오류가 발생하기 쉬움).

**참고 자료:** MetaCTF Flash CTF 2026 "Who's Counting?"

---

## 부호 있는 정수 오버플로가 있는 스레드 경쟁 조건(Codegate 2017)

**패턴(사냥):** 전투 시뮬레이션 바이너리는 스레드가 안전하지 않은 기술 선택을 사용합니다. 공격 스레드는 부호 있는 비교를 사용하여 `skill_id <= 4`를 확인한 다음 피해를 입히기 전에 잠시 대기합니다. 수면 중에는 다른 스킬로 전환합니다. 파이어볼 스킬은 `cdqe`(EAX를 RAX로 부호 확장)를 사용하여 `0xFFFFFFFF`(아이스소드 피해)를 `-1`로 부호 있는 64비트 값으로 변환합니다. 보스의 HP(`0x7FFFFFFFFFFFFFFF`)에서 `-1`를 빼면 부호 있는 오버플로가 음수 값으로 나타나 보스가 죽게 됩니다.

```python
# Race condition exploit:
# Thread A: select fireball (skill_id=2, passes <= 4 check)
# Thread A: sleeps for animation
# Main: switch to icesword (skill_id=5, damage=0xFFFFFFFF)
# Thread A: wakes, reads damage from icesword slot
# cdqe: 0xFFFFFFFF -> 0xFFFFFFFFFFFFFFFF (-1 signed)
# boss_hp -= (-1) -> boss_hp = 0x7FFFFFFFFFFFFFFF + 1 = negative -> dead

import time, threading
def race():
    select_skill(2)  # fireball - passes bounds check
    time.sleep(0.001)
    select_skill(5)  # icesword - race into damage calculation
```

**주요 통찰력:** `cdqe`(더블워드를 쿼드워드 확장으로 변환)은 32비트 EAX를 64비트 RAX로 부호 확장합니다. 공격 코드가 32비트 손상 값을 읽고 이를 부호 확장하면 `0xFFFFFFFF`는 `-1`가 됩니다. 음수를 빼면 HP가 추가되지만, HP가 이미 `INT64_MAX`에 있으면 더한 값이 음수로 오버플로되어 대상을 죽입니다.

---

## ESP32/Xtensa ROM 기호 맵을 사용한 펌웨어 반전(Insomni'hack 2017)

**패턴(Internet of Fail):** 기본 IDA 지원이 없는 ESP32 펌웨어(Xtensa 아키텍처). 함수 주소를 이름에 매핑하려면 ESP32 ROM 링커 스크립트(`esp32.rom.ld`)와 함께 radare2를 사용하세요. 공용 ESP32 HTTP 서버 소스 코드를 상호 참조하여 전역 상태 변수에서 작동하는 ~20개의 조건부 XOR 함수로 구성된 비밀번호 확인 논리를 식별합니다.

```bash
# Load ESP32 firmware in radare2
r2 -a xtensa -b 32 firmware.bin

# Apply ROM symbol map from ESP-IDF
# esp32.rom.ld maps addresses like:
# 0x40000000 = ets_printf
# 0x400013A0 = cache_Read_Enable
# Load as flags: . esp32.rom.ld.r2

# Identify HTTP request handler by cross-referencing
# with esp-idf/examples/protocols/http_server
# Look for URI handler registration patterns
```

**주요 통찰력:** ESP32의 Xtensa 아키텍처에는 주류 RE 도구 지원이 부족하지만 ESP-IDF SDK는 모든 ROM 기능 주소를 해당 이름에 매핑하는 ROM 링커 스크립트를 제공합니다. radare2에서 이를 기호로 로드하면 수백 개의 함수 호출이 즉시 해결됩니다. 공개 ESP-IDF 예제 코드를 사용한 상호 참조는 제거된 펌웨어에서도 애플리케이션 수준 패턴(HTTP 핸들러, WiFi 콜백)을 식별합니다.

---

## objdump 패턴 추출을 통한 일괄 Crackme 자동화(DEF CON 2017)

비교 값과 산술 연산을 추출하고 실행 없이 키를 계산하기 위해 스크립팅 `objdump`을 통해 수백 개의 동일한 구조 크랙을 해결합니다.

```bash
# Simple variant: extract CMP immediates directly
objdump -M intel -d $binary | grep -P "cmp\s+rdi" | \
    grep -oP "0x\w{1,2}" | xxd -r -p

# Complex variant: parse add/sub/cmp chains and reverse-compute
# Each binary: series of add/sub rdi,N then cmp rdi,target
# Reverse: start from target, undo operations in reverse order
python3 <<'EOF'
import subprocess, re, glob
for binary in sorted(glob.glob("crackmes/*")):
    asm = subprocess.check_output(["objdump", "-M", "intel", "-d", binary]).decode()
    ops = re.findall(r'(add|sub)\s+rdi,(0x\w+)', asm)
    target = int(re.search(r'cmp\s+rdi,(0x\w+)', asm).group(1), 16)
    # Reverse operations
    for op, val in reversed(ops):
        val = int(val, 16)
        target = (target - val) if op == 'add' else (target + val)
    print(chr(target & 0xff), end='')
EOF
```

**주요 통찰력:** 대규모 크랙미 챌린지(100~1000개의 바이너리)는 바이너리별 상수와 구조가 동일합니다. `objdump` 디스어셈블리 구문 분석을 스크립트하여 즉시 및 산술 시퀀스를 추출한 다음 키를 대수적으로 역계산합니다. 실행이나 에뮬레이션이 필요하지 않습니다.

---

## 포크 + 파이프 + 데드 브랜치 방지 분석(RCTF 2017)

바이너리는 부모가 데이터를 쓰고 종료하고, 자식이 파이프에서 읽고 계속하는 fork/pipe IPC를 사용합니다. 키 검증은 바이너리 패치가 필요한 데드 브랜치(항상 거짓 비교)에 있습니다.

```bash
# Detection: fork() + pipe() + read()/write() in main
# The child process reads from pipe, needs to know its own PID

# Dead branch pattern:
# cmp DWORD PTR [ebp-0xc], 0x1  ; compares 0 with 1, always false
# je  real_flag_computation      ; never taken

# Patch: change comparison value from 0x1 to 0x0
# Find: 83 7d f4 01 → change to: 83 7d f4 00
python3 -c "
data = open('binary','rb').read()
data = data.replace(b'\x83\x7d\xf4\x01', b'\x83\x7d\xf4\x00')
open('binary_patched','wb').write(data)
"
```

**주요 통찰력:** 포크+파이프는 상위가 데이터를 제공하고 종료되는 상위-하위 관계를 생성합니다. 데드 브랜치(항상 false로 평가되는 비교)는 실제 유효성 검사 논리를 숨깁니다. `strace`는 fork/pipe/read 패턴을 나타냅니다. 비교 상수를 패치하면 숨겨진 코드 경로에 도달합니다.

---

---

## 날짜 기반 키가 있는 시간 잠금 바이너리(Hack.lu 2017)

바이너리는 시스템 날짜를 읽고 특정 날짜(예: 2012년 12월 21일)에만 올바르게 실행됩니다. 날짜 상수는 Unix 타임스탬프 또는 구조화된 날짜 비교로 바이너리에 표시됩니다.

**탐지:** 인식 가능한 날짜 범위(Unix 타임스탬프: 2012 = ~1.35B, 2017 = ~1.5B)에 속하는 큰 정수 상수에 대한 비교를 찾습니다. 문화적 중요성이 도움이 됩니다: 종말 날짜, CTF 출시 날짜, 역사적 사건.

```bash
# Set system clock to the required date
sudo date -s "2012-12-21 00:00:00"
./binary

# Or use faketime to avoid system-wide change
LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="2012-12-21 00:00:00" ./binary

# Restore system time afterward
sudo ntpdate pool.ntp.org
```

**IDA/Ghidra에서:** `time()` 또는 `localtime()` 호출를 검색합니다. 살펴볼 구조체 `tm` 필드: `tm_year`(1900년 이후 연도), `tm_mon`(0 기반), `tm_mday`.

**주요 정보:** 시간 기반 키는 문화적으로 중요한 날짜를 사용합니다. 항상 역방향 코드의 날짜 비교를 확인하고 더 심층적인 분석을 시도하기 전에 시스템 시계를 설정하거나 가짜 시간을 사용해 보십시오.

**참고자료:** Hack.lu CTF 2017

---

## UnicornJS를 통한 이미지 픽셀의 ARM 코드(Hack.lu 2017)

JavaScript 챌린지는 이미지 픽셀 데이터에 ARM 바이트코드를 포함합니다. 이미지는 HTML/JS 소스에서 base64로 인코딩됩니다. 픽셀 RGBA 값은 ARM 명령어를 인코딩합니다. 번들로 제공되는 UnicornJS 라이브러리(JavaScript의 ARM CPU 에뮬레이터)는 바이트코드를 추출하고 실행합니다.

**Identification flow:**
1. JS 소스 → 디코드 → PNG/BMP 파일에서 base64 blob 찾기
2. UnicornJS 가져오기 식별(`unicorn.js`, `uc.js` 또는 유사) → ARM 에뮬레이션 확인
3. 픽셀 추출 루프: ARM 명령어 스트림을 형성하는 래스터 순서로 연결된 RGBA 바이트
4. 추출된 바이트를 ARM 디스어셈블러에 공급

```python
from PIL import Image
import capstone

img = Image.open('decoded.png').convert('RGBA')
pixels = list(img.getdata())

# Extract ARM bytecode from pixel data (4 bytes per pixel: R, G, B, A)
arm_code = bytes([channel for pixel in pixels for channel in pixel])

# Disassemble as ARM Thumb or ARM32
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
for insn in md.disasm(arm_code, 0x0):
    print(f"0x{insn.address:04x}: {insn.mnemonic} {insn.op_str}")
```

**주요 통찰력:** 다층 난독화: 이미지 픽셀의 ARM 코드, base64 인코딩, 런타임 시 UnicornJS를 통해 에뮬레이션됩니다. 어떤 ISA를 반전할지 알아보려면 먼저 에뮬레이터 라이브러리를 식별하십시오. 라이브러리 이름은 아키텍처를 나타냅니다.

**참고자료:** Hack.lu CTF 2017

---

## x86 16비트 MBR psadbw 제약 조건 해결(CSAW 2017)

부팅 가능한 MBR은 xmm 레지스터에서 SSE2 `psadbw`(Packed Sum of Absolute Differences of Bytes)를 사용하여 플래그를 검증합니다. 각 반복은 2개의 입력 바이트를 마스크하고, 알려진 상수에 대해 `psadbw`를 계산하고, 그 합계를 예상 값과 비교합니다.

**`psadbw` semantics:**
```asm
psadbw xmm0, xmm1
; For each of 8 byte pairs: sum += |xmm0[i] - xmm1[i]|
; Result stored as 16-bit integer in low qword of xmm0
```

이는 절대차의 합 방정식을 생성합니다.
```text
|a[0] - k[0]| + |a[1] - k[1]| + ... + |a[7] - k[7]| = C
```

**Solution approach:**
```python
import numpy as np
from itertools import product

# For each 2-byte masked group, extract the constants and expected sum
# Equations are not purely linear (absolute value), but printable ASCII
# constrains each byte to [0x20, 0x7e], limiting brute-force space

def solve_psadbw_group(known_constants, expected_sum, printable_range=(0x20, 0x7e)):
    """Brute-force 2 unknown bytes given sum-of-abs-diff constraint."""
    solutions = []
    for a, b in product(range(*printable_range), repeat=2):
        pair = [a, b]
        sad = sum(abs(pair[i] - known_constants[i]) for i in range(len(pair)))
        if sad == expected_sum:
            solutions.append(bytes([a, b]))
    return solutions

# For ambiguous cases with multiple solutions: apply additional constraints
# (flag format prefix, character frequency, subsequent iterations)
```

**주요 통찰력:** `psadbw`는 순전히 선형이 아니지만 바이트가 인쇄 가능한 ASCII로 제한되는 경우 제한된 무차별 대입 방식으로 풀 수 있는 절대차차합 방정식을 생성합니다. 각 2바이트 그룹은 독립적이며 검색 공간을 그룹당 95^2 = ~9000명의 후보로 유지합니다.

**참고자료:** CSAW CTF 2017

---

## 시그모이드 레이어 반전을 통한 TensorFlow DNN 반전(N1CTF 2018)

**패턴:** Binary는 시그모이드 활성화를 통해 5계층 심층 신경망을 구현합니다. 입력(플래그 문자)은 네트워크에 공급되기 전에 `1.0/char_value`로 변환됩니다. 이진수에서 가중치와 편향을 추출한 다음 역시그모이드를 적용하고 편향을 빼고 가중치 역행렬을 곱하여 레이어별로 역행렬을 계산합니다.

```python
import numpy as np

def sigmoid_inv(x):
    return -np.log(1.0/x - 1.0)

# Invert layer by layer from output to input
v = target_output
for i in range(num_layers - 1, -1, -1):
    v = np.dot(sigmoid_inv(v) - biases[i], np.linalg.inv(weights[i]))

# Input was 1.0/char, so flag chars are the multiplicative inverse
flag = ''.join(chr(int(round(1.0 / v[j]))) for j in range(len(v)))
```

**주요 통찰력:** 가역 활성화 함수(시그모이드, tanh) 및 제곱 가중치 행렬을 갖춘 신경망은 계층별로 수학적으로 역전될 수 있습니다. 역시그모이드를 적용하고, 편향을 빼고, 가중치 역수를 곱합니다. 역시 반전되어야 하는 입력 변환(예: 1/x)을 살펴보세요.

**탐지:** TensorFlow 또는 맞춤 DNN 구현을 사용한 바이너리입니다. `.rodata`에서 sigmoid/tanh 호출, 행렬 곱셈, 하드코딩된 부동 소수점 배열(weights/biases)을 찾아보세요. 제곱 가중치 행렬(N x N)은 네트워크가 가역적임을 나타냅니다.

**References:** N1CTF 2018

---

## x64 어셈블리에 대한 JIT 컴파일을 통한 BPF 필터 분석(Midnight Sun CTF 2018)

**패턴:** 바이너리는 BPF(Berkeley Packet Filter)가 연결된 원시 소켓을 생성합니다. 표준 BPF 디스어셈블러가 읽을 수 있는 출력을 생성하지 못하는 경우 커널의 BPF JIT 컴파일러를 활성화하여 BPF 바이트코드를 기본 x64 어셈블리로 변환한 다음 dmesg에서 컴파일된 코드를 읽습니다.

```bash
# Enable BPF JIT compilation
echo 1 > /proc/sys/net/core/bpf_jit_enable

# Run the binary, then read JIT-compiled BPF from kernel log
dmesg | grep -A 100 "flen="

# Analysis revealed: expects DNS TXT query on UDP port 3333
dig @target -p 3333 'M4d!bKn3~l' TXT
```

**주요 통찰력:** Linux는 BPF 필터를 기본 x64 기계어 코드로 JIT 컴파일할 수 있습니다. 표준 BPF 디스어셈블러가 실패하거나 읽을 수 없는 출력을 생성하는 경우 `bpf_jit_enable`를 활성화하고 dmesg에서 컴파일된 어셈블리를 읽습니다. 네이티브 코드는 BPF 바이트코드보다 이해하기 쉬운 경우가 많습니다.

**탐지:** `setsockopt`와 `SO_ATTACH_FILTER`, 원시 소켓 생성(`socket(AF_PACKET,...)`) 또는 내장된 `struct sock_fprog` 구조를 사용하는 바이너리. BPF 프로그램은 `struct sock_filter` 배열로 나타납니다(각각 8바이트: opcode, jt, jf, k).

**참고자료:** Midnight Sun CTF 2018

---

참조: 파트 1의 경우 [patterns-ctf.md](patterns-ctf.md), 파트 2의 경우 [patterns-ctf-2.md](patterns-ctf-2.md)(다층 자체 복호화 바이너리, 내장된 ZIP+XOR 라이선스, 스택 문자열 난독화, 접두사 해시 무차별 대입, CVP/LLL 격자, 결정 트리 난독화, GF(2^8) 가우스 제거).
