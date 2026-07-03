# CTF 리버스 - 경쟁별 패턴(2부)

## 목차
- [다층 자기 복호화 바이너리(DiceCTF 2026)](#multi-layer-self-decrypting-binary-dicectf-2026)
- [임베디드 ZIP + XOR 라이센스 복호화(MetaCTF 2026)](#embedded-zip--xor-license-decryption-metactf-2026)
- [.rodata XOR Blob의 스택 문자열 해독(Nullcon 2026)](#stack-string-deobfuscation-from-rodata-xor-blob-nullcon-2026)
- [접두사 해시 무차별 대입(Nullcon 2026)](#prefix-hash-brute-force-nullcon-2026)
- [CVP/LLL 제한된 정수 검증을 위한 격자(HTB ShadowLabyrinth)](#cvplll-lattice-for-constrained-integer-validation-htb-shadowlabyrinth)
- [의사결정 트리 함수 난독화(HTB WonderSMS)](#decision-tree-function-obfuscation-htb-wondersms)
- [플래그 복구를 위한 GF(2^8) 가우스 제거(ApoorvCTF 2026)](#gf28-gaussian-elimination-for-flag-recovery-apoorvctf-2026)
- [수정된 바이너리의 ROP 체인 난독화(PlaidCTF 2016)](#rop-chain-obfuscation-in-modified-binary-plaidctf-2016)

---

## 다층 자체 복호화 바이너리(DiceCTF 2026)

**패턴(다른 양파):** N 레이어(예: 256)가 있는 바이너리, 각각 2개의 키 바이트를 읽고 SHA-256 NI 명령어를 통해 키스트림을 파생하고 다음 레이어를 XOR 복호화한 후 해당 레이어로 점프합니다. 제한 시간(예: 30분) 내에 풀어야 합니다.

**올바른 키에 대한 Oracle:** 잘못된 키 바이트는 가비지 코드를 생성합니다. 올바른 키 바이트는 정확히 2 `call read@plt` 명령어(다음 레이어의 읽기)로 코드를 생성합니다. 이 오라클을 사용하여 레이어당 65536개의 후보를 모두 무차별 공격합니다.

**JIT 실행 접근 방식(가장 빠름):**
```c
// Map binary's memory at original virtual addresses into solver process
// Compile solver at non-overlapping address: -Wl,-Ttext-segment=0x10000000
void *text = mmap((void*)0x400000, text_size, PROT_RWX, MAP_FIXED|MAP_PRIVATE, fd, 0);
void *bss = mmap((void*)bss_addr, bss_size, PROT_RW, MAP_FIXED|MAP_SHARED, shm_fd, 0);

// Patch read@plt to inject candidate bytes instead of reading stdin
// Patch tail jmp/call to next layer with ret/NOP to return from layer

// Fork-per-candidate: COW gives isolated memory without memcpy
for (int candidate = 0; candidate < 65536; candidate++) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: remap BSS as MAP_PRIVATE (COW from shared file)
        mmap(bss_addr, bss_size, PROT_RW, MAP_FIXED|MAP_PRIVATE, shm_fd, 0);
        inject_key(candidate >> 8, candidate & 0xff);
        ((void(*)())layer_addr)();  // Execute layer as function call
        // Check: does decrypted code contain exactly 2 call read@plt?
        if (count_read_calls(next_layer_addr) == 2) signal_found(candidate);
        _exit(0);
    }
}
```

**Performance tiers:**
| Approach | Speed | 256-layer estimate |
|----------|-------|--------------------|
| Python subprocess | ~2/s | days |
| Ptrace 포크 주입 | ~119/s | 6+ hours |
| JIT + fork-per-candidate | ~1000/s | 140 min |
| JIT + 공유 BSS + 작업자 32명 | ~3500/s | **~17분** |

**공유 BSS 최적화:** BSS(16MB+)가 상위 항목의 `MAP_SHARED`로 `/dev/shm`에 저장됩니다. COW의 경우 어린이는 `MAP_PRIVATE`로 다시 매핑됩니다. 16MB 페이지 테이블 설정에서 ~4KB로 포크 오버헤드를 줄입니다.

**주요 통찰력:** 다층 암호 해독 문제는 근본적으로 빠른 무차별 엔진 구축에 관한 것입니다. JIT 실행(바이너리 메모리를 솔버에 매핑하고 코드를 함수 호출로 직접 실행)은 ptrace보다 훨씬 빠릅니다. 포크 기반 COW는 후보당 무료 메모리 격리를 제공합니다.

**Gotchas:**
- 실제 바이너리는 레이어 전환에 `jmp`(0xe9) 대신 `call`(0xe8)을 사용할 수 있습니다. — 테일 패치 조정
- BSS는 커널 brk 매핑을 통해 ELF MemSiz 이상으로 확장될 수 있습니다. — 추가 공간 매핑
- SHA-NI 명령은 `/proc/cpuinfo`에 광고되지 않은 경우에도 작동합니다.

---

## 임베디드 ZIP + XOR 라이센스 복호화(MetaCTF 2026)

**패턴(License To Rev):** 바이너리에는 인수로 라이센스 파일이 필요합니다. 예상 라이선스와 XOR 암호화 플래그가 포함된 내장형 ZIP 아카이브가 포함되어 있습니다.

**Recognition:**
- `strings`는 `EMBEDDED_ZIP` 및 `ENCRYPTED_MESSAGE` 기호를 나타냅니다.
- 바이너리는 제거되지 않습니다. — `nm` 또는 `readelf -s`는 `.rodata`의 데이터 기호를 표시합니다.
- `file`는 `licensed.c`라는 이름의 소스 파일인 PIE 실행 파일을 보여줍니다.

**Analysis workflow:**
1. **데이터 기호 찾기:**
```bash
readelf -s binary | grep -E "EMBEDDED|ENCRYPTED|LICENSE"
# EMBEDDED_ZIP at offset 0x2220, 384 bytes
# ENCRYPTED_MESSAGE at offset 0x21e0, 35 bytes
```

2. **포함된 ZIP 추출:**
```python
import struct
with open('binary', 'rb') as f:
    data = f.read()
# Find PK\x03\x04 magic in .rodata
zip_start = data.find(b'PK\x03\x04')
# Extract ZIP (size from symbol table or until next symbol)
open('embedded.zip', 'wb').write(data[zip_start:zip_start+384])
```

3. **ZIP에서 라이센스 추출:**
```bash
unzip embedded.zip  # Contains license.txt
```

4. **XOR 플래그를 해독합니다:**
```python
license = open('license.txt', 'rb').read()
enc_msg = open('encrypted_msg.bin', 'rb').read()  # Extract from .rodata
flag = bytes(a ^ b for a, b in zip(enc_msg, license))
print(flag.decode())
```

**주요 통찰력:** 바이너리를 실행하거나 만료 날짜 확인을 우회할 필요가 없습니다. 포함된 ZIP 및 암호화된 메시지는 모두 `.rodata`(추출 및 XOR 오프라인)에 있습니다.

**Disassembly confirms:**
- `memcmp(user_license, decompressed_embedded_zip, size)` — 라이선스 확인
- `EXPIRY_DATE=` 필드에서 `sscanf("%d-%d-%d")`를 사용하여 날짜 구문 분석
- XOR 루프: 바이트당 `ENCRYPTED_MESSAGE[i] ^ license[i]` → `putc()`

**교훈:** 바이너리에 이름이 지정된 기호(`EMBEDDED_*`, `ENCRYPTED_*`)가 있는 경우 실행하지 않고 바이너리에서 직접 데이터를 추출하세요. 알려진 일반 텍스트(라이센스)를 사용한 XOR은 쉽게 되돌릴 수 있습니다.

---

## .rodata XOR Blob의 스택 문자열 난독화(Nullcon 2026)

**패턴(stack_strings_1/2):** 바이너리는 `.rodata`의 blob을 mmap하고 XOR로 난독화한 다음 blob을 사용하여 입력을 검증합니다. 플래그는 검증 루프를 다시 구현하여 복구됩니다.

**Recognition:**
- `mmap()` 호출 후 `.rodata` 데이터에 대한 XOR 루프
- 실행 상태(`eax`, `ebx`, `r9`)가 `0x9E3779B9`, `0x85EBCA6B`, `0xA97288ED`와 같은 상수로 업데이트된 확인 루프
- `rol32()` 위치 의존적 교대를 이용한 작업
- 난독화 해제된 버퍼에 저장된 예상 바이트

**Approach:**
1. pyelftools를 사용하여 `.rodata` 블롭을 추출합니다.
   ```python
   from elftools.elf.elffile import ELFFile
   with open(binary, "rb") as f:
       elf = ELFFile(f)
       ro = elf.get_section_by_name(".rodata")
       blob = ro.data()[offset:offset+size]
   ```
2. 디스어셈블리에서 알려진 키를 사용하여 XOR을 통해 포함된 상수(길이, 마법 값) 복구
3. 바이트별 확인 루프를 다시 구현합니다.
   - 각 반복: 실행 상태에서 두 개의 해시 유사 값을 계산합니다.
   - 입력 바이트를 복구하기 위해 예상 바이트와 XOR을 함께 수행합니다.
   - 지속적인 추가로 실행 상태 업데이트

**변형(stack_strings_2):** 위치 순열 + 이전 문자에 대한 상태 종속성을 추가합니다.
- 위치 순열: 바이트 `i`는 출력에서 `pos[i]` 위치로 이동할 수 있습니다.
- 상태 의존성: `need = (expected - rol8(prev_char, 1)) & 0xFF`
- 각 반복마다 현재 문자를 업데이트하는 `state` 변수를 추적해야 합니다.

**찾아야 할 주요 상수:**
- `0x9E3779B9` (황금비 분수, 해시 함수에서 흔히 사용됨)
- `0x85EBCA6B` (MurmurHash3 종료자 상수)
- `0xA97288ED` (관련 해시 상수)
- `rol32()` 교대 근무 `i & 7`

---

## 접두사 해시 무차별 대입(Nullcon 2026)

**패턴(Hashinator):** 바이너리는 입력의 모든 접두사를 독립적으로 해시하고 접두사당 하나의 다이제스트를 출력합니다. N개의 출력 다이제스트가 주어지면 플래그에는 N-1개의 문자가 있습니다.

**공격:** 한 번에 한 문자씩 입력 복구:
```python
for pos in range(1, len(target_hashes)):
    for ch in charset:
        candidate = known_prefix + ch + padding
        hashes = run_binary(candidate)
        if hashes[pos] == target_hashes[pos]:
            known_prefix += ch
            break
```

**주요 통찰력:** 각 접두사 해시가 독립적인 경우(chaining/HMAC 아님) 문제는 `N` x `|charset|` 바이너리 실행으로 분해됩니다. 이는 한 번에 바이트씩 블록 암호화 공격에 해당하는 해시입니다.

**탐지:** 바이너리는 여러 해시 라인을 출력합니다. 마지막 문자를 변경하면 마지막 해시만 변경됩니다. 입력 길이가 다르면 출력 라인 수가 달라집니다.

---

## CVP/LLL 제한된 정수 검증을 위한 격자(HTB ShadowLabyrinth)

**패턴:** 바이너리는 그룹화된 입력 문자에 계수 행렬을 곱하고 예상되는 64비트 결과와 비교하여 확인하는 행렬 곱셈을 통해 플래그를 검증합니다. 솔루션은 인쇄 가능한 ASCII(32-126)여야 하므로 표준 대수학은 실패합니다. LLL 감소 기능을 갖춘 격자 기반 CVP(Closest Vector Problem)는 이를 효율적으로 해결합니다.

**Identification:**
1. 바이너리 그룹 입력 문자(예: 한 번에 4개)
2. 각 그룹에 계수 행렬을 곱합니다.
3. 하드코딩된 64비트 값과 비교한 결과
4. 제한된 범위의 정수 솔루션이 필요함(인쇄 가능한 ASCII)

**SageMath CVP 솔버:**
```python
from sage.all import *

def solve_constrained_matrix(coefficients, targets, char_range=(32, 126)):
    """
    coefficients: list of coefficient rows (e.g., 4 values per group)
    targets: expected output values
    char_range: valid character range (printable ASCII)
    """
    n = len(coefficients[0])  # characters per group
    mid = (char_range[0] + char_range[1]) // 2

    # Build lattice: [coeff_matrix | I*scale]
    # The target vector includes adjusted targets
    M = matrix(ZZ, n + len(targets), n + len(targets))
    scale = 1000  # Weight to constrain character range

    for i, row in enumerate(coefficients):
        for j, c in enumerate(row):
            M[j, i] = c
        M[n + i, i] = 1  # padding

    for j in range(n):
        M[j, len(targets) + j] = scale

    target_vec = vector(ZZ, [t - sum(c * mid for c in row)
                              for row, t in zip(coefficients, targets)]
                        + [0] * n)

    # LLL + CVP
    L = M.LLL()
    closest = L * L.solve_left(target_vec)  # or use Babai
    solution = [closest[len(targets) + j] // scale + mid for j in range(n)]
    return bytes(solution)
```

**2단계 검증 패턴:**
1. **1단계(행렬 수학):** CVP/LLL를 통해 해결 → 처음 N 문자 복구
2. 처음 N 문자는 AES 키가 됨 → 암호 해독 `file.bin` (마지막 16바이트 XOR + AES-256-CBC + zlib 압축 해제)
3. **2단계(커스텀 VM):** 해독된 바이트코드는 커스텀 VM에서 실행되고 다른 선형 시스템(mod 2^32)을 통해 나머지 문자의 유효성을 검사합니다.

**모듈형 선형 시스템 해석(2단계 — VM 검증):**
```python
import numpy as np
from sympy import Matrix

# M * x = v (mod 2^32)
M_mod = Matrix(coefficients) % (2**32)
v_mod = Matrix(targets) % (2**32)
# Gaussian elimination in Z/(2^32)
solution = M_mod.solve(v_mod)  # Returns flag characters
```

**주요 통찰력:** 바이너리가 큰 계수를 갖는 선형 조합을 통해 입력을 검증하고 솔루션이 작은 범위(인쇄 가능한 ASCII)에 있어야 하는 경우 이는 위장된 격자 문제입니다. LLL 감소 + CVP는 가장 가까운 격자점을 찾아 제한된 솔루션을 복구합니다. 상호 참조: LLL/CVP 기본 사항에 대해 `/ctf-crypto`를 호출합니다(ctf-crypto에서는 advanced-math.md).

**탐지:** 바이너리는 그룹화된 입력에 대해 행렬과 같은 연산을 수행하고 64비트 상수와 비교하며 무차별 검색 공간이 너무 큽니다(예: 그룹당 256^4 × 12개 그룹).

---

## 의사결정 트리 함수 난독화(HTB WonderSMS)

**패턴:** 이진은 ~200개 이상의 자동 생성 함수를 통해 입력을 라우팅합니다. 각 함수는 입력 위치에서 다항식을 계산하고, 상수와 비교하고, 분기합니다. left/right. 트리는 스크립팅된 추출 없이는 정적 분석을 비현실적으로 만듭니다.

**Identification:**
1. 무작위로 보이는 이름을 가진 다수의 유사한 함수(예: `f315732804`)
2. 각 함수는 특정 입력 위치에 대한 산술 연산을 계산합니다.
3. 함수는 다른 트리 함수 또는 최종 검증 함수를 호출합니다.
4. 디컴파일된 코드는 `if (expr cmp constant) call_left() else call_right()`를 보여줍니다.

**Ghidra 대량 추출을 위한 헤드리스 스크립팅:**
```python
# Extract comparison constants from all tree functions
# Run via: analyzeHeadless project/ tmp -import binary -postScript extract_tree.py
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *

fm = currentProgram.getFunctionManager()
results = []
for func in fm.getFunctions(True):
    name = func.getName()
    if name.startswith('f') and name[1:].isdigit():
        # Find CMP instruction and extract immediate constant
        inst_iter = currentProgram.getListing().getInstructions(func.getBody(), True)
        for inst in inst_iter:
            if inst.getMnemonicString() == 'CMP':
                operand = inst.getOpObjects(1)
                if operand:
                    results.append((name, int(operand[0].getValue())))
```

**알려진 출력 형식의 제약 조건 전파:**
1. 알려진 출력 바이트(예: `http://HTB{...}`)에서 시작 → 여러 입력 위치 수정
2. 산술적 제약을 통해 고정 위치 캐스케이드 → 종속 위치 결정
3. 트리 루트 방정식은 나머지 자유 변수를 고정합니다.
4. 여러 솔루션을 명확하게 하기 위해 부분 플래그의 영어 단어를 인식합니다.

**주요 통찰력:** 자동 생성된 의사결정 트리는 압도적으로 보이지만 구성상 반복적입니다. 각 기능을 수동으로 반전하는 대신 추출(Ghidra, Binary Ninja, radare2)을 스크립트로 작성하세요. 트리는 단지 디스패처일 뿐입니다. 실제 논리는 리프 함수와 해당 제약 조건에 있습니다.

**탐지:** 유사한 구조의 함수 수백 개가 포함된 바이너리, 함수당 3~5개의 입력 위치 참조, 두 개의 다른 함수 또는 공통 리프로 분기.

---

## 플래그 복구를 위한 GF(2^8) 가우스 제거(ApoorvCTF 2026)

**패턴(Forge):** 스트립된 이진법은 GF(2^8)에 대해 가우스 제거를 수행합니다(AES 다항식을 사용하여 256개 요소가 있는 갈루아 필드). `.rodata`에는 행렬과 증대 벡터가 포함되어 있습니다. 솔루션 벡터는 플래그입니다.

**AES 다항식을 사용한 GF(2^8) 산술(x^8+x^4+x^3+x+1 = 0x11b):**
```python
def gf_mul(a, b):
    """Multiply in GF(2^8) with AES reduction polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b  # Reduction: x^8 = x^4+x^3+x+1
        b >>= 1
    return p

def gf_inv(a):
    """Brute-force multiplicative inverse (fine for 256 elements)."""
    if a == 0: return 0
    for x in range(1, 256):
        if gf_mul(a, x) == 1:
            return x
    return 0
```

**선형 시스템 풀기:**
```python
# Extract N×N matrix + N-byte augmentation from binary .rodata
N = 56  # Flag length
# Build augmented matrix: N rows × (N+1) cols

for col in range(N):
    # Find non-zero pivot
    pivot = next((r for r in range(col, N) if aug[r][col] != 0), -1)
    if pivot != col:
        aug[col], aug[pivot] = aug[pivot], aug[col]
    # Scale pivot row by inverse
    inv = gf_inv(aug[col][col])
    aug[col] = [gf_mul(v, inv) for v in aug[col]]
    # Eliminate column in all other rows
    for row in range(N):
        if row == col: continue
        factor = aug[row][col]
        if factor == 0: continue
        aug[row] = [v ^ gf_mul(factor, aug[col][j]) for j, v in enumerate(aug[row])]

flag = bytes(aug[i][N] for i in range(N))
```

**주요 통찰력:** GF(2^8)은 일반적인 정수 산술이 아닙니다. 덧셈은 XOR이고 곱셈은 다항식 감소를 사용합니다. AES 다항식(0x11b)이 가장 일반적입니다. 디스어셈블리에서 상수 `0x1b`를 찾으세요. 바이너리는 나중에 AES-GCM으로 결과를 암호화할 수 있지만 원시 솔루션 벡터(사전 암호화)가 플래그입니다.

**감지:** `.rodata`(N²바이트)의 큰 행렬, XOR 기반 행 연산, 상수 `0x1b` 또는 `0x11b` 및 행렬 크기의 sqrt와 일치하는 플래그 길이가 있는 바이너리입니다.

---

## 수정된 바이너리의 ROP 체인 난독화(PlaidCTF 2016)

**패턴(매우 기발한 퀘스트):** 사용자 정의 `--pctfkey KEY` 옵션으로 `curl` 바이너리를 수정했습니다. 키 검증은 `esp`를 버퍼 주소로 대체하고 `magic_buf` 기호에 저장된 ~250KB ROP 체인으로 반환됩니다. ROP 체인은 XOR, MD5 및 상수 비교를 통해 키의 유효성을 검사합니다.

**Analysis approach:**

1. **ROP 디스패치 감지:** `mov esp, eax; ret` 또는 유사한 스택 피벗을 찾습니다. 이는 실행을 ROP 체인으로 리디렉션합니다.
2. **ROP 체인 덤프:** 체인의 각 반환 주소 다음에 명령을 분해하도록 GDB를 스크립트합니다.
```python
# GDB script to trace ROP gadgets
import gdb

magic_buf = 0x080b0000  # symbol address
buf_size = 0x40000       # quarter megabyte
offset = 0

while offset < buf_size:
    addr = int.from_bytes(gdb.selected_inferior().read_memory(magic_buf + offset, 4), 'little')
    gdb.execute(f'x/3i {addr}')
    # Advance past the gadget (typically 4 bytes per return address)
    offset += 4
```

3. **체인의 패턴 식별:** 펼쳐진 루프(반복되는 가젯 시퀀스), 데이터를 건너뛰는 `pop` 명령어, 큰 블록을 건너뛰는 `ret imm16` 명령어를 찾습니다.
4. **알고리즘 재구성:** 체인은 일반적으로 다음을 수행합니다.
   - 키 길이 확인(상수와 비교)
   - 문자 수준 작업(ASCII 값 합계, 상수와 XOR)
   - 해시 계산(파생값의 MD5)
   - 해시 접두사 비교
   - 해시를 키스트림으로 사용하는 입력의 XOR
   - 내장 상수와의 비교

5. **추출 및 해결:** 포함된 상수를 덤프하고 중간 값(예: 문자 합계 → 일치하는 접두사가 있는 MD5)을 무차별 대입한 다음 XOR을 수행하여 키를 복구합니다.
```python
import hashlib

# Brute-force the sum that produces correct MD5 prefix
target_prefix = 0xc0050bdd  # extracted from ROP chain
for s in range(128 * 0x35):  # max sum of printable chars * key_length
    h = hashlib.md5(str(s ^ xor_constant).encode()).hexdigest()
    if int(h[:8], 16) == target_prefix:
        md5_key = bytes.fromhex(h)
        break

# XOR embedded values with MD5 keystream to get flag
flag = bytes(v ^ md5_key[i % 16] for i, v in enumerate(embedded_values))
```

**주요 통찰력:** ROP 체인 난독화('ROPfuscation')는 반환 지향 가젯 체인에 알고리즘을 숨깁니다. 체인은 원시 주소로는 이해하기 어려워 보이지만 (a) 각 가젯의 분해를 덤프하고, (b) 반복을 필터링하고 영역을 건너뛰고, (c) 레지스터 효과에 주석을 달면 분석 가능해집니다. 체인은 기능적으로 일반 코드와 동일합니다. 순차 실행 대신 `ret`만 사용합니다. 대규모 체인(100,000개 이상의 가젯)에는 ~1000줄의 의사코드로 압축되는 펼쳐진 루프가 포함되는 경우가 많습니다.

참조: 1부(숨겨진 에뮬레이터 연산 코드, SPN 정적 추출, 이미지 XOR 부드러움, 한 번에 바이트 암호, 수학적 수렴 비트맵, Windows PE XOR 비트맵 OCR, 2단계 RC4+VM 로더, 커널 모듈 미로 해결, 다중 스레드 VM 채널)에 대한 [patterns-ctf.md](patterns-ctf.md). [patterns-ctf-3.md](patterns-ctf-3.md) 3부(Z3 단일 라인 Python 회로, 슬라이딩 창 팝카운트, 키보드 LED 모스 부호, C++ 소멸자 숨김 검증, syscall 부작용 메모리 손상, MFC 대화 상자 이벤트 핸들러, VM 순차 키 체인 무차별 대입, Burrows-Wheeler 변환 반전, OpenType 글꼴 합자 활용, 자체 수정 코드가 있는 GLSL 셰이더 VM, 명령 카운터 암호화 상태).
