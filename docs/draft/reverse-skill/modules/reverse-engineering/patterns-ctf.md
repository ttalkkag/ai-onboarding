# CTF 리버스 - 경쟁별 패턴(1부)

## 목차
- [숨겨진 에뮬레이터 Opcodes + LD_PRELOAD 키 추출(0xFun 2026)](#hidden-emulator-opcodes--ld_preload-key-extraction-0xfun-2026)
- [Spectre-RSB SPN 암호 — 정적 매개변수 추출(0xFun 2026)](#spectre-rsb-spn-cipher--static-parameter-extraction-0xfun-2026)
- [매끄러움을 통한 이미지 XOR 마스크 복구(VuwCTF 2025)](#image-xor-mask-recovery-via-smoothness-vuwctf-2025)
- [mmap RWX를 통한 데이터 섹션의 쉘코드(VuwCTF 2025)](#shellcode-in-data-section-via-mmap-rwx-vuwctf-2025)
- [재귀적 execve 빼기(VuwCTF 2025)](#recursive-execve-subtraction-vuwctf-2025)
- [바이트 단위 블록 암호 공격(UTCTF 2024)](#byte-at-a-time-block-cipher-attack-utctf-2024)
- [수학적 융합 비트맵(EHAX 2026)](#mathematical-convergence-bitmap-ehax-2026)
- [Windows PE XOR 비트맵 추출 + OCR(srdnlenCTF 2026)](#windows-pe-xor-bitmap-extraction--ocr-srdnlenctf-2026)
- [2단계 로더: RC4 Gate + VM 제약 조건(srdnlenCTF 2026)](#two-stage-loader-rc4-gate--vm-constraints-srdnlenctf-2026)
- [커널 모듈 미로 해결(DiceCTF 2026)](#kernel-module-maze-solving-dicectf-2026)
- [채널 동기화 기능을 갖춘 다중 스레드 VM(DiceCTF 2026)](#multi-threaded-vm-with-channel-synchronization-dicectf-2026)
- [문자열 비교를 통한 백도어 공유 라이브러리 탐지(Hack.lu CTF 2012)](#backdoored-shared-library-Detection-via-string-diffing-hacklu-ctf-2012)
- [RC4 플랫 바이너리가 포함된 사용자 정의 binfmt 커널 모듈(BSidesSF 2026)](#custom-binfmt-kernel-module-with-rc4-plat-binaries-bsidessf-2026)
- [해시 해결된 가져오기 / 가져오기 불가 랜섬웨어(BSidesSF 2026)](#hash-resolved-imports--no-import-ransomware-bsidessf-2026)
- [ELF 분석 방지를 위한 섹션 헤더 손상(BSidesSF 2026)](#elf-section-header-corruption-for-anti-analytic-bsidessf-2026)

---

## 숨겨진 에뮬레이터 Opcode + LD_PRELOAD 키 추출(0xFun 2026)

**패턴(CHIP-8):** 비표준 opcode `FxFF`는 숨겨진 `superChipRendrer()` → AES-256-CBC 암호 해독을 트리거합니다. 이진 상수에서 파생된 키입니다.

**Technique:**
1. 비표준 opcode에 대한 모든 명령어 디스패치 분기를 확인하세요.
2. 숨겨진 opcode는 암호화 기능(OpenSSL)을 트리거할 수 있습니다.
3. 런타임에 AES 키를 캡처하려면 `EVP_DecryptInit_ex`에 `LD_PRELOAD` 후크를 사용하세요.

```c
#include <openssl/evp.h>
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv) {
    // Log key
    for (int i = 0; i < 32; i++) printf("%02x", key[i]);
    printf("\n");
    // Call original
    return ((typeof(EVP_DecryptInit_ex)*)dlsym(RTLD_NEXT, "EVP_DecryptInit_ex"))
           (ctx, type, impl, key, iv);
}
```

```bash
gcc -shared -fPIC -ldl -lssl hook.c -o hook.so
LD_PRELOAD=./hook.so ./emulator rom.ch8
```

---

## Spectre-RSB SPN 암호 — 정적 매개변수 추출(0xFun 2026)

**패턴:** 바이너리는 캐시측 채널을 사용하여 S-박스를 구현하지만 모든 암호화 매개변수(라운드 키, S-박스 테이블, 순열)는 바이너리의 데이터 섹션에 있습니다.

**주요 정보:** 특수 하드웨어에서 실행하려고 하지 마세요. 매개변수를 정적으로 추출합니다.
- 8개 S-박스 × 8개 출력 비트, 각각 256개 항목
- 값 `0x340` = 비트 1, `0x100` = 비트 0
- 64바이트 순열 테이블, 8개의 라운드 키

```python
# Extract from binary data section
import struct
sbox = [[0]*256 for _ in range(8)]
for i in range(8):
    for j in range(256):
        val = struct.unpack('<I', data[sbox_offset + (i*256+j)*4 : ...])[0]
        sbox[i][j] = 1 if val == 0x340 else 0
```

**강의:** 부채널 구현은 메모리에 조회 테이블을 포함합니다. 정적으로 추출합니다.

---

## 부드러움을 통한 이미지 XOR 마스크 복구(VuwCTF 2025)

**패턴(삼각화):** 이미지는 삼각형 영역으로 나누어지고, 각 영역은 마스크를 알 수 없는 `key = (mask * x - y) & 0xFF`로 XOR 암호화됩니다(0-255).

**복구:** 자연스러운 이미지에는 부드러운 그라데이션이 있습니다. 무차별 마스크(지역당 256개 값), 이웃 픽셀 차이에 따른 점수:

```python
import numpy as np
from PIL import Image

img = np.array(Image.open('encrypted.png'))

def score_smoothness(region_pixels, mask, positions):
    decrypted = []
    for (x, y), pixel in zip(positions, region_pixels):
        key = (mask * x - y) & 0xFF
        decrypted.append(pixel ^ key)
    # Score: sum of absolute differences between adjacent pixels
    return -sum(abs(decrypted[i] - decrypted[i+1]) for i in range(len(decrypted)-1))

for region in regions:
    best_mask = max(range(256), key=lambda m: score_smoothness(region, m, positions))
```

**검색 공간:** 256개 후보 × N개 지역 = 사소함. 부드러움은 자연스러운 이미지에 대한 신뢰할 수 있는 점수 측정 기준입니다.

---

## mmap RWX(VuwCTF 2025)를 통한 데이터 섹션의 쉘코드

**패턴(함수 누락):** 바이너리는 데이터를 RWX 메모리(PROT_READ|PROT_WRITE|PROT_EXEC를 사용한 mmap)에 재배치하고 해당 메모리로 점프합니다.

**탐지:** PROT_EXEC 플래그가 있는 `mmap`를 찾으세요. 내장된 쉘코드는 회전 키와 함께 XOR을 사용하는 경우가 많습니다.

**분석:** 데이터 섹션 추출, XOR 키 적용(3바이트 회전 시도), 결과 분해.

---

## 재귀 execve 빼기(VuwCTF 2025)

**패턴(문자열 검사기):** Binary는 `execve`를 통해 자신을 재귀적으로 호출하여 매번 상수를 뺍니다.

**해결책:** 기본 사례를 찾아 역방향으로 작업합니다. `N * M + remainder`와 같은 수학적 관계인 경우가 많습니다.

---

## 한 번에 바이트 블록 암호화 공격(UTCTF 2024)

**패턴(PES-128):** 첫 번째 출력 바이트는 첫 번째 입력 바이트에만 의존합니다(확산 없음).

**공격:** 각 위치에 대해 256바이트 값을 모두 시도하고 출력 바이트를 대상 암호문과 비교합니다. 바이트당 하나의 일치 = 키를 모르는 상태에서 전체 일반 텍스트 복구.

**감지:** 하나의 입력 바이트 변경 → 해당 출력 바이트만 변경됩니다. 이는 크로스 바이트 확산이 0이라는 의미입니다. = 사소하게 깨질 수 있습니다.

---

## 수학적 융합 비트맵(EHAX 2026)

**패턴(계산):** Binary는 뉴턴 방법 수렴을 통해 복소평면 좌표를 분류합니다. 그리드로 정렬된 분류 결과는 ASCII 아트로 플래그를 표시합니다.

**Recognition:**
- 좌표 쌍(x, y)이 있는 입력 파일
- 바이너리는 수학 함수(예: z^3 - 1 = 0)를 반복하고 pass/fail를 출력합니다.
- 포인트 개수로 힌트를 얻은 그리드 크기(예: 2600 = 130×20)
- CTF에서 흔히 사용되는 5픽셀 높이의 ASCII 아트 글꼴

**z^3 - 1에 대한 뉴턴의 방법:**
```python
def newton_converges_to_one(px, py, max_iter=50, target_count=12):
    """Returns True if Newton's method converges to z=1 in exactly target_count steps."""
    x, y = px, py
    count = 0
    for _ in range(max_iter):
        f_real = x**3 - 3*x*y**2 - 1.0
        f_imag = 3*x**2*y - y**3
        J_rr = 3.0 * (x**2 - y**2)
        J_ri = 6.0 * x * y
        det = J_rr**2 + J_ri**2
        if det < 1e-9:
            break
        x -= (f_real * J_rr + f_imag * J_ri) / det
        y -= (f_imag * J_rr - f_real * J_ri) / det
        count += 1
        if abs(x - 1.0) < 1e-6 and abs(y) < 1e-6:
            break
    return count == target_count

# Read coordinates and render bitmap
points = [(float(x), float(y)) for x, y in ...]
bits = [1 if newton_converges_to_one(px, py) else 0 for px, py in points]
WIDTH = 130  # 2600 / 20 rows
for r in range(len(bits) // WIDTH):
    print(''.join('#' if bits[r*WIDTH+c] else '.' for c in range(WIDTH)))
```

**주요 통찰력:** 바이너리는 플래그 검사기가 아닌 수학적 분류자입니다. 플래그는 바이너리 출력이 아닌 분류의 시각적 패턴에 있습니다. 수학을 리버스 엔지니어링하고 모든 좌표에 적용하고 비트맵으로 시각화합니다.

---

## Windows PE XOR 비트맵 추출 + OCR(srdnlenCTF 2026)

**패턴(예술적 준비):** 바이너리는 입력 텍스트를 렌더링하고 렌더링된 비트맵을 `.rdata`의 상수로 XOR되어 저장된 예상 픽셀 데이터와 비교합니다. 계산할 필요가 없습니다. 예상 픽셀을 직접 추출합니다.

**Attack:**
1. 렌더링 및 비교 논리를 식별하기 위해 핵심 검사 기능을 역전시킵니다.
2. `.rdata`에서 예상되는 픽셀 덩어리를 찾습니다(비교에 가까운 참조된 큰 데이터 블록 찾기).
3. 예상되는 렌더링된 DIB를 복구하기 위해 상수(예: 0xAA)를 사용한 XOR
4. 플래그 텍스트를 복구하려면 이미지 및 OCR로 저장하세요.

```python
import numpy as np
from PIL import Image

with open("binary.exe", "rb") as f:
    data = f.read()

# Extract from .rdata section (offsets from reversing)
blob_offset = 0xC3620  # .rdata offset to XOR'd blob
blob_size = 0x15F90     # 450 * 50 * 4 (BGRA)
blob = np.frombuffer(data[blob_offset:blob_offset + blob_size], dtype=np.uint8)
expected = blob ^ 0xAA  # XOR with constant key

# Reshape as BGRA image (dimensions from reversing)
img = expected.reshape(50, 450, 4)
channel = img[:, :, 0]  # Take one channel (grayscale text)
Image.fromarray(channel, "L").save("target.png")

# OCR with charset whitelist
import subprocess
result = subprocess.run(
    ["tesseract", "target.png", "stdout", "-c",
     "tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"],
    capture_output=True, text=True)
print(result.stdout)
```

**주요 통찰력:** 바이너리가 텍스트를 렌더링하고 픽셀을 비교할 때 예상되는 픽셀 데이터는 이미지로 렌더링되는 플래그입니다. 렌더링 논리를 이해할 필요 없이 바이너리 데이터 섹션에서 직접 추출합니다. 문자 세트 화이트리스트가 있는 OCR은 CTF 플래그 문자의 정확성을 향상시킵니다.

---

## 2단계 로더: RC4 Gate + VM 제약 조건(srdnlenCTF 2026)

**패턴(Cornflake v3.5):** 2단계 악성 코드 로더 — 1단계에서는 RC4 사용자 이름 게이트를 사용하고, C2에서 다운로드한 2단계에는 VM 기반 비밀번호 유효성 검사가 포함됩니다.

**1단계 — RC4 사용자 이름 복구:**
```python
def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

# Key from binary strings, ciphertext from stored hex
username = rc4(b"s3cr3t_k3y_v1", bytes.fromhex("46f5289437bc009c17817e997ae82bfbd065545d"))
```

**2단계 — VM 제약 조건 추출:**
1. C2 엔드포인트에서 2단계 다운로드(예: `/updates/check.php`)
2. 역방향 VM 바이트코드 해석기(일반적으로 15-20개의 opcode)
3. 플래그 문자에 대한 선형 등식 제약 조건 추출
4. 제약 조건 시스템 해결(Z3 또는 수동)

**주요 통찰력:** 다단계 로더는 첫 번째 게이트에 간단한 암호화(RC4)를 사용하고 두 번째 게이트에 더 복잡한 검증(커스텀 VM)을 사용하는 경우가 많습니다. VM 메모리는 초기화되지 않을 수 있으며(모두 0) 메모리 종속 작업이 상수가 되므로 제약 조건 추출이 크게 단순화됩니다.

---

## 커널 모듈 미로 해결(DiceCTF 2026)

**패턴(탐색기):** Rust 커널 모듈은 `/dev/challenge` ioctls를 통해 3D 미로를 구현합니다. 미로를 탐색하고, 미끼 출구를 피하고(상태=2), 실제 출구를 찾고(상태=1), 깃발을 읽으세요.

**Ioctl enumeration:**
| Command | Description |
|---------|-------------|
| `0x80046481-83` | 미로 크기 가져오기(3개 축, 각각 8~16개) |
| `0x80046485` | 상태 가져오기: 0=재생 중, 1=승리, 2=미끼 |
| `0x80046486` | 벽 비트필드 가져오기(6방향) |
| `0x80406487` | 플래그 가져오기(64바이트, 상태=1인 경우에만) |
| `0x40046488` | 방향(0-5)으로 이동 |
| `0x6489` | Reset position |

**미끼 방지 기능이 있는 DFS 솔버:**
```c
// Minimal static binary using raw syscalls (no libc) for small upload size
// gcc -nostdlib -static -Os -fno-builtin -o solve solve.c -Wl,--gc-sections && strip solve

int visited[16][16][16];
int bad[16][16][16];   // decoy positions across resets

void dfs(int fd, int x, int y, int z) {
    if (visited[x][y][z] || bad[x][y][z]) return;
    visited[x][y][z] = 1;

    int status = ioctl_get_status(fd);
    if (status == 1) { read_flag(fd); exit(0); }
    if (status == 2) { bad[x][y][z] = 1; return; }  // decoy — mark bad

    int walls = ioctl_get_walls(fd);
    int dx[] = {1,-1,0,0,0,0}, dy[] = {0,0,1,-1,0,0}, dz[] = {0,0,0,0,1,-1};
    int opp[] = {2,3,0,1,5,4};  // opposite directions for backtracking

    for (int dir = 0; dir < 6; dir++) {
        if (!(walls & (1 << dir))) continue;  // wall present
        ioctl_move(fd, dir);
        dfs(fd, x+dx[dir], y+dy[dir], z+dz[dir]);
        ioctl_move(fd, opp[dir]);  // backtrack
    }
}
// After decoy hit: reset via ioctl 0x6489, clear visited, re-run DFS
```

**원격 배포:** netcat 셸을 통해 base64 청크를 통해 바이너리를 업로드하고, 디코딩하고, 실행합니다.

**주요 통찰:** 커널 모듈 문제의 경우 initramfs에 테스트 바이너리를 삽입하고 ioctl을 동적으로 검색하는 것이 제거된 커널 모듈의 정적 RE보다 빠릅니다. 빠른 업로드를 위해 솔버 바이너리를 최소화하십시오(원시 시스템 호출, libc 없음).

---

## 채널 동기화 기능을 갖춘 다중 스레드 VM(DiceCTF 2026)

**패턴(고정):** 사용자 지정 스택 기반 VM은 30자 플래그를 확인하는 16개의 동시 스레드를 실행합니다. 스레드는 futex 기반 채널을 통해 통신합니다. 파이프라인: 입력 → XOR 스크램블 → 변환 → Base-4 상태 머신 → 최종 확인.

**Analysis approach:**
1. GDB에서 채널 read/write 패턴을 추적하여 **스레드 역할 식별**
2. 특정 opcode의 중단점을 통해 **상수 추출**(XOR 스크램블 값, 조회 테이블)
3. **역논리 주의:** 유효성 검사는 유효한 경우 0을 반환하고, 차단된 경우에는 0이 아닌 값을 반환합니다(직관과 반대).
4. **futex 문제 감지:** 소유되지 않은 뮤텍스에서 `unlock_pi`는 EPERM=1을 반환하며, 이는 모든 계산을 변경할 수 있습니다.

**제약된 상태 머신에 대한 BFS 상태 공간 검색:**
```python
from collections import deque

def solve_flag(scramble_vals, lookup_table, initial_state, target_state):
    """BFS through state machine to find valid flag bytes."""
    flag = [None] * 30
    # Known prefix/suffix from flag format
    flag[0:5] = list(b'dice{')
    flag[29] = ord('}')

    # For each unknown position, try all printable ASCII
    states = {initial_state}
    for pos in range(28, 4, -1):  # processed in reverse
        next_states = {}
        for state in states:
            for ch in range(32, 127):
                transformed = transform(ch, scramble_vals[pos])
                digits = to_base4(transformed)
                new_state = apply_digits(state, digits, lookup_table)
                if new_state is not None:  # valid path exists
                    next_states.setdefault(new_state, []).append((state, ch))
        states = set(next_states.keys())

    # Trace back from target_state to recover flag
```

**주요 통찰력:** 다중 스레드 VM은 스레드 경계를 넘어 데이터 흐름을 추적해야 합니다. 채널 기반 통신은 파이프라인을 생성합니다. 어떤 채널이 어떤 채널인지 관찰하여 각 스레드의 역할(입력, 변환, 검증, 출력)을 식별합니다. reads/writes. 계산에 영향을 미치는 상수가 예상치 못한 소스(futex 반환 값, 스레드 ID)에서 나올 수 있습니다.

---

## 문자열 비교를 통한 백도어 공유 라이브러리 탐지(Hack.lu CTF 2012)

**패턴(Zombie Lockbox):** setuid 바이너리는 비밀번호 확인을 위해 `strcmp`를 사용합니다. 예상 비밀번호는 `strings`를 통해 볼 수 있고 GDB(suid 삭제)에서 작동하지만 정상적으로 실행되면 실패합니다. suid 상태에 따라 기능 동작을 패치하는 비표준 libc에 대한 바이너리 링크입니다.

**Detection steps:**
1. `ldd`를 사용하여 비표준 라이브러리 경로를 확인하세요.
```bash
ldd ./binary
# Suspicious: libc.so.6 => /lib/libc/libc.so.6  (non-standard path)
# Normal:    libc.so.6 => /lib32/libc.so.6
```

2. 의심스러운 libc와 시스템 libc 사이의 문자열 비교:
```bash
strings /lib/libc/libc.so.6 > suspicious_strings
strings /lib32/libc-2.15.so > normal_strings
diff suspicious_strings normal_strings
```

3. 패치된 함수(예: `puts`)를 분해하여 삽입된 코드를 찾습니다.
```bash
gdb /lib/libc/libc.so.6
(gdb) disas puts
# Look for unexpected calls or branches
# Injected code may check suid status (getuid/geteuid syscalls)
# and swap the expected password at runtime
```

**주요 통찰력:** 바이너리가 GDB와 일반 실행에서 다르게 동작하는 경우 비표준 라이브러리 경로가 있는지 `ldd`를 확인하세요. Suid 바이너리는 디버거에서 권한을 떨어뜨리므로 백도어가 있는 libc는 `getuid`/`geteuid` 시스템 호출을 통해 이를 감지하고 이에 따라 프로그램 동작을 변경할 수 있습니다. `strings | diff` 접근 방식은 완전히 분해하지 않고도 주입된 데이터를 신속하게 드러냅니다.

---

---

## RC4 플랫 바이너리가 포함된 사용자 정의 binfmt 커널 모듈(BSidesSF 2026)

**패턴(프라이빗 바이너리):** 사용자 정의 Linux 커널 모듈(`.ko`)은 비표준 바이너리 형식에 대한 `binfmt` 핸들러를 등록합니다. 특정 매직 넘버를 가진 파일이 실행되면 커널 모듈은 이를 가로채서 메모리의 내용을 해독하고 진입점으로 점프합니다.

**리버스 엔지니어링 접근 방식:**
1. **`.ko` 분석:** `register_binfmt()` 호출을 찾습니다. `load_binary` 콜백에 `struct linux_binfmt`를 등록합니다.
2. **매직 넘버 찾기:** `load_binary` 함수는 파일의 첫 번째 바이트를 특정 매직 넘버와 비교하여 형식을 식별합니다.
3. **암호화 키 추출:** 8바이트 상수를 로드하는 `movabs` 명령어를 찾습니다. 이는 대개 RC4 키 바이트입니다.
4. **암호화 체계 식별:** 일반적인 선택은 RC4, XOR 또는 AES-ECB입니다. RC4는 S-box 초기화 루프(256바이트 배열, 스왑 패턴)로 식별 가능
5. **플랫 바이너리 복호화:** 헤더를 건너뛰고 암호화된 파일 콘텐츠에 복구된 키를 적용합니다.

```python
from Crypto.Cipher import ARC4

# Extract RC4 key from kernel module (found via movabs instructions)
key = bytes([0x41, 0x42, 0x43, ...])  # Key bytes from .ko disassembly

with open('encrypted.bin', 'rb') as f:
    header = f.read(HEADER_SIZE)  # Skip binfmt header
    encrypted = f.read()

cipher = ARC4.new(key)
decrypted = cipher.decrypt(encrypted)

# The decrypted output is a flat binary (no ELF headers)
# Load at the fixed virtual address specified in the kernel module
# Disassemble with: objdump -b binary -m i386:x86-64 -D decrypted.bin
# Or in Ghidra: import as "Raw Binary", set base address from .ko
```

**커널 모듈에서 감지:**
- `register_binfmt` / `unregister_binfmt` 호출
- `vm_mmap()` 또는 `vm_brk()` 고정 주소에 메모리 할당
- 매핑된 메모리로 직접 점프(진입점 실행)
- S-box 초기화 패턴(RC4): 루프 0-255, `S[i]`을 `S[j]`로 교체

**주요 정보:** 플랫 바이너리에는 ELF 헤더가 없으므로 표준 도구에서는 이를 인식하지 못합니다. 커널 모듈에서 로드 주소를 추출하고(`vm_mmap` 호출의 주소 인수 찾기) 디스어셈블러의 해당 주소에서 해독된 blob을 가져와야 합니다. 커널 모듈의 RC4 키는 데이터 섹션이 아닌 `mov` 또는 `movabs` 명령어에 즉시 값으로 저장되는 경우가 많습니다.

**참조:** BSidesSF 2026 "프라이빗 바이너리"

---

## 해시 해결된 가져오기/가져오기 불가 랜섬웨어(BSidesSF 2026)

**패턴(어딘가에서 실행됨):** 악성 코드 바이너리에는 눈에 띄는 가져오기가 없습니다. 모든 API 호출은 기호 이름을 해싱하고 미리 계산된 해시 값과 비교하여 런타임에 확인됩니다. 바이너리는 `dlopen` + 사용자 정의 해시 테이블을 사용하여 libc 및 libcrypto 함수를 찾습니다.

**Identification:**
- `readelf -d`에는 동적 기호가 없거나 거의 표시되지 않습니다(단지 `dlopen`/`dlsym`).
- 문자열은 표준 API 이름을 나타내지 않습니다.
- 디스어셈블리는 해시 계산 루프와 간접 호출을 보여줍니다.
- RC4 암호화 내장 문자열(RSA 공개 키, 파일 경로, 암호 문구)

**분석 바로가기 — LD_PRELOAD 키 추출:**

전체 해시 확인 및 키 파생을 반대로 하는 대신 악성코드가 궁극적으로 호출하는 암호화 기능을 연결합니다.

```c
// hook_crypto.c — captures AES key used by the ransomware
#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/evp.h>
#include <stdio.h>

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv) {
    if (key) {
        FILE *f = fopen("/tmp/aes_key.bin", "wb");
        fwrite(key, 1, 32, f);  // AES-256
        fclose(f);
        fprintf(stderr, "[HOOK] AES key captured\n");
    }
    typedef int (*orig_t)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*,
                          const unsigned char*, const unsigned char*);
    orig_t orig = (orig_t)dlsym(RTLD_NEXT, "EVP_CipherInit_ex");
    return orig(ctx, type, impl, key, iv);
}
```

```bash
# Compile and run
gcc -shared -fPIC -o hook.so hook_crypto.c -ldl
# Run in Docker container (ransomware may be destructive!)
docker run --rm -v $(pwd):/work -w /work ubuntu:22.04 \
  bash -c "LD_PRELOAD=./hook.so ./ransomware; xxd /tmp/aes_key.bin"
```

**해시 확인 패턴:**
- **SipHash 변형:** 두 개의 64비트 시드, 기호 이름 바이트와 반복 혼합
- **DJB2/FNV 변형:** 인식 가능한 상수가 있는 더 간단한 해시 함수(`5381`, `0xcbf29ce484222325`)
- **ROR13 기반:** Windows 악성코드 즐겨찾기: `hash = (hash >> 13) | (hash << 19); hash += c`

**키 캡처 후 암호 해독:**
```python
from Crypto.Cipher import AES

key = open('/tmp/aes_key.bin', 'rb').read()
iv = open('/tmp/aes_iv.bin', 'rb').read()  # Also hookable
cipher = AES.new(key, AES.MODE_CBC, iv)

with open('flag.txt.enc', 'rb') as f:
    ct = f.read()
pt = cipher.decrypt(ct)
# Remove PKCS7 padding
pt = pt[:-pt[-1]]
print(pt.decode())
```

**주요 통찰력:** 바이너리가 해싱을 통해 모든 가져오기를 해결할 때 해시 함수를 역전시키고 레인보우 테이블을 구축하는 데 시간을 낭비하지 마십시오. 대신, 관심 있는 기능(OpenSSL 암호화 기능, 파일 I/O, 네트워크 호출)에 대한 `LD_PRELOAD` 후크가 있는 샌드박스 환경에서 악성코드를 실행하여 모든 것을 자체적으로 해결하도록 하세요. AES 키는 실행 전반에 걸쳐 결정적입니다. 즉, 한 번 작동하면 항상 작동합니다.

**안전:** 의심되는 랜섬웨어는 항상 Docker 컨테이너나 VM에서 실행하세요. 암호화된 파일의 복사본만 마운트하고 원본은 마운트하지 마세요.

**참고 자료:** BSidesSF 2026 "Ran Somewhere"

---

## ELF 분석 방지를 위한 섹션 헤더 손상(BSidesSF 2026)

**패턴(완고한-엘프):** ELF 바이너리가 의도적으로 섹션 헤더 테이블 항목을 손상시켜 표준 분석 도구(`readelf`, `objdump`, IDA, Ghidra)가 충돌하거나 오류를 생성하게 했습니다. 그러나 OS 로더가 사용하는 **프로그램 헤더**는 그대로 유지되므로 바이너리가 정상적으로 실행됩니다. 플래그는 매직 바이트로 표시된 손상된 섹션 뒤에 추가됩니다.

```python
import sys

# Standard tools fail on corrupted section headers
# Manual parsing bypasses section headers entirely

with open("stubborn_elf", "rb") as f:
    data = f.read()

# Search for magic marker appended after ELF sections
magic = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
idx = data.find(magic)
if idx >= 0:
    # Data after magic is XOR-encrypted
    encrypted = data[idx + len(magic):]
    decrypted = bytes(b ^ 0x42 for b in encrypted)
    print(decrypted.decode(errors='ignore'))
```

**주요 정보:** ELF 실행에는 섹션 헤더가 아닌 **프로그램 헤더**(PT_LOAD 세그먼트)가 필요합니다. 섹션 헤더는 디버거 및 분석 도구에 대한 메타데이터이며 런타임 시 선택 사항입니다. ELF 헤더의 `e_shoff`, `e_shnum` 또는 `e_shstrndx`가 손상되면 도구가 중단되지만 실행은 중단되지 않습니다. 도구가 실패하면 바이너리를 수동으로 구문 분석하거나 디스어셈블러에서 로드하기 전에 ELF 헤더를 패치하여 섹션 헤더 참조를 0으로 만듭니다.

**Recovery approach:**
```bash
# Patch section header offset to 0 (removes section table)
printf '\x00\x00\x00\x00\x00\x00\x00\x00' | dd of=binary bs=1 seek=40 conv=notrunc
# Now Ghidra/IDA can load it using program headers only

# Or use readelf -l (program headers only, ignores sections)
readelf -l stubborn_elf
```

**인식해야 할 경우:** `readelf -S` 충돌이 발생하거나 쓰레기가 표시됩니다. `file` 명령은 이를 ELF로 식별합니다. `readelf -l`(소문자 L, 프로그램 헤더)는 정상적으로 작동합니다. 도구 오류에도 불구하고 바이너리가 정상적으로 실행됩니다.

**참조:** BSidesSF 2026 "완고한 엘프"

---

참조: 파트 2의 경우 [patterns-ctf-2.md](patterns-ctf-2.md)(다층 자체 복호화 바이너리, 내장된 ZIP+XOR 라이센스, 스택 문자열 난독화, 접두사 해시 무차별 대입, CVP/LLL 격자, 의사 결정 트리 난독화, GF(2^8) 가우스 제거), 파트 3의 경우 [patterns-ctf-3.md](patterns-ctf-3.md) (Z3 부울 회로, 슬라이딩 윈도우 팝카운트, 키보드 LED 모스 부호, C++ 소멸자 숨김 검증, VM 순차 키 체인 무차별 대입, BWT 반전, OpenType 글꼴 합자 활용, 자체 수정 코드가 있는 GLSL 셰이더 VM).
