# CTF 리버스 - 언어별 기술

## 목차
- [Python 바이트코드 반전(dis.dis 출력)](#python-bytecode-reversing-disdis-output)
  - [공통 패턴: 분할 인덱스를 사용한 XOR 검증](#common-pattern-xor-validation-with-split-indices)
  - [바이트코드 분석 팁](#bytecode-analytic-tips)
- [Python Opcode 재매핑](#python-opcode-remapping)
  - [신분증](#identification)
  - [Recovery](#recovery)
- [Pyarmor 8/9 정적 언팩(1샷)](#pyarmor-89-static-unpack-1shot)
- [DOS 스텁 분석](#dos-stub-analytic)
- [HarmonyOS HAP/ABC 리버스(abc-decompiler)](#harmonyos-hapabc-reverse-abc-decompiler)
- [Brainfuck/Esolangs](#brainfuckesolangs)
  - [Brainfuck 문자별 정적 분석(BSidesSF 2026)](#brainfuck-character-by-character-static-analytic-bsidessf-2026)
  - [읽기 횟수 Oracle을 통한 Brainfuck 사이드 채널(BSidesSF 2026)](#brainfuck-side-channel-via-read-count-oracle-bsidessf-2026)
  - [Brainfuck 비교 관용구 감지(BSidesSF 2026)](#brainfuck-comparison-idiom-Detection-bsidessf-2026)
- [UEFI 바이너리 분석](#uefi-binary-analytic)
- [C로 변환](#transpilation-to-c)
- [코드 커버리지 부채널 공격](#code-coverage-side-channel-attack)
- [기능적 언어 반전(OPAL)](#기능적 언어-반전-opal)
- [Python 버전별 바이트코드(VuwCTF 2025)](#python-version-Specific-bytecode-vuwctf-2025)
- [비전단사적 치환 암호역전](#비전단사적 치환-암호-역전)
- [FRACTRAN 프로그램 반전(Boston Key Party 2016)](#fractran-program-inversion-boston-key-party-2016)

platform/framework-specific 기술(Android, Electron, Node.js, Verilog, Ruby/Perl 다중 언어 등)에 대해서는 [languages-platforms.md](languages-platforms.md)를 참조하세요.
Go 및 Rust 바이너리 리버싱에 대해서는 [languages-compiled.md](languages-compiled.md)를 참조하세요.

---

## Python 바이트코드 반전(dis.dis 출력)

### 일반적인 패턴: 분할 인덱스를 사용한 XOR 검증

챌린지는 원시 CPython 바이트 코드(dis.dis 어셈블리)를 제공합니다. 일반적인 패턴:
1. 플래그 길이 확인
2. key1이 있는 짝수 인덱스의 XOR 문자, 목록 p1과 비교
3. key2와 홀수 인덱스의 XOR 문자, 목록 p2와 비교

**Reversing:**
```python
# Given: p1, p2 (expected values), key1, key2 (XOR keys)
flag = [''] * flag_length
for i in range(len(p1)):
    flag[2*i] = chr(p1[i] ^ key1)      # Even indices
    flag[2*i+1] = chr(p2[i] ^ key2)    # Odd indices
print(''.join(flag))
```

### 바이트코드 분석 팁
- `LOAD_CONST` 다음에 `COMPARE_OP`를 입력하면 예상 값이 표시됩니다.
- `BINARY_XOR`는 변환을 식별합니다.
- `BUILD_TUPLE`/`BUILD_LIST` 상수 포함 = 예상 출력 배열
- 루프 구조: `FOR_ITER` + `BINARY_SUBSCR` = 플래그 문자 반복
- `CALL_FUNCTION` on `ord` = 문자를 정수로 변환

**주요 통찰력:** Python 바이트코드 문제는 명시적 스택 작업의 알고리즘을 제공합니다. `LOAD_CONST` 값(예상 출력), `BINARY_XOR`/`BINARY_ADD`(변환) 및 `BUILD_TUPLE`(대상 배열)에 중점을 두어 바이트코드를 실행하지 않고 유효성 검사 논리를 재구성합니다.

---

## Python Opcode 재매핑

### Identification
Opcode 오류로 인해 디컴파일러가 실패합니다.

### Recovery
1. PyInstaller 번들에서 수정된 `opcode.pyc` 찾기
2. 원본 Python opcode와 비교
3. 빌드 매핑: `{new_opcode: original_opcode}`
4. 패치 대상.pyc
5. Decompile normally

**바로가기(Hack.lu CTF 2013):** 챌린지에서 수정된 자체 Python 인터프리터(예: 사용자 정의 `./py` 바이너리)를 번들로 묶는 경우 `uncompyle2`/`uncompyle6`를 해당 인터프리터 환경에 설치하고 챌린지 자체 런타임을 사용하여 디컴파일합니다. 수정된 인터프리터는 자체 opcode 매핑을 이해하므로 표준 디컴파일 도구는 수동 opcode 복구 없이 작동합니다.

**Python 버전별 도구 선택:** `uncompyle6` Python 2.x–3.8을 지원합니다. Python 3.9+ 바이트코드의 경우 [`pycdc`](https://github.com/zrax/pycdc)(소스에서 컴파일: `git clone && cmake. && make`)를 사용하세요.

**주요 통찰력:** Opcode 재매핑은 모든 표준 디컴파일러를 손상시킵니다. 가장 빠른 해결 방법은 PyInstaller 번들에서 수정된 `opcode.pyc`를 찾아서 기본 Python opcode와 비교한 다음 디컴파일하기 전에 대상 `.pyc`을 다시 표준 opcode로 패치하는 것입니다.

---

## Pyarmor 8/9 정적 포장 풀기(1샷)

- 도구: `Lil-House/Pyarmor-Static-Unpack-1shot`
- 샘플 코드를 실행하지 않고 Pyarmor 8.x/9.x 기갑 스크립트에 사용
- 빠른 서명 확인: 페이로드는 일반적으로 `PY` + 6자리 숫자로 시작합니다(Pyarmor 7 이하 `PYARMOR` 형식은 지원되지 않음)

Workflow:
1. 대상 디렉터리에 강화된 스크립트와 일치하는 `pyarmor_runtime` 라이브러리가 포함되어 있는지 확인하세요.
2. 일회성 압축 해제를 실행하여 `.1shot.` 출력(디스어셈블리 + 실험적 디컴파일)을 내보냅니다.
3. 분해를 기본 진실로 취급하십시오. 일관성이 없는 경우 바이트코드로 디컴파일된 소스를 확인하세요.

```bash
python /path/to/oneshot/shot.py /path/to/scripts
```

Optional flags:
```bash
# Specify runtime explicitly
python /path/to/oneshot/shot.py /path/to/scripts -r /path/to/pyarmor_runtime.so

# Write outputs to another directory
python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output
```

Notes:
- `oneshot/pyarmor-1shot` 실행 파일은 `shot.py`을 실행하기 전에 존재해야 합니다.
- PyInstaller 번들 또는 아카이브를 먼저 압축을 푼 다음 1shot으로 처리해야 합니다.

**주요 통찰력:** Pyarmor 8/9는 런타임 암호 해독으로 스크립트를 래핑합니다. 1shot 도구는 armored bytecode와 `pyarmor_runtime` 라이브러리를 직접 처리하여 실행 없이 정적으로 압축을 푼다. 실험적으로 디컴파일된 소스가 일관되지 않은 것처럼 보일 경우 디스어셈블리 출력을 Ground Truth로 처리합니다.

---

## DOS 스텁 분석

PE 파일은 DOS 스텁의 코드를 숨길 수 있습니다.
1. Ghidra/IDA에서 대규모 DOS 스텁을 확인하세요.
2. DOSBox에서 실행
3. IDA에서 16비트 DOS로 로드
4. `int 16h`(키보드 입력)을 찾으세요.

**주요 정보:** PE 파일은 DOS 스텁(PE 헤더 앞)에 완전한 기능을 갖춘 16비트 DOS 프로그램을 삽입할 수 있습니다. 스텁이 비정상적으로 큰 경우 IDA에서 16비트 DOS로 로드하거나 DOSBox에서 실행하십시오. 챌린지 논리가 스텁에 완전히 존재할 수 있습니다.

---

## HarmonyOS HAP/ABC 역방향(abc-디컴파일러)

- 대상 파일: `.hap` 패키지 및 내장된 `.abc` 바이트코드
- 도구: `https://github.com/ohos-decompiler/abc-decompiler`
- 릴리스에서 `jadx-dev-all.jar` 다운로드

중요한 시작 참고 사항:
- `java -jar` GUI 모드로 들어갈 수 있음
- CLI 모드의 경우 항상 다음을 사용하세요.

```bash
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI [options] <input>
```

가장 일반적인 명령:
```bash
# Basic decompile to directory
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -d "out" ".abc"

# Decompile .abc (recommended for this scenario)
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple -d "out_hap" "modules.abc"
```

이 챌린지에 권장되는 매개변수:
- `-m simple`: SSA/PHI-heavy 실패를 방지하기 위해 높은 수준의 재구성을 줄입니다.
- `--log-level ERROR`: 심각한 오류만 유지
- 전체 권장 명령:

```bash
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple --log-level ERROR -d "out_abc_simple" "modules.abc"
```

매개변수 빠른 참조:
- `-d` 출력 디렉터리
- `--help` help

Notes:
- `.hap`는 패키지입니다. 먼저 압축을 풀고(zip) `.abc`를 찾아서 분석하세요.
- 공백이나 ASCII가 아닌 문자가 포함된 인용 경로
- 오래된 결과를 방지하려면 실행마다 새 출력 디렉터리 이름을 사용하세요.
- 오류가 항상 완전한 실패를 의미하는 것은 아닙니다. 우선순위를 정하세요 `out_xxx/sources/`
- `auto`이 실패하면 먼저 `-m simple`로 전환하세요.

Standard workflow:
1. `-m simple --log-level ERROR`로 실행
2. 출력에서 주요 비즈니스 파일 검사(예: `pages/Index.java`)
3. 더 깔끔한 출력이 필요한 경우 `-m auto` 또는 `-m restructure`를 사용하여 다시 시도하세요.
4. 일부 방법이 여전히 실패하면 `simple` 출력을 유지하고 대체 경로를 통해 논리 분석을 계속합니다.

**주요 통찰력:** HarmonyOS `.hap` 패키지는 `.abc` 바이트코드를 포함하는 ZIP 아카이브입니다. 가장 안정적인 디컴파일을 위해 abc-decompiler의 CLI 모드(`jadx.cli.JadxCLI`)를 `-m simple`와 함께 사용하세요. 파일을 처리하는 대신 GUI 모드가 실행될 수 있습니다.

---

## Brainfuck/Esolangs

- 알려진 도구(BF-it)로 컴파일되었는지 확인
- tape/memory 모델 이해
- 셀 작동의 정적 분석

### Brainfuck 문자별 정적 분석(BSidesSF 2026)

**패턴(i-love-my-bf-part1):** 입력 문자를 문자별로 검증하는 BF 프로그램은 인식 가능한 패턴을 따릅니다. `,`(문자 읽기) 다음에 해당 문자의 예상 ASCII 값과 개수가 같은 `+` 작업 시퀀스가 옵니다.

**Extraction technique:**
```python
import re

bf_code = open('challenge.bf', 'r').read()

# Split on comma (input read) — each segment handles one character
segments = bf_code.split(',')
expected = []

for seg in segments[1:]:  # Skip preamble before first comma
    # Count consecutive '+' operations before any branch/output
    plus_count = 0
    for ch in seg:
        if ch == '+':
            plus_count += 1
        elif ch in '-.[]><':
            break  # Stop at first non-increment operation
    if plus_count > 0:
        expected.append(chr(plus_count % 256))

flag = ''.join(expected)
print(f"Flag: {flag}")
```

**Variations:**
- `-` 연산: 문자 값 = `256 - minus_count`
- 혼합 `+`/`-`: 순 증분에 따라 값이 결정됩니다.
- 문자 간 셀 재설정(`[-]`): 각 세그먼트는 독립적입니다.
- 루프 기반 곱셈: `[->>+++<<]` 3을 곱합니다 — 내부 연산 수 계산

**탐지:** `,` 반복 패턴 뒤에 많은 `+` 또는 `-` 문자, 그 다음 비교 구조(`[-]` 또는 `[->+<]` 패턴)가 오는 대형 BF 파일입니다.

**주요 통찰력:** 입력을 확인하는 BF 프로그램은 구조적으로 간단합니다. 각 입력 바이트는 셀을 증가시켜 생성된 상수와 비교됩니다. 프로그램을 실행하지 않고 예상 입력을 복구하려면 증분 카운트를 추출하세요.

**참조:** BSidesSF 2026 "i-love-my-bf-part1"

### 읽기 횟수 Oracle을 통한 Brainfuck 사이드 채널(BSidesSF 2026)

**패턴(i-love-my-bf-part2):** BF 프로그램이 문자별로 입력을 확인할 때 올바른 문자로 인해 프로그램은 더 많은 입력 바이트를 소비하게 됩니다(다음 위치를 확인하기 위해 진행). 각 후보 입력에 대해 실행되는 `,`(읽기) 작업 수를 계산하면 가장 많은 읽기를 트리거하는 문자가 정확합니다.

```python
import itertools

def bytes_read_running_bf(bf_code, input_iter, braces):
    """Run BF and count how many input bytes were consumed."""
    tape = [0] * 30000
    ptr = ip = reads = 0
    input_list = list(input_iter)
    input_idx = 0
    while ip < len(bf_code):
        c = bf_code[ip]
        if c == ',':
            if input_idx < len(input_list):
                tape[ptr] = input_list[input_idx]
                input_idx += 1
                reads += 1
            else:
                return reads
        elif c == '.': pass
        elif c == '+': tape[ptr] = (tape[ptr] + 1) % 256
        elif c == '-': tape[ptr] = (tape[ptr] - 1) % 256
        elif c == '>': ptr += 1
        elif c == '<': ptr -= 1
        elif c == '[' and tape[ptr] == 0: ip = braces[ip]
        elif c == ']' and tape[ptr] != 0: ip = braces[ip]
        ip += 1
    return reads

# Recover flag character by character
PRINTABLE = list(range(32, 127))
flag = []
for pos in range(50):  # max flag length
    best_byte = None
    max_reads = 0
    baseline = bytes_read_running_bf(bf, flag + [PRINTABLE[0]], braces)
    for b in PRINTABLE[1:]:
        reads = bytes_read_running_bf(bf, flag + [b], braces)
        if reads > baseline:
            best_byte = b
            break
    if best_byte is None:
        break
    flag.append(best_byte)
print(bytes(flag).decode())
```

**주요 통찰력:** BF 입력 검증 프로그램은 순차적입니다. 즉, 한 문자를 읽고 확인한 후 일치하는 경우에만 다음 문자를 읽습니다. 더 많은 읽기를 유발하는 문자는 프로그램이 다음 위치를 확인하기 위해 검증 게이트를 지나 전진하기 때문에 정확합니다.

**참조:** BSidesSF 2026 "i-love-my-bf-part2"

### Brainfuck 비교 관용구 감지(BSidesSF 2026)

**패턴(i-love-my-bf-part3):** 고급 언어에서 컴파일된 BF 프로그램은 인식 가능한 비교 관용어를 사용합니다. 동등성 검사 `<[-<->] +<[>-<[-]]>[-<+>]`는 인접한 두 셀을 비교합니다. 실행 중에 이 패턴을 감지하도록 BF 인터프리터를 계측하면 테이프에서 직접 비교 피연산자(예상 플래그 바이트)를 추출할 수 있습니다.

```python
EQ_PATTERN = "<[-<->] +<[>-<[-]]>[-<+>]"

def instrumented_bf_run(bf_code, dummy_input):
    """Run BF, detect equality comparisons, extract operands."""
    tape = [0] * 30000
    ptr = ip = 0
    comparisons = []

    while ip < len(bf_code):
        # Check if current position starts the eq pattern
        if bf_code[ip:ip+len(EQ_PATTERN)] == EQ_PATTERN:
            # The two cells being compared are at ptr-2 and ptr-1
            lhs = tape[ptr - 2]  # User input byte
            rhs = tape[ptr - 1]  # Expected byte
            comparisons.append((chr(lhs), chr(rhs)))
        # ... normal BF execution ...
        ip += 1

    return comparisons

# Expected bytes from comparisons reveal the flag
```

**주요 통찰력:** 컴파일된 BF 프로그램은 동등 비교, 조건 분기 및 루프와 같은 작업에 고정된 관용구를 재사용합니다. BF 소스에서 또는 실행 중에 이러한 관용구를 패턴 일치시키면 프로그램 논리를 완전히 이해하지 않고도 상수를 추출할 수 있습니다.

**일반적인 BF 관용어:**
- `[-]` — 셀 지우기(0으로 설정)
- `[->+<]` — 셀을 오른쪽으로 이동
- `<[-<->] +<[>-<[-]]>[-<+>]` — 두 셀의 동일성 비교

**참조:** BSidesSF 2026 "i-love-my-bf-part3"

---

## UEFI 바이너리 분석

```bash
7z x firmware.bin -oextracted/
file extracted/* | grep "PE32+"
```

- Bootkit은 부트 로더를 대체합니다.
- 커스텀 VM은 복호화를 보호합니다.
- VM 바이트코드를 C로 리프트

**주요 정보:** UEFI 바이너리는 PE32+ 실행 파일입니다. `7z`로 펌웨어를 추출하고, `file`로 PE 파일을 식별하고 Ghidra/IDA.에 로드합니다. 부트킷은 부트 로더를 대체하므로 챌린지 로직에 대해서는 DXE 드라이버 및 부트 서비스 프로토콜에 중점을 둡니다.

---

## C로 변환

심하게 난독화된 코드의 경우:
```python
for opcode, args in instructions:
    if opcode == 'XOR':
        print(f"r{args[0]} ^= r{args[1]};")
    elif opcode == 'ADD':
        print(f"r{args[0]} += r{args[1]};")
```

지속적인 접기를 위해 `-O3`로 컴파일합니다.

**주요 통찰력:** 난독화된 VM 바이트코드를 C로 트랜스파일하고 `-O3`로 컴파일하면 컴파일러의 상수 폴딩 및 데드 코드 제거를 통해 알고리즘이 자동으로 단순화됩니다. 이는 복잡한 명령 세트에 대한 수동 난독화보다 빠릅니다.

---

## 코드 커버리지 부채널 공격

**패턴(Coverup, Nullcon 2026):** PHP 챌린지는 암호화된 출력과 함께 XDebug 코드 적용 범위 데이터를 제공합니다.

**작동 방식:**
- PHP 코드는 `xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK)`를 사용합니다.
- 암호화는 데이터 종속 분기를 사용합니다: `if ($xored == chr(0))... if ($xored == chr(1))...`
- Coverage JSON는 암호화 중에 실행된 분기를 나타냅니다.
- 이로 인해 발생한 XOR 중간 값 세트가 누출됩니다.

**Exploitation:**
```python
import json

# Load coverage data
with open('coverage.json') as f:
    cov = json.load(f)

# Extract executed XOR values from branch coverage
executed_xored = set()
for line_no, hit_count in cov['encrypt.php']['lines'].items():
    if hit_count > 0:
        # Map line numbers to the chr(N) value in the if-statement
        executed_xored.add(extract_value_from_line(line_no))

# For each position, filter candidates
for pos in range(len(ciphertext)):
    candidates = []
    for key_byte in range(256):
        xored = plaintext_byte ^ key_byte  # or reverse S-box lookup
        if xored in executed_xored:
            candidates.append(key_byte)
    # Combined with known plaintext prefix, this uniquely determines key
```

**주요 통찰력:** 코드 적용 범위는 강력한 오라클입니다. 어떤 조건부 경로가 선택되었는지 알려줍니다. 데이터 종속 분기를 사용한 모든 암호화는 적용 범위를 통해 정보를 유출합니다.

**완화 감지:** 이 공격을 물리치는 branchless/constant-time 암호화 구현을 찾으세요.

---

## 기능적 언어 역전(OPAL)

**패턴(Opalist, Nullcon 2026):** 순수 기능 언어인 OPAL(Optimized Applicative Language)에서 컴파일된 바이너리입니다.

**Recognition markers:**
- `.impl`(구현) 및 `.sign`(서명) 소스 파일
- `IMPLEMENTATION` / `SIGNATURE` 키워드
- 중첩된 `IF..THEN..ELSE..FI` 구조
- `f1`, `f2`,... `fN`라는 이름의 함수(숫자 명명)
- `seq[nat]`, `string`, `denotation` 유형을 많이 사용함

**Reversing approach:**
1. 순수 함수는 수학적으로 역전이 가능합니다. 파이프라인의 각 단계를 역으로 수행합니다.
2. 변환 체인 식별: `f_final(f_n(...f_2(f_1(input))...))`
3. 각 함수에 대해 역함수를 만듭니다.

**스크램블 기능을 위한 총 무차별 대입:**
변환이 원래(알 수 없는) 값에 따라 상태를 누적하는 경우:
```python
# Example: f8 adds cumulative offset based on parity of original bytes
# offset contribution per element depends on whether pre-scramble value is even/odd
# Total offset S = sum of contributions, but S mod 256 has only 256 possibilities

decoded = base64_decode(target)
for total_offset_S in range(256):
    candidate = [(b - total_offset_S) % 256 for b in decoded]
    # Verify: recompute S from candidate values
    recomputed_S = sum(contribution(i, candidate[i]) for i in range(len(candidate))) % 256
    if recomputed_S == total_offset_S:
        # Apply remaining inverse steps
        result = apply_inverse_substitution(candidate)
        if all(32 <= c < 127 for c in result):
            print(bytes(result))
```

**핵심 교훈:** 스크램블 함수에 닭고기-계란 종속성이 있는 경우(결과는 알 수 없는 원본에 따라 다름) 모든 가능한 상태(지수)보다는 집계 효과(종종 mod 256 = 256 가능성)를 무차별 대입합니다.

---

## Python 버전별 바이트코드(VuwCTF 2025)

**패턴(새로운 머신):** 챌린지는 특정 Python 버전(예: 3.14.0 알파)을 대상으로 합니다.

**주요 요구 사항:** 정확한 Python 버전을 컴파일하여 바이트코드를 분해합니다. — alpha/beta 버전은 안정 릴리스와 다른 opcode를 갖습니다.

```bash
# Build specific Python version
wget https://www.python.org/ftp/python/3.14.0/Python-3.14.0a4.tar.xz
tar xf Python-3.14.0a4.tar.xz
cd Python-3.14.0a4 && ./configure && make -j$(nproc)
./python -c "import dis, marshal; dis.dis(marshal.loads(open('challenge.pyc','rb').read()[16:]))"
```

**공통 유효성 검사:** 제곱된 ASCII 값의 튜플과 비교되는 플래그:
```python
# Reverse: flag[i] = sqrt(expected_tuple[i])
import math
flag = ''.join(chr(int(math.isqrt(v))) for v in expected_values)
```

---

## 비단사적 대체 암호 역전

**패턴(Coverup, Nullcon 2026):** S-box/substitution 테이블에 충돌이 있습니다(여러 입력이 동일한 출력에 매핑됨).

**Detection:**
```python
sbox = [...]  # substitution table
if len(set(sbox)) < len(sbox):
    print("Non-bijective! Collisions exist.")
```

**역방향 조회 구축:**
```python
from collections import defaultdict
rev_sub = defaultdict(list)
for i, v in enumerate(sbox):
    rev_sub[v].append(i)
# rev_sub[output] = [list of possible inputs]
```

**명확화 전략:**
1. 알려진 일반 텍스트 형식(예: `ENO{`, `flag{`)은 알려진 위치의 키 바이트를 수정합니다.
2. 부채널 데이터(코드 적용 범위, 타이밍)로 불가능한 후보 제거
3. 인쇄 가능한 ASCII 제약 조건(32-126)으로 후보 공간이 줄어듭니다.
4. 후보를 다시 암호화하고 알려진 암호문을 기준으로 확인합니다.

---

## FRACTRAN 프로그램 반전(Boston Key Party 2016)

FRACTRAN: 계산이 분수 테이블에 의한 반복 곱셈인 난해한 언어입니다. 입력은 소인수 분해(순차 소수의 지수인 ASCII 값)로 인코딩됩니다. 반전하려면: 각 분수의 분자와 분모를 바꾸고 반전된 프로그램을 통해 "성공" 출력을 거꾸로 실행합니다.

```python
# Original: for each step, find first fraction where n*frac is integer
def fractran_step(n, fractions):
    for num, den in fractions:
        if (n * num) % den == 0:
            return (n * num) // den
    return None  # Halt

# Inversion: swap num/denom in fraction table
inverted = [(d, n) for n, d in fraction_table]
# Run target output through inverted program to recover input
```

**주요 통찰력:** FRACTRAN 프로그램은 분자와 분모를 교환하여 반전될 수 있습니다. 소인수분해 인코딩은 I/O를 이해하는 데 핵심입니다. 결과를 인수분해하여 순차 소수의 지수를 추출하고 ASCII에 매핑합니다.

**탐지:** 챌린지는 분수, 소인수분해를 언급하거나 유리수 목록을 제공합니다.
