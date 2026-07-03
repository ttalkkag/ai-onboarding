# ELF 바이너리 심층분석 참고자료

> 리버스 엔지니어링 Linux/Android ELF 파일 시 구조 분석, 반분석 대립 식별 및 분석 기술.

---

## ELF 구조 빠른 확인

### 파일 헤더(ELF 헤더)

```text
오프셋 크기 필드 설명
0x00  4    e_ident[EI_MAG]   Magic: 7f 45 4c 46 ("\x7fELF")
0x04  1    e_ident[EI_CLASS] 1=32bit, 2=64bit
0x05  1    e_ident[EI_DATA]  1=LE, 2=BE
0x10  2    e_type            2=EXEC, 3=DYN(PIE/SO), 4=CORE
0x12  2    e_machine         0x03=x86, 0x3E=x86_64, 0xB7=AArch64, 0x28=ARM
0x18 8 e_entry 진입점 가상 주소
0x20 8 e_phoff 프로그램 헤더 테이블 오프셋
0x28 8 e_shoff 섹션 헤더 테이블 오프셋(스트립 후 0일 수 있음)
0x38 2 e_phnum 프로그램 헤더 수
0x3C 2 e_shnum 섹션 헤더 수
```

### 프로그램 헤더

```text
유형 값 이름 설명
0x01 PT_LOAD 로드 가능 세그먼트(코드/데이터)
0x02 PT_DYNAMIC 동적 링크 정보
0x03 PT_INTERP 인터프리터 경로(/lib/ld-linux.so)
0x04 PT_NOTE 보조 정보
0x06 PT_PHDR 프로그램 헤더 테이블 자체
0x6474e550 PT_GNU_EH_FRAME 예외 처리
0x6474e551 PT_GNU_STACK 스택 실행 가능 플래그
0x6474e552 PT_GNU_RELRO 읽기 전용 재배치
```

### 공통 섹션

| 섹션 이름| 설명|
|------|------|
| `.text` | 코드 조각|
| `.rodata` | 읽기 전용 데이터(문자열 상수)|
| `.data` | 전역 변수가 초기화되었습니다.|
| `.bss` | 전역 변수가 초기화되지 않았습니다.|
| `.plt` / `.got` | 동적 링크 점프 테이블|
| `.init_array` | 생성자 포인터 배열|
| `.fini_array` | 소멸자 포인터 배열|
| `.dynamic` | 동적링크 정보|
| `.symtab` / `.dynsym` |기호 테이블|
| `.strtab` / `.dynstr` | 스트링 테이블|

---

## 안티분석 기술 식별

### 일반적인 ELF 안티분석 기술

| 기술| 특징| 대결|
|------|------|---------|
| 손상된 프로그램 헤더| PHDR은 가비지 데이터(예: 0x0a)로 채워집니다.| 손상된 PHDR을 수동으로 복구하거나 무시합니다.|
| 섹션 헤더 없음| `e_shoff = 0`, `e_shnum = 0` | 프로그램 헤더 분석에만 의존하고 섹션에는 의존하지 않습니다.|
| 스트립| 없음 `.symtab`, 모든 함수 이름이 손실됩니다.| GoReSym(Go) / 서명 매칭 / FLIRT|
| 정적 링크| 없음 `.dynamic`, 거대한 크기| FLIRT/Lumina를 사용하여 라이브러리 기능 식별|
|위장 파일 형식| 접미사.sh/.txt/.jpg| `file` 명령/매직 바이트를 사용하여 결정합니다.|
| UPX 포장| `UPX!` 태그가 포함되어 있습니다.| `upx -d` 포격|
| 맞춤형 쉘| 진입점은 압축 해제 코드로 점프합니다.| OEP로 동적으로 실행한 후 덤프|
| 디버깅 방지| ptrace(TRACEME) | LD_PRELOAD 후크/패치|
| 안티 VM| 확인 /proc/cpuinfo| cpuinfo 또는 후크 읽기 수정|
| 코드 암호화| 런타임 시.text 해독| 복호화 후 중단점 덤프|

### 자체 추출/자체 수정 코드 식별

```text
특징:
1. 진입점 근처에 mmap(PROT_READ|PROT_WRITE|PROT_EXEC) 호출이 있습니다.
2. memcpy 또는 순환 복사가 이어집니다.
3. 그런 다음 mprotect를 사용하여 권한을 변경합니다.
4. 마지막으로 새로 매핑된 주소로 br/jmp

분석 전략:
1. mmap 호출 찾기 → 반환된 주소 기록
2. mprotect(PROT_EXEC) 후에 중단점을 설정합니다.
3. 압축이 풀린 메모리 영역을 덤프합니다.
4. 새로운 이진 분석
```

---

## ARM64(AArch64) 역방향 훑어보기

### 등록하다

| 등록하다| 목적|
|--------|------|
| x0-x7 | 매개변수/반환 값|
| x8 | 간접 결과(syscall 번호)|
| x9-x15 | 임시등록부|
| x16-x17 | IP0/IP1(PLT 점프)|
| x18 | 플랫폼 레지스터(Android: 섀도우 콜 스택)|
| x19-x28 | 수신자 저장|
| x29 (FP) | 프레임 포인터|
| x30 (LR) | 링크 레지스터(반환 주소)|
| SP | 스택 포인터|
| PC | 프로그램 카운터|

### 일반적인 명령 패턴

```text
기능 프롤로그:
  stp x29, x30, [sp, #-N]! # FP와 LR을 저장합니다.
  mov x29, sp # 프레임 포인터 설정

기능 종료:
  ldp x29, x30, [sp], #N # FP 및 LR 복원
  ret # 반환 (br x30)

시스템 호출:
  mov x8, #NR # 시스템콜 번호
  svc #0 # syscall을 트리거합니다.

조건부 분기:
  cmp x0, #0
b.eq 라벨 # 점프와 동일
  b.ne label # 점프와 같지 않음
  cbz x0, 라벨 # x0 == 0 점프
  cbnz x0, 라벨 # x0 != 0 점프

주소 로드 중:
  adrp x0, 페이지 # 로드 페이지 주소 상위 비트
  add x0, x0, #offset #하위 12비트 오프셋 추가
  ldr x0, [x1, #offset] # 메모리에서 로드
```

### Linux ARM64 시스템 호출 번호

| 번호| 이름| 설명|
|------|------|------|
| 56 | openat | 파일 열기|
| 63 | read | 읽다|
| 64 | write |쓰다|
| 57 | close | 닫기|
| 222 | mmap | 메모리 맵|
| 226 | mprotect | 메모리 권한 수정|
| 117 | ptrace | 프로세스 추적|
| 220 | clone | 프로세스/스레드 생성|
| 221 | execve | 프로그램 실행|
| 93 | exit | 종료|
| 94 | exit_group | 프로세스 그룹 종료|

---

## 공통 압축/패키징 알고리즘 식별

| 알고리즘| 특징 식별| 감압 방식|
|------|---------|---------|
| **LZSS** | 비트 스트림 + 리터럴/일치 태그| 사용자 정의 압축 해제기(예: 이 보고서)|
| **ZLIB/Deflate** | 마법: `78 01`/`78 9C`/`78 DA`| `zlib.decompress()` |
| **GZIP** | 마법: `1F 8B`| `gzip -d` / `gunzip` |
| **LZ4** | Magic: `04 22 4D 18` | `lz4 -d` |
| **LZMA/XZ** | 마법: `FD 37 7A 58 5A 00` (XZ)| `xz -d` / `lzma -d` |
| **Brotli** | 고정된 마법 없음, 상황에 따라 다름| `brotli -d` |
| **Zstandard** | 마법: `28 B5 2F FD`| `zstd -d` |
| **UPX** | 문자열 `UPX!`| `upx -d` |
|**맞춤형**| 진입점에는 감압 루프가 있습니다.| 알고리즘을 반대로 하고 압축 해제기를 작성합니다.|

### 사용자 지정 압축에 대한 단서 식별

```text
1. 진입점 근처에 루프 + 비트 연산(shift, AND, OR)이 있습니다.
2. "슬라이딩 윈도우" 카피백(출력 버퍼에서 다시 읽기)이 있습니다 → LZ 시리즈
3. 빈도표/허프만 트리 구성 → Deflate/Huffman
4. 고정된 크기의 블록 처리 → 블록 압축(LZ4/Snappy)이 있습니다.
5. 산술부호화 특성(간격 축소) 있음 → LZMA/ANS
```

---

## 리눅스 프로세스 주입 기술

### mmap + 코드 삽입

```text
과정:
1. mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)
2. 매핑 영역에 shellcode/payload를 씁니다.
3. mprotect(addr, size, PROT_READ|PROT_EXEC) # 실행 파일로 변경
4. 매핑된 주소로 점프하여 실행

특징:
- mmap 반환 값이 저장됩니다.
- memcpy 또는 루프 쓰기가 이어집니다.
- 그런 다음 mprotect를 사용하여 권한을 변경합니다.
- 이 주소의 마지막 br/blr
```

### ptrace 주입

```text
과정:
1. ptrace(PTRACE_ATTACH, target_pid)
2. waitpid(target_pid)
3. ptrace(PTRACE_GETREGS, target_pid, &regs)
4. 삽입된 코드를 가리키도록 regs.pc를 수정합니다.
5. ptrace(PTRACE_SETREGS, target_pid, &regs)
6. ptrace(PTRACE_CONT, target_pid)

특징:
- /proc/<pid>/mem을 열거나 ptrace를 사용하세요.
- 대상 프로세스 레지스터 읽기/수정
- 대상 프로세스 공간에 쉘코드 쓰기
```

### /proc/self/mem 자체 수정

```text
과정:
1. open("/proc/self/mem", O_RDWR)
2. lseek(fd, target_addr, SEEK_SET)
3. write(fd, new_code, size)

목적:
- W^X 보호 우회(mmap 페이지는 동시에 W+X일 수 없음)
- 자체 코드 세그먼트 수정(.text는 일반적으로 읽기 전용임)
- 런타임 패치 명령
```

---

## 대규모 전략 분석 ELF

5MB 이상의 대형 바이너리의 경우:

```text
1. 퀵스카우트(5분)
   - file/rabin2 -I → 아키텍처, 유형, 보호
   - 문자열 | grep -i "error\|fail\|http\|/proc\|/dev" → 키 문자열
   - rabin2 -i → 가져오기 기능(있는 경우)
   - rabin2 -E → 내보내기 기능

2. 구조 분석(10분)
   - readelf -l → 프로그램 헤더(LOAD 섹션 레이아웃)
   - 진입점 근처의 코드 → 압축해제/복호화 여부
-.init_array → 생성자 찾기(아마도 디버깅 방지 기능 포함)

3. 위치 키 로직
   - 문자열 상호 참조로 시작
   - 시스템콜로 시작 (mmap/ptrace/open)
   - 네트워크 기능 시작 (connect/send/recv)

4. 분열과 정복
   - 자동 추출인 경우 → 먼저 압축을 풀고 페이로드를 분석합니다.
   - 다중 모듈인 경우 → 기능 블록별로 분석
   - Binary-diff를 사용하여 다른 버전 비교
```

---

## 도구 명령 빠른 검토

```bash
# 기본정보
file binary
readelf -h binary          # ELF 머리
readelf -l binary          # 프로그램 헤더
readelf -S binary          # 섹션 헤더(있는 경우)
rabin2 -I binary           # 종합정보

# 문자열
strings -a binary | less
rabin2 -z binary           # 데이터 세그먼트 문자열
rabin2 -zz binary          # 전체 파일 문자열

# 분해
r2 -A binary               # radare2 분석
objdump -d binary          # GNU 분해
aarch64-linux-gnu-objdump -d binary  # ARM64 교차 분해

# 동적 분석
strace -f ./binary         # 시스템 호출 추적
ltrace -f ./binary         # 라이브러리 함수 추적
qemu-aarch64 -strace ./binary  # ARM64 에뮬레이트 실행

# 메모리 덤프
gdb -p <pid> -ex "dump memory out.bin 0xADDR 0xADDR+SIZE" -ex quit

# 고장난 수리 ELF
# e_phnum을 수동으로 수정하거나 손상된 PHDR을 패치하세요.
python -c "
import struct
with open('binary', 'r+b') as f:
    f.seek(0x38)  # e_phnum offset (64-bit)
    f.write(struct.pack('<H', 2))  # PHDR 수량을 수정하도록 수정됨
"
```
