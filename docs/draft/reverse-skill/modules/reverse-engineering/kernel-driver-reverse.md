# 커널 드라이버 리버스 엔지니어링

> Windows/Linux 커널 드라이버 리버스 엔지니어링, 루트킷 분석, C/C++ 바이너리 패턴 인식을 다룹니다.

---

## Windows 드라이버 리버스 엔지니어링

### 드라이버 유형

| 유형| 특징| 분석 초점|
|------|------|---------|
| WDM(Windows 드라이버 모델)| 이전 드라이버, IRP를 수동으로 관리|DriverEntry → 장치 생성 → 발송 루틴|
| KMDF(커널 모드 드라이버 프레임워크)| 최신 프레임워크, 이벤트 중심| EvtDriverDeviceAdd → 대기열 → I/O 콜백|
| WDF(윈도우 드라이버 파운데이션)| KMDF + UMDF를 종합적으로| WdfDriverCreate 호출을 살펴보세요.|
| Minifilter | 파일 시스템 필터 드라이버| FltRegisterFilter → Pre/Post 콜백|

### WDM 기반 분석 프로세스

```text
1. DriverEntry 찾기(진입점)
   - IDA 자동 식별 또는 IoCreateDevice / IoCreateSymbolicLink 검색

2. 장치 이름과 심볼릭 링크 찾기
   - IoCreateDevice → 장치 이름(예: \Device\MyDriver)
   - IoCreateSymbolicLink → SymLink(예: \DosDevices\MyDriver)

3. Find the Dispatch routine
   - DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl
   - DeviceIoControl을 통해 사용자 모드에서 호출되는 진입점입니다.

4. Analyze IOCTL processing
   - 스위치(IoControlCode)는 다양한 기능을 분배합니다.
   - IOCTL 인코딩: CTL_CODE(DeviceType, Function, Method, Access)
   - Method: METHOD_BUFFERED / METHOD_IN_DIRECT / METHOD_OUT_DIRECT / METHOD_NEITHER

5. 허점 찾기
   - 사용자가 제어 가능한 버퍼 미확인 길이 → 오버플로
   - METHOD_NEITHER는 I/O 관리자가 검증하지 않은 사용자 포인터를 전달하므로 드라이버가 `ProbeForRead`/`ProbeForWrite`, 예외 처리, 길이 검증을 해야 합니다. 검증 결함이 있을 때 임의 읽기·쓰기 원시 동작으로 이어질 수 있습니다.
   - IOCTL 권한이 확인되지 않음 → 권한이 없는 사용자가 호출 가능
```

### IOCTL 인코딩 분석

```python
# IOCTL 코드 구문 분석
def decode_ioctl(code):
    device_type = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3

    methods = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
    access_types = {0: "ANY", 1: "READ", 2: "WRITE", 3: "READ|WRITE"}

    return f"DevType=0x{device_type:X} Func=0x{function:X} Method={methods[method]} Access={access_types[access]}"

# 예
decode_ioctl(0x80002034)
# DevType=0x8000 Func=0x80D Method=BUFFERED Access=ANY
```

### IDA 플러그인

| 플러그인| 목적| 링크|
|------|------|------|
| **드라이버 버디 리로디드**| IOCTL, Dispatch 및 장치 이름을 자동으로 식별합니다.| https://github.com/VoidSec/DriverBuddyReloaded |
| **WinDbg + IDA** | 커널 디버깅 + 정적 분석 협력| 내장|
| **FLIRT/Lumina** | WDK 라이브러리 기능 식별| IDA 내장|

### 참고 기사

- [Windows 드라이버 RE 방법론(VoidSec)](https://voidsec.com/windows-drivers-reverse-engineering-methodology/) — 가장 완벽한 WDM 드라이버 리버스 엔지니어링 방법론
- [드라이버 후진 101](https://eversinc33.com/posts/driver-reversing.html) — WDM vs KMDF 비교
- [취약한 킬러 드라이버를 반전시키는 방법론](https://whiteknightlabs.com/2025/10/28/methodology-of-reversing-vulnerable-killer-drivers/) — 취약점 동인 분석

---

## Linux 커널 모듈 리버스 엔지니어링

### LKM(로더블 커널 모듈) 구조

```text
주요 기능:
- init_module / module_init → 모듈이 로드될 때 실행
- cleanup_module / module_exit → 모듈 제거 시 실행

주요 구조:
- struct file_operations → 캐릭터 디바이스의 open/read/write/ioctl
- struct net_device_ops → 네트워크 장치 작업
- struct block_device_operations → 블록 장치 작업
```

### 분석과정

```text
1. 커널 모듈인지 확인
   파일 module.ko → "ELF 64-bit... relocatable" (재배치 가능, 실행 불가)

2. init/exit 기능 찾기
   readelf -s module.ko | grep -E "init_module|cleanup_module"
   `.modinfo`에는 라이선스·의존성·별칭 같은 메타데이터가 있으므로 init/exit 함수는 심볼과 `module_init`/`module_exit`가 만든 참조에서 찾으세요.

3. file_operations 구조를 찾으세요.
   register_chrdev/cdev_add/misc_register 검색
   → fops 구조 찾기 → ioctl/read/write 핸들러 함수 찾기

4. ioctl 처리 분석
   Unlocked_ioctl / compat_ioctl 함수
   → 스위치(cmd) 배포

5. 루트킷 동작을 찾아보세요
   - sys_call_table 수정 → syscall 후크
   - /proc 파일 시스템 수정 → 프로세스/파일 숨기기
   - 넷필터 훅 등록 → 네트워크 연결 숨기기
   - VFS 레이어 수정 → 숨김 파일
```

### 루트킷 공통 기술

| 기술| 특징| 탐지 방법|
|------|------|---------|
| syscall 테이블 후크| `sys_call_table` 항목 수정| 인메모리 테이블과 온디스크 vmlinux 비교|
| VFS hook | `file_operations` 함수 포인터 수정| 각 포인터의 소유 모듈을 확인하고 알려진 커널·정상 모듈 텍스트와 비교하세요. 코어 커널 밖의 주소만으로는 후크라고 단정할 수 없습니다.|
| Netfilter hook | `nf_register_net_hook` | netfilter 후크 연결 목록 탐색|
| kprobe/ftrace 갈고리| kprobe 또는 ftrace 콜백 등록| ftrace 등록 목록 확인|
| eBPF rootkit | 악성 BPF 프로그램 로드| `bpftool prog list` |
| DKOM | 커널 객체(프로세스 연결 리스트)를 직접 수정합니다.|task_struct 연결 목록과 /proc 트래버스|

### 도구

| 도구| 목적|
|------|------|
| `crash` | 커널 덤프 분석|
| `volatility3` | 메모리 포렌식(Volatility 3 Linux ISF 심볼 사용)|
| `dmesg` / `journalctl` | 커널 로그|
| `lsmod` / `/proc/modules` | 로드된 모듈 목록|
| `modinfo` | 모듈 메타 정보|
| `strace` | 시스템 호출 추적(사용자 모드 관점)|

---

## C/C++ 역 패턴 인식

### C 언어의 일반적인 패턴

| 소스 코드 모드| 분해 특성|
|---------|-----------|
| `if-else` | `cmp` + `jcc` (조건부 점프)|
| `switch-case` | 점프 테이블(`jmp [rax*8 + table]`) 또는 연속 `cmp`|
| `for` 루프| `cmp` + `jl/jle` + 루프 본문 + `inc/add` + `jmp` 바운스|
| `while` 루프| 조건부 판단은 루프의 맨 위에 있습니다.|
| `do-while` | 조건부 판단은 루프의 맨 아래에 있습니다.|
| 함수 포인터 호출| `call rax` 또는 `call [reg+offset]`|
|`struct` 접근| `[reg+고정오프셋]`(예: `[rdi+0x10]`)|
| `malloc` + 사용| `call malloc` → 반환값은 레지스터에 저장됨 → 이 레지스터 + 오프셋을 사용한 후속 액세스|
| 문자열 비교| `call strcmp` 또는 `repe cmpsb`|

### C++ 특정 모드

| 소스 코드 모드| 분해 특성|
|---------|-----------|
| **가상 함수 호출**| 객체 포인터에서 vptr을 읽은 뒤 `call [reg+offset]`; 구체적인 레지스터는 ABI에 따라 다름|
| **생성자**| 메모리 할당 → vtable 포인터 쓰기 → 멤버 초기화|
| **소멸자**| 정리 회원 → 전화 가능 `operator delete`|
| **this 포인터**| Microsoft x64에서는 보통 RCX, System V AMD64에서는 보통 RDI; ABI와 thunk를 먼저 확인|
| **상속**| vtable에는 상위 클래스 가상 함수 + 하위 클래스 재정의가 포함되어 있습니다.|
| **다중 상속**| 개체 내에 여러 개의 vtable 포인터가 있습니다(오프셋이 다름).|
| **RTTI** | Itanium ABI와 MSVC는 서로 다른 vtable/vftable 전위 메타데이터를 사용함|
| **예외 처리**| `__cxa_throw` / `_CxxThrowException` |
| **STL 컨테이너**| `std::vector`가 세 포인터처럼 보이는 구현이 흔하지만 표준이 고정한 ABI는 아님|
| **std::string** | SSO 방식과 필드 배치는 표준 라이브러리·ABI·버전에 따라 다름|

### vtable 역방향 방법

```text
1. vtable 찾기
   - 연속된 함수 포인터 배열 검색(.rodata 또는.rdata 섹션에서)
   - `mov [rcx], offset vtable`는 생성자의 vtable 포인터에 기록됩니다.

2. 클래스 계층 구조 결정
   - Itanium C++ ABI에서는 address point 앞의 음수 인덱스에 offset-to-top과 RTTI가 있습니다.
   - MSVC에서는 vftable 바로 앞 포인터 슬롯이 Complete Object Locator를 가리키는 구성이 흔합니다.
   - 여러 vtable이 처음 몇 개의 항목을 공유 → 상속 관계

3. 가상 기능 표시
   - 첫 슬롯이 소멸자라고 가정하지 말고 호출 지점·RTTI·ABI의 destructor variant 규칙으로 확인합니다.
   - 오프셋에 의한 후속 주석: vtable[1] = func1, vtable[2] = func2...

4. IDA에서의 작업
   - vtable 주소에 구조체 생성(각 필드는 함수 포인터임)
   - `call [rax+offset]`에 주석을 추가하여 호출된 가상 함수를 나타냅니다.
```

### 구조 복구

```text
방법 1: 액세스 패턴에서 추론
  mov eax, [rdi+0x00]  → field_0: int/ptr (4/8 bytes)
  mov ecx, [rdi+0x08]  → field_8: int/ptr
  movss xmm0, [rdi+0x10] → field_10: float

방법 2: sizeof에서 추론
  malloc(0x30) 호출 → 구조체 크기 0x30(48바이트)

방법 3: 생성자에서 추론
  생성자는 모든 필드를 초기화합니다. → 필드 유형 및 오프셋이 한 눈에 명확합니다.

방법 4: IDA의 "구조체 만들기" 기능을 사용하세요.
  액세스 모드 선택 → 편집 → 구조체 → 선택 항목에서 구조체 생성
```

---

## 일반적인 컴파일러 특성

| 컴파일러| 특징 식별|
|--------|---------|
| MSVC | `_security_cookie` 확인, `__fastcall` 호출 규칙, 리치 헤더|
| GCC | `__stack_chk_fail`、`-fstack-protector`、`.note.GNU-stack` |
| Clang/LLVM | GCC와 비슷하지만 최적화 모드가 다릅니다. `__asan_*`(새니타이저가 켜져 있는 경우)|
| MinGW | GCC 기능 + Windows API 호출|
| AOSP Clang | Android 전용 `__android_log_print`, PGO 태그|

### 최적화 수준 식별

| 최적화 수준| 특징|
|---------|------|
| -O0 | 많은 중복 mov, 스택의 모든 변수, 인라인되지 않은 함수|
| -O1 | 기본 최적화, 레지스터의 일부 변수|
| -O2 | 루프 언롤링, 함수 인라인, 테일 콜 최적화|
| -O3 | 적극적 인라인·루프·벡터화 최적화가 나타날 수 있음|
| -Os | 코드 크기 최적화; 크기를 늘리는 변환은 억제될 수 있음|
| PGO | 핫 경로 최적화, 콜드 코드를 `.text.cold`로 분리|
| LTO | 크로스 모듈 인라이닝, 전역 데드 코드 제거|

---

## 커널 디버깅 환경

### Windows

```text
디버거: WinDbg 미리보기
연결 방법: 네트워크 디버깅(권장) 또는 직렬 포트

디버깅된 컴퓨터 설정:
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.x.x port:50000

디버깅 기계 연결:
WinDbg → File → Attach to Kernel → Net → Port:50000 Key:xxx

일반적으로 사용되는 명령:
!analyze -v # 자동으로 충돌 분석
lm # 로드된 모듈 목록
!drvobj \Driver\xxx # 드라이버 개체 보기
dt nt!_DRIVER_OBJECT # 표시 구조
bp 모듈!함수 # 하위 중단점
```

### Linux

```text
디버거: GDB + QEMU 또는 kgdb

QEMU 커널 디버깅:
qemu-system-x86_64 -kernel bzImage -s -S ...
gdb vmlinux -ex "target remote :1234"

일반적으로 사용되는 명령:
info threads # 커널 스레드
lx-symbols # 커널 기호 로드 (scripts/gdb/ 필요)
p init_task # 초기화 프로세스 보기
lx-dmesg # 커널 로그
```

---

## 참고자료

| 자원| 설명| 링크|
|------|------|------|
| VoidSec 기반 리버스 엔지니어링 방법론| Windows WDM 드라이버 전체 분석 프로세스| https://voidsec.com/windows-drivers-reverse-engineering-methodology/ |
| 탄력적 루트킷 시리즈| Linux 루트킷 분류 + 탐지| https://security-labs.elastic.co/security-labs/linux-rootkits-1-hooked-on-linux |
| 드라이버 버디 리로디드| IDA 운전자 분석 플러그인| https://github.com/VoidSec/DriverBuddyReloaded |
| LOLDrivers | 알려진 취약점이 있는 드라이버 목록| https://www.loldrivers.io/ |
| Windows 드라이버 샘플| Microsoft 공식 드라이버 예| https://github.com/microsoft/Windows-driver-samples |
| Linux 커널 모듈 프로그래밍| 커널 모듈 개발 튜토리얼| https://sysprog21.github.io/lkmpg/ |
| Trail of Bits - C++ 탈가상화| vtable 역방향 방법| https://blog.trailofbits.com/2017/02/13/devirtualizing-c-with-binary-ninja/ |
