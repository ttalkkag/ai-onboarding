---
name: binary-diff
description: |
  버전 간 기호 마이그레이션 및 바이너리 비교. 이전 버전의 기호/역방향 결과가 있고 새 버전으로 빠르게 마이그레이션해야 할 때 사용합니다.
  적용 가능한 시나리오: 새 커널·드라이버의 공개 PDB를 구할 수 없거나, 프로그램 업데이트 후 함수 이름과 오프셋을 이전 버전 결과에서 마이그레이션해야 할 때 사용합니다.
  핵심 방법: LLM를 사용하여 구조화된 차이 후보를 만들고, 프로그래밍 방식의 검증을 거쳐 적용합니다.
  트리거 키워드: 기호 마이그레이션, 바인딩, 버전 간, PDB 누락, 함수 오프셋 마이그레이션, 기호 마이그레이션, 바이너리 diff, 버전 비교.
---

# 버전 간 기호 마이그레이션(Binary Diff)

## 적용 범위

작업이 다음 시나리오에 해당할 때 이 기술을 사용하십시오.

1. **커널/드라이버 PDB 누락** — 이전 버전 ntoskrnl.exe의 기호는 있지만 대상 빌드의 공개 PDB를 구할 수 없는 경우, 이전 버전 기호를 앵커로 내보내지 않은 함수의 새 후보 주소를 찾습니다.
2. **프로그램 업데이트 후 기호 마이그레이션** — 이전에 프로그램을 리버스 엔지니어링한 적이 있으며 프로그램이 업데이트되었습니다. 다시 리버스 엔지니어링하고 싶지 않아서 이전 버전의 결과를 일괄 마이그레이션해야 합니다.
3. **보호 메커니즘 업데이트** — 이전 버전은 완전히 반대 결과를 가지며 새 버전은 동일한 기능의 새로운 오프셋을 빠르게 찾아야 합니다.
4. **"이전 버전 기호 + 서명되지 않은 새 버전"의 이진 비교 시나리오**

### 다른 기술과의 업무 분담

| 장면| 무엇을 사용해야합니까?|
|------|--------|
| 바이너리를 처음부터 되돌리기| `ida-reverse/` 또는 `radare2/`|
| 이전 버전의 결과가 있습니다. 새 버전으로 마이그레이션하세요.| **이 스킬**|
| 완전히 다른 두 가지 이진 비교| BinDiff/Diaphora(기존 도구)|

### 방법 선택

| 방법| 강점| 한계|
|------|------|------|
| 수동 비교 | 분석가가 근거를 직접 확인 | 함수 수가 많으면 오래 걸림 |
| BinDiff/Diaphora | 구조가 유사한 대량 함수의 후보 생성 | 최적화·인라이닝 변화가 크면 오탐 가능 |
| LLM 보조 비교 | 의사코드와 이름 단서의 의미 비교 | 비용·지연·정확도가 모델과 입력에 따라 달라지며 검증이 필수 |

## 핵심 원칙

```text
이전 버전의 함수(서명됨) 동일한 함수의 새 버전(부호 없음)
    ↓                              ↓
디스어셈블리 + 의사코드 내보내기 디스어셈블리 + 의사코드 내보내기
    ↓                              ↓
    └──────── LLM 구조적 비교 ────────┘
                    ↓
         출력 YAML (기호 맵)
                    ↓
         파싱 → 결정론적 검증 → dry-run → 승인된 행만 IDB에 적용
```

핵심 사항:
- 프롬프트는 프로그래밍 방식으로 채워지는 고정 템플릿입니다.
- 입력 및 출력 형식 결정, 프로그래밍 분석
- LLM는 "두 개의 코드를 읽고 해당 관계를 찾는" 단계만 담당합니다.
- 시간과 토큰 비용은 함수 크기, 모델, 재시도 횟수에 따라 기록합니다.

## 프롬프트 템플릿

### 표준 비교 프롬프트

````text
I have disassembly outputs and procedure code of the same function.

This is the function for reference:

**Disassembly for Reference**
```c
{disasm_for_reference}
```

**Procedure code for Reference**
```c
{procedure_for_reference}
```

This is the function you need to reverse-engineering:

**Disassembly to reverse-engineering**
```c
{disasm_code}
```

**Procedure code to reverse-engineering**
```c
{procedure}
```

What you need to do is to collect all references to "{symbol_name_list}" in the function you need to reverse-engineering and output those references as YAML.

Example:
```yaml
found_vcall: # 가상 함수에 대한 간접 호출이나 가상 함수 포인터 가져오기를 위한 것입니다.
  - insn_va: '0x180777700' # 항상 변위 오프셋이 있는 명령어입니다.
    insn_disasm: call [rax+68h] # 항상 변위 오프셋이 있는 명령어여야 합니다.
    vfunc_offset: '0x68'
    func_name: ILoopMode_OnLoopActivate
  - insn_va: '0x180777778' # 항상 변위 오프셋이 있는 명령이어야 합니다.
    insn_disasm: mov rax, [rax+80h] # 항상 변위 오프셋이 있는 명령어입니다.
    vfunc_offset: '0x80'
    func_name: INetworkMessages_GetNetworkGroupCount

found_call: # 비가상 정규 함수를 직접 호출하기 위한 것입니다.
  - insn_va: '0x180888800'
    insn_disasm: call sub_180999900
    target_va: '0x180999900'
    func_name: CLoopMode_RegisterEventMapInternal
  - insn_va: '0x180888880'
    insn_disasm: call sub_180555500
    target_va: '0x180555500'
    func_name: CLoopMode_SetSystemState

found_funcptr: # 가상이 아닌 일반 함수 포인터에 대한 것입니다.
  - insn_va: '0x180666600' # 반드시 load/reference 함수 포인터 대상 주소여야 합니다.
    insn_disasm: lea rdx, sub_15BC910 # 반드시 load/reference 함수 포인터 대상 주소이어야 합니다
    target_va: '0x15BC910'
    funcptr_name: CLoopMode_OnClientPollNetworking

found_gv: # 전역변수 참조용입니다.
  - insn_va: '0x180444400'
    insn_disasm: mov rcx, cs:qword_180666600 # 전역 변수는 load/reference이어야 합니다.
    target_va: '0x180666600'
    gv_name: g_pNetworkMessages
  - insn_va: '0x180333300'
    insn_disasm: lea rax, unk_180222200 # 전역 변수는 load/reference이어야 합니다.
    target_va: '0x180222200'
    gv_name: s_EventManager

found_struct_offset: # 이것은 구조체 오프셋을 참조하기 위한 것입니다. 가상 함수 포인터가 여기에 있어서는 안 된다는 점에 유의하세요! 가상 함수 포인터는 항상found_vcall에 있어야 합니다!
  - insn_va: '0x1801BA12A' # 항상 변위 오프셋이 있는 명령이어야 합니다.
    insn_disasm: mov rcx, [r14+58h] # 항상 변위 오프셋이 있는 명령어입니다.
    offset: '0x58'
    size: 8
    struct_name: CResourceService
    member_name: m_pEntitySystem
```

If nothing found, output an empty YAML. DO NOT output anything other than the desired YAML. DO NOT collect unrelated symbols.
````

### 변수 설명

| 변수| 소스| 설명|
|------|------|------|
| `{disasm_for_reference}` | 이전 버전 IDA 내보내기| 서명된 분해|
| `{procedure_for_reference}` | 이전 버전 IDA 내보내기| 서명된 의사코드|
| `{disasm_code}` | 새 버전 IDA 내보내기| 서명되지 않은 분해|
| `{procedure}` | 새 버전 IDA 내보내기| 서명되지 않은 의사코드|
| `{symbol_name_list}` | 이전 버전에서 추출| 새 버전에 배치해야 하는 기호 목록|

## 작업흐름

### 완전한 과정

```text
1단계: 데이터 준비
  - IDA에 로드된 레거시 바이너리(PDB/기호 포함)
  - IDA에 로드된 새 버전 바이너리(부호 없음)
  - 두 버전에서 동일한 앵커 함수(내보낸 함수, 문자열 참조 등)를 찾습니다.

2단계: 일괄 내보내기
- 이전 버전에서 내보내기: 앵커 기능 분해 + 의사코드(기호 이름 포함)
  - 새 버전에서 내보내기: 동일한 앵커 함수의 디스어셈블리 + 의사 코드(기호 이름 없음)

3단계: LLM 비교
  - 프롬프트 템플릿으로 데이터 입력
  - 승인된 LLM API와 현재 검토된 모델을 사용합니다.
  - YAML 구문 분석을 통해 반환됨

4단계: 후보 검증 및 승인 후 적용
  - YAML을 후보 계획으로 파싱하고, 명령 피연산자·섹션 범위·함수 시작점·이름 충돌을 결정론적으로 검증합니다.
  - dry-run diff와 거절 사유를 검토한 뒤 승인된 행만 IDAPython 등으로 적용합니다.

5단계: 반복
  - 마이그레이션된 기능의 첫 번째 라운드가 새로운 앵커 포인트가 됩니다.
  - 이 기능을 입력하고 내부 호출를 계속 비교하십시오.
  - 모든 목적 함수가 다루어질 때까지 반복합니다.
```

### 앵커 선택 전략

| 앵커 유형| 신뢰성| 설명|
|---------|--------|------|
| 내보내기 기능| 최고|이름은 동일하지만 주소는 변경될 수 있습니다.|
| 문자열 참조| 높다| 문자열의 내용은 변경되지 않지만 참조 위치는 변경될 수 있습니다.|
| 상수/매직 넘버| 중간| 고유값은 유지될 수 있지만 충돌과 컴파일러 변환을 확인해야 합니다.|
| 코드 패턴| 중간| 기능 구조는 비슷해도 최적화와 주소가 크게 달라질 수 있습니다.|

### 일괄 처리 제안

- 한 번에 하나의 함수를 비교합니다(컨텍스트 폭발을 방지하기 위해).
- 모델 선택은 현재 제공자의 컨텍스트 한도, 데이터 처리 조건, 평가 결과를 기준으로 합니다.
- 큰 함수는 호출 단위와 근거가 보존되도록 나눈 뒤 결과를 합칩니다.
- 동시성은 제공자 제한과 재시도 정책을 확인한 뒤 점진적으로 높입니다.
- 반복 호출을 방지하기 위한 결과 캐싱

## 출력 형식

### YAML 5가지 기호 유형 출력

| 유형| 의미| 주요 분야|
|------|------|---------|
| `found_vcall` |가상 함수 호출(간접 호출)| `vfunc_offset`, `func_name` |
| `found_call` | 직접 함수 호출| `insn_va`, `target_va`, `func_name` |
| `found_funcptr` | 함수 포인터 참조| `insn_va`, `target_va`, `funcptr_name` |
| `found_gv` | 전역 변수 참조| `insn_va`, `target_va`, `gv_name` |
| `found_struct_offset` | 구조 오프셋 참조| `offset`, `struct_name`, `member_name` |

### 구문 분석된 애플리케이션 작업

```text
found_call → idapro_rename(addr=call_target, name=func_name)
found_vcall → idapro_set_comments(addr=insn_va, comment="vcall: {func_name} @ +{offset}")
found_funcptr → idapro_rename(addr=funcptr_target, name=funcptr_name)
found_gv → idapro_rename(addr=gv_addr, name=gv_name)
found_struct_offset → idapro_set_comments(addr=insn_va, comment="{struct_name}.{member_name}")
```

`insn_va`는 참조 명령의 주소이고 `target_va`는 이름을 붙일 함수·포인터·전역의 주소입니다. 적용 전에 IDA가 디코딩한 피연산자와 `target_va`가 일치하는지 확인하며, `insn_va` 자체를 대상 이름으로 바꾸지 마세요.

## 일반적인 시나리오 예

### 시나리오 1: ntoskrnl.exe PDB 누락

```text
이미 있음: ntoskrnl.exe 10.0.26100.2000 + 전체 PDB
대상: ntoskrnl.exe 10.0.26100.2605(공개 PDB 미확보)
요구 사항: PspSetCreateProcessNotifyRoutine의 새 주소를 찾습니다.

단계:
1. 두 버전 모두 IDA에 로드됩니다.
2. 내보낸 함수 PsSetCreateProcessNotifyRoutine을 찾습니다(두 버전 모두에 있음).
3. 이전 버전에서는 PspSetCreateProcessNotifyRoutine(서명됨)을 호출했습니다.
4. 새 버전에서는 sub_140822108(서명되지 않음)을 호출합니다.
5. LLM 한눈에 보기: sub_140822108 = PspSetCreateProcessNotifyRoutine
6. 일괄 적용
```

### 시나리오 2: 업데이트 적용 후 마이그레이션

```text
이미 사용 가능: target.exe v1.0에 대한 전체 리버스 엔지니어링 결과(200개 이상의 함수 이름 지정)
대상: target.exe v1.1(모든 기호 손실)
요구 사항: 함수 이름 200개 일괄 마이그레이션

단계:
1. 이전 버전에서 명명된 모든 함수의 디스어셈블리 + 의사코드 내보내기
2. 새 버전에서 함수/문자열을 내보내 해당 앵커 포인트를 찾습니다.
3. 일괄호출 LLM 비교
4. YAML 후보를 검증하고 dry-run을 검토한 뒤 승인된 이름만 적용
5. 반복하고 심화하기
```

## LLM 선택 기준

- 저장소에 특정 모델명을 영구 기본값으로 고정하지 말고, 실행 시점의 공식 모델 문서와 내부 평가 결과를 확인하세요.
- 동일한 검증 세트로 후보 누락률과 잘못된 주소 제안률을 측정하세요.
- 바이너리·의사코드가 외부로 전송될 수 있으므로 조직의 데이터 처리·보존·지역 정책을 먼저 확인하세요.

## 주의할 점

- **전체 바이너리를 LLM에 던지지 마세요** — 한 번에 하나의 함수만 비교하세요
- **외부 전송 승인** — 독점 코드, 고객 데이터, 키·토큰·개인정보가 포함된 입력은 승인 없이 외부 API로 보내지 말고 필요한 부분만 최소화·마스킹하세요.
- **앵커 포인트는 신뢰할 수 있어야 합니다** — 앵커 포인트 자체가 옳거나 그르면 모든 후속 단계가 헛될 것입니다.
- **결과는 수동 검사가 필요함** — LLM 100% 정확하지는 않으며 주요 기호를 확인해야 함
- **중간 결과 캐시** — 반복 호출로 인한 토큰 낭비 방지
- **컨텍스트 제한 참고** — 매우 큰 기능(>1000라인의 디스어셈블리)을 분할하거나 대규모 컨텍스트 모델을 사용해야 함

---

## 주문형 부트스트랩

### 도구 종속성

| 도구| 목적| 자동으로 설치 가능|
|------|------|-----------|
| IDA Pro | 디스어셈블리/의사코드 내보내기| ✗(상용 소프트웨어)|
| Python | 스크립트 실행, API 호출| ✗(별도 설치·버전 확인) |
| PyYAML | 구문 분석 LLM 반환 YAML| ✗(승인된 환경에 별도 설치) |
| LLM API | 비교 수행| API 키 필요|

### 설명

이 기술의 핵심은 무거운 도구 설치에 의존하지 않고 주로 다음 사항에 의존합니다.
- IDA Pro가 이미 존재함(`ida-reverse/` 스킬로 관리됨)
- Python + requests/httpx(조정 API)
- LLM API 끝점

---

## 라우팅 컨텍스트

**상류 입구**: `../../SKILL.md`(마스터 제어), `../../routing.md`
**트리거 조건**: 이전 버전 기호/역결과가 있으며 새 버전으로 마이그레이션해야 합니다.
**다운스트림 내보내기**:
- 먼저 바이너리를 열어야 합니다 → `ida-reverse/`
- 버전 차이를 빠르게 재확인해야 함 → `radare2/`

**동일 레벨 연관 모듈**: `ida-reverse/` (데이터 내보내기 및 기호 적용 모두 통과 IDA)
