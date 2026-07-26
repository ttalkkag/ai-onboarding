---
name: ida-reverse
description: |
  IDA 프로 역분석 보조 스킬. 사용자가 리버스 엔지니어링, 디컴파일, 바이너리/PE/ELF/APK/DLL/SO 분석, 크래킹, 비밀번호 찾기, 취약성 분석, 바이러스 분석, 펌웨어 분석 또는 exe/dll/so/elf/macho/sys과 같은 파일 분석이 필요하다고 언급할 때 이 기술을 사용하십시오.

  사용자가 "IDA" 또는 "리버스 엔지니어링"을 명시적으로 언급하는지 여부에 관계없이 바이너리 파일을 분석하려는 경우 이 기술을 사용하십시오. 여기에는 "이 exe 보기", "이 dll 분석", "해독 도움말", "비밀번호 찾기", "이 소프트웨어 등록 방법" 등과 같은 요청이 포함됩니다.

  현재 MCP 클라이언트가 실제로 공개한 도구와 상류 ida-pro-mcp 문서를 확인한 뒤 사용하십시오.
---

# IDA 프로 역분석 기술

> **상태 경고(2026-07-18):** 이 파일의 `idapro_*` 도구 목록과 Windows PowerShell 운영 절차는 레거시 스냅샷입니다. 현재 큐레이션에는 `scripts/start.ps1`·`scripts/open.ps1`가 없고, 상류 프로젝트는 GUI MCP 플러그인 대신 `idalib-mcp`를 권장합니다. 현재 상류 `main`(`1be78d0`, 2026-07-13)의 세션 API는 `idb_open()`·`idb_list()`·`idb_save()`이며 `idb_close()`는 없습니다. 데이터베이스 분석 도구 호출은 `idb_open()`이 반환한 세션 ID를 `database`에 명시해야 합니다. 실제 서버가 공개한 스키마를 확인하기 전에는 아래 레거시 명령을 실행 가능한 계약으로 취급하지 마세요.

## 현재 상류의 최소 세션 계약

```text
idb_open("/absolute/path/to/target", preferred_session_id="target")
# 반환된 실제 세션 ID를 기록한다(기존 worker/GUI를 채택하면 선호 ID와 다를 수 있음).
decompile("main", database="<returned-session-id>")
idb_save("<returned-session-id>")  # 저장이 필요할 때만
```

현재 모델에는 암묵적 “현재 데이터베이스”가 없습니다. `database`는 파일명이나 경로가 아니라
반환된 세션 ID만 받습니다. headless worker는 supervisor보다 오래 살아남고 기본 유휴 TTL 뒤
자체 종료하므로, 닫기 도구가 있다고 가정하지 마세요. 설치·전송 방식과 도구 스키마는 실행
시점의 [상류 README](https://github.com/mrexodia/ida-pro-mcp)를 우선합니다.

## 레거시 스냅샷: 알려진 문제 및 고찰(실행 금지)

### 밟혀진 구덩이들

1. **`idalib_open` 코드 AI 클라이언트 MCP**의 일부를 통해 직접 호출할 수 없습니다.
   - 코드 AI 클라이언트 MCP 클라이언트의 일부에는 `idalib_open`의 출력 스키마 확인에 버그가 있습니다.
   - 오류:`Structured content does not match the tool's output schema`
   - **해결책**: `scripts/open.ps1` 스크립트를 사용하여 HTTP API 직접 조정을 통과하고 MCP 확인 레이어를 우회합니다.
   - 파일이 열리면 데이터베이스가 공유 컨텍스트에 바인딩되어 다른 모든 `idapro_*` 도구에서 직접 사용할 수 있습니다.

2. **`C:\Windows\System32\` 파일을 열 수 있는 권한이 없습니다**
   - idalib는 System32 디렉터리의 파일을 직접 읽을 수 없습니다.
   - **해결책**: `open.ps1`가 자동으로 감지하여 임시 디렉터리에 복사한 다음 엽니다.

3. **서버 명령 차단 대화 시작**
   - `idalib-mcp` 시작 후에도 INFO 로그가 콘솔에 계속 출력됩니다.
   - **해결책**: `scripts/start.ps1`(백그라운드에서 자동으로 시작하려면 `-WindowStyle Hidden`)을 사용하세요.
   - 스크립트는 서비스가 준비될 때까지 기다렸다가 대화를 차단하지 않고 자동으로 종료됩니다.

4. **MCP 서버 이름에는 하이픈을 사용할 수 없습니다**
   - 이전에는 서버 이름으로 `ida-pro-mcp`을 사용하여 도구 등록 문제가 발생할 수 있었습니다.
   - **현재 구성**: 서버 이름 `idapro`, 도구 접두어 `idapro_*`

5. **원격 HTTP 대 로컬 스튜디오**
   - `type:"local"`(stdio) 모드: `idalib_open`에도 스키마 확인 문제가 있습니다.
   - `type:"remote"`(HTTP) 모드: 스크립트를 사용하여 먼저 파일을 직접 연 다음 MCP 도구를 사용할 수 있습니다.
   - **현재 솔루션**: 원격 HTTP 모드

6. **PR #389 일부 스키마 문제 수정**
   - 작성자 mrexodia는 문제 #388 이후 PR #389를 통해 수정 사항을 병합했습니다.
   - HTTP 모드에서 구조화된 콘텐츠 스키마를 수정했지만 일부 코드의 AI 클라이언트 측 유효성 검사에는 여전히 문제가 있습니다.
   - 최신 `main` 브랜치 버전 설치됨

7. **idalib 시간 초과로 인해 고아 작업자 프로세스 잠금 파일이 남음**
   - 첫 번째 `open.ps1` 시간 초과 이후 idalib의 Python 작업자 하위 프로세스는 고아 프로세스가 되어 `.id0`/`.id1`/`.nam`을 물어뜯습니다.
   - 후속 도구 또는 IDA를 GUI로 수동으로 드래그하면 "권한 부족"이 보고됩니다.
   - **해결책**: `start.ps1` 프로세스 트리를 종료하고 더 이상 고아를 남기지 않으려면 대신 `taskkill /F /T`를 사용하세요.
   - **맨 아래로 돌아가기**: `open.ps1` 자동 다운그레이드를 추가하여 이전 라이브러리가 잠겨 있음을 감지하고 자동으로 Temp에 복사하고 GUID 접두사를 추가합니다.

8. **자동 분석으로 열기가 멈춘 것 같습니다**
   - `idalib_open(run_auto_analysis=true)` 오랜 시간 동안 패킷이 반환되지 않을 수 있지만 실제로는 백엔드에서 지속적으로 오픈 및 분석을 진행하고 있습니다.
   - 이전에는 사용자 측에서 "PowerShell에 출력이 없습니다."라는 메시지가 표시되어 스크립트가 멈춘 것으로 오해하기 쉬웠습니다.
   - **현재 해결책**: `open.ps1` `-TimeoutSeconds`을 추가하고 백그라운드 요청 + 포그라운드 폴링 + 예약된 진행 출력으로 변경
   - 세션이 준비되었는지 확인하기 위해 폴링하면 준비 시 `OK:파일명:session_id`가 반환되고, 시간이 초과되면 `ERR:open_timeout_xxs`가 반환됩니다.

### 작업 흐름 원칙

|단계| 무엇을 해야할지| 무엇을 사용해야합니까?|
|------|--------|--------|
| 1 | HTTP 서버가 실행 중인지 확인하세요.| `scripts/start.ps1`(매개변수 없음)|
| 2 | 대상 바이너리 파일을 엽니다.| `scripts/open.ps1 -Path "xxx.exe"` |
| 3 | 72개의 MCP 도구를 모두 사용하세요.| `idapro_*` 도구를 직접 호출하세요.|
| 4 | 분석 완료| 자동으로 사용 가능한 도구|

## 스크립트 리소스

### start.ps1 — MCP HTTP 서버 시작

경로:`scripts/start.ps1`

- `taskkill /F /T`를 사용하여 이전 프로세스 트리를 종료합니다(작업자 하위 프로세스를 함께 정리) → 백그라운드에서 시작 `idalib-mcp` → 준비 대기(최대 15초)
- 성공 출력 `OK:72`, 실패 출력 `ERR:timeout`
- 서버는 백그라운드에서 실행되며 대화를 차단하지 않습니다.

**호출 방법**:
```
powershell -File "<skill-root>\ida-reverse\scripts\start.ps1"
```

### open.ps1 — 바이너리 파일 열기

경로:`scripts/open.ps1`

- `idalib_open`에서 HTTP API까지 직접 조정하고 MCP 스키마 확인을 우회합니다.
- System32 경로를 자동으로 감지하고 임시 디렉터리에 복사
- 동일한 이름을 가진 오래된 데이터베이스 파일을 자동으로 정리합니다(`.id0`/`.id1`/`.nam`/`.til`/`.i64`)
- 잠겨 있는 경우 이전 라이브러리를 자동으로 다운그레이드합니다. Temp에 복사하고 GUID 접두사를 추가한 후 오류 보고 없이 엽니다.
- 긴 동기화 대기로 인해 스크립트가 응답하지 않게 되는 것을 방지하려면 실행을 위해 열기 요청을 백그라운드에 배치하세요.
- `-TimeoutSeconds`를 지원하고 시간 초과 후 `ERR:open_timeout_xxs`를 반환하며 무기한으로 멈추지 않습니다.
- 아직 분석 중인지 쉽게 판단할 수 있도록 10초마다 `INFO:opening:경과시간/타임아웃초`를 출력합니다.
- `OK:파일명:session_id` 출력에 성공하고, 다운그레이드 시 `(temp copy)` 표시를 추가합니다.
- 실패 시 임시 복사를 자동으로 재시도합니다.

**호출 방법**:
```
powershell -File "<skill-root>\ida-reverse\scripts\open.ps1" -Path "C:\path\to\file.exe"
```

**선택적 매개변수**:
```
#SessionId 지정
powershell -File "scripts\open.ps1" -Path "file.exe" -SessionId "my_session"

# 자동 분석 건너뛰기(대용량 파일에 권장)
powershell -File "scripts\open.ps1" -Path "large.exe" -NoAutoAnalysis

#자동 분석으로 오랜 시간 동안 반품이 되지 않도록 타임아웃을 설정하세요.
powershell -File "scripts\open.ps1" -Path "file.exe" -TimeoutSeconds 600
```

**출력 규칙**:
```
# 분석중 (10초마다 출력)
INFO:opening:11/600s

# 성공적으로 열렸습니다
OK:sample.exe:abcd1234

# 성공적으로 열렸지만 파일 잠금으로 인해 임시 복사로 다운그레이드되었습니다.
OK:1234abcd-sample.exe:abcd1234 (temp copy)

# 시간 초과 제한에 도달했습니다.
ERR:open_timeout_600s
```

**실제 측정 지침**:
- `Snipaste.exe` 자동 분석의 경우 실제 측정이 성공적으로 반환되기까지 약 `324s` 정도 소요되는데, 이는 "스크립트 교착 상태"가 아닌 "오랜 시간 동안 분석하는 중"에 속합니다.
- 따라서 GUI 프로그램이나 더 복잡한 샘플을 접할 때는 먼저 명시적으로 `-TimeoutSeconds 600`를 설정하는 것이 좋습니다.

## 핵심 도구 목록

### 프로필 분석(1단계)
- `idapro_survey_binary(detail_level="minimal")` — 빠른 개요: 함수 수, 문자열, 세그먼트, 진입점, 가져오기 카테고리(암호화/네트워크/파일 IO)
- `idapro_list_funcs(queries)` — 목록 기능(페이지 매김, 이름으로 필터링)
- `idapro_list_globals(queries)` — 전역 변수 나열
- `idapro_entity_query(kind, filter)` — 통합 쿼리: functions/globals/imports/strings/names

### 디컴파일 및 디스어셈블
- `idapro_decompile(addr)` — 의사코드로 디컴파일
- `idapro_disasm(addr, max_instructions=N)` — 분해
- `idapro_analyze_function(addr, include_asm=false)` — 종합 분석(의사 코드 + 문자열 + 상수 + 호출자 + 호출 수신자 + 블록)
- `idapro_func_profile(queries)` — 기능 요약 표시기

### 상호 참조 및 데이터 흐름
- `idapro_xrefs_to(addrs)` — 대상 주소를 참조한 사람이 누구인지 확인
- `idapro_xref_query(addr, direction)` — 고급 외부 참조 쿼리(방향/유형 필터링)
- `idapro_callees(addrs)` — 하위 기능 목록
- `idapro_callgraph(roots, max_depth)` — 호출 그래프
- `idapro_trace_data_flow(addr, direction, max_depth)` — 데이터 흐름 추적(forward/backward)

### 검색
- `idapro_find_regex(pattern, limit)` — 일반 검색 문자열
- `idapro_search_text(pattern)` — 디스어셈블리 목록에서 텍스트 검색
- `idapro_find_bytes(patterns, limit)` — 바이트 패턴 검색(?? 와일드카드 지원)
- `idapro_find(type, targets)` — 고급 검색(즉시/문자열/참조)

### 메모리 및 데이터
- `idapro_get_bytes(addrs)` — 원시 바이트 읽기
- `idapro_get_string(addrs)` — 문자열 읽기
- `idapro_get_int(queries)` — 정수 값 읽기
- `idapro_get_global_value(queries)` — 전역 변수 값 읽기
- `idapro_read_struct(queries)` — 구조 필드 값 읽기
- `idapro_search_structs(filter)` — 검색 구조

### 작업 수정
- `idapro_set_comments(items)` — 주석 추가(디스어셈블리 + 디컴파일 양방향 동기화)
- `idapro_append_comments(items)` — 댓글 추가
- `idapro_rename(batch)` — 일괄 이름 바꾸기(함수/전역/로컬/스택 변수)
- `idapro_patch_asm(items)` — 패치 조립 지침
- `idapro_patch(patches)` — 패치 바이트
- `idapro_define_func(items)` — 함수 정의
- `idapro_undefine(items)` — 정의 취소
- `idapro_define_code(items)` — 바이트를 코드로 변환

### 유형 시스템
- `idapro_declare_type(decls)` — C 구조체/열거/공용체 선언
- `idapro_set_type(edits)` — 함수/전역/로컬에 유형 적용
- `idapro_infer_types(addrs)` — 추론된 유형
- `idapro_type_query(queries)` — 선언된 유형 쿼리
- `idapro_type_inspect(queries)` — 유형 세부정보 보기

### 스택 프레임
- `idapro_stack_frame(addrs)` — 스택 프레임 변수 보기
- `idapro_declare_stack(items)` — 스택 변수 선언
- `idapro_delete_stack(items)` — 스택 변수 삭제

### 서명
- `idapro_make_signature(addrs)` — 주소에 대한 고유한 바이트 서명을 생성합니다.
- `idapro_make_signature_for_function(addrs)` — 함수에 대한 서명 생성
- `idapro_find_xref_signatures(addrs)` — 주소를 참조하는 코드에 대한 서명 생성

### 디버거(?ext=dbg 필요)
- `idapro_open_file(file_path)` — GUI IDA 인스턴스에서 파일 열기
- 디버거 도구는 기본적으로 숨겨져 있으며 URL 매개변수 `?ext=dbg`를 통해 활성화할 수 있습니다.

### 세션 관리
- `idapro_idalib_open(input_path)` — ⚠️ 스키마 확인 버그가 있습니다. 대신 `open.ps1` 스크립트를 사용하세요.
- `idapro_idalib_list()` — 모든 세션 나열
- `idapro_idalib_current()` — 현재 컨텍스트가 바인딩된 세션
- `idapro_idalib_switch(session_id)` — 다른 세션으로 전환
- `idapro_idalib_close(session_id)` — 세션 닫기
- `idapro_idalib_save(path)` — 데이터베이스 저장
- `idapro_idalib_health(session_id)` — 작업자 건강 상태 확인

### 기타
- `idapro_int_convert(inputs)` — 진수 변환(**이것을 사용해야 합니다. 진수를 직접 계산하지 마세요!**)
- `idapro_export_funcs(addrs, format)` — 내보낸 기능(json/c_header/prototypes)
- `idapro_py_eval(code)` — IDA 컨텍스트에서 Python을 실행합니다.
- `idapro_server_health()` — 서버 상태 확인
- `idapro_server_warmup()` — 준비 하위 시스템(문자열 캐시, Hex-Ray 등)

## 역분석 완료 워크플로

### 1단계: 서버 시작
HTTP 서비스가 백그라운드에서 실행되고 있는지 확인하세요.
```
powershell -File "scripts/start.ps1"
```
출력 `OK:72`은 준비가되었음을 나타냅니다.

### 2단계: 파일 열기
```
powershell -파일 "scripts/open.ps1" -경로 "C:\target.exe" -TimeoutSeconds 600
```
성공을 나타내려면 `OK:파일명:session_id`를 출력합니다(임시 복사본으로 자동 다운그레이드를 나타내려면 `(temp copy)`가 뒤따릅니다).
분석 시간이 길면 `INFO:opening:...`가 주기적으로 출력됩니다. 시간 초과에 도달하면 `ERR:open_timeout_xxs`가 출력됩니다.

### 3단계: 글로벌 개요
```
idapro_survey_binary(detail_level="minimal")
```
팔로우:
- 건축물(x86/x64/ARM)
- 진입점(main/WinMain/DllMain)
- 흥미로운 문자열(URL, 경로, 오류 메시지)
- 가져오기 분류(암호화기능? 네트워크API? 파일작업?)
- 인기 있는 기능(외부 참조 수가 많은 기능은 종종 중요한 논리임)

### 4단계: 주요 기능에 대해 자세히 알아보기
```
idapro_analyze_function(addr="키 함수 이름")
```
또는:
```
idapro_decompile(addr="함수 이름")
idapro_disasm(addr="함수 이름", max_instructions=50)
```

### 5단계: 데이터 흐름 및 상호 참조
```
idapro_xrefs_to(addrs="키 주소/문자열")
idapro_callgraph(roots=["주요 기능"], max_length=3)
idapro_trace_data_flow(addr="키 주소", 방향="뒤로", max_length=5)
```

### 6단계: 기록 및 최적화
```
idapro_set_comments(items=[{"addr": "0x140001000", "comment": "이해해 주시기 바랍니다"}])
idapro_rename(batch={"func": [{"addr": "함수 주소", "name": "의미 있는 이름"}]})
```

### 7단계: 보고서 출력
분석이 완료되면 결과와 단계를 문서화하는 `report.md`가 생성됩니다.

## 프롬프트 엔지니어링 지침

1. **기본 수학을 수동으로 수행하지 마세요** — 숫자를 변환해야 할 때마다 `idapro_int_convert`를 사용하세요.
2. **먼저 설문조사를 실시한 후 심층 분석** — 먼저 개요를 살펴본 후 대상 분석을 수행합니다.
3. **지속적인 주석 및 이름 변경** — 후속 분석의 정확성을 높이기 위해 분석 프로세스 중에 함수 이름과 변수 이름을 지속적으로 업데이트합니다.
4. **상호 참조 추적** — 흥미로운 데이터/문자열을 찾고 `xrefs_to`를 사용하여 누가 인용했는지 확인하세요.
5. **난독화된 코드 발생** — 먼저 문자열 해독, 가져오기 해시 제거, 제어 흐름 평면화 제거 등과 같은 전처리를 수행합니다.
6. **C++ STL 코드** — FLIRT/Lumina를 사용하여 라이브러리 기능을 식별한 다음 비즈니스 로직을 분석합니다.
7. **무차별 대입을 하지 마세요** — 분석은 계산을 지원하기 위해 간단한 Python을 사용하여 분해를 통해 솔루션을 도출해야 합니다.
8. **"데이터베이스 바인딩 없음" 발생** - 아직 열린 바이너리 파일이 없습니다. 먼저 `open.ps1`를 실행하세요.
9. **"데이터베이스 열기 실패" 발생** - 이전 데이터베이스 파일이 잠겨 있을 수 있습니다. `open.ps1`가 자동으로 임시 복사본으로 다운그레이드됩니다(출력에 `(temp copy)` 표시가 포함됨)
10. **자동 분석으로 GUI/복합 샘플을 열 때** — `-TimeoutSeconds 600`가 기본적으로 추가됩니다. 긴 `INFO:opening:...`를 스크립트가 멈췄다고 잘못 판단하지 마십시오.

---

## 라우팅 컨텍스트

**상류 입구**: `../../SKILL.md`(마스터 제어), `../../routing.md`
**업스트림 대안**: `radare2/` (IDA을 열고 싶지 않다면 먼저 r2를 빠르게 스카우트할 수 있습니다)
**다운스트림 내보내기**:
- Frida 동적 확인 → `reverse-engineering/tools-dynamic.md` 필요
- 기호 실행 필요 /angr → `reverse-engineering/tools-dynamic.md`
- 보편적인 역방향 방법론이 필요하다 → `../reverse-engineering/methodology.md`

**유사한 연결 모듈**: `radare2/`(IDA을 사용할 수 없는 경우 대체 솔루션)

---

## 주문형 부트스트랩

현재 큐레이션에는 자동 부트스트랩이 없습니다. 아래는 외부 상류 도구를 별도로 도입할 때의 최소 전제 조건입니다.

### 자동화 기능 경계

| 도구| 자동으로 설치 가능| 설치방법| 설명|
|------|-----------|---------|------|
| idalib-mcp | ✗ | 상류 ida-pro-mcp 설치 지침 | Python 3.11+, 활성화된 idalib, uv 필요 |
| IDA 프로 바디| ✗ | 상용 소프트웨어, 수동 설치 필요| 설치 디렉터리를 가리키도록 `IDADIR` 환경 변수를 설정합니다.|

### 설치 방향

```cmd
# idalib 활성화 후, stdio 기반 MCP 서버 예
uv run idalib-mcp --stdio

# 또는 로컬 HTTP 서버에서 바이너리 열기
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable
```

구체적인 설치와 클라이언트 등록 명령은 `mrexodia/ida-pro-mcp`의 현재 README를 따르세요. GUI 플러그인 설치 경로는 상류에서 비권장·향후 폐기 예정입니다.

### 전제 조건

- IDA Pro 8.3 이상(상류는 9 권장)과 활성화된 idalib가 필요하며 IDA Free는 지원되지 않습니다.
- Python 3.11 이상과 uv가 필요합니다.
