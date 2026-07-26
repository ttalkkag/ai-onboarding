# IDA Pro MCP 도구 빠른 확인

> **레거시 참고(2026-07-18):** 이 치트시트는 특정 시점의 `idapro_*` 클라이언트 별칭을 기록한 스냅샷입니다. 현재 상류 `main`(`1be78d0`)에서는 데이터베이스 분석 도구가 `idb_open()`이 반환한 세션 ID를 `database`에 명시해야 하며, `idb_close()`나 암묵적 현재 데이터베이스는 제공하지 않습니다. 여기서 참조하는 PowerShell 스크립트도 큐레이션에 포함되지 않습니다. 현재 서버가 실제로 공개한 스키마를 우선하고 아래 명령은 실행 가능한 계약으로 사용하지 마세요.

---

## 시작 및 세션 관리

### 서버가 시작됩니다

```powershell
# MCP HTTP 서버 시작(백그라운드에서 자동)
powershell -File "scripts/start.ps1"
# 출력 OK:72는 준비되었음을 나타냅니다.

# 대상 파일 열기(스키마 검증 우회)
powershell -File "scripts/open.ps1" -Path "C:\target.exe"
# 출력 확인:파일 이름:session_id

# 대용량 파일/GUI 프로그램에 대한 시간 제한을 추가하는 것이 좋습니다.
powershell -File "scripts/open.ps1" -Path "C:\big.exe" -TimeoutSeconds 600

# 자동 분석 건너뛰기(빠른 열기)
powershell -File "scripts/open.ps1" -Path "C:\huge.sys" -NoAutoAnalysis
```

### 대화 도구

| 도구| 목적| 예|
|------|------|------|
| `idapro_idalib_list()` | 모든 세션 나열| — |
| `idapro_idalib_current()` | 현재 바인딩된 세션| — |
| `idapro_idalib_switch(session_id)` | 세션 전환| 여러 파일을 비교할 때|
| `idapro_idalib_close(session_id)` | 세션 종료|리소스 해제|
| `idapro_idalib_save(path)` | 데이터베이스 저장| 분석 진행 상황 저장|
| `idapro_idalib_health(session_id)` | 작업자 상태 확인| 문제 해결|
| `idapro_server_health()` | 서버 상태 점검| — |
| `idapro_server_warmup()` | 예열 하위 시스템| 처음 사용하기 전에|

---

## 1단계: 개요

### Survey_binary — 빠른 개요

```
idapro_survey_binary(detail_level="minimal")
```

반환:
- 건축물(x86/x64/ARM/MIPS)
- 진입점
- 총 기능 수
- 문자열 통계
- 세그먼트 정보
- 가져오기 분류(암호화/네트워크/파일 IO/레지스트리)
- 높은 외부 참조 인기 기능

**detail_level 옵션**:
- `"minimal"` — 빠른 개요(첫 번째 선택 권장)
- `"standard"` — 자세한 내용이 포함되어 있습니다.
- `"full"` — 전체 정보

### 기능 목록

```
# 모든 함수를 나열합니다(페이지가 매겨져 있음)
idapro_list_funcs(queries=[{"offset": 0, "limit": 50}])

# 이름으로 필터링
idapro_list_funcs(queries=[{"filter": "crypt", "offset": 0, "limit": 20}])
idapro_list_funcs(queries=[{"filter": "main", "offset": 0, "limit": 10}])
```

### 통합 쿼리

```
# 가져온 함수 쿼리
idapro_entity_query(kind="imports", filter="Create")

# 쿼리 문자열
idapro_entity_query(kind="strings", filter="http")

# 명명된 모든 기호를 쿼리합니다.
idapro_entity_query(kind="names", filter="")
```

---

## 디컴파일 및 디스어셈블

### 디컴파일(의사코드)

```
# 함수 이름으로
idapro_decompile(addr="main")
idapro_decompile(addr="sub_140001000")

# 주소로
idapro_decompile(addr="0x140001000")
```

### 분해

```
#기본 명령어 수
idapro_disasm(addr="main")

# 명령어 수를 지정합니다.
idapro_disasm(addr="0x401000", max_instructions=100)
```

### 종합분석(권장)

```
# 일회성 획득: 의사코드 + 문자열 + 상수 + 호출자 + 호출 수신자 + 기본 블록
idapro_analyze_function(addr="main", include_asm=false)

# 어셈블리가 포함되어 있습니다.
idapro_analyze_function(addr="sub_401000", include_asm=true)
```

### 기능 요약

```
# 기능 표시기를 일괄적으로 가져옵니다(크기, 블록 수, 외부 참조 수)
idapro_func_profile(queries=["main", "sub_401000", "sub_402000"])
```

---

## 상호 참조 및 호출 그래프

### 누가 그 표적을 인용했는가

```
# 누가 함수를 호출했는지 확인
idapro_xrefs_to(addrs=["sub_401000"])

# 특정 문자열/데이터를 누가 인용했는지 확인
idapro_xrefs_to(addrs=["0x404000"])

# 일괄 쿼리
idapro_xrefs_to(addrs=["CreateFileW", "ReadFile", "WriteFile"])
```

### 고급 외부 참조 쿼리

```
#방향과 종류를 지정한다
idapro_xref_query(addr="0x401000", direct="to") # 누가 나를 인용했나요?
idapro_xref_query(addr="0x401000", direct="from") # 누구를 인용해야 할까요?
```

### 호출된 함수 목록

```
idapro_callees(addrs=["main"])
```

### 호출 그래프

```
# 메인, 깊이 3에서 시작
idapro_callgraph(roots=["main"], max_depth=3)

# 여러 출발점
idapro_callgraph(roots=["sub_401000", "sub_402000"], max_depth=2)
```

### 데이터 흐름 추적

```
# 역추적: 이 값은 어디에서 왔는가?
idapro_trace_data_flow(addr="0x401050", direction="backward", max_depth=5)

# 앞으로 추적: 이 값은 어디로 흘러가나요?
idapro_trace_data_flow(addr="0x401050", direction="forward", max_depth=5)
```

---

## 검색

### 문자열 검색(일반)

```
# 검색 URL
idapro_find_regex(pattern="https?://", limit=20)

# 파일 경로 검색
idapro_find_regex(pattern="C:\\\\", limit=20)

#오류 메시지 검색
idapro_find_regex(pattern="error|fail|invalid", limit=30)

# 키/비밀번호 관련 검색
idapro_find_regex(pattern="key|password|secret|token", limit=20)
```

### 디스어셈블리 텍스트 검색

```
# 분해 목록에서 검색
idapro_search_text(pattern="call    sub_")
idapro_search_text(pattern="xor     eax, eax")
```

### 바이트 패턴 검색

```
# 정확한 바이트
idapro_find_bytes(patterns=["48 8B 05"], limit=10)

# 와일드카드 포함
idapro_find_bytes(patterns=["48 89 ?? 24 ??"], limit=10)

#다양한 모드
idapro_find_bytes(patterns=["CC CC CC CC", "90 90 90 90"], limit=5)
```

### 고급 검색

```
#즉각적인 데이터 검색
idapro_find(type="immediate", targets=["0xDEADBEEF"])

#검색 문자열 참조
idapro_find(type="string", targets=["password"])
```

---

## 메모리 및 데이터 읽기

### 원시 바이트 읽기

```
idapro_get_bytes(addrs=[{"addr": "0x401000", "size": 64}])
```

### 문자열 읽기

```
idapro_get_string(addrs=["0x404000", "0x404100"])
```

### 정수 읽기

```
idapro_get_int(queries=[{"addr": "0x405000", "size": 4}])
```

### 전역 변수 읽기

```
idapro_get_global_value(queries=["g_flag", "g_key_size"])
```

### 구조 읽기

```
idapro_read_struct(queries=[{"addr": "0x405000", "type": "HEADER"}])
```

### 검색구조

```
idapro_search_structs(filter="FILE")
```

---

## 작업 수정

### 댓글 추가

```
#싱글댓글
idapro_set_comments(items=[{"addr": "0x401000", "comment": "암호해독 기능 항목"}])

# 일괄 댓글
idapro_set_comments(items=[
    {"addr": "0x401000", "comment": "XOR 복호화 루프"},
    {"addr": "0x401050", "comment": "키 초기화"},
    {"addr": "0x4010A0", "comment": "결과 확인"}
])

#댓글 추가(기존 댓글을 덮어쓰지 마세요)
idapro_append_comments(items=[{"addr": "0x401000", "comment": "보충: 키 길이 16"}])
```

### 이름 바꾸기

```
# 함수 이름 바꾸기
idapro_rename(batch={"func": [
    {"addr": "sub_401000", "name": "decrypt_payload"},
    {"addr": "sub_402000", "name": "verify_license"}
]})

# 전역 변수 이름 바꾸기
idapro_rename(batch={"global": [
    {"addr": "0x405000", "name": "g_encryption_key"}
]})

# 지역 변수 이름 바꾸기
idapro_rename(batch={"local": [
    {"func": "decrypt_payload", "old": "v1", "name": "plaintext_buf"}
]})
```

### 패치 컴파일

```
# NOP 감지 코드 제거
idapro_patch_asm(items=[{"addr": "0x401050", "asm": "nop"}])

#점프 수정
idapro_patch_asm(items=[{"addr": "0x401060", "asm": "jmp 0x401080"}])

# 강제 반환 true
idapro_patch_asm(items=[
    {"addr": "0x401000", "asm": "mov eax, 1"},
    {"addr": "0x401005", "asm": "ret"}
])
```

### 패치 바이트

```
# 직접 바이트 쓰기
idapro_patch(patches=[{"addr": "0x401050", "bytes": "9090909090"}])
```

---

## 유형 시스템

### 구조 선언

```
idapro_declare_type(decls=[{
    "name": "PacketHeader",
    "decl": "struct PacketHeader { uint32_t magic; uint16_t type; uint16_t length; uint8_t data[0]; };"
}])
```

### 애플리케이션 유형

```
# 함수의 프로토타입 설정
idapro_set_type(edits=[{
    "addr": "sub_401000",
    "type": "int __fastcall decrypt(void *buf, int size, const char *key)"
}])

# 전역 변수의 유형을 설정합니다.
idapro_set_type(edits=[{
    "addr": "0x405000",
    "type": "PacketHeader"
}])
```

### 추론된 유형

```
idapro_infer_types(addrs=["sub_401000", "sub_402000"])
```

### 쿼리/뷰 유형

```
idapro_type_query(queries=["Packet"])
idapro_type_inspect(queries=["PacketHeader"])
```

---

## 스택 프레임 분석

```
# 함수 스택 프레임 보기
idapro_stack_frame(addrs=["main", "sub_401000"])

# 스택 변수 선언
idapro_declare_stack(items=[{
    "func": "sub_401000",
    "offset": -0x20,
    "name": "local_buf",
    "type": "char [32]"
}])
```

---

## 서명 생성

```
# 주소에 대한 고유한 바이트 서명을 생성합니다.
idapro_make_signature(addrs=["0x401000"])

# 전체 함수에 대한 서명을 생성합니다.
idapro_make_signature_for_function(addrs=["decrypt_payload"])

# 주소를 참조하는 코드에 대한 서명을 생성합니다.
idapro_find_xref_signatures(addrs=["0x405000"])
```

---

## 기본 변환

```
# 16진수 → 10진수
idapro_int_convert(inputs=["0x401000"])

# 십진수 → 16진수
idapro_int_convert(inputs=["4198400"])

# 일괄 변환
idapro_int_convert(inputs=["0xDEAD", "0xBEEF", "12345"])
```

> ⚠️ **기본 변환에는 항상 이 도구를 사용하세요. 직접 계산하지 마세요! **

---

## 내보내기 및 스크립트

### 내보내기 기능

```
# JSON 형식
idapro_export_funcs(addrs=["main", "sub_401000"], format="json")

# C 헤더 파일
idapro_export_funcs(addrs=["main", "sub_401000"], format="c_header")

# 함수 프로토타입
idapro_export_funcs(addrs=["main", "sub_401000"], format="prototypes")
```

### Python 스크립트 실행

```
# IDA 컨텍스트에서 Python을 실행합니다.
idapro_py_eval(code="import idautils; print(list(idautils.Functions())[:10])")

# 세그먼트 정보 얻기
idapro_py_eval(code="import idc; print(idc.get_segm_name(0x401000))")

# 일괄 작업
idapro_py_eval(code="import ida_funcs; f=ida_funcs.get_func(0x401000); print(f.size())")
```

---

## 일반적인 분석 프로세스

### 악성 코드 분석

```text
1. Survey_binary → 가져오기(네트워크 API? 암호화? 레지스트리?) 참조
2. find_regex("http|socket|connect") → 네트워크 관련 문자열 찾기
3. xrefs_to(네트워크 문자열 주소) → 참조 함수 찾기
4. 디컴파일(참조 기능) → 통신 로직 참조
5. Trace_data_flow(암호화 매개변수, "backward") → 키 소스 추적
6. set_comments + 이름 바꾸기 → 검색 표시
```

### 등록 확인 크랙

```text
1. find_regex("serial|license|register|valid") → 검증 관련 문자열 찾기
2. xrefs_to(검증 문자열) → 검증 함수 찾기
3. analyze_function(검증함수) → 로직 이해
4. callgraph(검증함수, 2) → 콜체인 참조
5. patch_asm(조건부 점프 주소, "jmp Always_pass") → 패치
```

### CTF 리버스

```text
1. Survey_binary → 구조 및 입력 확인
2. decompile("main") → 메인 로직 살펴보기
3. find_regex("flag|corright|wrong") → 판단점 찾기
4. Trace_data_flow(판단점, "backward") → 추적 입력 변환
5. Python을 사용하여 계산/복호화 지원 → 플래그 가져오기
```

### 취약점 분석

```text
1.entity_query(kind="imports", filter="strcpy|sprintf|gets") → 위험한 함수 찾기
2. xrefs_to (위험한 함수) → 콜포인트 찾기
3. analyze_function(콜포인트가 위치한 함수) → 컨텍스트 보기
4. stack_frame(function) → 버퍼 크기 확인
5. Trace_data_flow(위험 매개변수, "backward") → 사용자 제어 확인
```

---

## 일반적인 오류 및 해결 방법

| 오류| 이유| 해결하다|
|------|------|------|
| "데이터베이스 바인딩 없음"| 열린 파일 없음| 실행 `open.ps1`|
| "데이터베이스를 열지 못했습니다."|이전 데이터베이스가 잠겨 있습니다.| `open.ps1` Temp로 자동 다운그레이드|
| 스키마 확인 실패| MCP 클라이언트 버그| `idalib_open` 대신 `open.ps1`를 사용하세요.|
| 도구 시간 초과| 대용량 파일 분석| `-TimeoutSeconds 600` 추가|
| "ERR:시간 초과"(start.ps1)| 서버 시작 실패| Python/idalib-mcp 설치 확인|
| 베이스 변환 오류| 수동 계산 오류| `idapro_int_convert` 사용|
| 함수 이름을 찾을 수 없습니다| 이름이 정확하지 않습니다.| 먼저 검색하려면 `list_funcs` + 필터를 사용하세요.|
