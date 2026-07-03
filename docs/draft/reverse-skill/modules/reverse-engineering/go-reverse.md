# Go 바이너리 리버스 엔지니어링 가이드

> Go-컴파일된 바이너리에는 고유한 문제가 있습니다. 정적 연결은 거대한 크기, 수만 개의 기능, 특수 문자열 형식 및 기호 제거 후 복구의 어려움으로 이어집니다.
> 이 문서에서는 도구 체인, 복구 기술 및 실제 워크플로를 다룹니다.

---

## 바이너리 기능 인식으로 이동

Go를 사용하여 바이너리가 컴파일되었는지 빠르게 확인합니다.

```bash
# 문자열 특성
strings binary | grep -E "runtime\.|go\.buildid|GOROOT"

# rabin2 정찰
rabin2 -z binary | grep -i "runtime"

# 비정상적으로 큰 파일 크기(정적으로 연결된 런타임)
# 일반적인 Hello World: C ~20KB, Go ~2MB
```

일반적인 기능:
- `runtime.` 접두사가 포함된 다수의 함수
- `go.buildid` 섹션 포함
- `GOROOT`, `GOPATH` 경로 문자열을 포함합니다.
- 기능 수 5000-50000+(전체 런타임 및 표준 라이브러리 포함)

---

## 핵심 툴체인

### 기호 복구

| 도구| 목적| 링크|
|------|------|------|
| **GoReSym** | Mandiant 제작, Go 기호 정보 파싱(pclntab/moduledata)| https://github.com/mandiant/GoReSym |
| **GoResolver** | Volexity를 통해 CFG 유사성으로 Garble 바이너리를 자동으로 해독합니다.| https://github.com/volexity/GoResolver |
| **redress** | 스트립된 Go 바이너리 분석, 유형/인터페이스/패키지 구조 복원| https://github.com/goretk/redress |
| **GoStringUngarbler** | Garble 난독화된 문자열을 복구하기 위해 특별히 설계된 Google에서 제작| https://github.com/mandiant/GoStringUngarbler |

### IDA 플러그인

| 도구| 목적| 링크|
|------|------|------|
| **go_parser** | IDA 플러그인, 구문 분석 moduledata/pclntab/유형 정보| https://github.com/0xjiayu/go_parser |
| **IDAGolangHelper** | IDA 스크립트 세트, Go 타입 정보 파싱| https://github.com/sibears/IDAGolangHelper |
| **AlphaGolang** | SentinelLabs의 IDAPython 스크립트 세트| https://github.com/SentineLabs/AlphaGolang |
| **IDA 9.2+ 기본 지원**| Hex-Rays 공식 Go 디컴파일 개선| https://hex-rays.com/blog/stop-guessing-and-start-going |

### Ghidra 플러그인

| 도구| 목적| 링크|
|------|------|------|
| **Ghidra + GoReSym 출력**| GoReSym을 사용하여 기호 내보내기 및 가져오기 Ghidra|함께 사용|
| **golang_loader_assist** | Ghidra 로딩 지원 이동| 커뮤니티 스크립트|

### 독립형 분석 도구

| 도구| 목적| 링크|
|------|------|------|
| **gore** | 리버스 엔지니어링 라이브러리 이동(기본 교정)| https://github.com/goretk/gore |
| **garble** | 난독화 도구 사용(이를 알고 맞서 싸우세요)| https://github.com/burrowers/garble |

---

## Go 바이너리의 주요 구조

### pclntab(PC 라인 테이블)

Go 바이너리의 가장 중요한 구조는 다음과 같습니다.
- 모든 함수 이름 및 주소 매핑
- 소스 파일 경로
- 라인 번호 정보
- 스택 프레임 크기

기호가 제거되더라도 pclntab은 일반적으로 여전히 존재합니다(Go 런타임은 이에 따라 다름).

```text
포지셔닝 방법:
1. 매직 바이트 검색: 0xFFFFFFFF0(Go 1.16+) 또는 0xFFFFFFFFB(Go 1.18+)
2. GoReSym을 이용한 자동 위치 지정
3. go_parser IDA 플러그인을 사용하여 자동으로 구문 분석
```

### moduledata

다음을 포함합니다:
- pclntab 포인터
- 유형 정보 테이블
- itab(인터페이스 테이블)
- 글로벌 변수 정보

### 문자열 형식

Go 문자열은 C 스타일의 null 종료형이 아니지만 `(pointer, length)` 구조입니다.

```text
C 문자열: "hello\0"
Go 문자열: struct { ptr *byte; len int } → ptr은 "hello"(\0 없음)를 가리킵니다.
```

이로 인해 IDA/Ghidra 기본 문자열 인식에서 많은 수의 Go 문자열이 누락되었습니다.

**해결책**:
- `go_parser`로 Go 문자열을 자동으로 식별합니다.
- GoReSym을 사용하여 문자열 목록 내보내기
- 수동: `runtime.stringtable` 찾기 또는 상호 참조를 통해 찾기

---

## 실용적인 작업 흐름

### 시나리오 1: 스트라이프되지 않은 Go 바이너리

```text
1. GoReSym -t -d -p binary > symbols.json
   → 모든 함수 이름, 유형, 소스 파일 경로 내보내기
2. IDA/Ghidra에 로드
3. GoReSym에서 기호 정보 가져오기
4. 런타임* 및 표준 라이브러리 함수를 필터링하고 사용자 코드에 집중
5. main.main에서 분석 시작
```

### 시나리오 2: 스트리핑 후 바이너리로 전환

```text
1. GoReSym -t -d -p binary > symbols.json
→ 제거하더라도 pclntab은 대개 그대로 유지됩니다.
2. GoReSym이 실패하는 경우 → 수정 사용
   redress -src 바이너리 #소스 파일 경로 복원
   redress -pkg 바이너리 #패키지 구조 복원
   redress -type bin #복원 유형 정보
3. IDA + go_parser 플러그인에 로드
4. go_parser를 실행하여 자동 복원
5. 복원된 main.main에서 시작합니다.
```

### 시나리오 3: 왜곡된 Go 바이너리

```text
Garble은 다음을 수행합니다.
- 함수 이름 무작위화 (main.main → main.a3f2b1c)
- 암호화된 문자열
- 파일 경로 정보 제거
- 난독화된 패키지 이름

대책:
1. GoResolver(CFG 서명 매칭)
   → 제어 흐름 그래프 유사성을 통해 표준 라이브러리 함수 이름 복구
2. GoStringUngarbler(문자열 해독)
   → Garble의 문자열 암호화 모드를 자동으로 식별하고 복호화합니다.
3. 동적해석(Frida/dlv)
   → Hook 실제 동작을 관찰하는 런타임 기능
4. Comparative analysis
   → 동일한 버전의 Go의 Hello World를 컴파일하고 Binary-diff를 사용하여 런타임 부분을 비교합니다.
```

### 시나리오 4: CGo 하이브리드 컴파일

```text
1. CGo 경계 식별(_cgo_* 함수)
2. go_parser를 사용하여 Go 부분을 복원합니다.
3. 파트 C는 기존의 IDA를 사용하여 분석됩니다.
4. _cgo_topofstack 및 crosscall2와 같은 브리징 기능에 주의하세요.
```

---

## 자주 사용하는 명령어를 빠르게 확인

```bash
# GoReSym: export symbols
GoReSym -t -d -p binary > symbols.json
GoReSym -t -d -p binary -o ida_script.py  # Generate IDA script

# 수정: 제거된 바이너리 구문 분석
redress -src binary          # 소스 파일 경로
redress -pkg binary          # Package structure
redress -type binary         # type information
redress -interface binary    # Interface information
redress -filepath binary     # full file path

# GoResolver: Garble 난독화 해제
GoResolver -binary binary -output resolved.json

# GoStringUngarbler: Garble 문자열 해독
GoStringUngarbler -i binary -o deobfuscated_binary

# Go 버전을 빠르게 확인
strings binary | grep "go1\."
GoReSym -p binary | grep "Version"
```

---

## IDA에서 분석 파이프라인으로 이동

```text
1. 바이너리 로드(올바른 아키텍처 선택)
2. 자동 분석이 완료될 때까지 기다립니다.
3. go_parser 플러그인을 실행합니다:
   - File → Script File → go_parser.py
   - 또는 편집 → 플러그인 → Go Parser
4. 플러그인은 자동으로 다음을 수행합니다.
   - pclntab 구문 분석
   - 복원 기능 이름
   - 태그 이동 문자열
   - 구문 분석 유형 정보
5. 보기를 필터링합니다.
   - 런타임.* 기능 숨기기
   - main.* 및 타사 패키지에 중점을 둡니다.
6. main.main에서 리버스 엔지니어링을 시작합니다.
```

---

## 일반적인 함정

| 함정| 설명| 해결하다|
|------|------|------|
| 기능이 너무 많아 명확하게 볼 수 없음|Go 정적 링크 결과는 5000-50000개 함수입니다.| 패키지 이름으로 필터링하고 main.* 및 비즈니스 패키지만 확인하세요.|
| 불완전한 문자열 인식| Go 문자열은 null로 끝나지 않습니다.| go_parser 또는 GoReSym을 사용하여 복원|
| 디컴파일 결과를 읽기가 어렵습니다.| Go의 defer/goroutine/interface는 의사코드를 복잡하게 만듭니다| IDA 9.2+에는 개선 사항이 있거나 동적 분석의 도움을 받을 수 있습니다.|
| 혼란스러운 혼란| 함수 이름/문자열은 모두 무작위입니다.| GoResolver + GoStringUngarbler|
| 버전 차이| Go 버전마다 pclntab 형식이 다릅니다.| GoReSym은 Go 1.2-1.23+를 지원합니다.|
| CGo 경계| Go와 C 코드 혼합| _cgo_* 함수를 구분선으로 식별|

---

## 다른 기술과의 협력

|수요| 무엇을 사용해야합니까?|
|------|--------|
| IDA Go 바이너리 심층 분석| `ida-reverse/` + go_parser 플러그인|
| Ghidra 분석(무료)| Ghidra + GoReSym 기호 가져오기|
| 빠른 정찰| `radare2/` — `rabin2 -z` 문자열을 보세요|
| 다이나믹 훅| Frida(Hook 런타임 기능) 또는 dlv(Go 네이티브 디버거)|
| 버전 간 비교| `binary-diff/` — 기호가 새 버전으로 마이그레이션된 이전 버전|
| 왜곡 난독화| GoResolver + GoStringUngarbler|
