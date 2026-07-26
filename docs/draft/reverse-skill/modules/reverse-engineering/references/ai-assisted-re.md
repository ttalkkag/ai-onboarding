# AI 지원 리버스 엔지니어링

> LLM 드라이버 디컴파일/다중 에이전트 검증/신경 의미 복구
> 2025-2026 가장 큰 패러다임 변화

## 핵심 도구 및 모델

### [LLM4Decompile](https://github.com/albertan017/LLM4Decompile)
- 바이너리 → 소스 코드 디컴파일에 LLM를 사용하는 최초의 오픈 소스 프레임워크
- 현재 공개 모델/워크플로의 공식 지원 범위는 Linux x86-64(GCC O0-O3)이며 ARM/MIPS 지원은 명시되어 있지 않음
- 입력: 어셈블리 코드 → 출력: C 소스코드
- Decompile-Bench에는 약 200만 개의 정제된 binary-source 함수 쌍이 포함됨

### [Decaf (2026)](https://arxiv.org/abs/2605.11501)
- **컴파일러 피드백과 검색**: 여러 후보를 컴파일하고 자동 피드백/재순위화로 기능적으로 올바른 후보를 선택합니다.
- 효과: 디컴파일률 26% → 83.9% (ExeBench Real -O2)
- 주요 통찰: 피드백 루프는 대규모 모델보다 더 효과적입니다.

### [제약 조건 기반 다중 에이전트(2026)](https://arxiv.org/abs/2604.23940)
- 3단계 검증 파이프라인:
  1. 문법적 정확성(파싱)
  2. 컴파일 가능성(GCC)
  3. 행동 동등성(LLM 테스트 사례 생성)
- 84-97%의 반복 가능한 실행률, 매번 $0.03-0.05

### [REMEND (2026)](https://doi.org/10.1145/3749988)
- 전문 분야: 이진수에서 수학 방정식 추출
- 논문 보고값: 3개 ISA, 3개 최적화 수준, 2개 언어에서 단일 모델 정확도 89.8~92.4%
- 논문 보고값: 최대 12M 매개변수, 함수당 평균 실행 시간 0.132초. 하드웨어·데이터셋 조건을 포함한 독립 재현값은 아님
- 저자 공개 artifact와 재현 절차: <https://huggingface.co/udiboy1209/REMEND>

### [Glaurung](https://github.com/mjbommar/glaurung)
- 오픈 소스 Ghidra 대안, Rust 커널 + Python 바인딩
- **AI 기본 아키텍처**: LLM 에이전트가 각 분석 레이어에 내장되어 있습니다.
- 증거 유물: plain/rich/JSON/JSONL LLM에서 소비할 수 있는 다중 형식 출력
- 현재: ELF/PE/Mach-O 정적 분석과 x86/x64·ARM/ARM64·RISC-V의 제한된 디스어셈블리, IOC/엔트로피 분석. 디컴파일 품질과 일부 아키텍처는 활발히 개발 중

## 워크플로우: AI로 강화된 이진 분석

### 1. LLM 보조 신속 정찰

```text
□ 문자열 추출 → LLM 의미 분류(URL/키/경로/프로토콜)
□ 테이블 가져오기 분석 → LLM 추론 기능 (암호화=OpenSSL? 네트워크=libcurl?)
□ 디스어셈블리 프래그먼트 → LLM 인식 패턴(암호알고리즘, 안티디버깅, 가상머신 탐지)
□ 오류 메시지 → LLM 유추된 컨텍스트 ("잘못된 라이선스" → 승인 논리 위치)
```

### 2. 신경 분해

```bash
# LLM4Decompile 공식 저장소에는 아래와 같은 범용 --binary/--arch CLI가 없습니다.
# README의 전처리 절차로 x86-64 함수 하나를 objdump 어셈블리로 만든 뒤
# Transformers 예제 또는 ghidra/demo.py를 사용하세요.

# 검증 결과(재컴파일 + 비교)
gcc -O2 -o target_recompiled target.c -fPIC -shared
# → 출력 동작의 동등성 확인
```

### 3. 다중 에이전트 인증

```text
에이전트 1(구문): 생성된 C 코드를 구문 분석할 수 있는지 확인
  ↓ 실패 → 피드백 오류 메시지를 LLM 에 다시 시도하세요
에이전트 2(컴파일): GCC 컴파일 → 확인 warnings/errors
  ↓ 실패 → LLM에 대한 피드백 컴파일 오류
에이전트 3(동작): LLM 입력 생성 → 원본 버전과 다시 컴파일된 버전 실행 → 출력 비교
  ↓ 불일치 → 피드백 차이 LLM → 반복 수정
```

### 4. LLM 보조 정적 분석

```text
□ 함수 이름 바꾸기: 디컴파일된 의사코드 입력 → LLM 의미 이름 제안
□ 유형 복구: 분석 컨텍스트 → LLM 구조/클래스 정의 유추
□ 알고리즘 식별: 어셈블리 조각 → LLM 비밀번호 알고리즘 식별(AES/TEA/RC4/custom)
□ 프로토콜 역방향: 네트워크 패킷 순서 → LLM 프로토콜 형식 추론
□ 댓글 생성: 코드 디컴파일 → LLM 중국어/영어 댓글 생성
```

### 5. [macOS/iOS 프라이빗 프레임워크 리버스(MOTIF)](https://arxiv.org/abs/2601.01673)

```text
문제: macOS 개인 프레임워크에 문서가 없고 유형 정보가 누락되었습니다.
시나리오: LLM 사용 패턴 분석 → 메서드 시그니처 및 매개변수 유형 추론
효과: ObjC 시그니처 복구 15% → 86% (정적 분석 대비)
```

## LLM 프롬프트 템플릿

### 기능 의미 분석

```
You are a reverse engineering expert. Analyze this decompiled function:

[의사코드]

1. What does this function do? (one sentence)
2. Suggest a meaningful function name.
3. What are the input parameters and their likely types?
4. What is the return value?
5. What external APIs/functions does it depend on?
6. Any security-relevant operations (crypto, auth, network, file I/O)?
```

### 알고리즘 식별

```
Analyze this assembly/disassembly for cryptographic operations:

[조립코드]

1. Is this a known cryptographic algorithm? (AES/DES/RC4/TEA/ChaCha20/custom?)
2. Identify the key schedule and round structure.
3. What is the key size?
4. Are there any hardcoded constants that identify the algorithm?
```

### 프로토콜 형식 추론

```
Given this network packet sequence, infer the protocol structure:

[hex dump]

1. Identify magic bytes and length fields.
2. Propose a struct definition for the packet header.
3. What field(s) appear to be checksums/CRCs?
4. Is this a known protocol or custom?
```

## 도구 선택

| 장면| 권장 도구| 비용|
|------|---------|------|
| 빠른 디컴파일| LLM4Decompile | 무료(로컬 GPU)|
| 고정밀 디컴파일| 제약 조건 기반 다중 에이전트| ~$0.05/바이너리|
| 수학 함수 추출| REMEND | 무료|
| 지원 플랫폼의 자동 정찰| Glaurung (Rust/Python) | 무료 및 오픈 소스|
| LLM 상호작용| 선택한 모델/제공자 | 현재 토큰 가격과 실제 입력량으로 산정|

## 한계

- **복잡한 제어 흐름**: 코드 가상화/난독화는 여전히 어렵습니다(제어 흐름 평면화, VMProtect).
- **간접 호출**: 가상 함수 테이블과 함수 포인터는 복원이 어렵습니다.
- **인라인 함수**: 컴파일러 인라인 이후 경계가 흐려짐
- **부동 소수점 연산**: 벡터화된 명령어의 의미 복구를 개선해야 합니다.
- **컨텍스트와 품질**: 한도는 모델/토크나이저마다 다르며, 한도 안에서도 큰 함수는 의미 복구 품질이 떨어질 수 있으므로 함수·CFG 단위로 분할하고 실행 검증합니다.

LLM 출력은 읽기 쉬워 보여도 의미가 틀릴 수 있습니다. 재컴파일 성공만으로 동등성을 주장하지 말고, 승인된 격리 환경에서 원본과 후보의 입력/출력·부작용을 비교하세요.

Source: 위 각 절의 원 논문·공식 저장소 링크(2026-07-14 확인)
