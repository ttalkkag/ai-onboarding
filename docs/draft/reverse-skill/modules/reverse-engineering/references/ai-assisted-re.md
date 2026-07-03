# AI 지원 리버스 엔지니어링

> LLM 드라이버 디컴파일/다중 에이전트 검증/신경 의미 복구
> 2025-2026 가장 큰 패러다임 변화

## 핵심 도구 및 모델

### LLM4Decompile
- 바이너리 → 소스 코드 디컴파일에 LLM를 사용하는 최초의 오픈 소스 프레임워크
- x86/ARM/MIPS 다중 아키텍처 지원
- 입력: 어셈블리 코드 → 출력: C 소스코드
- 훈련 데이터: 백만 레벨 소스 코드-어셈블리 쌍

### Decaf (2026)
- **컴파일러 피드백 검증**: LLM→컴파일→원래 바이너리 비교를 통해 생성된 소스 코드를 컴파일합니다.
- 효과: 디컴파일률 26% → 83.9% (ExeBench Real -O2)
- 주요 통찰: 피드백 루프는 대규모 모델보다 더 효과적입니다.

### 제약 조건 기반 다중 에이전트(2026)
- 3단계 검증 파이프라인:
  1. 문법적 정확성(파싱)
  2. 컴파일 가능성(GCC)
  3. 행동 동등성(LLM 테스트 사례 생성)
- 84-97%의 반복 가능한 실행률, 매번 $0.03-0.05

### REMEND (2026)
- 전문 분야: 이진수에서 수학 방정식 추출
- 89.8-92.4% 정확도(3개 ISA × 3개 최적화 수준 × 2개 언어)
- 속도: 0.132s/기능, 12M 매개변수만

### Glaurung
- 오픈 소스 Ghidra 대안, Rust 커널 + Python 바인딩
- **AI 기본 아키텍처**: LLM 에이전트가 각 분석 레이어에 내장되어 있습니다.
- 증거 유물: plain/rich/JSON/JSONL LLM에서 소비할 수 있는 다중 형식 출력
- 지원: ELF/PE/Mach-O, x86/ARM/RISC-V, IOC 감지, 엔트로피 분석

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
# LLM4Decompile
python llm4decompile.py --binary target.so --arch arm64 --output target.c

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

### 5. macOS/iOS 프라이빗 프레임워크 리버스(MOTIF)

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
| 모든 플랫폼 RE| Glaurung (Rust) | 무료 및 오픈 소스|
|LLM 상호작용| 클로드 API / GPT-4 / DeepSeek| ~$0.01-0.10/시간|

## 한계

- **복잡한 제어 흐름**: 코드 가상화/난독화는 여전히 어렵습니다(제어 흐름 평면화, VMProtect).
- **간접 호출**: 가상 함수 테이블과 함수 포인터는 복원이 어렵습니다.
- **인라인 함수**: 컴파일러 인라인 이후 경계가 흐려짐
- **부동 소수점 연산**: 벡터화된 명령어의 의미 복구를 개선해야 합니다.
- **컨텍스트 창**: 큰 기능(>1000줄)이 LLM 컨텍스트 제한을 초과합니다.

Source: Decaf(2026), REMEND(2026), Constraint-Guided Multi-Agent Decompilation(2026), LLM4Decompile, Glaurung
