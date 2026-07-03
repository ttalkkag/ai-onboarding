---
name: secure-onboard
description: Use when downloading, cloning, or first-running an unfamiliar project/repository (e.g. a "review this code" request from a recruiter/stranger, a fresh git clone, a code sample) — performs a read-only security scan for install-script backdoors and malicious patterns BEFORE any install or execution, then installs/runs only with explicit human approval (sandboxed, scripts disabled), and produces a report covering project structure, findings, and what was installed/run.
---

# secure-onboard — 낯선 프로젝트 안전 인수(온보딩)

## 언제 쓰는가 (라우팅)

다음 상황에서 이 스킬을 사용한다:

- 처음 보는 저장소를 `git clone` / 다운로드했고 아직 설치·실행 전일 때
- "이 코드 좀 봐줄 수 있나요?" 류의 외부 요청(채용 사칭 포함)으로 받은 코드
- 신뢰도가 검증되지 않은 샘플/템플릿/서드파티 프로젝트를 처음 돌려볼 때
- 호출 트리거 예: "보안 검사", "secure onboard", "이거 안전한지 확인", "설치해도 돼?"

배경 위협: `npm install` 한 번이 `prepare`/`postinstall` 등 라이프사이클 훅을 통해
원격 임의 코드를 실행시키는 공급망 백도어. (참고 사례: LinkedIn 채용 사칭 백도어,
https://roman.pt/posts/linkedin-backdoor/ )

## 절대 규칙 (위반 금지)

1. **검사 전에 절대 설치·실행하지 않는다.** `npm/pnpm/yarn install`, `pip install`,
   `make`, `npm start`, 빌드 명령 등 어떤 코드 실행도 1차 보안 검사 전에는 금지.
2. **설치/실행은 사용자의 명시적 승인 후에만.** 무엇을, 왜 실행하는지 먼저 보고하고 승인을 받는다.
3. **가능하면 샌드박스에서.** Docker 컨테이너·일회용 VM 등 격리 환경을 우선한다.
   부득이 로컬이라면 라이프사이클 훅을 차단(`--ignore-scripts`)한다.
4. **스캐너는 읽기 전용.** `scan.sh`는 파일을 읽고 패턴만 검사하며 네트워크/실행을 하지 않는다.

## 워크플로우 (4단계)

> 각 단계는 `../plan/workflow.md`에 상세 절차가 있다. 체크리스트는 `../research/threat-catalog.md`.

1. **프로젝트 구성 확인** → 디렉토리/매니페스트로 생태계·진입점 파악
2. **보안 검사** → `scan.sh <대상>` 실행 후 HIGH/MED 항목을 직접 열어 검증
3. **승인 게이트 → 설치/실행** → 위험 보고 → 사용자 승인 → 샌드박스·`--ignore-scripts` 우선 실행
4. **결과 보고서 생성** → `../plan/report-template.md`로 구성/검사결과/설치·실행 내역 정리

### 빠른 시작

```bash
# 1+2단계: 구성 확인 + 보안 검사 (읽기 전용, 아무것도 설치/실행 안 함)
docs/draft/scan.sh <대상_디렉토리> --out security-report.md
# 종료코드 0 = HIGH 없음, 1 = HIGH 있음(사람 검토 필수), 2 = 입력 오류
```

스캔 결과 HIGH가 있거나 의심 항목이 보이면 멈추고 사용자에게 보고한다.
스캔이 깨끗해도 그것은 "휴리스틱 1차 점검 통과"일 뿐이며, 설치는 여전히 승인 게이트를 거친다.

### (선택) 심층 분석 티어 → reverse-skill

1차 스캔이 더 깊은 분석이 필요한 신호(난독화 JS, 인코딩 페이로드, 의심 바이너리/네이티브
모듈, 의존성·공급망 이상)를 내면 `reverse-skill` 브리지 스킬(`docs/draft/reverse-skill/SKILL.md`)로
에스컬레이션한다. 관련 서브스킬: `js-reverse`(디오브퍼스케이션), `malware-analysis`(IOC/YARA),
`supply-chain-security`(SBOM/SCA), `reverse-engineering`/`radare2`(바이너리). 단, **도구 자동
설치는 금지**이고 동적 분석은 샌드박스+승인 게이트를 그대로 따른다.

## 판단 가이드

- **HIGH 발견**: 로컬 설치·실행 금지. 내용을 사용자에게 보고하고, 진행하려면 샌드박스에서만.
- **MED만 발견**: 해당 파일을 열어 의도 확인 → 사용자에게 요약 보고 후 승인 시 진행.
- **신호 없음**: 그래도 첫 설치는 `--ignore-scripts` 또는 샌드박스로 보수적으로.

## 산출물

- `security-report.md` (또는 사용자 지정 경로): 프로젝트 구성 + 보안 검사 결과 + 설치·실행 내역.
  템플릿은 `../plan/report-template.md` 참고. 신뢰 불가 대상의 보고서는 대상 저장소
  바깥(작업 디렉토리)에 저장한다.

## 구성 파일

- `scan.sh` — 읽기 전용 보안 스캐너 MVP
- `../plan/workflow.md` — 4단계 상세 절차
- `../research/threat-catalog.md` — 위협 체크리스트 (스캔 자동 항목 + 수동 검토 항목)
- `../plan/report-template.md` — 결과 보고서 템플릿
