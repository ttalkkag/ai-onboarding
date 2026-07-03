# secure-onboard

낯선 프로젝트/코드를 **내려받아 최초로 실행하기 전에** 보안 검사를 수행하는 스킬.

`npm install` 한 번이 `prepare`/`postinstall` 같은 라이프사이클 훅을 통해 원격 임의
코드를 실행시키는 공급망 백도어(예: LinkedIn 채용 사칭 백도어,
<https://roman.pt/posts/linkedin-backdoor/>)를 1차로 막는 것이 목적이다.

## 워크플로우

```
1. 프로젝트 구성 확인  →  2. 보안 검사(읽기 전용)  →  3. 승인 게이트 + 설치/실행(샌드박스 우선)  →  4. 결과 보고서
```

- 스캐너는 **읽기 전용**이며 어떤 코드도 설치·실행하지 않는다.
- 설치/실행은 **사용자 명시적 승인** 후, **샌드박스·`--ignore-scripts` 우선**으로만.

## 사용법

```bash
# 구성 확인 + 보안 검사 (아무것도 설치/실행하지 않음)
docs/draft/scan.sh <대상_디렉토리> --out security-report.md
```

종료코드: `0`=HIGH 없음 · `1`=HIGH 있음(사람 검토 필수) · `2`=입력 오류

자동 검사: npm 라이프사이클 훅, `curl|sh`, 원시 IP 연결, `eval`/`base64`/`child_process`,
환경변수 유출, 커스텀 `.npmrc`, 테스트로 위장한 비대/난독 파일 등. 다중 생태계는 존재를 감지하고,
현행 MVP는 npm lifecycle과 범용 정적 패턴을 우선 탐지한다.

## 구성

| 경로 | 설명 |
|------|------|
| `docs/draft/SKILL.md` | 스킬 진입점 초안 — 동작 원칙·라우팅·절대 규칙 |
| `docs/draft/scan.sh` | 읽기 전용 보안 스캐너 MVP |
| `docs/plan/workflow.md` | 4단계 상세 절차 |
| `docs/research/threat-catalog.md` | 위협 체크리스트 (자동/수동) |
| `docs/plan/report-template.md` | 결과 보고서 템플릿 |

## 스킬로 등록하려면 (선택)

이 디렉토리는 프로젝트 루트 전용으로 두되, 에이전트가 스킬로 인식하게 하려면
`SKILL.md`를 스킬 경로(예: `.skills/secure-onboard/`)로 심볼릭 링크하거나 복사한다.

```bash
ln -s /절대/경로/ai-onboarding/docs/draft .skills/secure-onboard   # 예시 (대상 경로는 실제 위치로)
```

## 한계

휴리스틱 기반이라 오탐·미탐이 가능하다. "신호 없음"이 "안전 증명"은 아니며, HIGH/MED는
반드시 사람이 해당 파일을 열어 확정해야 한다.
