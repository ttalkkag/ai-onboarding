# research — 탐지 근거와 후보 기술

> 이 디렉터리는 제품 정책의 정본이 아니다. 충돌하면 루트 `README.md`, `CONTEXT.md`, `../plan/`을 따른다.

## 인덱스

| 문서 | 내용 |
|------|------|
| `threat-catalog.md` | 작업별 HIGH/LOW/INFO 규칙 후보 |
| `osv.md` | OSV·악성 패키지 데이터의 의미, 한계와 후속 도입 선택지 |
| `reverse-skill-harvest.md` | 수집 문서에서 가져올 수 있는 정적 탐지 아이디어 |
| `capability-tiers.md` | 공용 로컬 코어와 선택 정적 도구 후보 |
| `external-harness-harvest.md` | promptfoo·codex-security·인접 가드레일 조사와 기존 결정에 대한 diff |

원자료는 `../draft/`에 보존한다. 원자료의 명령·도구·플로우는 검증 전까지 제품 기능이 아니다.

## 현재 결론

### R1. 제품은 AI CLI 작업 게이트다

Secure Onboard는 프로젝트 전체를 `안전/위험`으로 인증하지 않는다. Claude Code·Codex가 계획한 구체 작업을 실행 직전에 검사해 `HIGH`, `LOW`, `INFO`로 판정한다. HIGH만 AI 자동 실행을 차단한다.

### R2. 실제 tool call과 대상 입력을 불신한다

- 대상 코드·설정·자연어 지시·도구 경로는 신뢰하지 않는다.
- 실제 판정 입력은 PreToolUse가 받은 tool name·command·argv·cwd다.
- 검사 코어와 선택 도구는 출처·버전·무결성·환경 주입·자원 제한을 검증한다.

### R3. 수집한 reverse-skill과 `scan.sh`는 참고 코퍼스다

설치 훅, 난독화, 유출 sink, 악성 패키지와 바이너리 IOC 같은 지식만 규칙 후보로 가져온다. 기존 공유 스킬·이분 판정·MED·자동 설치·동적 실행 절차는 현재 제품 계약이 아니다.

### R4. AI가 외부 프로젝트를 처리할 수 있다

외부 코드·파일을 Claude Code·Codex가 읽는 것은 지원 범위다. 로컬 CLI는 로컬 모델이나 무전송을 뜻하지 않으며 공급자 전송·보존은 각 클라이언트와 계정 정책을 따른다. Secure Onboard는 별도 제3자 분석 서비스 전송과 로컬 로그의 비밀값 노출을 추가하지 않는다.

### R5. 공용 코어와 두 플러그인 어댑터를 사용한다

공유 저장소 스킬 심볼릭 링크 대신 공용 로컬 코어와 Claude Code·Codex별 plugin manifest/hook adapter를 사용한다. 현재 권장 배포안은 사용자 영역에 공용 코어를 한 번 설치하고 프로젝트 모드는 사용자 소유 registry로 활성화하는 방식이다. 실제 프로젝트별 plugin/package 설치까지 제공할지는 M1 전 사용자 확인 사항이다.

### R6. M0로 hook 경계를 먼저 검증한다

지금 시작 가능한 구현은 두 CLI의 native hook payload와 deny·continue·result·Stop 동작을 고정 sentinel로 확인하는 M0 tracer-bullet이다. M1 범위는 npm 설치, 로컬 파일 열기와 명시적 read-only scan으로 확정했다. EICAR는 고정 commit의 `standard/eicar.com.txt` 단일 파일을 격리된 opt-in signature/cache fixture로만 사용한다. container 분석, OSV/MAL 평판 데이터, 다중 생태계, Docker와 광범위 정적 분석기는 M2 이후 검토한다.
