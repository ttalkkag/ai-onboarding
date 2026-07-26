# 계획·리서치 문서 검토

> **역사 문서:** 2026-07-22에 제품이 Claude Code·Codex 플러그인 기반 작업 게이트로 재정의됐다. 이 문서의 공용 저장소 스킬, `안전/위험`, `MED`, AI 원문 접근 금지, atime·OSV M1 blocker 결론은 대체됐다. 최신 정책과 구현 준비도는 `README.md`와 `../plan/`을 우선한다.

- 검토일: 2026-07-15, 결정 반영 재검증 2026-07-18
- 범위: `docs/plan/**`, `docs/research/**`, `docs/draft/README.md`, `docs/draft/SKILL.md`,
  `docs/draft/reverse-skill/SKILL.md`, `docs/draft/reverse-skill/routing.md`
- 방법: 지정된 14개 Markdown 전문 독해, 상대 링크 검증, 현행 `scan.sh`와의 표본 대조,
  업스트림 커밋·아카이브 실측, 2026-07-18 기준 공식/일차 출처 웹 대조

> **후속 상태(2026-07-18):** 제품은 단일 설치 전 검사기, `docs/draft/`는 참고 자료, AI/API/mobile은 선택 정적 프로파일, 대상 실행은 항상 금지로 확정됐다. 상태 표기도 `Pre-0.1`로 정정됐다. 아래 PR-01–12는 2026-07-15 당시 발견 기록이며, 현재 상태는 바로 아래 재대조 결과를 우선한다.

## 2026-07-18 결정 재대조

| 상태 | 항목 |
|---|---|
| 결정·문서 교정으로 해결 | PR-04 문자열 컨텍스트, PR-08 범위 분리, PR-09 완화 규칙 우선순위, PR-12의 초안 지위, `Plan Complete` 과장, 승인 후 대상 실행 경로 |
| 구현 전 해결 | PR-01·03·05–07·11의 신뢰 wrapper, 파서 substrate, TCB manifest, 자원 제한, 회귀 oracle과 임계값 |
| 저장소 공개·배포 전 해결 | PR-10의 reverse-skill LICENSE·provenance |
| 참고 자료 채택 때만 필요 | 동적 도구·실행 절차의 안전 계약(다른 주제별 리뷰 참조) |
| 부분 해결·재정의 | PR-02의 전체 DB 기본 포함은 폐기했고 남은 `MAL-` 팩 문제를 PR-14로 구체화 |
| 이번 재검증에서 추가 | PR-13 Windows 심볼릭 링크 배포, PR-14 OSV 데이터팩 인증·`MAL-` 생성·판정 계약, PR-15 읽기 시 접근 시각 변경, PR-16 에이전트 버전·스킬 링크 토폴로지 |

문서에서 “대상 분석 단계 네트워크 0”과 “Claude Code·Codex에 마스킹 근거 전달”이 동시에 적힌 모순은 직접 교정했다. 대상 분석 중 **로컬 엔진·정적 도구의 임의 네트워크는 0**이고, 분석 뒤 스키마를 통과한 마스킹 근거만 별도 중계 경로로 지원 에이전트에 전달할 수 있다.

## 결론

설치 전 대상 불간섭, 이분 실행 판정, 결정론적 로컬 분석과 제한된 AI 상관분석이라는 핵심 방향은 일관된다. 현재 문서는 스스로를 **`Pre-0.1` 기획 초안**으로 표시하므로 과장도 해소됐다. 다만 구현 준비 완료로 올리기 전에는 아래 계약을 닫아야 한다.

구현 전에 최소한 다음을 확정해야 한다.

1. Tier-1 도구의 **대상 제어 설정·ignore 파일을 무시하는 신뢰 wrapper**
2. 첫 OSV 생태계·최대 허용 나이와 프로젝트가 만들 `MAL-` 데이터팩의 생성·서명·갱신 방식
3. JSON·TOML·YAML을 구조 파싱할 실제 substrate·버전·배포 방식
4. 정의된 TCB의 버전·provenance·업데이트·rollback manifest와 격리 구현
5. 실행 가능한 픽스처·oracle·하네스로 성공 기준을 재현 가능하게 만들기
6. Windows에서 `.agents/skills`와 `.claude/skills`가 실제 디렉터리로 발견되는 배포 방식
7. 지원 파일시스템별 접근 시각을 포함한 원본 메타데이터 보존 방식
8. 스킬↔엔진과 보고서 JSON 스키마
9. Claude Code·Codex 최소 지원 버전과 실제로 지원되는 스킬 링크 토폴로지

## 우선순위별 발견 사항

### PR-01 · P0 · argv allowlist만으로는 Tier-1 미탐 우회를 막지 못함

- **영향**: 악성 대상이 자신의 설정·ignore 파일로 스캔 대상이나 취약점을 숨기면, 안전한 서브커맨드만
  호출해도 검사 결과가 조작된다.
- **근거**: `proposal.md` M5는 `osv-scanner scan`과 argv allowlist만 구속한다. 그러나 OSV-Scanner는 대상 주변의
  `osv-scanner.toml`에서 취약점·패키지 무시를 적용하며, 신뢰할 `--config`로만 이를 전역 덮어쓸 수 있다.
  Semgrep도 `.gitignore`·`.semgrepignore`를 존중하고 `.min.js`를 기본 제외한다. 이는 문서가 목표로 삼은
  minified `dist/` 검사와 직접 충돌한다. 설치 단계도 같은 문제를 가진다. pnpm의 `--ignore-scripts`는
  실행 가능한 `.pnpmfile.mjs`를 차단하지 않으며, v11은 버전 불일치 시 선언된 pnpm 다운로드가 기본이다.
  Yarn의 대상 `yarnPath`는 로컬 바이너리를 실행할 수 있고 `enableScripts: false`도 workspace `postinstall`은
  예외로 실행한다.
- **권고**: 도구별 wrapper가 (1) 절대경로·고정 버전 실행파일, (2) 대상 밖 신뢰 설정, (3) 신뢰 파일
  열거기, (4) 대상 읽기 전용·출력 외부화, (5) 정리된 환경변수·cwd, (6) 시간·메모리·출력 제한을
  강제하게 한다. OSV는 완전 무네트워크가 필요하면 `--offline-vulnerabilities`만이 아니라 `--offline`과
  의존성 해석 정책을 명시한다. pnpm wrapper는 `--ignore-pnpmfile --pm-on-fail=error`, Yarn wrapper는
  신뢰한 바이너리·`YARN_IGNORE_PATH=1`과 대상 밖 설정을 사용한다. 다만 Yarn workspace script 예외 때문에
  이 플래그들을 샌드박스 대체물로 보지 않는다. 악성 ignore/config·`.pnpmfile.mjs`·`yarnPath` 픽스처를
  수용 테스트로 추가한다.
- **출처**: [OSV-Scanner configuration](https://google.github.io/osv-scanner/configuration/),
  [OSV-Scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/),
  [Semgrep file targeting/ignore 동작](https://semgrep.dev/blog/2026/making-semgrep-rip-how-ripgrep-inspired-us-to-shave-hours-off-some-scans/),
  [pnpm `.pnpmfile.mjs`](https://pnpm.io/pnpmfile), [pnpm settings](https://pnpm.io/settings),
  [Yarn settings](https://yarnpkg.com/configuration/yarnrc/)

### PR-02 · 부분 해결 · 전체 OSV DB 번들은 초기 배포 목표와 충돌함

- **영향**: “제로 의존·어디서든 즉시·단일 배포”를 유지하면서 여러 생태계 `all.zip`을 함께 번들하기는
  크기·갱신·라이선스·무결성 운영상 현실적이지 않다. 오래된 DB는 오히려 잘못된 안심을 준다.
- **근거**: 2026-07-14 HTTP HEAD 실측으로 npm `all.zip`은 211,588,684 bytes, PyPI는 31,734,960 bytes,
  전체 `all.zip`은 1,341,291,934 bytes였고 같은 날 갱신됐다. OSV는 생태계별 dump와 증분
  `modified_id.csv`를 제공한다. 또한 `proposal.md`는 M4까지를 Tier-0라고 하면서 OSV 오프라인 통합을 M5에
  배치해 `capability-tiers.md`의 Tier-0 정의와 마일스톤이 서로 다르다.
- **권고**: 다음 중 하나를 결정한다. (A) `MAL-` 중심 소형 인덱스만 Tier-0에 번들, (B) OSV DB를
  버전된 별도 데이터팩/로컬 캐시로 배포, (C) OSV를 Tier-1로 재분류. 어느 안이든 `generated_at`,
  `max_age`, 생태계, 출처·라이선스, SHA-256/서명, 원자적 갱신, 신선도 경고를 데이터 매니페스트에
  기록한다.
- **출처**: [OSV data dumps](https://google.github.io/osv.dev/data/),
  [npm all.zip](https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip),
  [PyPI all.zip](https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip),
  [전체 all.zip](https://osv-vulnerabilities.storage.googleapis.com/all.zip)

현재 계획은 전체 DB를 기본 패키지에 넣지 않고 `MAL-` 중심으로 시작하는 방향을 채택했다. 첫 생태계·최대 허용 나이는 아직 미결이며, 전용 `MAL-` 공식 덤프가 없다는 추가 문제는 PR-14에서 다룬다.

### PR-03 · P0 · 제로 의존 구조 파싱 계약이 구현 가능하게 정의되지 않음

- **영향**: D1을 미결로 둔 채 JSON·TOML·YAML·언어별 매니페스트를 “정식 파서”로 읽겠다고 하면,
  M1 작업 단위·배포물·fail-closed 경계를 정할 수 없다.
- **근거**: Python 표준 `tomllib`은 3.11에 추가됐고 YAML 파서는 표준 라이브러리에 없다. `node`·`jq`도
  JSON 파서를 그대로 TOML/YAML 파서로 대체하지 못한다. 참고 구현 `docs/draft/scan.sh`의 실제 구조 파싱은
  `package.json`에 집중해 있다.
- **권고**: M1 전에 (A) Python 최소 버전+고정 파서를 번들한 실행물, (B) 단일 Go/Rust 바이너리,
  (C) 생태계별 보수적 narrow parser 중 하나를 고른다. 포맷별 지원 버전·중복 키·앵커·멀티라인·인코딩·오류
  처리와 파서 부재/오류 시 종료코드를 명세한다.
- **출처**: [Python `tomllib`](https://docs.python.org/3/library/tomllib.html),
  [Python 표준 라이브러리 인덱스](https://docs.python.org/3/library/index.html)

### PR-04 · 해결됨 · “문자열 제거”와 “문자열 디코드·실행흐름 추적”이 서로 모순됐음

- **영향**: 문자열 리터럴을 전체 제거하면 base64/URL/쉘 명령·`eval`로 흐르는 페이로드를 잃어 핵심
  미탐 전략이 작동하지 않는다.
- **당시 근거**: 종전 `proposal.md` §4.3은 “주석·문자열 리터럴 제거 후 매칭”을 요구하고, §4.4는 리터럴의 base64/hex를
  디코드하고 싱크까지 추적하라고 한다. B2도 주석·문서 코드와 실행 문자열을 하나의 “문자열”로 묶는다.
- **권고**: 전체 제거가 아니라 AST/CST 컨텍스트로 (1) 주석·문서는 비활성, (2) 실행 표현식의 리터럴은 유지,
  (3) 디코드 함수·프로세스/네트워크/동적 실행 sink로 도달하는 값을 별도 추적한다. B2를 “주석·문서”와
  “실행 식에서 sink로 도달하는 리터럴” 두 픽스처로 분리한다.

현재 기획은 주석·문서 문맥과 실행 표현식을 구분하고 제한 디코드 뒤 sink 상관분석을 요구하도록 고쳐졌다. 구현 픽스처는 PR-07에 남는다.

### PR-05 · 결정 해결·구현 필요 · 운영자 도구는 검증 제외가 아니라 TCB임

- **영향**: 분석기 자체가 탈취되면 신뢰하지 않는 파일을 읽는 것만으로도 임의 코드 실행·유출·결과 조작이
  가능하다. “의도해서 설치함”은 무결성 근거가 아니다.
- **당시 근거**: 종전 `proposal.md`·`research/README.md`·`capability-tiers.md`는 운영자 도구를 “검증 대상 아님”으로 절대화했다.
  OWASP는 빌드·패키지 관리·개발 도구를 공급망의 하부로 다루며, OSV-Scanner도 릴리스에 SLSA provenance를 제공한다.
- **권고**: “secure-onboard가 검사하는 target 범위 밖”과 “무검증 신뢰”를 분리한다. 도구별 소스·버전·해시/서명·
  provenance·업데이트 주기·롤백을 기록한 버전 고정 TCB 매니페스트를 두고, 분석기도 최소권한으로 실행한다.
- **출처**: [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html),
  [OSV-Scanner build provenance](https://google.github.io/osv-scanner/installation/)

현재 문서는 검사 엔진과 도구를 검증·고정할 TCB로 정의한다. 실제 매니페스트·격리·업데이트·rollback 구현은 아직 없다.

### PR-06 · P1 · “정적”이라도 악성 파서 입력·압축 폭탄을 가정해야 함

- **영향**: Semgrep·LIEF·rabin2·jadx·GuardDog·압축 해제기는 대상 코드를 “실행”하지 않아도 적대적 바이트를
  파싱한다. 파서 취약점·CPU/메모리 고갈·압축 폭탄·외부 출력 경로 쓰기는 S1/S2를 우회할 수 있다.
- **근거**: 종전 `capability-tiers.md`의 `upx -d`/`xz -d`는 원본 대상을 변경·삭제할 수 있었다. 이 항목은 복사본·
  `-o`/표준출력/`--keep`·크기 제한으로 직접 교정했지만, 나머지 Tier-1 도구에는 공통 자원 계약이 없다.
- **권고**: 모든 파서를 시간·RSS·파일 수·개별/총 출력크기·재귀 깊이 제한 아래에서 돌리고, 대상을 read-only로,
  cwd·임시·출력을 대상 밖으로 고정한다. 시간 초과·충돌·파싱 오류는 “안전”이 아니라 “미완료/fail-closed”로
  보고한다.
- **출처**: [UPX project](https://github.com/upx/upx), [XZ manual](https://tukaani.org/xz/man/xz.1.html)

### PR-07 · P1 · 회귀 코퍼스가 정량 KPI의 oracle로는 불완전함

- **영향**: 동일한 결과에도 구현자마다 통과/실패를 다르게 판정할 수 있어 “recall 100%, B 오탐 0”을 자동 게이트할
  수 없다. 문서만 있고 실행 증거가 없는 과거 통과 주장은 재현할 수 없다.
- **근거**: B 섹션은 “잡지 말 것/저등급”이라고 하면서 B3·B5에 MED를 허용하고 B4는 “감점”만 적어 정확한 값이
  없다. finding을 케이스 단위로 셀지 파일/규칙 적중 단위로 셀지도 미정이다. 저장소에는 실행 가능한
  픽스처/하네스가 없다. `proposal.md`의 “회귀 픽스처 전부 통과” 표현은 이번에 수동 시나리오 점검으로
  정정했다.
- **권고**: 각 픽스처에 기대 `rule_id`, 파일/라인, 정확한 등급·건수, 종료코드, 필수 rationale를 저장한다.
  발견 항목 단위 confusion matrix로 precision/recall/FPR/FNR를 정의하고 B3·B4·B5의 통과 값을 정확히 쓴다. M1 전 최소
  tracer-bullet 하네스를 두고 내부 주장은 명령·버전·출력으로 보존한다.
- **추가 재대조**: 종전 A7은 `node_modules/`가 동봉됐다는 사실 자체를 HIGH로 뒀다. 그러나 npm은
  `bundleDependencies`/`bundledDependencies`로 의존성을 정상적으로 패키지 tarball에 포함하는 기능을 공식 지원한다.
  동봉 의존성은 전부 검사해야 하는 강한 **검사 범위 신호**지만, 그 존재만으로 차단 근거가 되지는 않는다. 정상
  번들 의존성 B8과 데이터 경계 B9를 목표표에 추가하고, A7은 실제 설치 훅 도달성처럼 별도 근거가 있을 때만
  HIGH가 되도록 oracle을 이번에 분리했다. 실행 가능한 픽스처와 하네스는 여전히 필요하다.
- **추가 출처**: [npm `package.json`의 `bundleDependencies`](https://docs.npmjs.com/files/package.json/),
  [npm package contents](https://docs.npmjs.com/cli/publish/)

### PR-08 · 해결됨 · 단일 위협 목표와 확장 SAST 카탈로그의 범위가 달랐음

- **영향**: JWT/OAuth/SSRF, Android 설정, LLM 에이전시 등 범용 SAST를 코어 성공 기준에 포함하면 “설치 시점 자동
  실행 백도어” 탐지의 재현율·오탐 개선에 집중하기 어렵다.
- **근거**: `proposal.md` §1.1은 막으려는 위협을 하나로 고정하지만 §5와 `reverse-skill-harvest.md` §6–8은
  AI/LLM·API·모바일 보안 전반을 채택 후보로 넣는다.
- **권고**: 코어 게이트는 “설치/빌드/CI 트리거 → 코드 실행/네트워크/유출 sink”에 집중한다. 나머지는
  생태계 감지 후 명시적으로 켜는 선택 프로파일/Tier 모듈로 나누고, 코어 KPI와 모듈 KPI를 분리한다.

현재 D2와 제안서는 AI/LLM·API·mobile을 대상 유형별 선택 정적 프로파일로 분리하고 코어와 별도 검증하도록 고쳤다.

### PR-09 · 설계 해결·구현 필요 · 문자열 allowlist·디렉터리 감점은 도달성보다 우선할 수 없음

- **영향**: `prepare: "husky"`만 보고 INFO로 내리면, 신뢰할 수 없는 의존성이 같은 이름의 bin을 제공하거나 lockfile이
  변조된 경우를 놓친다. `testdata/`·`vendor/`라는 이유로 감점하면, 실제 install hook에서 도달하는 위장 파일을
  숨길 수 있다.
- **근거**: B1은 명령 문자열로만 allowlist를 적용하고, B4는 testdata 감점만 명세한다. 반면 W1은 install hook에서
  도달한 test 파일을 승격시켜야 함을 보여 규칙 우선순위가 문서 안에서도 명시적이지 않다.
- **권고**: 완화 신호는 승격 신호를 덮지 못하게 한다. hook에서 도달하면 test/vendor/minified 감점을 취소한다.
  패키지 allowlist는 이름 대신 정확한 패키지 식별정보·고정 버전·lockfile 무결성·해석된 registry·동봉 코드를 확인할 때만
  적용한다. 엔트로피·암호 상수는 독립 HIGH 근거가 아니라 최소 길이·파일 종류·도달성과 결합한 보조
  신호로만 사용한다.

현재 B1·B4와 W1은 정확한 의존성·lockfile·registry 근거와 실제 도달성을 우선하도록 고쳤다. 결정론적 구현과 회귀 픽스처는 아직 없다.

### PR-10 · P1 · reverse-skill 배포물의 라이선스·provenance가 불완전함

- **영향**: 업스트림 Markdown의 상당 부분을 저장소에 포함한 상태에서 제3자에게 공개·배포하면서 MIT 저작권·허가
  고지를 함께 보존하지 않으면 라이선스 요건 위반 소지가 있다. 어느 파일을 어떻게 수정했는지도 재현할 수 없다.
  제품 기능으로 채택하는지와 무관한 저장소 배포 문제다. 이 항목은 법률 자문이 아니며 배포 위험 표시이다.
- **근거**: 로컬 큐레이션판은 13개 모듈, Markdown 71개로 확인됐고 루트에 LICENSE 파일이 없다. 업스트림 정확한
  commit은 `fe2e2def5ec21dbda9d84f69c1ef8b20d53fc269`, 원본 MIT LICENSE는 고지 보존을 요구한다.
- **권고**: 저장소 공개·배포 전에 `LICENSE.upstream`(검증한 원문)과 파일별 upstream path·commit·SHA-256·로컬
  변경 요약을 담은 `PROVENANCE.md`/기계 판독 매니페스트를 추가한다. `SKILL.md`에는 이번에 정확한 commit URL과
  고지 보존 의무를 추가했지만, 실제 LICENSE 파일은 아직 필요하다.
- **출처**: [업스트림 고정 commit](https://github.com/zhaoxuya520/reverse-skill/commit/fe2e2def5ec21dbda9d84f69c1ef8b20d53fc269),
  [업스트림 MIT LICENSE](https://raw.githubusercontent.com/zhaoxuya520/reverse-skill/fe2e2def5ec21dbda9d84f69c1ef8b20d53fc269/LICENSE)

### PR-11 · P2 · 타이포스쿼팅 데이터의 모수·갱신 정책이 없음

- **영향**: “상위 N 인기 패키지”의 출처·N·기준일이 없으면 번들을 재현하거나 오탐률을 해석할 수 없다.
- **근거**: 지정한 ecosyste.ms 데이터셋은 인기 패키지 전체 목록이 아니라, 표적과 악성 이름이 확인된 143개
  큐레이션 항목이다.
- **권고**: 테스트용 확정 타이포 목록과 운영용 인기 패키지 모수를 분리한다. 생태계별 출처, 스냅샷 commit/날짜,
  라이선스, N, 정규화·거리 규칙, 예외, 갱신 주기를 기록한다.
- **출처**: [ecosyste.ms typosquatting dataset](https://github.com/ecosyste-ms/typosquatting-dataset),
  [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages)

### PR-12 · 해결됨 · 초안과 제품 스킬 등록 방식이 섞여 있었음

- **영향**: `SKILL.md`나 `draft/`만 복사하면 `../plan`·`../research`가 깨지고, 다른 cwd에서 `docs/draft/scan.sh`를
  실행하면 스크립트를 찾지 못한다. 심볼릭 해석 방식은 에이전트/로더에 따라 다를 수 있다.
- **근거**: `draft/README.md`의 “복사” 안내는 이번에 제거했지만, `draft/SKILL.md`의 빠른 시작과 구성 참조는 여전히
  저장소 루트 배치를 가정한다.
- **해결**: 후자를 채택해 `docs/draft/` 전체를 참고 자료로 명시했다. 실제 제품 스킬은 아직 없으며
  `.skills/secure-onboard/SKILL.md`에 새로 만들 예정이다. 다만 선택한 심볼릭 링크 배포의 Windows 문제는
  PR-13으로 분리한다.

### PR-13 · P0 · Git 심볼릭 링크만으로는 Windows 스킬 발견을 보장하지 못함

- **영향**: Windows에서 `.agents/skills`나 `.claude/skills`가 디렉터리 링크가 아니라 `../.skills`라는 문자열을
  담은 일반 파일로 체크아웃되면 Codex와 Claude Code 모두 제품 스킬을 발견하지 못한다. 공용 정본 결정은 유지되지만
  현재 배포 수단만으로는 Windows 지원 계약을 충족하지 못한다.
- **근거**: Codex는 저장소의 `.agents/skills`, Claude Code는 `.claude/skills`를 공식 프로젝트 경로로 사용한다.
  Git은 `core.symlinks=false`에서 링크를 작은 일반 파일로 체크아웃한다. Git for Windows는 Developer Mode 또는
  적절한 권한이 없으면 심볼릭 링크 지원이 기본 비활성화될 수 있다. 현재 macOS 작업트리와 Git index의 mode
  `120000`을 확인했고, 별도 임시 clone에 `core.symlinks=false`를 강제하자 세 링크가 모두 일반 파일이 되며
  `.agents/skills` 내용이 `../.skills` 한 줄로 남는 실패도 재현했다. 실제 Windows 호스트 검증은 아직 없다.
- **권고**: Windows·macOS tracer-bullet에서 깨끗한 clone과 ZIP 배포를 각각 검사한다. 실패하면 (A) 서명된 설치기가
  플랫폼별 링크/정션을 만들거나, (B) 생성된 두 디렉터리를 CI가 byte-for-byte 동기화하는 방식 중 하나를 선택한다.
  사용자에게 Developer Mode나 관리자 권한을 암묵적으로 요구하지 않는다.
- **완료 기준**: 기본 Windows 사용자 환경과 macOS에서 두 에이전트가 같은 skill version/hash를 발견하고,
  링크가 일반 파일이면 설치 전 검사가 명시적으로 실패해야 한다.
- **출처**: [Codex skills](https://learn.chatgpt.com/docs/build-skills.md),
  [Claude Code skills](https://code.claude.com/docs/en/skills),
  [Git `core.symlinks`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-coresymlinks),
  [Git for Windows known issues](https://github.com/git-for-windows/build-extra/blob/main/ReleaseNotes.md),
  [Windows symbolic-link privilege](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsymboliclinka)

### PR-14 · P0 · OSV 체크섬과 `MAL-` 데이터팩의 공급자 인증 계약이 없음

- **영향**: 내려받은 파일에 로컬 SHA-256만 계산하면 같은 파일을 다시 식별할 수는 있지만, 공격자가 바꾼 파일이
  공식 원본이라는 사실까지 증명하지는 못한다. 또한 OSV는 전체·생태계별 덤프를 제공할 뿐 전용 `MAL-` 소형 팩을
  제공하지 않아, 현재 권장안에는 아직 생성 주체가 없다.
- **근거**: OSV 데이터 문서는 `all.zip`, 생태계별 `all.zip`, `modified_id.csv`를 문서화한다. GCS는 객체 응답에
  CRC32C와 가능한 경우 MD5를 `x-goog-hash`로 제공하지만 OSV 덤프의 별도 서명은 문서화하지 않는다. OpenSSF
  Malicious Packages는 OSV 레코드 저장소이며 릴리스 아카이브가 아니라 commit 단위 원자료다. 이 저장소 자체도
  악성이 명확하지 않은 경계성 typosquatting·spam·난독 패키지가 포함될 수 있고, 부분 버전 오탐 처리는 아직
  미완성이라고 명시한다. 따라서 철회되지 않은 `MAL-` 이름·버전 일치만으로 A10을 곧바로 차단하던 종전 oracle은
  데이터가 실제로 뒷받침하는 범위보다 강했다.
- **권고**: 공식 HTTPS origin과 GCS 객체 generation/체크섬을 확인하고 로컬 SHA-256을 provenance로 기록한다.
  작은 `MAL-` 팩은 고정 commit의 OpenSSF 레코드에서 재현 가능하게 생성하고, 철회·경계 사례를 처리한 뒤 프로젝트
  릴리스 키로 서명한다. ingestion 시 `withdrawn`과 `database_specific`의 부분 버전 오탐을 보존하고,
  확인된 악성·경계 사례·분류 미완료를 구분한다. 단독 차단 가능한 레코드 기준을 고정하거나, 경계 레코드는 별도
  정적 증거가 있을 때만 차단한다. 클라이언트는 내장 공개키로 팩 서명을 검증하고 실패하면 OSV 검사를 미완료 처리한다.
- **완료 기준**: 정상 팩, 바이트 손상, 이전 generation replay, 잘못된 서명, 철회 레코드와 부분 버전 오탐을 포함한
  픽스처 및 경계성 레코드가 각각 정책에 맞는 finding과 최종 판정으로 수렴해야 한다.
- **출처**: [OSV data dumps](https://google.github.io/osv.dev/data/),
  [Cloud Storage checksums](https://cloud.google.com/storage/docs/data-validation),
  [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)

### PR-15 · P0 · 읽기 전용만으로 “타임스탬프 변경 0”을 보장할 수 없음

- **영향**: 현재 S2는 내용·권한·타임스탬프·메타데이터 변경 0을 불변식으로 둔다. 그러나 파일시스템에 따라 파일을
  읽는 행위가 마지막 접근 시각을 갱신하므로, 해시·파싱 자체가 불변식을 깨뜨릴 수 있다. 단순히 쓰기 권한을 제거한
  디렉터리를 읽었다는 사실은 이 요구의 증거가 아니다.
- **근거**: macOS `mount`는 읽을 때 접근 시각을 갱신하지 않는 별도 `noatime` 옵션과 항상 갱신하는
  `strictatime` 옵션을 문서화한다. Windows도 NTFS Last Access Time 갱신을 켜고 끄는 볼륨 정책을 제공하며,
  NTFS 외 파일시스템의 동작도 같다고 가정할 수 없다.
- **권고**: “원본 보존”에 접근 시각이 포함되는지 계약으로 명시한다. 포함한다면 지원 파일시스템별 no-atime
  읽기 전용 뷰, 불변 snapshot 또는 동등한 수단을 마련하고, 사전 확인이 불가능한 환경에서는 대상을 열기 전에
  필수 검사 미지원으로 `위험` 처리한다. 포함하지 않는다면 사용자 결정으로 불변식과 보고서 문구를 함께 좁혀야 한다.
- **완료 기준**: Windows·macOS의 지원 파일시스템 행렬에서 내용·권한·수정·생성·접근 시각을 전후 비교하고,
  접근 시각 갱신을 강제한 픽스처가 보존 수단 없이는 fail-closed 되는 것을 입증한다.
- **출처**: [macOS `mount` noatime/strictatime](https://keith.github.io/xcode-man-pages/mount.8.html),
  [Windows `fsutil behavior disablelastaccess`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior)

### PR-16 · P0 · 지원 에이전트 버전과 현재 스킬 루트 링크 토폴로지가 계약에 없음

- **영향**: Git 심볼릭 링크가 정상 체크아웃돼도 에이전트가 링크된 스킬 루트를 탐색하지 않으면 제품 진입점이
  사라진다. “특정 버전을 가정하지 않는다”는 배포 원칙만으로는 공식 지원이 추가되기 전 버전과 토폴로지 차이를
  처리할 수 없다.
- **근거**: Codex의 현재 공식 저장소 경로는 `.agents/skills`이고 공식 문서는 심볼릭 링크된 스킬 폴더를 지원한다고
  설명한다. Claude Code의 현재 프로젝트 경로는 `.claude/skills`지만, 공식 문서가 명시한 심볼릭 링크 지원은
  **그 디렉터리 안의 개별 `<skill-name>` 항목**이 다른 디렉터리를 가리키는 경우뿐이며 최소 버전 요건을 달지 않는다. (공식 문서의 `2.1.203 이상` 요건은 심볼릭 링크가 아니라 디렉터리-한정 중첩 스킬 변형을 미한정 이름으로 호출하는 별개 기능에 대한 것이다.) 현재 저장소는
  개별 항목이 아니라 `.agents/skills`와 `.claude/skills` 루트 자체를 `../.skills`로 연결한다. 2026-07-18 로컬
  환경은 Claude Code 2.1.210이고 현재 Codex 세션은 `sample` 스킬을 발견했지만, 이는 Claude의 루트 링크 발견이나
  Windows·깨끗한 clone의 동작을 증명하지 않는다.
- **권고**: 지원할 Claude Code·Codex 최소 버전을 명시하고, (A) 공식 경로를 실제 디렉터리로 만든 뒤 그 안의
  개별 스킬을 정본에 링크하거나, (B) 설치기가 플랫폼에 맞는 링크/정션을 만들거나, (C) 생성된 복사본의 hash를
  CI가 강제하는 방식 중 tracer-bullet을 통과한 하나를 고른다. PR-13의 `core.symlinks=false`와 함께 검사하되,
  “링크 대상이 같다”와 “두 에이전트가 발견·실행한다”를 별도 assertion으로 둔다.
- **완료 기준**: 정한 최소·최신 지원 버전과 Windows·macOS의 깨끗한 clone/ZIP에서 두 에이전트가 동일한
  skill hash를 보고하고, 지원하지 않는 버전·일반 파일·깨진 링크는 제품 검사를 시작하기 전에 명시적으로 실패한다.
- **출처**: [Codex skills](https://learn.chatgpt.com/docs/build-skills.md),
  [Claude Code skills](https://code.claude.com/docs/en/skills)

## 이번 검토에서 발견되어 직접 교정된 항목

- 결정 레지스터가 “모두 미결”이라고 하면서 D3·D4·D7을 확정한 문서 모순을 정정했다.
- `precision`을 오탐률, `recall`을 미탐률로 부른 용어 오류를 정밀도·재현율로 정정하고 FPR/FNR을 분리했다.
- B3·B5에 저등급 finding을 허용하면서 “B 오탐 0”이라고 한 회귀 게이트를 기대 finding tuple과 단독 차단 오분류 기준으로 정정했다.
- 저장소에 실행 하네스가 없는데 “회귀 픽스처 전부 통과”라고 한 주장을 수동 시나리오 점검으로 정정했다.
- `find` 전체가 `-print0`라는 과장을 “보안 관련 파일 열거”로 정확히 제한했다.
- Docker 예시가 원본 target을 RW mount하고 `npm install`·테스트하던 문제를 read-only 원본 + 일회용
  volume + 이미지 digest + 테스트 네트워크/권한 축소 흐름으로 교체했다.
- Bun은 미신뢰 dependency script를 기본 차단하지만 주요 인기 패키지 수백 개(현재 기본 신뢰 목록 약 370개)의 기본 신뢰 목록이 있음을 반영했고,
  `allowBuilds`를 pnpm 10.26+/11으로 버전화했다.
- pnpm의 `.pnpmfile.mjs`와 자동 package-manager 다운로드를 함께 차단하도록
  `--ignore-pnpmfile --pm-on-fail=error`를 추가했다. Yarn은 `yarnPath`와 workspace script 예외 때문에
  `enableScripts: false`만으로 안전하다고 보지 않도록 정정했다.
- `pip-audit`의 `--no-deps`·`--require-hashes`·`--locked`를 동시 강제하던 오류를 requirements/lockfile별 서로 다른
  안전 모드로 정정했고 `--disable-pip`을 명시했다.
- `nm`·`otool`을 모든 macOS에 보장된다고 가정하지 않도록 CLT 감지형으로 정정했다.
- `upx`/`xz`/`zstd` 언팩이 원본 target을 변경·삭제할 수 있는 문제를 대상 밖 복사본·출력 지정·크기 제한으로
  정정했다.
- `draft/` 복사 시 상대 참조가 깨지는 안내를 제거했고, reverse-skill에 정확한 upstream commit URL과
  MIT 고지 보존 요건을 추가했다.
- 보고서의 Docker 실행 환경에 image digest를 기록하도록 템플릿을 정정했다.
- 보고서가 실패 상태에서도 사실을 기록할 수 있도록 원본 보존·외부 전송 확인을 고정된 “없음” 대신
  `없음/확인 실패`로 바꾸고, 조건부 검사에 `해당 없음` 상태와 사용 조건을 추가했다.
- 워크플로가 대상을 열기 전에 파일시스템 접근 시각 정책과 보존 수단을 확인하고, 입증할 수 없으면 대상을 열지 않은 채 `위험`으로 끝내도록 누락 단계를 추가했다.
- 제안서의 의미가 불분명한 “로컬/승인 비유출 AI”를 “허용된 마스킹 근거를 통한 AI 상관분석”으로 정정했다.
- 정상 번들 의존성과 경계성 `MAL-` 레코드가 존재만으로 차단되던 A7·A10을 정정하고 B8·B9 반례를 추가했다.
- 공식 OSV 덤프의 GCS 체크섬과 프로젝트 자체 `MAL-` 팩의 릴리스 서명·원본 commit·disposition 검증을 같은 “공식 데이터팩”으로 뭉뚱그리지 않도록 갱신 플로우를 분리했다.
- 원문에 프롬프트 인젝션 문자열이 있다는 사실과 그것이 모델 제어 채널에 도달한 검사기 무결성 실패를 구분했다.
- 업스트림에 두 `bootstrap-reverse.sh`가 있어 613줄 실측 대상을
  `skills/scripts/bootstrap-reverse.sh`로 정확히 적었다.

### 현행 `scan.sh`와의 문서 대조에서 발견된 보안 회귀

아래 항목은 검토 중 기준 버전에서 발견됐고, 현재 작업트리의 `scan.sh` 수정으로 해소되었다. 아직 저장소에
회귀 하네스가 없으므로 각 항목을 고정 픽스처로 보존해야 한다.

- 대상 cwd에서 `python3` 호출 시 대상이 제공한 `json.py`/`sitecustomize`가 로드될 수 있었음 → `python3 -I`.
- 대상 밖 `--out` 기존 symlink·hardlink가 대상 내부 파일을 가리키면 쓰기 가드를 우회함 → 기존 경로 거부와 noclobber 새 파일 생성.
- `find_source_files`가 `dist/`·`build/`를 제외해 기획이 탐지하려는 minified 배포물을 건너뜀 → 해당 prune 제거.
- `node .husky/...`를 정상 훅 도구로 감점하면 대상 JS를 실행하는 명령을 안전하게 보는 문제 → 단일
  알려진 bin 이름으로 축소.
- `NODE_OPTIONS=--require ...`로 parser 실행 전 대상 코드를 로드할 수 있음 → `NODE_OPTIONS`·`NODE_PATH` 정리.

## 공식 출처로 확인한 기타 사실

- LinkedIn 채용 사칭 사례의 `prepare → app:pre → app/index.js → app/test/index.js`, 서버 응답 실행,
  도용된 신원의 39개 commit 설명은 원문과 일치한다:
  <https://roman.pt/posts/linkedin-backdoor/>
- Bun의 dependency lifecycle 정책은 “모두 기본 금지”가 아니라 기본 신뢰 목록을 포함한다:
  <https://bun.sh/docs/pm/lifecycle>
- pnpm `allowBuilds`는 10.26에 추가됐고 v11에서 기존 build allowlist 설정을 대체한다:
  <https://pnpm.io/settings>
- pnpm의 `ignoreScripts`는 `.pnpmfile.mjs`를 막지 않으며 `ignorePnpmfile`을 함께 쓰도록 공식 문서가 권고한다:
  <https://pnpm.io/pnpmfile>
- Yarn modern의 `yarnPath`는 대상 바이너리를 실행할 수 있고 `enableScripts: false`도 workspace script는
  예외로 둔다:
  <https://yarnpkg.com/configuration/yarnrc/>
- `pip-audit -r`은 안전한 단순 텍스트 대조가 아니라 pip resolution과 유사한 신뢰 모델을 갖는다. 고정
  requirements와 lockfile 모드를 구분해야 한다: <https://github.com/pypa/pip-audit>
- capa의 현재 지원 형식에 Mach-O는 포함되지 않아 `capability-tiers.md`의 제한 표기는 올바르다:
  <https://github.com/mandiant/capa>
- TruffleHog verification을 끄는 `--no-verification` 안전 조건은 현재 CLI에도 존재한다:
  <https://github.com/trufflesecurity/trufflehog>
- Docker bind mount는 기본적으로 host 파일에 쓸 수 있고 `readonly`/`ro`로 명시해야 읽기 전용이 된다:
  <https://docs.docker.com/engine/storage/bind-mounts/>

## 파일별 검토 체크리스트

| 파일 | 검토 | 결과 |
|---|---:|---|
| `docs/plan/decisions.md` | ☑ | 확정·미결 분리. 에이전트 버전·링크 배포와 OSV 데이터팩 계약은 남음 |
| `docs/plan/proposal.md` | ☑ | Pre-0.1 범위 정합화. PR-01·03·05–07·11·13–16은 구현 전 해결 필요 |
| `docs/plan/report-template.md` | ☑ | 실패·해당 없음 상태까지 표현하도록 교정. 정확한 JSON 스키마는 미결 |
| `docs/plan/use-cases.md` | ☑ | 목표/현행 분리 및 정상 동봉 의존성·`MAL-` 경계 oracle 교정. 실행 픽스처·하네스 필요 |
| `docs/plan/workflow.md` | ☑ | 로컬 엔진 네트워크 차단과 지원 에이전트 중계 경로 분리. 실제 격리 구현은 미완료 |
| `docs/research/README.md` | ☑ | 현재 결정과 정합. 로컬 엔진 네트워크와 지원 에이전트 경로를 분리 |
| `docs/research/capability-tiers.md` | ☑ | 도구 지형은 유용. OSV 팩 인증·설정 신뢰·자원 계약은 미해결 |
| `docs/research/osv.md` | ☑ | 공식 덤프·오프라인 모드·GCS 체크섬 확인. 전용 MAL 팩과 배포 서명은 미해결 |
| `docs/research/reverse-skill-harvest.md` | ☑ | 13개 모듈/Markdown 71개 수 확인. AI/API/mobile 선택 프로파일 분리 반영 |
| `docs/research/threat-catalog.md` | ☑ | 번들·`MAL-`·프롬프트 인젝션의 단독 차단 과장을 교정. 임계값·allowlist는 구현 전 고정 필요 |
| `docs/draft/README.md` | ☑ | 깨지는 복사 안내 제거. 자체 완결형 배포는 PR-12 참조 |
| `docs/draft/SKILL.md` | ☑ | 등록하지 않는 참고 초안으로 지위 명확화 |
| `docs/draft/reverse-skill/SKILL.md` | ☑ | 정확한 commit URL·MIT 요건 추가. 실제 LICENSE/provenance 파일 필요 |
| `docs/draft/reverse-skill/routing.md` | ☑ | 제품 라우터가 아닌 참고 분류표로 지위 명확화. 동적 절차는 제품 밖 |

## 링크·출처·실측 검증 결과

- 지정 범위의 Markdown 상대 링크: 깨진 링크 없음.
- reverse-skill 로컬 큐레이션판: 13개 모듈, 모듈 Markdown 69개, 전체 Markdown 71개, 비-Markdown 파일 0개.
- 업스트림 commit·날짜·MIT LICENSE 확인. `skills/scripts/bootstrap-reverse.sh` 613줄, `kali/scripts/bootstrap-reverse.sh`
  538줄로 경로를 정확히 구분함.
- 저장소에 실행 가능한 코퍼스 픽스처·회귀 하네스는 없음. 문서 읽기·링크 검증 외의 KPI 통과는 주장하지 않음.

## 현재 구현 전 결정 질문

1. Python 번들 또는 단일 Go/Rust 바이너리 중 어느 substrate가 두 운영체제 tracer-bullet을 통과하는가?
2. 모델 밖 대상 선택 UI/CLI와 스킬↔엔진 도구 스키마를 어떻게 고정할 것인가?
3. 어떤 Claude Code·Codex 버전을 최소 지원하며, Windows·macOS에서 단일 스킬 정본을 두 공식 경로에 안전하게 배포할 토폴로지는 무엇인가?
4. 원본 보존에 접근 시각을 포함할 것인가? 포함한다면 지원 파일시스템별 보존 수단은 무엇인가?
5. 첫 OSV 생태계와 최대 허용 나이는 무엇이며, `MAL-` 팩을 누가 생성·서명·갱신하는가?
6. 필수 검사 목록, 차단 규칙·임계값, finding 단위와 최종 판정 oracle은 무엇인가?
7. 보고서 JSON 스키마와 TCB 버전·provenance·업데이트 소유자는 무엇인가?
