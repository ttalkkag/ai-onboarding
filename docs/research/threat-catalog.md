# 위협 체크리스트

`docs/draft/scan.sh`가 자동으로 검사하는 항목과, 사람이 추가로 봐야 하는 항목.

## 스캐너가 자동 검사 (휴리스틱)

| # | 항목 | 기본 등급 | 근거 |
|---|------|-----------|------|
| 1 | 저장소에 `node_modules/` 포함 | HIGH | 변조된 의존성을 그대로 실행시키려는 시도일 수 있음 |
| 2 | 설치 라이프사이클 훅 `preinstall`/`install`/`postinstall`/`prepare` | HIGH | `npm install` 만으로 임의 코드 실행 (글의 핵심 벡터) |
| 2b | 동일 훅이 husky/lefthook 등 알려진 도구 | INFO | 오탐 완화 — 그래도 값 확인 |
| 3 | `curl … \| sh` 등 다운로드-후-실행 | HIGH | 원격 코드 실행 |
| 4 | 원시 IP(`http://1.2.3.4`)로의 연결 | HIGH | C2 서버 의심 |
| 5 | `eval()` / `new Function()` | MED | 동적 코드 실행 |
| 6 | `base64` 디코딩 / `atob` / `Buffer.from(...,'base64')` | MED | 페이로드 은닉 |
| 7 | `child_process`/`exec`/`spawn`/`subprocess`/`os.system` | MED | 외부 프로세스 실행 |
| 8 | 환경변수 + 네트워크 전송 인접 | MED | 비밀정보 유출 |
| 9 | 지갑/키/시드 식별자(`PRIVATE_KEY`,`MNEMONIC` 등) | INFO | 암호화폐 타깃 공격 흔함 |
| 10 | 커스텀 `.npmrc`(registry/token 재정의) | MED | 신뢰 불가 레지스트리 유도 |
| 11 | 테스트 경로 위장 + 설치 훅에서 로드되는 파일 또는 비대/초장문/난독 파일 | MED | LinkedIn 사례의 `app/test/index.js`는 테스트 스위트 위장 + `prepare` 경로에서 로드됨. 크기 임계값은 합성 스트레스 신호로만 사용 |
| 12 | 초장문 라인(>5000자) | MED | 난독화/패킹된 코드 |

> 휴리스틱은 **오탐·미탐이 모두 가능**하다. HIGH/MED는 사람이 파일을 열어 확정해야 하고,
> "신호 없음"이 "안전 증명"은 아니다.

## 사람이 추가로 검토

- **라이프사이클 훅 실체**: 훅이 부르는 스크립트 파일을 끝까지 따라가 무엇을 하는지 확인.
- **의존성 신뢰도**: 처음 보는 패키지명, 타이포스쿼팅(`expresss`, `lodahs`), 최근 생성된 패키지.
- **git 메타데이터**: 커밋 작성자/이메일이 도용된 신원인지, 커밋 히스토리가 부자연스러운지
  (글의 사례는 실존 개발자 신원을 도용한 커밋 39개).
- **요청 맥락**: 채용/면접 사칭으로 "빨리 돌려보라"는 압박이 있었는지 — 의심을 건너뛰게 만드는 사회공학.
- **네트워크 목적지**: 외부로 나가는 모든 URL/호스트가 정당한지.
- **인코딩된 문자열**: base64/hex 블롭을 실제로 디코딩해 내용 확인(읽기 전용으로).
- **빌드/CI**: `Dockerfile`, `.github/workflows`, `Makefile`에 숨은 설치-시 실행 단계.
- **패키지 매니저 정책**: npm `--ignore-scripts`/`min-release-age`, pnpm `allowBuilds`/`minimumReleaseAge`, Bun `trustedDependencies`/`minimumReleaseAge`, Yarn `enableScripts`/`npmMinimalAgeGate` 등 버전별 차단 기능을 확인.

## 안전 수칙 (글의 교훈)

- 낯선 사람의 "코드 리뷰" 요청은 **로컬 대신 샌드박스/일회용 VPS**에서.
- 설치 시 **라이프사이클 훅 차단**(`--ignore-scripts`)을 기본값으로.
- 피곤하거나 급할 때 `npm install`을 반사적으로 치지 않기 — 누구나 표적이 될 수 있다.
- 읽기 전용 도구도 만능이 아니다. 자동 검사 + 사람 검토를 함께.
