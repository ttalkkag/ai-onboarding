# 작업 게이트 위협 카탈로그

> 상태: **M1·M2 규칙 후보 목록**. 실제 단계와 rule ID·oracle은 `../plan/use-cases.md`가 정본이다.

## 등급 원칙

- `HIGH`: 현재 요청한 작업에서 중대한 피해 경로가 확인됐거나 검사를 신뢰할 수 없음
- `LOW`: 사용자가 알아야 할 단독 신호·민감정보·불확실성이 있으나 즉시 차단 근거는 아님
- `INFO`: 경고할 근거가 없거나 범위 설명용 사실

단일 문자열이나 “검증되지 않음”만으로 HIGH를 만들지 않는다. 실행·설치·열기 진입점에서 위험 sink까지 도달하는지, 확정 악성 데이터와 일치하는지, 정상 반대 근거가 있는지를 함께 본다.

## 결정론적 규칙 후보

| # | 항목 | 기본 등급 | HIGH 승격 조건 |
|---|------|-----------|----------------|
| 1 | 동봉 `node_modules`·vendor 의존성 | INFO | 요청한 action에서 변조·위험 script까지 도달 |
| 2 | `preinstall`·`install`·`postinstall`·`prepare` | LOW | 현재 install에서 외부 실행·유출 sink까지 도달 |
| 3 | PEP 517 backend, `setup.py`, `build.rs`, Make 기본 target | LOW | 현재 build/install에서 위험 sink까지 도달 |
| 4 | CI `run`, `pull_request_target`, shell injection | LOW | 신뢰하지 않은 PR code·artifact가 privileged token·secret이 있는 환경에서 실행되는 경로 확인 |
| 5 | `curl … \| sh` 등 다운로드 후 실행 | HIGH | 기본 HIGH — 명령이 현재 action에서 도달 가능해야 함 |
| 6 | 원시 IP·의심 도메인 | LOW | 프로세스 실행·2차 payload·비밀 유출과 연결 |
| 7 | `eval`, `new Function`, `exec`, `spawn`, `subprocess`, `os.system` | LOW | 불신 입력·다운로드 payload가 sink에 도달 |
| 8 | base64·hex·문자열 조립·초장문·고엔트로피 | LOW | 디코드 결과가 실행·유출 sink에 도달 |
| 9 | credential source에서 network sink로 흐름 | HIGH | 기본 HIGH — 실행 가능한 source→sink 경로 필요 |
| 10 | token·key·password·내부 URL·운영 설정의 존재 | LOW | 외부 전송 또는 위험 명령 인자로 연결 |
| 11 | registry·package manager 설정 재정의 | LOW | 공격자 registry에서 받아 즉시 실행하는 경로 확인 |
| 12 | 비철회 확정 악성 레코드의 정확한 생태계·이름·영향 버전 일치 | HIGH | 데이터 출처·버전·disposition 검증 필요 |
| 13 | 앱에서 기대한 lockfile 누락·변조, direct URL, dependency confusion 신호 | LOW | library처럼 lockfile 미체크인이 정상인 문맥을 제외하고 실제 공격자 source·payload와 결합 |
| 14 | 확장자와 실제 형식 불일치·동봉 실행파일·native module | LOW | 요청한 open/execute에서 실행 코드에 도달 |
| 15 | 고정 EICAR 단일 파일 시그니처 | HIGH | commit/path/68 bytes/content SHA-256가 모두 일치하는 정적 fixture oracle 전용; 실제 악성코드 주장은 금지 |
| 16 | 대상 텍스트가 사용자 승인·정책 채널로 승격됨 | HIGH | 단순 prompt 문자열이 아니라 실제 command origin/재확인 상태 변경이 관찰됨 |
| 17 | scanner·parser·로그 오류 또는 timeout | HIGH | 보호 action은 deny, read-only scan은 HIGH finding report; adapter 자체가 실행되지 못한 경로는 비보장 |
| 18 | npm 12+ 대상이 install script 기본 차단을 선제 해제 (`package.json`의 `allowScripts`, `.npmrc`의 `allow-scripts`, `dangerously-allow-all-scripts`) | LOW | 해제된 script가 현재 install에서 외부 실행·유출 sink까지 도달 |
| 19 | AI 에이전트 설정·MCP 자격증명 파일을 읽어 외부로 보냄 (`.claude.json`, `.cursor/mcp.json`, `.config/zed/settings.json`, VS Code `.mcp.json` 등) | LOW | 9번과 동일 기준 — credential source에서 network sink까지 실행 가능한 경로 확인 |

설치 훅 자체는 정상 패키지에도 흔하므로 존재만으로 HIGH가 아니다. 반대로 확정 악성 레코드와 정확히 일치하거나 현재 작업이 위험 sink까지 도달하면 HIGH다.

### install script 신호의 양방향 한계

2번과 18번은 **한쪽 방향으로만** 쓴다. lifecycle script의 **존재**는 LOW 신호지만 **부재는 안전 근거가 아니다.**

- 악성 코드가 lifecycle script 대신 **module body**에 있으면 script 검사로는 걸리지 않는다. `--ignore-scripts`로도 막히지 않는다.
- `binding.gyp`가 있고 자체 `install`·`preinstall`이 없으면 npm이 `node-gyp rebuild`를 암묵적 install 명령으로 만든다. `scripts`가 비어 있어도 코드가 실행된다.

18번은 특히 **완화가 아니라 탐지 지점**이다. npm 12의 기본 차단을 해제하는 스위치는 대상 저장소의 `package.json`·`.npmrc`에 있고, 이 제품의 대상은 방금 받은 신뢰 불가 저장소이므로 그 파일은 공격자 통제 하다. name-only 승인 엔트리는 특정 버전이 아니라 이후 모든 버전을 허용하며, `npx`·`npm exec`에는 이 게이트 자체가 없다. 따라서 "npm이 기본 차단하므로 안전"으로 축약하지 않고 effective 설정을 판정 입력으로 읽는다. 이는 아래 "프로젝트 설정·ignore·환경 주입을 신뢰하지 않는다" 규칙과 11번의 구체화다.

근거와 1차 출처는 `external-harness-harvest.md` §C3·§C4에 있다.

## AI 상관분석 후보

아래 항목을 실제 실행 게이트 판정에 연결하는 기능은 M2 후보다. M1의 AI는 설명을 도울 뿐 로컬 판정을 바꾸지 않는다.

- 사용자 요청, AI 후보, 실제 tool input의 명령 출처를 구분한다.
- lifecycle·build·open 진입점에서 실제 호출 파일과 sink까지 연결한다.
- 주석·문서 예시·test fixture와 실행 가능한 표현을 구분한다.
- 제한적으로 디코드한 값을 process·network·exfiltration sink와 연결한다.
- 비밀값의 종류·위치·사용 흐름을 확인하되 로컬 로그에는 값 자체를 남기지 않는다.
- 정상 도구 allowlist는 이름만 믿지 않고 정확한 dependency·version·lockfile 근거와 함께 본다.
- 대상 자연어가 사용자 재확인이나 command origin을 변경하지 못하게 한다.

AI는 외부 프로젝트 원문을 Claude Code·Codex의 정상 데이터 흐름 안에서 분석할 수 있다. 이 사실 자체는 검사기 무결성 실패가 아니다. 실패는 대상 콘텐츠가 제어 채널로 승격돼 실제 tool call·판정·재확인 상태를 부당하게 바꾼 경우다.

## 작업 판정 연결

- 복수 finding은 `HIGH > LOW > INFO` 중 최댓값을 사용한다.
- 결정론적 HIGH는 AI가 낮추지 못한다.
- M2의 검증된 AI assessment만 추가 상관 근거로 LOW·INFO를 HIGH로 높일 수 있다.
- HIGH만 PreToolUse에서 deny한다.
- LOW는 실행 전 경고 후 계속하고 INFO는 기록 후 계속한다.
- LOW·INFO의 continue는 Claude Code·Codex 자체 approval을 자동 승인하지 않는다.

## 검사기가 지켜야 할 규칙

- 실제 판정은 PreToolUse tool input을 기준으로 한다.
- allow/deny 판정은 명령 문자열의 prefix·root command가 아니라 argv 구조를 파싱해 정한다. pipe, `;`, `&&`, command substitution, heredoc과 `bash -c` 내부를 각각 본다. prefix 매칭은 보안 통제가 아니다(`external-harness-harvest.md` §C10).
- 검사 과정에서 대상 install·build·open·execute를 대신 수행하지 않는다.
- 프로젝트 설정·ignore·환경 주입을 신뢰하지 않는다.
- 명령 원문·비밀값·소스 원문·절대 경로를 로그·캐시에 저장하지 않는다.
- 대상 repo 안에 activation state·로그·캐시를 쓰지 않는다.
- 캐시 hit여도 HIGH 차단·LOW 경고·매 시도 event를 반복한다.
- HIGH 명령 제공 뒤 AI는 실행하지 않으며 일반 터미널 실행을 `executed`로 기록하지 않는다.
