# 결정 레지스터 (Decision Register)

이 문서는 사용자와 합의한 제품 정책의 정본이다. 구현 세부 설명은 `proposal.md`, 상태 전이는 `workflow.md`, 필드 계약은 `report-template.md`를 따른다.

- 제품 상태: **M0 hook tracer-bullet GO / 전체 M1 NO-GO**
- 기준일: 2026-07-26
- 등급 표기: `HIGH`, `LOW`, `INFO`만 허용

## D0. 제품 정의

**결정:** Secure Onboard는 외부 코드·파일·프로젝트를 다루는 Claude Code CLI와 Codex CLI의 **선택형 로컬 실행 가드레일**이다.

- 별도 Finder·파일 탐색기 프로그램이나 일반 터미널 감시기가 아니다.
- 사용자의 AI 요청과 실제 로컬 도구 호출을 연결해 실행 전 위험을 설명한다.
- 사용자가 설치·비활성화·삭제할 수 있으므로 강제 보안 통제나 완전한 감사 시스템으로 표현하지 않는다.
- 관리자와 직원을 구분하지 않는다. 플러그인을 설치한 사람은 모두 `사용자`다.

## D1. 지원 표면과 비보장

**결정:** v0.1 지원 표면은 Claude Code CLI와 Codex CLI의 활성·신뢰된 플러그인 훅이 관찰하는 로컬 도구 호출이다.

다음은 관찰·차단·감사를 보장하지 않는다.

- Finder, Windows 파일 탐색기와 OS GUI 실행
- 일반 터미널에서 사용자가 직접 실행한 명령
- 다른 IDE·에이전트·백그라운드 프로세스
- 플러그인 또는 훅이 꺼졌거나 신뢰되지 않은 세션
- `--bare` 또는 `CLAUDE_CODE_SIMPLE=1`로 시작해 Secure Onboard plugin을 명시적으로 전달하지 않은 Claude Code 세션
- hosted 도구와 클라이언트가 훅 경로에서 제외한 특수 도구
- 이미 허용된 대화형 프로세스에 후속 입력을 보내는 경로
- 같은 이벤트에서 병렬로 시작되는 다른 플러그인·프로젝트 훅의 자체 부작용
- 조직 관리 설정이 제품 훅을 통째로 배제한 환경. Claude Code의 managed `allowManagedHooksOnly`는 managed hook과 force-enable된 plugin의 훅만 로드하므로 사용자가 설치한 Secure Onboard 훅이 실행되지 않고, managed `disableAllHooks`와 Codex `requirements.toml`의 hooks 비활성도 같다. 제품은 이 상태를 우회하지 않으며 `status`에서 확인 가능한 범위까지만 보고한다
- Codex에서 번들 훅 정의를 아직 검토·신뢰하지 않았거나 정의 변경으로 신뢰가 만료된 세션. **플러그인 설치·활성화만으로는 훅이 실행되지 않는다**

Codex 공식 문서도 훅을 완전한 enforcement boundary가 아닌 guardrail로 설명한다. Claude Code와 Codex의 훅 지원 범위·출력 형식·신뢰 절차가 다르므로 클라이언트별 어댑터와 회귀 테스트를 둔다.

- [Codex plugin packaging](https://developers.openai.com/plugins/build/plugins)
- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
- [Claude Code plugins](https://code.claude.com/docs/en/plugins)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)

## D2. 설치와 활성화

**결정:** 관리형 배포는 사용하지 않으며 사용자는 전역 또는 특정 프로젝트에서만 제품을 사용할 수 있고 프로젝트 비활성화가 우선한다.

- **전역 활성화:** 프로젝트별 비활성화를 제외한 모든 프로젝트에 적용
- **프로젝트 활성화:** 사용자 로컬 레지스트리에서 선택한 프로젝트에만 적용

“프로젝트 단위 설치”는 사용자 영역에 공용 코어와 adapter를 한 번 설치한 뒤 로컬 registry에서 **프로젝트 활성화**만 관리하는 방식으로 확정한다. 실제 프로젝트별 package/plugin 설치는 제공하지 않으며 실행 코드와 상태를 대상 저장소에 체크인하지 않는다.

Claude Code 자체는 `user`, `project`, `local` plugin scope를 지원한다. Secure Onboard가 user-scope 설치와 자체 프로젝트 registry를 사용하는 것은 Codex와 동작을 맞추고 외부 저장소가 보안 실행 코드를 소유하지 않게 하려는 제품 결정이지 Claude Code의 기능 한계가 아니다.

자체 scope 판정 우선순위는 다음과 같다.

1. 현재 프로젝트가 비활성 목록에 있으면 `OFF`
2. 현재 프로젝트가 활성 목록에 있으면 `ON`
3. 전역 활성화이면 `ON`
4. 그 밖에는 `OFF`

자체 scope와 실제 보호 상태를 혼합하지 않는다. 유효 보호 상태는 다음 세 값이다.

- `VERIFIED_ACTIVE`: scope가 ON이고 현재 세션의 정확한 plugin/hook 경로가 heartbeat 또는 self-test로 확인됨
- `OFF`: scope가 OFF이거나 plugin 미설치·명시적 비활성·확인 가능한 hooks OFF 상태
- `UNKNOWN`: scope는 ON일 수 있지만 현재 세션 hook 실행·Codex hash trust·Claude 실행 mode 등을 기계적으로 확인할 근거가 부족함

프로젝트는 심볼릭 링크 별칭이 아닌 정규화된 물리 경로와 사용자별 불투명 ID로 식별한다. 중첩 프로젝트에서는 가장 구체적인 프로젝트 항목이 우선한다. 프로젝트 설정·환경변수·대상 파일·도구 출력이 제안하는 경로를 Secure Onboard registry·로그·캐시의 권위 있는 위치로 받아들이지 않는다.

그러나 같은 사용자 권한으로 이미 실행된 외부 코드는 사용자 영역 상태를 직접 수정할 수 있다. 이 제품은 권한 분리, 변조 방지 저장소 또는 중앙 감사 경계가 아니다.

다만 관리형 정책이 없으므로 Claude 프로젝트/local 설정은 plugin 또는 hooks를, Codex trusted-project 설정은 hooks를 꺼서 유효 보호 상태를 `OFF`로 만들 수 있다. Codex의 project-scoped plugin enable/disable은 공식 기능으로 가정하지 않는다. 이 경우도 지원되는 사용자 비활성화 경로이며 제품이 막는다고 주장하지 않는다. 확인 근거가 없으면 OFF나 ACTIVE로 추정하지 않고 `UNKNOWN`으로 표시한다.

`UNKNOWN`은 모든 현재 action을 자동 통과시키는 판정이 아니다. registry·GatePolicy·CoverageManifest는 유효하지만 client trust·heartbeat의 전체 상태만 확인할 수 없는 상황에서 실제 지원 `PreToolUse`가 이 훅에 도착하면 그 **관찰된 action 하나는 정상 게이트**한다. 다만 세션 전체가 보호됐다고 주장하지 않고 `protection_status_unknown` limitation/event를 남긴다. GatePolicy·CoverageManifest가 valid일 때 registry만 실패하면 fail-closed state failure를 적용하고, GatePolicy 또는 참조 CoverageManifest도 실패하면 고정 bootstrap HIGH를 우선 적용한다.

## D3. 트리거와 도구 경계

**결정:** 다음 사용자 의도를 의미 트리거로 취급한다.

- 프로그램·스크립트·파일 실행 또는 열기
- 패키지·프로그램 설치, 업데이트 또는 제거
- 빌드·테스트처럼 대상 코드를 실행할 수 있는 작업
- 설정·권한·보안 옵션 변경
- 명시적인 보안 확인·검사 요청

의미 트리거는 설명과 명령 출처 구분을 위한 보조 입력이다. 실제 차단의 권위 있는 입력은 `PreToolUse`가 받은 실행 직전 도구 이름과 인자다. prompt event는 클라이언트별 provenance가 실제 인간 제출로 검증된 경우에만 사용자 명령·재확인의 권위 있는 source로 사용한다. Codex 공식 `UserPromptSubmit`에는 인간 입력을 자동 continuation과 구분하는 provenance 필드가 없으므로 기본값은 `unverified`다. Codex의 HIGH 재확인은 모델 transcript와 분리된 Secure Onboard 소유 로컬 확인 채널에서만 받고 session·action·short ref·context fingerprint·TTL에 결합한다. 이 채널을 지원하지 못하는 client/version/OS는 Codex HIGH 명령 공개 coverage에 포함하지 않는다.

`PermissionRequest`는 원래 승인 요청이 없는 호출을 놓칠 수 있으므로 1차 게이트로 사용하지 않는다. 결과 훅은 이미 실행된 LOW·INFO 작업 결과 기록에만 사용하며, Claude Code의 `PostToolUse`/`PostToolUseFailure`와 Codex의 `PostToolUse`를 어댑터가 공통 success/failure로 정규화한다.

명시적인 `scan`·`check` 요청은 대상을 실행하지 않는 읽기 전용 검사 작업이다. 검사에서 HIGH finding이 나와도 검사 자체를 차단하지 않고 `ScanReport`로 결과를 보여 준다. 이후 같은 대상을 설치·열기·실행하려는 별도 action이 생기면 그 action을 새로 판정한다. 검사 도구가 대상 코드를 실행하거나 기본 앱으로 여는 동작은 허용하지 않는다.

M1 alpha는 M0에서 검증된 shell/exec 경로의 npm 설치·로컬 파일 열기와 구조화된 읽기 전용 scan helper만 지원 grammar로 삼는다. 설정·권한 변경, build/test/update/remove, 네이티브 file write/edit와 일반 MCP는 의미 트리거로는 인식하되 M2 전까지 M1 보호 범위에 포함하지 않는다.

- 실행 직전 입력에서 `action_kind`를 먼저 분류한다. npm build/test/configure처럼 M1 action kind 밖이면 세부 option을 해석하기 전에 `NOT_COVERED`로 통과시키고 redacted coverage event만 남긴다. `INFO` 보안 판정이나 보호 성공으로 표현하지 않는다.
- action kind와 entry가 M1 지원 후보인데 client/tool schema, M0에서 허용한 shell dialect 또는 단일 대상 grammar를 해석할 수 없으면 D4의 고정 fail-closed 정책을 적용한다.
- hook 경로 자체에 들어오지 않는 도구는 event도 만들 수 없으며 차단을 보장하지 않는다.

## D4. 발견 등급과 보호 작업 판정

**결정:** finding과 보호 작업 판정은 모두 `HIGH`, `LOW`, `INFO` 세 이름만 사용하되 서로 다른 필드로 기록한다. 보호 작업별 최종 판정은 다음과 같다.

| 판정 | 기준 | Secure Onboard 동작 |
|------|------|---------------------|
| `HIGH` | 중대한 보안 영향이 확인됐거나 필수 검사를 신뢰할 수 없음 | 보호 action의 AI 도구 호출 차단 |
| `LOW` | 사용자가 알아야 할 위험·민감정보·오탐 가능성이 있으나 즉시 차단 근거는 아님 | 실행 전 경고·설명 후 계속 |
| `INFO` | 경고할 위험이 확인되지 않음 | 로컬 기록 후 계속 |

복수 finding의 작업 판정은 가장 높은 등급을 사용한다. `MED`, `안전`, `위험`, `조건부 승인`은 제품 판정으로 사용하지 않는다. `INFO`는 안전 보증이 아니다.

읽기 전용 보안 검사 자체는 보호 action이 아니다. `ScanReport.max_finding_severity`로 HIGH finding을 보고할 수 있지만 `ActionDecision`을 만들지 않는다. HIGH 차단은 검사 대상에 대한 후속 execute/open/install action에 적용한다. configure/permission 같은 다른 후속 action은 해당 action kind가 향후 지원 grammar에 명시적으로 추가된 뒤에만 같은 원칙을 적용한다.

**결정:** 다음 실패가 보호 action의 실행 직전 게이트에서 발생하면 `guardrail.scan_failure`, `guardrail.log_failure` 또는 `guardrail.state_failure` HIGH로 deny한다. 읽기 전용 scan에서 발생하면 HIGH finding의 `ScanReport`를 만들며 scan 자체를 deny하지 않는다.

- 필수 파서·검사 코어 오류 또는 timeout
- 실행 직전 호출을 정규화할 수 없음
- 캐시 손상과 재검사 실패
- 필수 로컬 이벤트 기록 실패

LOW 판정을 만들었지만 adapter가 지원 버전의 계약에 맞는 실행 전 경고 출력을 생성·stdout에 쓰지 못한 경우에는 LOW 계약을 충족하지 못하므로 고정 `guardrail.warning_failure` HIGH deny다. command hook에는 host의 parse·표시 ACK가 없으므로 `warned_low`는 경고 출력을 동기식으로 방출했다는 뜻일 뿐 사용자 열람이나 client 표시 완료 증명이 아니다. 실제 표시 능력은 client/version/OS별 M0 terminal fixture로 검증한다.

`GatePolicy`를 읽거나 검증할 수 없는 bootstrap 실패는 내장 `guardrail.policy_bootstrap_failure` HIGH deny로 고정하고 stale·부분 policy를 사용하지 않는다. read-only scan helper가 실제 호출된 경우에는 gate 없이 같은 rule의 HIGH failure report를 만든다.

훅 자체가 로드되지 않거나 클라이언트가 훅 오류 뒤 실행을 계속하는 상황은 제품이 강제로 막을 수 없는 비보장 경계다. 상태 진단과 수용 테스트로 탐지하되 강제 차단을 주장하지 않는다.

## D5. AI 판정 권한

**제품 결정:** 결정론적 로컬 규칙과 AI 상관분석이 함께 판정에 영향을 줄 수 있다.

- 검증된 결정론적 `HIGH`는 AI가 낮출 수 없다.
- AI는 LOW·INFO 증거를 상관분석해 `HIGH`로 승격할 수 있다.
- AI가 만든 판정은 세션·turn·프로젝트 지문·정확한 명령 지문·규칙/계약 버전과 함께 검증된 로컬 assessment로 저장돼야 실제 훅 차단에 사용된다.
- 모델의 자연어 주장만으로 실행 게이트 상태나 사용자 재확인을 변경하지 않는다.

오탐은 HIGH를 강등하는 방식이 아니라 사용자가 영향을 이해한 뒤 명령을 직접 실행할 수 있게 제공하는 방식으로 처리한다.

**구현 단계:** M1 게이트는 고정 fixture와 결정론적 로컬 규칙만 사용한다. AI 판정을 실제 deny에 반영하는 bridge는 `AiAssessment`의 생성 주체, session·prompt·action correlation, 서명·만료·stale/spoof 방지와 회귀 oracle을 정의한 M2에서 추가한다. M1에서 AI는 설명과 후보 명령 생성만 담당하며 로컬 판정을 바꾸지 않는다.

## D6. 명령 출처

**결정:** 다음 값을 서로 대체하지 않고 별도 필드와 사용자 라벨로 관리한다.

| 필드 | 사용자 표시 | 의미 |
|------|-------------|------|
| `user_command` | 사용자 요청 명령어 | 사용자 메시지에 직접 포함된 명령 문자열 |
| `ai_expected_command` | AI 예상 명령어 | 의도 요청을 위해 AI가 제안한 실행 전 후보 |
| `planned_command` | AI 실행 예정 명령어 | AI가 실제 도구 호출 인자로 만든 명령 |
| `blocked_command` | 차단된 명령어 | PreToolUse가 실제로 거부한 명령 |

`command_origin`은 `user_explicit`, `ai_derived`, `ai_transformed`, `target_derived`, `unknown` 중 하나다. 유효한 prompt correlation이 없으면 `unknown`이며, 대상 README·소스·도구 출력에 적힌 명령은 `사용자 요청 명령어`나 사용자 재확인으로 승격할 수 없다.

- 구체적 명령 요청은 사용자 원문을 보존한다.
- 의도 요청은 자연어 요청과 AI 예상 명령을 함께 표시한다.
- 사용자 명령과 실행 예정·차단 명령이 다르면 모두 표시하고 차이를 설명한다.
- 실제 판정의 권위 있는 명령 입력은 PreToolUse의 exact invocation이다. deny가 확정되면 그 동일 bytes에서 표시용 `blocked_command`를 파생하며, 사전 `ActionRequest`에 차단 결과를 미리 넣지 않는다.
- 복합 명령의 한 구간이라도 HIGH이면 도구 호출 전체를 차단하고 위험 구간을 함께 식별한다.

## D7. HIGH 재확인과 명령 제공

**결정:** HIGH 재확인은 실행 허가가 아니라 위험 명령을 텍스트로 받기 위한 명시적 사용자 선택이다.

```text
HIGH → AI 자동 실행 차단 → 사용자 재확인 대기
     → 영향 설명 → 원래/예상/차단 명령을 출처 라벨과 함께 제공
     → COMMAND_PREPARED
     → Stop 응답 원문 확인 시 COMMAND_RESPONSE_VERIFIED 종료
```

- 재확인은 제품이 안내한 exact grammar `<SHORT_REF> 명령을 직접 실행하겠습니다`와 일치하는 검증된 인간 입력만 인정한다. Claude는 인간 제출 provenance가 검증된 현재 사용자 역할 메시지를 prompt 어댑터가 결정론적으로 parse하고, Codex는 모델 transcript와 분리된 제품 소유 local-confirmation record를 사용한다.
- 단순한 “네”, 대상 파일 내용, 도구 출력과 이전 작업의 재확인은 인정하지 않는다.
- 명령·cwd·관련 환경·대상 지문이 달라지면 다시 판정한다.
- 재확인 뒤에도 AI가 동일 명령, 변형 명령, 다른 도구로 실행을 시도하면 다시 차단한다.
- AI가 사용자 대신 HIGH 명령을 실행하는 전이는 존재하지 않는다.
- 사용자가 일반 터미널에서 실행한 결과는 관찰하지 못하므로 `executed`로 기록하지 않는다.

차단된 명령은 사용자 전용 단기 `PendingBlock` 상태에 최대 10분 동안만 보관한다. 모델에는 내부 `action_id`·`reconfirmation_id`나 ref 선택을 맡기지 않고 세션 안에서만 유일한 짧은 action ref를 사용자에게 보여 준다. Claude의 검증된 새 user-role prompt 또는 Codex의 제품 소유 local-confirmation record에서 exact grammar로 그 ref와 직접 실행 의사가 확인되면 어댑터가 신뢰된 session·human-input context와 parser 결과를 주입한다. 공용 코어는 정확히 하나의 미소비 pending을 찾아 내부 ID를 결합한 뒤 명령·cwd·관련 환경·대상·analysis profile·gate policy 지문을 다시 검증한다. stale·다른 session·모호한 ref 또는 재관찰 불가는 payload 없이 종료한다.

동시에 여러 HIGH가 생길 수 있으므로 짧은 ref는 live session에서 유일해야 하며 각 재확인은 한 pending에 한 번만 소비된다. 동일 native hook·재확인·disclose·Stop의 재전송은 idempotent하게 처리하고 terminal event를 중복 기록하지 않는다. helper 반환은 `high_command_prepared`, 지원되는 Stop 훅이 마지막 assistant 응답 원문의 marker·digest를 확인한 때만 `high_command_response_verified`로 기록한다. 이는 UI 전달·렌더 완료·사용자 열람 ACK가 아니다. AI가 명령을 기억에서 재구성하거나 활동 로그·캐시에서 되읽지 않는다.

명령 제공 뒤에도 차단 대상 tool handler 실행과 그 target command process start는 0이어야 한다. PreToolUse lifecycle dispatch 자체, hook adapter, 읽기 전용 scanner와 제품 관리용 disclose helper는 이 수치에서 제외한다. 같은 이벤트의 sibling hook 부작용은 이 제품이 막는다고 주장하지 않는다.

공개할 exact invocation과 원문 bytes를 신뢰할 수 없거나 pending state를 만들지 못한 operational failure는 명령을 추측하지 않고 `disclosure_eligible=false`로 끝낸다. 신뢰 가능한 exact blocked command가 남아 있는 HIGH는 원인이 보안 finding인지 guardrail failure인지와 무관하게 같은 재확인 절차로 제공할 수 있다.

재확인 뒤에는 비밀값의 출처와 무관하게 secret을 포함한 차단 명령 bytes를 치환·정규화 없이 그대로 제공한다. 별도의 secret 개수 재확인은 사용하지 않는다. 이 정책은 비밀 노출 위험을 의도적으로 수용하므로 영향 설명에 명시한다.

다만 ANSI/OSC·양방향 제어문자·NUL·코드펜스 탈출처럼 **터미널 표시 자체를 조작하는 bytes는 예외**이며 실행시키지 않고 가시적인 dialect별 안전 표현으로 바꾼다. 이 표시본은 원문과 같다고 주장하지 않고 `표시 안전 변환`으로 라벨링한다. 위험 명령 원문은 정의상 신뢰할 수 없는 대상에서 유래할 수 있고, 제어 시퀀스를 그대로 출력하면 사용자가 화면에서 보는 명령과 실제로 복사해 붙여넣는 명령이 달라질 수 있다. 그러면 “사용자가 위험을 이해한 상태에서 직접 선택한다”는 이 절의 전제 자체가 무너지므로 secret literal 정책과 무관하게 항상 적용한다.

원문은 사용자별 `PendingBlock`에 최대 10분만 보관하며 활동 로그·캐시에는 명령 원문이나 secret을 저장하지 않는다.

## D8. 데이터 경계

**결정:** 외부 프로젝트의 코드·파일을 Claude Code·Codex가 처리하는 것은 지원 범위다.

- `로컬 CLI`는 로컬 모델이나 무전송을 뜻하지 않는다.
- AI 공급자에게 전달되는 코드·프롬프트는 해당 클라이언트와 계정의 데이터 정책을 따른다.
- Secure Onboard는 판정에 불필요한 추가 제3자 전송과 로컬 로그의 비밀값 노출을 만들지 않는다.
- 보안상 AI 전송 자체가 금지된 프로젝트에서는 플러그인만 끄는 것이 아니라 Claude Code·Codex 사용 여부를 별도로 결정해야 한다.

## D9. 로컬 활동 기록

**결정:** “AI 내부 로그”는 모델 기억이 아니라 공용 로컬 코어가 쓰는 사용자 소유 활동 기록이다.

필수 이벤트는 `scope_enabled`, `scope_disabled`, `protection_status_unknown`, `scan_started`, `scan_reported`, `cache_hit`, `cache_miss`, `coverage_not_supported`, `allowed_info`, `warned_low`, `high_detected`, `high_blocked`, `user_reconfirmed`, `high_command_prepared`, `high_command_response_verified`, `high_command_closed`, `tool_completed`, `tool_failed`, `ingress_conflict`, `orphan_result`다.

- `tool_completed`와 `tool_failed`는 클라이언트 결과 훅으로 실제 관찰한 LOW·INFO 작업에만 쓴다.
- `coverage_not_supported`는 훅이 관찰했지만 현재 지원 grammar 밖이어서 통과시킨 진단이며 `INFO` 판정이나 보호 성공이 아니다.
- HIGH에는 `high_command_response_verified` 이후 실행 이벤트를 만들지 않는다.
- 명령 원문·비밀값·소스 원문·절대 경로를 저장하지 않는다. 사용자별 HMAC 식별자, 작업 종류, 등급, rule ID, 버전과 시각만 저장한다.
- event와 terminal tombstone은 각각 30일 또는 최근 1,000건 중 먼저 도달하는 한도이며 사용자가 삭제할 수 있다.
- 사용자 전용 디렉터리/파일 권한과 원자적 쓰기를 사용하고 심볼릭 링크를 따르지 않는다.
- 사용자가 수정·삭제할 수 있으므로 변조 방지 중앙 감사 로그라고 주장하지 않는다.

위 원문 저장 금지는 활동 기록과 캐시에 적용한다. D7의 단기 `PendingBlock`은 명령 제공과 stale 재검증에 필요한 원문 명령·물리 cwd·target locator·관련 환경 이름을 둘 수 있는 예외이며 사용자 전용 권한, 10분 TTL과 즉시 삭제를 강제한다. 사용자가 직접 입력하지 않은 환경 값 원문은 저장하지 않는다.

## D10. 검사 캐시

**결정:** 프로젝트 전체를 영구적으로 “검증됨” 처리하지 않고 다음 두 캐시를 사용자 영역에 둔다.

1. **증거 캐시:** 대상 콘텐츠·권한·심볼릭 링크 지문 + 코어·규칙 bundle·보안 데이터 버전 + analysis profile digest
2. **작업 판정 캐시:** 증거 지문 + 정확한 도구/명령·물리 cwd·resolved 실행 파일·관련 effective 환경/설정 지문 + gate policy digest

경로·mtime만으로 재사용하지 않는다. 한 바이트, 명령, cwd, 실행 파일, 관련 환경·package-manager 설정, 규칙·데이터·analysis profile 또는 gate policy 변경은 관련 캐시를 무효화한다. 유효한 GatePolicy를 읽은 뒤 rule bundle 로딩·검증이 실패하면 보호 action은 fail-closed HIGH, read-only scan은 HIGH finding이다. GatePolicy 자체 로딩·검증 실패는 D4의 고정 bootstrap HIGH다. cache hit는 중복 분석만 생략하며 HIGH 차단·LOW 경고·매 시도 이벤트 기록은 생략하지 않는다. AI assessment를 도입하는 M2에서는 AI 계약·model·assessment correlation을 별도 key에 추가한다.

M1의 remote registry npm install은 실제 설치될 transitive bytes·npm config·platform을 로컬에서 immutable하게 묶지 못하므로 action cache를 항상 bypass하고 `guardrail.scan_failure` HIGH로 deny한다. exact local `.tgz`의 content/integrity와 effective executable·환경을 확인할 수 있을 때만 action cache를 허용한다. 이 local artifact에서 선택적 평판 정보만 없으면 `npm.reputation_unknown` LOW를 사용할 수 있고, 평판 규칙을 적용하지 않는 고정 fixture는 `not_applicable`로 둘 수 있다. context를 입증할 수 없는 다른 client/tool도 bypass한다. M1 캐시에는 AI assessment 필드를 넣지 않는다.

M1 검사 코어는 registry 평판 조회나 artifact 다운로드를 위해 별도 network egress를 만들지 않는다. exact local immutable `.tgz`만 판정의 권위 있는 artifact로 사용하고, lockfile·package-manager cache는 metadata 보조 입력일 뿐 remote install bytes의 증거로 사용하지 않는다. online resolve는 대상 식별정보·proxy/auth 전송과 실패 정책을 별도 고지·계약한 후속 opt-in 기능이다.

cache read·MAC·schema 검증 실패는 레코드를 폐기하고 fresh scan한다. fresh scan이 성공하면 cache writeback 실패는 현재 판정을 유지하되 `bypass`로 기록하고 stale allow를 사용하지 않는다. fresh scan, rule bundle 또는 필수 활동 로그가 실패한 보호 action은 fail-closed HIGH다. GatePolicy 자체 실패는 항상 bootstrap HIGH다. operational failure·adapter fallback·failed scan 결과는 항상 bypass하며 action/evidence cache에 쓰지 않는다.

실행 직전에 대상 지문을 다시 확인하고 바뀌면 재검사한다. 훅과 일반 파일시스템만으로 모든 TOCTOU를 제거할 수 없고, 버전이 고정되지 않은 원격 패키지는 같은 이름의 미래 바이트까지 보증하지 않는다. 마지막 접근 시각(`atime`)은 지문과 원본 보존 보장에 포함하지 않는다.

## D11. M1 범위와 테스트 자료

**결정:** 첫 fixture-backed end-to-end alpha vertical slice는 다음 세 흐름이다.

1. Node/npm 패키지 설치
2. 로컬 파일을 OS 기본 앱 또는 실행기로 열기
3. 위 대상에 대한 명시적 읽기 전용 보안 검사

세 흐름에서 Claude Code CLI와 Codex CLI, Windows와 macOS, 전역·프로젝트 활성화, HIGH/LOW/INFO, 명령 출처, 로그, 캐시를 fixture로 검증한다. 이 단계는 고정 테스트 자료로 계약을 관통하는 alpha이지 일반 외부 패키지·파일을 폭넓게 탐지하는 출시 제품이 아니다.

[EICAR 테스트 저장소](https://github.com/kimchanhyung98/eicar-testfile)는 저장소 전체를 clone하거나 실행하지 않는다. opt-in 격리 환경에서 commit `6ad94b0dfe2a12556ad8f9b31ebce46fa113f6f8`의 `standard/eicar.com.txt` 단일 68-byte 파일과 content SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`을 고정해 서명·캐시 HIGH fixture로 사용한다. EICAR는 실제 악성코드는 아니지만 DOS 실행 형식을 가진 테스트 파일이고 AV/EDR이 격리할 수 있다. container, 설치 훅·비밀값 흐름·프롬프트 인젝션·권한 변경은 별도 M2 합성 fixture로 검증한다.

OSV/MAL 데이터팩, 다중 패키지 생태계, Docker 분석기, 모바일/API/LLM 프로파일은 M1 이후다.

## D12. 구현 착수 조건

**결정:** 전체 M1 제품 구현은 아직 시작하지 않는다. 다음 단계로 허용되는 구현 작업은 두 클라이언트의 hook 사실을 고정하는 **M0 호환성 tracer-bullet**이다.

M0는 다음만 검증한다.

- 실제 plugin manifest와 UserPromptSubmit·PreToolUse·result·Stop hook payload
- 개별 native tool call ID와 session correlation
- 문서화된 HIGH deny 응답 뒤 차단 대상 tool handler 실행·target command process start 0
- LOW/INFO continue가 native sandbox·approval을 우회하지 않음
- Claude·Codex별 plugin/hooks 비활성 상태와 확인 가능한 self-test·status 필드
- 같은 이벤트의 sibling hook과 훅 자체 오류·timeout·malformed output의 관찰 결과

M0 결과로 native fixture와 coverage matrix를 체크인한 뒤, durable storage·canonical encoding·HMAC·시간/자원 한도를 확정하고 `use-cases.md`의 immutable fixture manifest·expected JSON을 고정해야 M1 계약을 잠근다. 검증 결과가 가정과 다르면 지원 범위를 축소한다.

Codex에서 인간 prompt와 자동 continuation을 구분하지 못하므로 제품 소유 로컬 확인 채널의 action-bound transport를 구현·검증하기 전까지 Codex의 HIGH 명령 공개를 포함한 full M1 지원을 선언하지 않는다. M1 GO에는 disclosure helper와 구조화된 scan helper의 신뢰 transport가 필요하다. 범위 밖 `NOT_COVERED` 처리, 중복·병렬 호출의 idempotency, case×client/version×OS 적용 행렬과 adversarial negative fixture를 추가한다.

## D13. M1 구조 결정

**결정:** 다음 네 항목을 M1의 고정 제품 정책으로 사용한다.

1. **프로젝트 모드 배포:** 사용자 영역에 공용 코어와 adapter를 한 번 설치하고 로컬 registry로 프로젝트별 활성화 상태만 관리한다.
2. **HIGH 명령의 secret:** 출처와 무관하게 exact blocked command의 secret 원문 bytes를 치환·정규화 없이 그대로 제공한다. **터미널 제어문자는 예외다.** ANSI/OSC·양방향 제어문자·NUL·코드펜스 탈출은 항상 가시적인 dialect별 안전 표현으로 바꾸고 `표시 안전 변환`으로 라벨링한다. 활동 로그·캐시에는 원문을 넣지 않는다.
3. **Codex 재확인:** 모델 transcript와 분리된 Secure Onboard 소유 로컬 확인 채널을 사용한다. 이 채널을 지원하지 못하는 조합은 Codex HIGH 명령 공개 coverage에서 제외한다.
4. **durable state:** daemon 없는 사용자별 SQLite database와 transaction/outbox를 사용하고 key는 OS credential store에 둔다. DB는 사용자 영역에 하나만 두되 모든 scope state·pending·event·cache row를 nullable `project_id`와 `directory_id`로 구분한다. `directory_id`는 정규화된 물리 디렉터리의 사용자별 HMAC 식별자이며 원문 절대 경로를 활동 로그·캐시에 저장하지 않는다.
