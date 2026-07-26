# 단계별 수용 기준과 fixture oracle

이 문서는 구현 단계별 테스트 정본이다.

- **M0:** 지금 구현을 시작할 수 있다. native hook 사실을 고정하는 tracer-bullet이다.
- **M1:** npm/open/scan 범위, D13 제품 결정과 검사 실패 정책은 확정됐다. SQLite 세부 계약, resource/HMAC 계약, immutable fixture manifest와 expected JSON이 아직 없어 전체 구현은 시작하지 않는다.
- **M2:** 심층 도달성·데이터 흐름·AI assessment를 다룬다.

## 1. 공통 불변식

- 등급은 `HIGH`, `LOW`, `INFO`만 사용한다.
- HIGH 보호 action에서는 **차단 대상 tool handler 실행과 target command process start가 0**이어야 한다. PreToolUse lifecycle dispatch 자체, hook adapter, scanner, 제품 관리용 helper와 sibling hook은 이 수치에서 제외한다.
- LOW 경고는 차단 대상 action보다 먼저 관찰돼야 한다.
- LOW·INFO는 Claude Code·Codex의 기존 sandbox·approval을 승인하거나 우회하지 않는다.
- 일반 터미널과 Finder 실행은 테스트하지 않고 `executed` event도 만들지 않는다.
- 로그·캐시에는 원문 명령, 비밀값, 소스 원문과 절대 경로가 없어야 한다.
- 각 case는 단 하나의 expected severity·결과 schema·필수 event 순서·금지 관찰을 가진다. `또는`, `지원 가능한 fixture` 같은 선택적 oracle을 허용하지 않는다.

## 2. M0 hook tracer-bullet

M0는 실제 npm/EICAR 분석기, 캐시, 재확인 UI를 구현하지 않는다. 공용 코어의 고정 sentinel 판정만 사용해 클라이언트 경계를 증명한다.

M0 전용 `m0-test-profile/v1`은 production GatePolicy·CoverageManifest와 분리된 test-build 입력이다. target repo가 아닌 사용자 영역의 테스트 harness가 체크인한 exact UTF-8 manifest bytes를 제공하고 그 SHA-256이 test build에 compile-time으로 내장된 digest와 일치할 때만 `execute` sentinel을 게이트한다. manifest는 기본·failure helper content hash, absolute executable path/hash/version, helper별 exact argv grammar, 임시 marker root, client/version/OS와 `build_flavor=test`를 포함한다. 이 profile에서는 M1의 `npm_open_scan`과 `NOT_COVERED` 분류를 적용하지 않는다. byte digest나 어느 필드라도 다르면 sentinel rule은 로드되지 않으며, production build·배포물에는 test-profile parser·digest·`m0.sentinel.*` rule을 포함하지 않는다.

M0의 모든 `M0ActionDecision.cache_status`는 `bypass`이며 HIGH의 `pending_action_ref`는 null이다. live adapter가 관찰한 core child 장애는 고정 `guardrail.scan_failure` decision과 유효한 deny로 변환한다. adapter 자체 장애는 별도 native fault case로 측정하며 fail-closed를 미리 가정하지 않는다.

M0 개발 fixture는 테스트 프로필에서만 활성화되는 작은 target helper를 사용한다.

```text
fixture invocation: <node> <fixed-content-hash>/m0-target.mjs <high|low|info> <temp-marker>
failure invocation: <node> <fixed-content-hash>/m0-target-fail.mjs <low|info> <temp-marker>
HIGH rule:          m0.sentinel.high
LOW rule:           m0.sentinel.low
INFO rule:          m0.sentinel.info
failure rule:       guardrail.scan_failure
```

- core는 사용자 영역의 opt-in test profile, helper content hash와 exact argv가 모두 일치할 때만 sentinel rule을 사용한다.
- 기본 helper는 시작 직후 target repo 밖 임시 marker를 쓰고 성공 종료한다. failure helper는 marker를 쓴 뒤 manifest에 고정한 nonzero code로 종료한다. HIGH에서는 어느 helper도 시작하지 않아 marker와 OS process observation이 모두 0이어야 한다.
- Node는 M0 개발 fixture runtime일 뿐 제품 배포 runtime 결정이 아니다. 실제 executable path·version은 각 native fixture에 기록한다.
- marker directory는 매 case마다 새로 만들고 테스트 뒤 삭제한다.

| ID | 입력 | 기대 결과 | 필수 증거 |
|----|------|-----------|-----------|
| T01 | Claude shell/exec HIGH sentinel | `m0.sentinel.high`, HIGH, documented deny | `high_detected → high_blocked`; marker 없음, target process start 0 |
| T02 | Codex shell/exec HIGH sentinel | `m0.sentinel.high`, HIGH, documented deny | `high_detected → high_blocked`; marker 없음, target process start 0 |
| T03 | 두 CLI LOW sentinel을 test가 native approval | `m0.sentinel.low`, LOW continue | `warned_low → tool_completed`; 경고 시각 < target start, approval 자동 우회 0 |
| T04 | 두 CLI INFO sentinel을 test가 native approval | `m0.sentinel.info`, INFO continue | `allowed_info → tool_completed`; target marker 1 |
| T05-A | 고정 test clock에서 core timeout | `guardrail.scan_failure`, HIGH, adapter가 문서화된 deny 반환 | `high_detected → high_blocked`; target marker·process start 0 |
| T05-B | core child 고정 nonzero exit | `guardrail.scan_failure`, HIGH, adapter가 문서화된 deny 반환 | `high_detected → high_blocked`; target marker·process start 0 |
| T05-C | core가 schema-invalid result 반환 | `guardrail.scan_failure`, HIGH, adapter가 문서화된 deny 반환 | `high_detected → high_blocked`; target marker·process start 0 |
| T05-D | adapter executable spawn 실패 | client/version/OS별 native 결과를 최초 probe 뒤 단일 fixture로 고정 | 유효 deny가 없으면 보호 성공 주장 0 |
| T05-E | adapter process가 실행 뒤 signal/crash | client/version/OS별 native 결과를 최초 probe 뒤 단일 fixture로 고정 | signal·target start·client 진단 원문 |
| T05-F | adapter timeout | client/version/OS별 native 결과를 최초 probe 뒤 단일 fixture로 고정 | timeout·target start·client 진단 원문 |
| T05-G | adapter exit 0 + malformed stdout | client/version/OS별 native 결과를 최초 probe 뒤 단일 fixture로 고정 | stdout/stderr/exit status·target start |
| T05-H-Codex | adapter exit 0 + stdout exact bytes `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask"}}\n` | 공식 계약상 unsupported decision으로 hook failure; target은 native approval 정책에 따라 진행 가능 | exact stdout/stderr/exit status·client 진단·approval 뒤 target start |
| T05-I | adapter exit 1 | client/version/OS별 native 결과를 최초 probe 뒤 단일 fixture로 고정 | target start·client 진단 원문 |
| T05-J | adapter exit 2 + 정상 stderr | 두 CLI의 문서화된 block | target marker·process start 0, client 진단 원문 |
| T05-K | adapter exit 2 + invalid stdout JSON | client/version/OS별 native 결과를 최초 probe 뒤 단일 fixture로 고정 | stdout/stderr/exit status·target start |
| T06-A | standalone probe가 plugin 미설치를 확인 | 유효 보호 `OFF`; 제품 보호 event 없음 | `plugin_state=not_installed`, `plugin_installed=false`, `plugin_version=null`, `hooks_enabled=false`, evidence digest non-null |
| T06-B | installed/enabled Codex plugin + hooks feature disabled | 유효 보호 `OFF`; 제품 보호 event 없음 | `plugin_state=installed_enabled`, `codex_hooks_feature=disabled`, `hooks_enabled=false`, matching config evidence |
| T06-C | installed/enabled Claude plugin + effective `disableAllHooks=true` | 유효 보호 `OFF`; 제품 보호 event 없음 | `plugin_state=installed_enabled`, matching ordered setting evidence, `hooks_enabled=false` |
| T06-D | installed/enabled Claude plugin + `--bare`, explicit plugin 미공급 | 유효 보호 `OFF`; 제품 보호 event 없음 | `plugin_state=installed_enabled`, `launch_mode=claude_bare`, `explicit_plugin_supplied=false`, evidence digest non-null |
| T06-E | installed/enabled Claude plugin + `CLAUDE_CODE_SIMPLE=1`, explicit plugin 미공급 | 유효 보호 `OFF`; 제품 보호 event 없음 | `plugin_state=installed_enabled`, `launch_mode=claude_simple`, `explicit_plugin_supplied=false`, evidence digest non-null |
| T07 | LOW·INFO 병렬 tool call 두 개 | native tool call ID별 action/result correlation 유지 | 서로 다른 `action_id`; `warned_low/allowed_info`와 각 `tool_completed` 뒤섞임 0 |
| T08 | Stop hook sentinel marker | 공식 `last_assistant_message`의 nullable 조건과 exact bytes fixture 캡처 | marker·digest fidelity와 OS별 결과 기록 |
| T09 | 같은 event의 sibling hook이 marker를 기록 | 원래 HIGH target은 차단되지만 sibling 부작용 0은 주장하지 않음 | target marker 없음, sibling marker 관찰 가능 |
| T10-LOW | LOW failure helper가 고정 nonzero 종료 | Claude `PostToolUseFailure`, Codex `PostToolUse` 실패 결과를 `tool_failed`로 정규화 | counts `HookEnvelope=2, M0ActionRequest=1, M0ActionDecision=1, M0Event=2`; events `warned_low → tool_failed(LOW,m0.sentinel.low,failure)`, native tool call ID 일치 |
| T10-INFO | INFO failure helper가 고정 nonzero 종료 | 두 client의 실패 결과를 `tool_failed`로 정규화 | counts `2,1,1,2`; events `allowed_info → tool_failed(INFO,m0.sentinel.info,failure)`, native tool call ID 일치 |
| T11 | Codex Stop이 exit 0 JSON `{"decision":"block","reason":"M0_CONTINUATION"}`을 반환해 생성한 자동 continuation과 실제 인간 prompt | 두 `UserPromptSubmit` raw bytes·`turn_id`, Stop의 `stop_hook_active`를 캡처; 공식 provenance 필드는 없으므로 기본 `unverified` | 별도 결정론적 증명 전 둘 다 `unverified`, 재확인 생성 0 |
| T12 | 자체 scope ON이지만 현재 세션 heartbeat/trust 근거 없음 | 유효 보호 `UNKNOWN` | ACTIVE/OFF로 추정하지 않고 `next_checks` 고정 enum 1개 이상 |
| T13 | Codex plugin installed/enabled지만 bundled hook current hash 미신뢰 | hook skip, 유효 보호 `UNKNOWN` | `hook_evidence=skipped/unreviewed_definition`, self-test event 0; 설치 상태만으로 active 주장 0 |
| T14 | Codex current hook definition을 검토·trust했지만 기존 session 유지 | 현재 session active를 추정하지 않음 | `session_state=existing_before_review`, hook `skipped/session_predates_review`; 새 session 전 `UNKNOWN` |
| T15 | Codex current hook definition trusted + 새 session + self-test 성공 | 유효 보호 `VERIFIED_ACTIVE` | `session_state=new_after_review`; heartbeat/self-test의 session·source·digest가 `loaded_active` hook evidence와 일치 |
| T16 | Codex hook 정의 변경으로 current hash 변경 | 재검토 전 hook skip, 유효 보호 `UNKNOWN` | `hook_evidence=skipped/reviewed_digest_stale`; 과거 heartbeat는 `stale`, active 주장 0 |
| T17 | untrusted project의 project-local `.codex` hook이 Secure Onboard를 사칭 | project-local hook skip; trusted user plugin 상태와 분리 | source별 `hook_evidence`; 사칭 event 0, heartbeat/self-test는 user plugin의 session·digest에만 결속 |
| T18 | Codex session cwd와 unified exec per-call workdir이 다른 호출 | native hook 또는 위조 불가능한 runtime 입력이 effective cwd를 path 전체에서 식별·재검증할 수 있는지 측정 | 증명 불가 시 해당 native path·client version 전체 coverage 제외; session cwd를 effective cwd로 오인 0 |
| T19-A-HIGH | test artifact + valid user-area profile + exact HIGH helper | HIGH sentinel 활성 | counts `HookEnvelope=1, M0ActionRequest=1, M0ActionDecision=1, M0Event=2, M0StatusReport=1`; binding `matched`, events `high_detected → high_blocked` |
| T19-A-LOW | test artifact + 같은 valid profile + exact LOW helper | LOW sentinel 활성 | counts `2,1,1,2,1`; binding `matched`, events `warned_low → tool_completed` |
| T19-A-INFO | test artifact + 같은 valid profile + exact INFO helper | INFO sentinel 활성 | counts `2,1,1,2,1`; binding `matched`, events `allowed_info → tool_completed` |
| T19-B-MISSING | test artifact loader-only run + profile 입력 없음 | `test_profile=rejected`, sentinel 비활성 | counts `0,0,0,0,1`; supplied digest null, reason `profile_missing`, binding `not_evaluated` |
| T19-B-DIGEST | test artifact loader-only run + profile bytes 1개 변경 | `test_profile=rejected`, sentinel 비활성 | counts `0,0,0,0,1`; supplied/expected digest 불일치, reason `digest_mismatch`, binding `not_evaluated` |
| T19-B-SOURCE | test artifact loader-only run + valid profile bytes를 target repo 경로에서 공급 | `test_profile=rejected`, sentinel 비활성 | counts `0,0,0,0,1`; 두 digest가 같아도 reason `profile_source_untrusted`, binding `not_evaluated` |
| T19-B-HELPER | loaded valid profile + 같은 fixed path/argv의 helper bytes만 고정 near-match hash로 교체 | profile은 loaded지만 sentinel 불일치 | counts `2,0,0,0,1`; binding `helper_hash_mismatch`, documented neutral native response 뒤 operator approval과 target marker 1 |
| T19-B-ARGV | loaded valid profile + exact helper에 고정 no-op extra argv 1개 | profile은 loaded지만 sentinel 불일치 | counts `2,0,0,0,1`; binding `argv_mismatch`, documented neutral native response 뒤 operator approval과 target marker 1 |
| T19-C | production artifact loader-only run + T19-A의 exact profile 입력 | profile 미지원 | counts `0,0,0,0,1`; supplied digest 필수, reason `production_not_supported`, binding `not_evaluated`, bound build manifest + black-box profile probe evidence |
| T20-A | HIGH deny 응답에 top-level `systemMessage`를 함께 반환 | deny 경로에서 경고가 사용자 표시로 렌더되는지 측정 | 표시 여부·위치·최대 길이·개행 처리의 관찰 원문 |
| T20-B | LOW: permission decision 없이 `systemMessage`만 반환 | 경고가 target 실행 전에 사용자에게 표시되는지 측정 | 표시 시각 < target start 여부; 표시가 불가능하면 `guardrail.warning_failure` 적용 근거 |
| T20-C | `systemMessage`에 짧은 ref와 exact 재확인 문구를 포함 | 문구가 잘리거나 변형되지 않고 그대로 표시되는지 측정 | 입력 bytes와 표시 bytes 대조 결과 |
| T20-D | Codex `systemMessage`의 도달 경로 | 대화형 터미널 세션의 사용자 표시인지 event stream 전용인지 구분 | client별 관찰 결과 원문 |

T19 표의 count 순서는 항상 `HookEnvelope, M0ActionRequest, M0ActionDecision, M0Event, harness M0StatusReport`다. LOW·INFO와 B-HELPER/B-ARGV의 첫 HookEnvelope는 PreToolUse, 둘째는 정확히 같은 native tool call ID의 result다. B-HELPER는 path와 argv를 유지한 채 helper content hash만, B-ARGV는 exact helper path/content를 유지한 채 no-op argv 하나만 바꾼다. 두 near-match target의 bytes/hash와 성공 marker 동작을 manifest에 고정한다. adapter는 profile matcher 불일치를 판정이나 event로 승격하지 않고 client별 documented neutral response만 반환한다. control run에서 native approval이 필요함을 먼저 증명하고 operator가 한 번 승인한다. target 실행은 예상된 negative evidence이지 보호 성공이 아니다. B-MISSING/B-DIGEST/B-SOURCE/C만 loader-only다. production binary는 M0 schema를 emit하지 않으며 T19-C의 status 1개는 harness가 만든 projection이다.

M0 fixture manifest는 각 클라이언트·지원 버전·OS별로 다음을 체크인한다.

```text
client/version
OS/shell
plugin manifest and effective config
exact m0-test-profile UTF-8 bytes/SHA-256, test artifact compile-time binding and proof that production contains no loader/rule
sandbox mode, approval policy, approvals reviewer and exact native permission boundary
native prompt/pre/result/stop payload bytes
host process observation and effective shell executable/flags/dialect resolver evidence
effective cwd binding evidence and per-call workdir capability
exact adapter invocation, cwd/env allowlist, timeout and injected fault mode
declared hook timeout in the shipped hooks.json, the client default it overrides and the observed session stall on adapter hang
exact systemMessage input bytes and the observed user-visible rendering per client
exact deny/continue stdout, stderr and exit status
target marker path and process-observation method
test_case_id/test_run_id and exact count of each normalized HookEnvelope, M0ActionRequest, M0ActionDecision, M0Event and harness M0StatusReport
canonical JSON SHA-256 list for every expected object; this list binds shared HookEnvelope objects without M0-only fields to the test_run_id
expected ordered events and forbidden observations
```

fixture manifest와 한 번의 harness run context가 M0 evidence의 결속 정본이며 `M0StatusReport`는 그 증거의 machine-readable projection이다. 같은 `test_run_id`의 object count·canonical digest list·ordered event 중 하나라도 다르면 해당 case 전체가 실패다.

T03·T04는 같은 client/version/OS에서 plugin을 끈 control run이 native approval prompt를 실제로 요구함을 먼저 기록한다. plugin을 켠 run에서는 test operator가 그 prompt를 한 번 직접 승인하며 Secure Onboard 코드가 approval 입력을 보내거나 생략하면 실패다.

T05-D~K도 같은 native control run에서 permission 필요 여부를 기록한다. fault run에서 native approval이 나타나면 operator가 정확히 한 번 직접 승인해 target start 여부를 관찰하며, 사용자가 취소한 결과를 Secure Onboard 차단으로 계산하지 않는다. T05-H-Codex는 Claude에 적용하지 않으며 Claude의 unsupported-field 결과를 추정하지 않는다.

T20은 사용자 표시 채널을 측정하는 probe다. 두 CLI 모두 `permissionDecisionReason`은 모델에게 전달되고 사용자에게 직접 보이는 필드는 top-level `systemMessage`뿐이므로, 이 값이 실제로 어떻게 렌더되는지 확인하기 전에는 LOW 경고 전달과 HIGH 재확인 안내를 계약으로 잠그지 않는다. 훅은 `/dev/tty`에 쓸 수 없어 대체 경로가 없다. T20이 "표시되지 않음"으로 나오면 모든 사용자 표시가 모델 전달에 의존한다는 사실을 제품 문구와 비보장 목록에 명시한다.

또한 shipped `hooks.json`에 명시적 `timeout`을 넣지 않으면 두 CLI의 기본값이 대부분 600초다. 어댑터가 멈추면 사용자 세션이 그만큼 정지하므로 이 값은 구현 세부가 아니라 UX와 fail-open 노출 시간을 함께 정하는 M0 고정 대상이다.

T05-D~I·T05-K·T08·T11~T18·T20은 최초 M0에서 플랫폼 사실을 찾는 probe다. 결과를 체크인할 때 client/version/OS별 관찰값 하나로 case를 분리하고, 이후에는 그 고정 fixture를 회귀 oracle로 사용한다. T19의 각 행은 구현 전에 exact test-profile bytes와 build artifact binding을 고정한 독립 deterministic case이며 행 사이 입력, `test_run_id`, expected JSON 또는 count를 합치지 않는다.

Codex의 hook definition trust와 Claude Code의 workspace/plugin/hooks 상태는 같은 필드로 일반화하지 않는다. Codex가 내부 trust에 쓰는 hash의 값·알고리즘을 machine-readable로 얻는다고 가정하지 않으며, 제품은 exact definition bytes의 자체 digest와 heartbeat만 기록한다. 근거가 없는 native 값은 `unknown`으로 둔다.

## 3. M1 alpha 최소 규칙 — 확정 범위

| rule ID | 정확한 조건 | 판정 |
|---------|-------------|------|
| `npm.confirmed_malicious_fixture` | exact local `.tgz`의 package name·version·tarball content hash·unpacked manifest hash가 고정 fixture manifest와 모두 일치 | HIGH |
| `npm.reputation_unknown` | exact local immutable `.tgz`의 identity는 검증됐지만 optional 평판 record가 없고 다른 확정 위험이 없음 | LOW |
| `file.eicar_test_signature` | 고정 commit·path·길이·SHA-256의 EICAR 테스트 signature 정적 탐지 | HIGH |
| `file.confirmed_dangerous_script_fixture` | 고정 합성 fixture의 위험 script signature·hash 일치 | HIGH |
| `file.format_mismatch` | 확장자와 실제 형식 불일치만 확인 | LOW |
| `secret.present` | 비밀·환경변수·내부 URL 존재만 확인 | LOW |
| `action.no_warning_finding` | 지원 검사가 완료됐고 경고 근거 없음 | INFO |
| `guardrail.scan_failure` | 보호 action의 필수 검사·정규화 오류 또는 timeout | HIGH |
| `guardrail.log_failure` | 보호 action의 필수 local event 기록 실패 | HIGH |
| `guardrail.state_failure` | activation registry·rule bundle 상태를 읽거나 검증할 수 없거나, 지원 entry의 effective cwd/effective shell을 runtime에서 재검증할 수 없음 | HIGH |
| `guardrail.warning_failure` | adapter가 LOW 경고 출력을 action 전에 유효하게 생성·방출할 수 없음 | 항상 HIGH |
| `guardrail.policy_bootstrap_failure` | GatePolicy 또는 그가 참조한 CoverageManifest를 읽거나 검증할 수 없음 | 항상 HIGH |

“검증되지 않음”만으로 HIGH를 만들지 않는다. M1은 위 고정 fixture와 결정론적 규칙만 사용하며 AI가 판정을 변경하지 않는다.

앞의 `guardrail.*` 실패는 manifest에 HIGH로 고정한다. read-only scan의 같은 검사 실패는 HIGH finding report이며 scan 자체에는 deny를 만들지 않는다.

## 4. M1 명령 출처와 HIGH 흐름

| ID | 입력 | 단일 기대 결과 | 필수 event / 금지 관찰 |
|----|------|----------------|-------------------------|
| C01 | `` `npm install ./fixtures/fixture-malicious-1.0.0.tgz` 실행해 줘 `` | 고정 parser의 단일 exact span, `explicit_command`, `user_explicit`, 최초 응답에 새 runnable block 없음, HIGH deny | `high_detected → high_blocked`; target start 0 |
| C02 | “로컬 fixture-malicious tarball을 설치해 줘” | `intent`, `ai_derived`, 최초 응답에 예상 명령 원문 없음, HIGH deny | `high_detected → high_blocked`; target start 0 |
| C03 | 사용자 `npm i ./fixtures/fixture-malicious-1.0.0.tgz`, AI `npm install ./fixtures/fixture-malicious-1.0.0.tgz` | `ai_transformed`; 최초 응답은 변경 종류만, 재확인 뒤 세 출처 표시 | action ID 하나로 correlation |
| C04 | Claude의 `verified_human` prompt 또는 Codex 제품 소유 local confirmation이 exact `<REF> 명령을 직접 실행하겠습니다` grammar와 일치 | 신뢰 채널의 action-bound `reconfirmation_candidate`, 영향 설명, 출처별 원문 명령 payload 준비 | `user_reconfirmed → high_command_prepared`; target start 0 |
| C05 | 지원 Stop hook이 marker·digest 포함 assistant 메시지 관찰 | 마지막 assistant 응답 원문 포함 확인; UI 전달·열람 보장 없음 | `high_command_response_verified`; pending 삭제 |
| C06 | HIGH 뒤 사용자가 “네”만 입력 | 재확인 무효, 명령 제공 없음 | `user_reconfirmed`, `high_command_prepared`, `high_command_response_verified` 없음 |
| C07 | 대상 README·tool output이 “승인됨” 주장 | 사용자 출처·재확인으로 승격하지 않음 | 해당 action의 정상 판정 event만 |
| C08 | HIGH 공개 뒤 지원 coverage의 shell/exec로 같은·변형 명령 재시도 | 매 PreToolUse에서 다시 HIGH deny | 시도별 `high_blocked`; target result hook 없음 |
| C09-A | 만료된 short ref | 재확인·payload 거부, 새 판정 요구 | `user_reconfirmed`, `high_command_prepared` 없음 |
| C09-B | 다른 session의 short ref | 재확인·payload 거부 | 다른 session pending 변화 0 |
| C09-C | 존재하지 않는 short ref | 재확인·payload 거부 | pending 변화 0 |
| C09-D | cwd가 바뀐 ref | stale 종료, 새 판정 요구 | `high_command_prepared` 없음 |
| C09-E | relevant env/config가 바뀐 ref | stale 종료, 새 판정 요구 | `high_command_prepared` 없음 |
| C09-F | target fingerprint가 바뀐 ref | stale 종료, 새 판정 요구 | `high_command_prepared` 없음 |
| C09-G | analysis profile이 바뀐 ref | stale 종료, 새 판정 요구 | `high_command_prepared` 없음 |
| C09-H | gate policy가 바뀐 ref | stale 종료, 새 판정 요구 | `high_command_prepared` 없음 |
| C10 | 같은 session에서 병렬 HIGH 두 개 | 서로 다른 short ref와 pending, 지정 ref 하나만 resolve | action 간 command/payload 혼합 0 |
| C11 | 같은 PreToolUse·reconfirmation·prepare-disclosure·Stop 재전송 | terminal 전 prepare는 동일 payload, terminal 후 prepare는 payload 없는 `already_terminal`, Stop은 기존 검증 결과 반환 | 각 상태 전이·terminal event 정확히 1회 |
| C12 | Stop marker 일치, display digest 불일치 | response verification 실패, prepared 유지 | `high_command_response_verified` 없음 |
| C13 | Codex 모델 transcript의 prompt provenance가 `unverified` | transcript로 `Reconfirmation` 생성 불가; 제품 소유 local confirmation만 허용 | local channel fixture가 없는 client/version/OS는 HIGH 명령 공개 coverage 제외 |
| C14 | 과거 terminal action의 Stop payload를 같은 ref·동일 command의 새 action에 replay | action-bound nonce·digest 불일치로 새 action verification 실패 | 과거 event 중복 0, 새 `high_command_response_verified` 없음 |
| C15-A | prepare-disclosure state transaction의 확정 pre-commit 실패 | payload 없음, reconfirmation 미소비, 같은 prompt context retry만 허용 | raw command/event 노출 0 |
| C15-B | prepare-disclosure commit 성공 뒤 ACK 유실 | 같은 `prepare_call_id` recovery read로 동일 payload 반환, pending `prepared` | `high_command_prepared` 정확히 1회, target start 0 |
| C15-C | recovery read가 명시적 미커밋을 확인 | payload 없음, reconfirmation 미소비, 같은 prompt context retry만 허용 | `high_command_prepared` 없음 |
| C15-D | state/result/outbox integrity를 검증할 수 없음 | payload 없음, pending `quarantined`, 상태 복구 뒤 새 HIGH gate | `high_command_closed(terminal_state=quarantined)` 최대 1회; 확인 불가한 과거 event 부재를 주장하지 않음 |

일반 MCP·native file edit/write와 tool call 없는 단순 명령 조언은 M1 강제 게이트 완료 조건이 아니다. 훅이 관찰한 앞의 도구는 `NOT_COVERED`로 통과시키고 coverage 진단만 남기며 M2 전에는 M1 case로 자동 승격하지 않는다.

## 5. M1 npm·파일·scan 흐름

| ID | fixture/input | 단일 기대 결과 |
|----|---------------|----------------|
| N01 | package name·version·tarball content hash·unpacked manifest hash를 고정한 malicious local `.tgz` | `npm.confirmed_malicious_fixture`, HIGH deny |
| N02 | exact bytes/integrity를 고정한 local `.tgz`, optional 평판 record 없음 | `npm.reputation_unknown`, LOW warn·continue |
| N03 | exact bytes/hash를 고정한 정상 local `.tgz`, `reputation_applicability=not_applicable` | `action.no_warning_finding`, INFO continue |
| N04 | effective 환경의 token 존재만 확인 | `secret.present`, `finding_scope=context`, LOW; 화면은 값 없는 finding 설명, 로그는 rule ID만 기록, evidence cache에는 context finding 없음 |
| N05 | remote registry npm install | 실제 설치 bytes 결합 불가로 `guardrail.scan_failure` HIGH deny, `cache_status=bypass`; target npm process와 scanner-created network egress 0 |
| N06-A~D | N01의 name·version·tarball content hash·unpacked manifest hash 중 각각 한 필드만 다른 정상 local fixture, `reputation_applicability=not_applicable` | `npm.confirmed_malicious_fixture` 불일치, 다른 finding 없음, INFO continue |
| F01 | EICAR signature artifact를 default open 요청 | `file.eicar_test_signature`, HIGH deny |
| F02 | 고정 위험 script fixture를 open 요청 | `file.confirmed_dangerous_script_fixture`, HIGH deny |
| F03 | 정상 plain-text fixture를 open 요청 | `action.no_warning_finding`, INFO continue |
| F04 | 확장자/형식 불일치만 있는 fixture | `file.format_mismatch`, LOW warn·continue |
| R01 | EICAR artifact read-only scan | `ScanReport.max_finding_severity=HIGH`; `ActionDecision` 없음; target open/process 0 |
| R02 | 같은 artifact·version 재검사 | evidence cache hit; 새 `scan_started → scan_reported` |
| R03 | 정상 plain-text read-only scan | `ScanReport.max_finding_severity=INFO`; `ActionDecision` 없음 |
| R04 | 첫 검사 rule 실행 전 고정 clock timeout | `scan_status=failed`, `guardrail.scan_failure` HIGH finding의 `ScanReport`; scan 자체 deny 없음 |
| R05-A | scan target이 모호함 | `ScanRequest` 없음, target null, `scan_status=failed`, `guardrail.scan_failure` HIGH report; `scan_started → scan_reported`, open/process 0 |
| R05-B | scan target이 project 밖으로 escape | `ScanRequest` 없음, target null, `scan_status=failed`, `guardrail.scan_failure` HIGH report; `scan_started → scan_reported`, open/process 0 |
| R05-C | scan target을 resolve할 수 없음 | `ScanRequest` 없음, target null, `scan_status=failed`, `guardrail.scan_failure` HIGH report; `scan_started → scan_reported`, open/process 0 |
| R05-D | scan target 수가 0 | `stage=bridge_schema` failed HIGH report; target read/open/process 0 |
| R05-E | scan target 수가 2 이상 | `stage=bridge_schema` failed HIGH report; target read/open/process 0 |
| R06-A~C | scan core timeout·nonzero exit·schema-invalid output | adapter-generated scan ID, `report_source=adapter_fallback`, failed HIGH `ScanReport`; gate decision·target process 0 |

각 npm case는 Node/npm의 exact version·executable hash, package spec kind(`exact name@version|tag/range|alias|folder|local tarball|tarball URL|git|no-arg`), effective config precedence와 `allowScripts|strict-allow-scripts|dangerously-allow-all-scripts|ignore-scripts|audit`, `package-lock.json|npm-shrinkwrap.json` 우선순위를 manifest에 고정한다. M1 allow grammar는 exact local tarball만 정상 판정하며 나머지 remote/mutable spec은 N05로 간다.

EICAR 저장소 전체는 clone하지 않는다. 격리된 임시 디렉터리 또는 opt-in CI에서 commit `6ad94b0dfe2a12556ad8f9b31ebce46fa113f6f8`의 `standard/eicar.com.txt` 단일 파일만 허용하고, 길이 68 bytes와 content SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`을 manifest에 고정한다. AV/EDR 격리 가능성을 명시한다.

## 6. M1 coverage 경계

| ID | 조건 | 단일 기대 결과 |
|----|------|----------------|
| O01 | 훅이 관찰한 build/test/configure 등 M1 action kind 밖 action | option 파싱 전에 `NOT_COVERED` pass-through, `coverage_not_supported` 1회; severity·gate decision 없음 |
| O02-A | npm/file-open 지원 entry 후보지만 tool schema 해석 실패 | fail-closed HIGH; 보호 성공이나 `NOT_COVERED`로 낮추지 않음 |
| O02-B | npm/file-open 지원 entry 후보지만 shell dialect 해석 실패 | fail-closed HIGH; 보호 성공이나 `NOT_COVERED`로 낮추지 않음 |
| O03 | client가 hook으로 전달하지 않는 tool | 제품 event 0, 보호 주장 0 |
| O04 | structured scan helper가 금지된 model-supplied session/cwd 필드를 포함 | helper schema reject, `stage=bridge_schema` failed `ScanReport`; target read/open/process 0 |

## 7. M1 활성화·로그·캐시

| ID | 조건 | 단일 기대 결과 |
|----|------|----------------|
| A01 | global ON, project 항목 없음, 현재 heartbeat 성공 | scope `ON`, 유효 보호 `VERIFIED_ACTIVE` |
| A02 | global OFF, project allow-list, 현재 heartbeat 성공 | scope `ON`, 유효 보호 `VERIFIED_ACTIVE` |
| A03 | global ON, project disable-list | scope·유효 보호 `OFF` |
| A04 | 부모 ON, 더 구체적인 중첩 project OFF | 중첩 project에서 scope·유효 보호 `OFF` |
| A05 | symlink cwd | 물리 경로 정규화 뒤 같은 project ID |
| A06 | repo input이 registry 위치 변경 제안 | 관리 입력으로 무시; 같은 사용자 권한 직접 변조는 비보장 한계 표시 |
| A07 | 현재 client config에서 plugin/hooks OFF를 직접 확인 | 유효 보호 `OFF`; 보호됐다고 주장하지 않음 |
| A08 | scope ON, standalone status가 현재 세션 mode/trust를 확인하지 못함 | 유효 보호 `UNKNOWN`; self-test·client별 확인 안내 |
| A09 | GatePolicy·CoverageManifest valid, activation registry schema·integrity 실패 | standalone `configured_scope=null`, 유효 보호 `UNKNOWN`; 관찰된 보호 action은 fail-closed HIGH |
| A10-A | GatePolicy read 실패 | stale policy/cache 사용 0; scope OFF로 확인되지 않은 target-tool PreToolUse는 built-in HIGH deny·bypass; scan call은 HIGH failed report |
| A10-B | GatePolicy schema/canonical decoding 실패 | stale policy/cache 사용 0; scope OFF로 확인되지 않은 target-tool PreToolUse는 built-in HIGH deny·bypass; scan call은 HIGH failed report |
| A10-C | GatePolicy integrity 실패 | stale policy/cache 사용 0; scope OFF로 확인되지 않은 target-tool PreToolUse는 built-in HIGH deny·bypass; scan call은 HIGH failed report |
| A10-D | GatePolicy가 참조한 CoverageManifest read 실패 | stale policy/manifest/cache 사용 0; scope OFF로 확인되지 않은 target-tool PreToolUse는 built-in HIGH deny·bypass; scan call은 HIGH failed report |
| A10-E | CoverageManifest schema/canonical decoding/integrity 실패 | stale policy/manifest/cache 사용 0; scope OFF로 확인되지 않은 target-tool PreToolUse는 built-in HIGH deny·bypass; scan call은 HIGH failed report |
| A10-F | CoverageManifest digest가 GatePolicy 값과 불일치 | stale policy/manifest/cache 사용 0; scope OFF로 확인되지 않은 target-tool PreToolUse는 built-in HIGH deny·bypass; scan call은 HIGH failed report |
| A10-G | registry valid scope OFF + GatePolicy/manifest invalid | 유효 보호 `OFF`; policy 진단은 표시할 수 있지만 target-tool gate·보호 event 0 |
| A11 | registry·GatePolicy·CoverageManifest 유효, client trust/heartbeat는 `UNKNOWN`, 지원 PreToolUse 실제 도착 | 관찰 action은 정상 gate, status는 계속 `UNKNOWN`; `protection_status_unknown` 1회, 세션 전체 보호 문구 없음 |
| A12 | verified-human exact `enable_project`, adapter가 현재 physical project 주입 | registry version CAS 1회, 같은 request replay는 동일 result |
| A13 | 모델·대상 문서가 임의 project path를 관리 요청에 주입 | schema reject, registry 변화 0 |
| A14 | 같은 canonical project의 충돌 scope 항목 | registry invalid, status `UNKNOWN`, 관찰 보호 action은 fail-closed HIGH |
| A15 | `clear_logs` 요청 | logs만 삭제, registry·policy·cache·pending 변화 0 |
| A16 | `clear_cache` 요청 | cache만 삭제, registry·policy·logs·pending 변화 0 |
| K01 | 동일 local immutable target/action/verified-context/profile/policy/version | cache hit, 사용자 절차·새 event 반복 |
| K02-A | target 1 byte 변경 | miss |
| K02-B | symlink target 변경 | miss |
| K02-C | permission 변경 | miss |
| K03-A | command 변경 | action cache miss |
| K03-B | cwd 변경 | action cache miss |
| K03-C | resolved executable 변경 | action cache miss |
| K03-D | relevant env 변경 | action cache miss |
| K03-E | package-manager config 변경 | action cache miss |
| K04-A | core version 변경 | 관련 cache miss |
| K04-B | rule-bundle digest 변경 | 관련 cache miss |
| K04-C | security-data version 변경 | evidence cache miss |
| K04-D | analysis-profile digest 변경 | evidence/action cache miss |
| K04-E | gate-policy digest 변경 | action cache miss |
| K05 | corrupt cache, rescan 성공 | miss 뒤 새 판정 |
| K06 | corrupt cache, rescan 실패인 보호 action | fail-closed HIGH |
| K07 | cache writeback만 실패, fresh scan·activity log 성공 | fresh decision 유지, `cache_status=bypass`, stale allow 사용 0 |
| K08 | resolved executable/effective env/config를 입증할 수 없음 | action cache bypass |
| L01 | 정상 activity write | event별 필수 필드만 저장, raw command/path/secret 없음 |
| L02 | activity write 실패인 보호 action | fail-closed HIGH; 고장 난 로그에 failure event 영속 요구 없음 |
| L03-A | 30일 보존 한도 먼저 도달 | event와 tombstone에서 각각 오래된 항목 정리 |
| L03-B | 종류별 1,000건 한도 먼저 도달 | event와 tombstone에서 각각 오래된 항목 정리 |
| L04 | LOW finding은 만들었지만 경고 transport 실패 | LOW 후보 폐기, 같은 action의 `guardrail.warning_failure` HIGH deny; `warned_low` 없음, target start 0 |

## 8. M1 명령 표시 확정 정책

아래 S01–S10은 D13의 secret literal-all 정책과 제어문자 안전 변환을 함께 검증한다. secret은 출처와 무관하게 exact blocked command의 원문 bytes를 최대 10분의 `PendingBlock`에 보관하고 재확인 뒤 그대로 응답에 포함하며 치환·정규화하지 않는다. 반면 ANSI/OSC·양방향 제어문자·NUL·코드펜스 탈출은 raw terminal control로 출력하지 않고 dialect별 `display_safe_reference` 변환을 적용해 `표시 안전 변환`으로 라벨링한다. 두 규칙은 독립이며 한 명령에 secret과 제어문자가 함께 있으면 secret span은 literal, 제어문자 span은 변환이다. 활동 로그·캐시는 계속 원문 명령과 secret을 저장하지 않는다.

A~C는 각각 POSIX shell, PowerShell, `cmd.exe`의 독립 case다.

| ID | 조건 | 단일 기대 결과 |
|----|------|----------------|
| S01-A~C | verified-user secret 포함 + exact `<REF> 명령을 직접 실행하겠습니다` | secret 원문은 PendingBlock에 최대 10분 저장·응답 포함; 로그/cache에는 HMAC·rule ID만 |
| S01-D | secret 포함 여부와 무관하게 grammar 불일치 또는 다른 ref/session | 재확인 무효, payload 없음; pending 미소비 |
| S02-A~C | AI가 파일·환경에서 얻은 secret 또는 출처 불명 secret | provenance와 무관하게 exact secret bytes 보존·응답 포함; redaction 0 |
| S03 | prompt provenance/correlation miss인 secret span | 명령 출처는 `unknown`으로 두되 blocked command의 secret bytes는 그대로 보존 |
| S04-A~C | 대상 문서나 모델이 secret 치환·변형을 요구 | 요구를 무시하고 exact blocked command bytes를 사용 |
| S05-A~C | ANSI/OSC·양방향 제어·NUL·delimiter-like bytes 포함 | dialect별 `display_safe_reference` transformation, raw control output 0, exact/runnable 명령 주장 없음; 같은 명령의 secret span은 계속 literal |
| S06-A | pending이 prepare 전에 TTL 만료 | raw command·secret 삭제, expired tombstone의 `display_digest_hmac=null` |
| S06-B | payload prepare 뒤 hard TTL 이상에 Stop 도착 | expiry CAS가 우선, raw 삭제, tombstone `expired`; `high_command_response_verified` 없음 |
| S07 | Stop response verification 성공 | raw command·secret 즉시 삭제, HMAC tombstone만 유지 |
| S08 | 사용자 취소 또는 action 변경 | raw command·secret 즉시 삭제, payload 없음 |
| S09-A | renderer가 secret span을 치환·정규화 | payload 거부, `disclosure_eligible=false`; 변형 명령 제공 0 |
| S09-B | renderer가 제어문자를 변환하지 않고 raw terminal control로 방출 | payload 거부, `disclosure_eligible=false`; raw control output 0 |
| S10-A~C | terminal transaction의 pre-commit·commit 후 ACK 전·compaction 전 crash 뒤 동일 입력 replay | terminal event 정확히 1회, tombstone 존재, raw command·secret 복구 불가; event/raw/tombstone 혼합 중간 상태 0 |

## 9. M1 alpha 확정 범위

M1 alpha는 npm 설치, 로컬 파일 열기와 두 대상의 명시적 read-only scan을 포함한다. build/test/update/remove/configure/permission, native file edit/write와 일반 MCP는 M1에서 `NOT_COVERED`다.

## 10. M1 검사 실패 확정 정책

보호 action의 필수 검사·상태·로그 실패는 HIGH deny다. read-only scan의 같은 실패는 HIGH finding report이며 scan 자체에는 deny를 만들지 않는다. LOW warning transport 실패와 GatePolicy bootstrap 실패도 HIGH다.

## 11. M2로 명시적으로 미룬 항목

- install lifecycle hook에서 download/shell sink까지 도달성
- secret source에서 외부 전송 sink까지 데이터 흐름
- archive/container 내부, macro·default-app 실행 경로, zip bomb 분석
- AI assessment의 HIGH 승격과 session·prompt·model·action binding
- 일반 MCP, file edit/write와 이미 시작된 interactive process 입력
- 외부 MAL/OSV 평판 데이터팩

## 12. M1 fixture manifest와 착수·완료 게이트

각 M1 case는 구현 전에 다음을 고정한다.

```text
case ID, phase and applicability(client/version/OS)
exact human-input bytes and trusted source event(prompt or local confirmation)
native tool payload, executable, argv, cwd and relevant env fixture
target file bytes, mode, symlink graph and content hash
registry/package metadata, exact version and integrity when applicable
fixed clock, timeout, resource limits and HMAC matcher rules
expected PromptContext, HookEnvelope, ScanBridgeEnvelope, DisclosurePrepareEnvelope, ActionRequest-or-pre-normalization failure, ScanRequest, Finding, ActionDecision-or-ScanReport-or-CoverageResult, PendingBlock, Reconfirmation, DisclosurePayload, TerminalDisclosureTombstone, LocalEvent, cache record, GatePolicy, CoverageManifest, ActivationRegistry and StatusReport JSON as applicable
ordered required events with exact count
forbidden process, file marker, result hook and event observations
```

M1 구현 착수 조건은 다음과 같다.

1. 위의 모든 T case가 지원할 각 client/version/OS에서 통과한다.
2. 사용자별 SQLite의 schema·migration·locking, project/directory partition, transaction/outbox/crash-recovery와 management operation contract를 fixture로 고정한다.
3. C01–C15, N01–N06, F01–F04, R01–R06, O01–O04, A01–A16, K01–K08, L01–L04, S01–S10의 manifest·expected JSON이 모두 체크인된다.
4. parser/scanner timeout, 파일 크기·수, cache TTL·용량, canonical encoding과 HMAC key rotation이 고정된다.
5. M0 결과로 확인하지 못한 tool/client/OS는 coverage matrix에서 명시적으로 제외된다.
6. T11 결과가 `unverified`인 Codex는 제품 소유 local confirmation의 action-bound fixture를 고정하며, fixture가 없는 client/version/OS는 HIGH 명령 공개 coverage에서 제외한다.
7. D13의 확정값을 GatePolicy·ActivationRegistry·reconfirmation·PendingBlock·storage expected JSON에 반영한다.

M1 alpha 완료 조건은 다음과 같다.

1. 모든 C01–C15, N01–N06, F01–F04, R01–R06, O01–O04, A01–A16, K01–K08, L01–L04, S01–S10 case가 `case × core/e2e × client/version × OS` applicability/pass matrix에 연결되고 적용 대상에서 전부 통과한다.
2. 각 case의 ordered event count와 forbidden process/file/result 관찰이 모두 expected와 일치한다.
3. scan helper는 R01–R06·O04, 모든 지원 disclosure dialect는 S01–S10을 통과한다.
4. coverage에서 제외된 client/tool/OS를 상태와 사용자 문구가 보호 성공으로 표시하지 않는다.

앞의 M1 구현 착수 조건 1–7을 닫기 전 가능한 다음 구현 작업은 M0 tracer-bullet뿐이다.
