# 실행 게이트 출력·로컬 계약

> 상태: **M0 증거 계약 + M1 후보 계약**. 네이티브 hook payload와 deny 응답은 M0 tracer-bullet에서 고정한다. M1 exact invocation은 transient하게 HMAC으로 식별하고 선택된 표시 정책을 적용한 단기 값만 `PendingBlock`에 최대 10분 보관하며 활동 로그·캐시에는 저장하지 않는다.

## 1. 사용자 표시

모든 판정은 다음 정보를 쉬운 말로 보여 준다.

```text
판정: <HIGH | LOW | INFO>
상태: <AI 자동 실행 차단 | 경고 후 계속 | 기록 후 계속 | 읽기 전용 검사 결과>
요청 유형: <구체적 명령어 | 의도 기반 요청 | 출처 확인 불가>
작업: <설치 | 열기 | 실행 | 설정 | 권한 | 검사 | 기타>
대상: <비밀값 없는 짧은 식별 정보>

발견 내용: <무엇이 발견됐는지>
영향: <실행할 경우 가능한 결과>
오탐 가능성·반대 근거: <정상 개발 파일일 가능성과 확인 근거>
더 안전한 대안: <정적 확인, 버전 고정, 텍스트 보기 등>
```

`INFO`는 별도 경고 UI를 생략할 수 있지만 로컬 활동 기록은 남긴다. `INFO`를 안전 보증으로 표현하지 않는다.

### 1.1 최초 HIGH 차단

최초 차단 응답에는 AI가 새로 제공하는 실행 가능한 명령 블록을 넣지 않는다. 공개 가능한 exact invocation과 pending state가 있을 때는 다음 형식이다.

```text
요청 유형: <구체적 명령어 | 의도 기반 요청 | 출처 확인 불가>
명령 출처: <사용자 직접 제공 | AI 생성 | AI 변형 | 대상 유래 | 확인 불가>
작업 요약: <비실행 설명>
명령 상태: 실행되지 않음 — 작업 <짧은 action ref> 재확인 대기
재확인 방법: <짧은 action ref> 명령을 직접 실행하겠습니다
```

사용자가 명령을 직접 적었다면 그 사실만 표시한다. AI가 명령을 변경했다면 옵션·cwd·wrapper 등 변경 종류만 설명한다.

`disclosure_eligible=false`인 operational HIGH에는 action ref나 재확인 문구를 만들지 않고 다음처럼 제한을 설명한다.

```text
명령 상태: 실행되지 않음 — 신뢰 가능한 exact 명령을 제공할 수 없음
제한 사유: <정규화·상태·표시·pending 생성 실패 중 redacted reason>
다음 단계: 상태를 복구한 뒤 작업을 새로 요청
```

### 1.2 명시적 재확인 뒤

사용자가 현재 user-role 메시지에서 특정 action ref와 직접 실행 의사를 명시한 경우에만 명령을 제공한다.

```text
사용자 요청 명령어:
<사용자가 직접 입력한 명령이 있을 때>

AI 예상 명령어:
<의도 요청에서 AI가 만든 후보가 있을 때>

AI 실행 예정 명령어:
<AI가 실제 tool input을 만들었을 때>

차단된 명령어:
<PreToolUse가 거부한 정확한 명령>

차이: <서로 다른 값의 옵션·cwd·wrapper·실행 파일 차이>
명령 상태: 사용자에게 제공됨 — 실행 여부 확인 불가
```

동일한 값은 한 번만 표시하고 출처 라벨을 병기한다. 실제 `PreToolUse` 호출이 있었고 `rendering=literal`이면 `차단된 명령어`가 실행 직전 exact 값이다. `rendering=display_safe_reference`이면 제어문자만 안전 표현으로 바꾼 `차단 명령의 표시 안전 변환본`이며 exact bytes라고 주장하지 않는다. AI는 명령을 대신 실행하지 않는다.

### 1.3 명령 원문과 비밀값

재확인 뒤에는 secret 출처와 무관하게 exact blocked command의 비밀값 원문 bytes를 치환·정규화 없이 그대로 제공한다. **터미널 표시 자체를 조작하는 bytes만 예외다.**

- secret 개수나 출처에 따른 별도 재확인 분기는 두지 않는다.
- ANSI/OSC·양방향 제어문자·NUL·코드펜스 탈출은 터미널에서 동작시키지 않고 가시적인 dialect별 안전 표현으로 바꾼다. 변환이 하나라도 적용되면 `rendering=display_safe_reference`로 표시하고 exact/runnable 값이라고 주장하지 않는다.
- 이 예외를 두는 이유는 위험 명령 원문이 정의상 신뢰할 수 없는 대상에서 유래할 수 있기 때문이다. 제어 시퀀스를 그대로 출력하면 사용자가 화면에서 보는 명령과 실제로 복사해 붙여넣는 명령이 달라질 수 있고, 그러면 “위험을 이해한 상태의 선택”이라는 이 절의 전제가 무너진다. secret literal 정책과 독립적으로 항상 적용한다.
- 비밀 노출 가능성과 제어문자 변환 사실을 함께 영향 설명에 명시한다.
- 명령 segment 검증은 시각적 렌더링이 아니라 raw response bytes·길이·digest로 수행한다. 제어문자 변환이 적용된 segment는 변환 후 bytes를 기준으로 계산한다.
- 원문은 사용자별 `PendingBlock`에 최대 10분만 보관하고 로그·캐시에는 비밀값과 명령 원문을 저장하지 않는다.

## 2. 신뢰 경계와 명령 출처

명령 출처의 권위 있는 source event는 어댑터가 **인간 제출로 검증한** prompt event다. HIGH 재확인은 Claude의 검증된 prompt event 또는 Codex의 제품 소유 local-confirmation record 중 하나를 사용한다.

- prompt 어댑터만 `PromptContext`를 만들 수 있다. `Reconfirmation` source event는 Claude prompt 어댑터 또는 Codex local-confirmation adapter만 만들 수 있다.
- Claude Code와 Codex의 prompt provenance는 별도로 검증한다. Codex 공식 `UserPromptSubmit`에는 인간 입력과 자동 continuation을 구분하는 필드가 없으므로 기본값은 `source_assurance=unverified`다. Codex 재확인은 prompt가 아니라 모델 transcript와 분리된 Secure Onboard 소유 로컬 확인 채널에서 만든 action-bound record만 사용한다.
- 스킬·모델·대상 문서·tool output은 분류 후보를 제안할 수 있지만 사용자 명령이나 재확인을 스스로 확정할 수 없다.
- provenance가 검증되지 않았거나 correlation이 없거나 만료되면 `request_kind=unknown`, `command_origin=unknown`으로 처리한다. 이를 `user_explicit` 또는 재확인으로 추정하지 않는다.
- 실제 차단 입력은 `PreToolUse`가 받은 tool name·input·cwd다.

`user_explicit`은 사용자 명령, 실행 파일·argv와 실행 context가 모두 같을 때만 사용한다. 명령·wrapper·옵션·cwd·관련 환경 중 하나라도 AI가 바꾸면 `ai_transformed`가 우선한다.

## 3. 공통 식별자

| 필드 | 의미 |
|------|------|
| `session_id` | 클라이언트 세션 ID 또는 어댑터가 만든 세션 ID |
| `adapter_turn_id` | 어댑터가 보존하는 nullable turn ID. Codex hook의 native `turn_id`는 반드시 그대로 매핑하며 다른 클라이언트는 동등성이 fixture로 증명될 때만 채움 |
| `native_tool_call_id` | 클라이언트의 `tool_use_id` 등 개별 tool call ID. PreToolUse·result correlation에 필수 |
| `prompt_context_id` | 하나의 실제 user-role prompt event ID |
| `action_id` | 공용 코어가 ingress에서 한 보호 action에 발급한 ID. core 자체가 시작되지 못한 adapter fallback만 어댑터가 같은 형식으로 발급 |
| `scan_id` | 읽기 전용 scan bridge ingress에서 공용 코어가 발급한 ID. core 자체가 시작되지 못한 scan adapter fallback만 어댑터가 같은 형식으로 발급 |
| `event_id` | 활동 기록 한 건의 고유 ID. correlation ID로 재사용하지 않음 |

모든 ID는 같은 사용자·세션 밖에서 의미를 추측할 수 없는 값으로 만든다.

### 3.0 `M0TestProfile v1`

M0 test artifact가 sentinel을 활성화하는 유일한 입력은 다음 strict schema의 exact UTF-8 bytes다. 아래 값은 필드 계약 예시이며 실제 지원값은 client별 fixture 파일에 기록한다.

```json
{
  "schema_version": "m0-test-profile/v1",
  "build_flavor": "test",
  "client": "codex",
  "client_version": "M0_FIXED_VERSION",
  "os": "macos",
  "architecture": "arm64",
  "fixture_runtime": {
    "executable_path": "/absolute/path/to/node",
    "executable_sha256": "sha256:fixture-runtime",
    "version_output": "vM0_FIXED_VERSION"
  },
  "shell_binding": {
    "executable_path": "/bin/zsh",
    "executable_sha256": "sha256:physical-shell-bytes",
    "flags": ["-lc"],
    "dialect": "posix_sh",
    "resolution_fingerprint": "sha256:effective-shell"
  },
  "helpers": [
    {
      "role": "default",
      "relative_path": "helpers/m0-target.mjs",
      "content_sha256": "sha256:default-helper",
      "command_grammar": "posix_ascii_argv4/v1",
      "allowed_sentinels": ["high", "low", "info"]
    },
    {
      "role": "failure",
      "relative_path": "helpers/m0-target-fail.mjs",
      "content_sha256": "sha256:failure-helper",
      "command_grammar": "posix_ascii_argv4/v1",
      "allowed_sentinels": ["low", "info"]
    }
  ],
  "marker_root_relative": "markers"
}
```

모든 object는 위 key를 정확히 한 번씩 가지며 additional field를 거부한다. `helpers`는 `default`, `failure`가 이 순서로 정확히 한 번씩 있어야 하고 `allowed_sentinels`도 예시의 순서·값과 같아야 한다. 문자열은 Unicode normalization을 하지 않고 JSON decode 결과의 UTF-8 bytes를 그대로 비교한다. profile 파일 자체는 UTF-8 BOM이 없는 JSON object 하나와 마지막 LF 하나로 끝나며, compile-time digest와 supplied digest는 **그 LF를 포함한 전체 파일 bytes**의 SHA-256이다. JSON duplicate key, invalid UTF-8, trailing non-whitespace와 심볼릭 링크 profile path는 거부한다.

M0 macOS fixture의 `posix_ascii_argv4/v1`은 shell text 전체가 `runtime-path U+0020 helper-path U+0020 sentinel U+0020 marker-path`인 정확히 네 token인 grammar다. leading/trailing whitespace, 연속 whitespace, quote, backslash, 제어문자와 shell metacharacter `;&|<>()$`를 허용하지 않는다. runtime token은 profile의 exact absolute path와 같고 helper token은 harness가 제공한 physical trusted root와 `relative_path`를 결합한 path와 byte-for-byte 같아야 한다. sentinel은 해당 helper allow-list에 있어야 하며, marker는 symlink를 거치지 않은 `<trusted-root>/<marker_root_relative>/<test_run_id>/<test_case_id>.marker`의 physical path여야 한다. Windows 또는 공백을 포함한 path grammar는 M0 실증 뒤 새 schema version으로 추가하며 이 버전에서 추정 지원하지 않는다.

`fixture_runtime.executable_path`와 shell path는 절대 physical path다. helper `relative_path`와 `marker_root_relative`는 absolute path, `.`, `..`, symlink를 허용하지 않고 매 실행의 사용자 전용 trusted root 아래에서만 해석한다. runtime hook이 읽는 trusted root와 `profiles`, `helpers`, marker directory chain은 현재 effective user 소유 0700이고 profile/helper file은 같은 user 소유 0600이어야 한다. 저장소에 체크인한 0755/0644 fixture 원본은 증거·복사 source일 뿐 runtime trusted root로 직접 로드하지 않으며, native harness가 0700/0600 private copy를 만든 뒤 hook에 넘긴다.

profile/runtime/helper/shell bytes의 SHA-256은 leaf에 `O_NOFOLLOW`를 적용해 연 같은 physical file descriptor를 64KiB chunk로 읽고, 읽기 전후 descriptor·path metadata와 canonical path가 그대로인지 확인한다. 총 byte 상한은 profile 64KiB, helper 1MiB, fixture runtime과 shell 각각 64MiB다. profile load는 두 helper를 모두 검사하고 실제 command match 직전 선택된 helper를 다시 검사한다. `fixture_runtime.version_output`은 fixture manifest 생성 시 그 physical runtime의 `--version` raw stdout에서 마지막 LF만 제외해 관찰한 값이다. action마다 `--version`을 다시 실행하지는 않으며, 같은 runtime bytes digest를 재검증해 그 생성 시점 관찰과 결속한다.

`shell_binding.resolution_fingerprint`는 M0 host-process probe에서 고정한 executable path·flags·dialect 조합의 observation label이고 shell executable bytes의 digest가 아니다. `executable_sha256`이 exact shell bytes를 별도로 결속하며, 두 값과 physical path를 action마다 모두 재검증한다. 이 test-only 결속만으로 native effective shell 지원을 주장하지 않고 별도 live evidence가 생기기 전까지 coverage의 `verified`와 `included`는 0으로 유지한다. profile path는 target project의 physical root 밖에 있어야 하며 source 검증 전에 target project가 제공한 environment나 설정으로 위치를 바꾸지 않는다. M0의 portable Rust reader와 macOS 전용 생성기는 leaf FD 및 전후 identity를 결속하지만 parent directory chain을 dirfd로 잠그지는 않는다. 따라서 동시 parent rename/symlink 교체를 커널 수준에서 제거했다고 주장하지 않으며 이 잔여 TOCTOU 때문에 protection coverage를 확대하지 않는다.

### 3.1 M0 전용 증거 스키마

M0는 아직 정하지 않은 production registry·GatePolicy·CoverageManifest·HMAC key를 만들지 않는다. `HookEnvelope`의 native mapping 뒤에는 아래 test-only 스키마를 사용하며, production `ActionRequest v1`, `LocalEvent v1`, `StatusReport v1`의 성공으로 계산하지 않는다. exact test-profile UTF-8 bytes의 SHA-256과 fixture의 고정 clock·placeholder ID만 사용하고 비밀값·실사용자 데이터는 넣지 않는다.

```json
{
  "schema_version": "m0-action-request/v1",
  "phase": "m0",
  "test_case_id": "T02",
  "test_run_id": "m0-run-t02-01",
  "test_profile_digest": "sha256:m0-test-profile-bytes",
  "action_id": "m0-action-01",
  "envelope_id": "envelope-01",
  "client": "codex",
  "session_fixture_id": "m0-session-01",
  "native_tool_call_id": "tool-call-01",
  "sentinel": "high",
  "invocation": {
    "kind": "shell_text",
    "shell_executable": "/bin/zsh",
    "shell_flags": ["-lc"],
    "dialect": "posix_sh",
    "command_text": "<M0_FIXED_HELPER_INVOCATION>",
    "shell_resolution_source": "m0_runtime_probe",
    "shell_resolution_fingerprint": "sha256:effective-shell"
  },
  "physical_cwd_fixture": "<M0_TEMP_CWD>",
  "cwd_resolution_source": "m0_effective_cwd_binding"
}
```

```json
{
  "schema_version": "m0-action-decision/v1",
  "phase": "m0",
  "test_case_id": "T02",
  "test_run_id": "m0-run-t02-01",
  "decision_id": "m0-decision-01",
  "action_id": "m0-action-01",
  "client": "codex",
  "session_fixture_id": "m0-session-01",
  "native_tool_call_id": "tool-call-01",
  "severity": "HIGH",
  "gate_decision": "deny",
  "rule_id": "m0.sentinel.high",
  "decision_source": "core",
  "failure_code": null,
  "cache_status": "bypass",
  "pending_action_ref": null
}
```

```json
{
  "schema_version": "m0-event/v1",
  "phase": "m0",
  "test_case_id": "T02",
  "test_run_id": "m0-run-t02-01",
  "event_id": "m0-event-01",
  "observed_at": "2026-07-22T00:00:00Z",
  "event_type": "high_blocked",
  "client": "codex",
  "session_fixture_id": "m0-session-01",
  "action_id": "m0-action-01",
  "native_tool_call_id": "tool-call-01",
  "severity": "HIGH",
  "rule_id": "m0.sentinel.high",
  "outcome": null
}
```

```json
{
  "schema_version": "m0-status-report/v1",
  "phase": "m0",
  "report_source": "test_harness",
  "test_case_id": "T19-A-HIGH",
  "test_run_id": "m0-run-t19-a-high-01",
  "client": "codex",
  "client_version": "M0_FIXED_VERSION",
  "plugin_version": "M0_FIXED_PLUGIN_VERSION",
  "os": "macos",
  "architecture": "arm64",
  "client_executable": {
    "invoked_path": "/absolute/path/to/codex",
    "resolved_path": "/absolute/path/to/codex-native",
    "sha256": "sha256:codex-native",
    "version_output": "codex-cli M0_FIXED_VERSION"
  },
  "client_runtime_artifact": {
    "role": "native_backend",
    "absolute_path": "/absolute/path/to/codex-native-backend",
    "sha256": "sha256:codex-native-backend"
  },
  "artifact_kind": "test",
  "artifact_digest": "sha256:m0-test-artifact",
  "configured_scope_fixture": "ON",
  "plugin_installed": true,
  "hooks_enabled": true,
  "client_mode_evidence": {
    "plugin_state": "installed_enabled",
    "launch_mode": "normal",
    "explicit_plugin_supplied": null,
    "disable_all_hooks": null,
    "codex_hooks_feature": "enabled",
    "setting_evidence": [
      {
        "source": "codex_user_config",
        "source_digest": "sha256:codex-user-config-bytes",
        "claim": "codex_hooks_feature_enabled"
      }
    ],
    "evidence_digest": "sha256:codex-launch-and-config-fixture"
  },
  "session_fixture_id": "m0-session-new-01",
  "session_state": "new_after_review",
  "hook_evidence": [
    {
      "source": "codex_user_plugin",
      "definition_digest": "sha256:current-definition-bytes",
      "disposition": "loaded_active",
      "reason": "selected_reviewed_definition"
    }
  ],
  "bundled_hook_definition_digest": "sha256:current-definition-bytes",
  "reviewed_hook_definition_digest": "sha256:current-definition-bytes",
  "product_hook_review": "verified",
  "heartbeat": {
    "status": "passed",
    "evidence_scope": "current",
    "session_fixture_id": "m0-session-new-01",
    "hook_source": "codex_user_plugin",
    "hook_definition_digest": "sha256:current-definition-bytes"
  },
  "self_test": {
    "status": "passed",
    "evidence_scope": "current",
    "session_fixture_id": "m0-session-new-01",
    "hook_source": "codex_user_plugin",
    "hook_definition_digest": "sha256:current-definition-bytes"
  },
  "client_trust": "unknown",
  "effective_protection": "VERIFIED_ACTIVE",
  "test_profile": "loaded",
  "test_profile_expected_digest": "sha256:m0-test-profile-bytes",
  "test_profile_supplied_digest": "sha256:m0-test-profile-bytes",
  "test_profile_rejection_reason": null,
  "sentinel_binding_result": "matched",
  "next_checks": [],
  "run_evidence": {
    "object_counts": {
      "hook_envelope": 1,
      "m0_action_request": 1,
      "m0_action_decision": 1,
      "m0_event": 2,
      "m0_status_report": 1
    },
    "canonical_digests": {
      "hook_envelope": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      "m0_action_request": ["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
      "m0_action_decision": ["sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
      "m0_event": [
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      ]
    },
    "ordered_events": ["high_detected", "high_blocked"],
    "observations": {
      "target_process_start_count": 0,
      "target_marker_count": 0,
      "operator_approval_count": 0,
      "secure_onboard_approval_count": 0,
      "uncorrelated_result_count": 0
    }
  },
  "artifact_inspection": null,
  "reasons": [],
  "limitations": [
    "Codex internal trust hash is not machine-readable",
    "M0 status does not represent production protection"
  ]
}
```

`sentinel`은 `high|low|info`이며 severity/gate/rule 조합은 각각 `HIGH/deny/m0.sentinel.high`, `LOW/continue/m0.sentinel.low`, `INFO/continue/m0.sentinel.info`다. 모든 `M0ActionDecision.pending_action_ref`는 null이다. 성공 helper의 ordered event는 HIGH `high_detected → high_blocked`, LOW `warned_low → tool_completed`, INFO `allowed_info → tool_completed`로 고정한다. core child 장애는 `severity=HIGH`, `gate_decision=deny`, `rule_id=guardrail.scan_failure`, `decision_source=adapter_fallback`, 고정 `failure_code=core_timeout|core_nonzero|core_schema_invalid`, event `high_detected → high_blocked`다. 다른 result outcome은 개별 T case가 정확히 하나의 event variant를 고정한다. `m0-event`는 production local history에 쓰지 않는다.

LOW·INFO result correlation은 사용자 전용 state root에서 `prepared → delivered` 두 단계로 유지한다. PreToolUse는 native 응답을 stdout에 쓰고 flush한 뒤 해당 envelope/request/decision/event/native-output evidence를 모두 기록하며, 마지막에 prepared decision bytes의 domain-separated SHA-256을 담은 delivered marker를 `create_new`로 만든다. result hook은 decision과 marker가 모두 존재하고 marker digest가 decision bytes와 일치할 때만 결과 event를 만든다. stdout 또는 post-response evidence가 실패하거나 그 사이 process가 종료되면 prepared file만 남고 result는 이를 소비하지 않으며 pre hook은 native blocking exit 2로 끝난다. 동일 decision의 중복 호출은 같은 marker를 idempotent하게 확인하고 실패한 호출이 다른 호출의 delivered 상태를 삭제하지 않는다.

M0 core child는 native hook의 5초 제한보다 짧은 최대 4초 deadline 안에서 실행한다. Unix에서는 child를 별도 process group으로 시작하고 정상 종료·timeout·`try_wait` 오류 모두에서 남은 group을 `SIGKILL`로 정리한 뒤 직접 child를 reap하고 stdin/stdout/stderr worker를 join한다. 따라서 같은 group에서 pipe를 상속한 descendant가 core timeout을 native hook timeout까지 늘릴 수 없다. non-Unix의 process-tree 종료는 M0에서 검증하지 않았으며 해당 조합을 coverage에 포함하지 않는다.

`M0Event`는 예시의 모든 top-level 필드를 항상 유지한다. event별 유효 조합은 다음뿐이다.

| `event_type` | `severity` | `rule_id` | `outcome` |
|--------------|------------|-----------|-----------|
| `high_detected`, `high_blocked` | `HIGH` | `m0.sentinel.high|guardrail.scan_failure` 중 해당 decision과 같은 값 | null |
| `warned_low` | `LOW` | `m0.sentinel.low` | null |
| `allowed_info` | `INFO` | `m0.sentinel.info` | null |
| `tool_completed` | 앞선 decision의 `LOW|INFO` | 앞선 decision의 exact rule ID | `success` |
| `tool_failed` | 앞선 decision의 `LOW|INFO` | 앞선 decision의 exact rule ID | `failure` |

모든 event는 같은 `test_case_id|test_run_id|client|session_fixture_id|action_id|native_tool_call_id`의 `M0ActionDecision`에 연결된다. HIGH에는 result event를 만들지 않고 LOW·INFO result event는 같은 native tool call ID의 실제 result hook이 있을 때만 만든다. 이 표 밖 event type·nullability·조합은 schema-invalid다.

`m0-status-report`의 상태 계약은 다음과 같다.

| 조건 | 필수/nullable 규칙 |
|------|--------------------|
| 공통 | `report_source=test_harness`, `test_case_id`, 한 harness invocation의 고유 `test_run_id`, `client`, nullable exact `client_version|plugin_version`, `os=macos|windows`, `architecture=arm64|x86_64`, `client_executable`, `client_runtime_artifact`, `artifact_kind=test|production`, `artifact_digest`, `configured_scope_fixture=ON|OFF|null`, `plugin_installed=true|false|null`, `hooks_enabled=true|false|null`, `client_mode_evidence`, native plugin/hook evidence, `effective_protection`, `sentinel_binding_result`, `next_checks`, nullable `run_evidence|artifact_inspection`, `reasons`, `limitations` 필수. `client_executable`은 exact `invoked_path`, symlink를 해소한 `resolved_path`, resolved file bytes의 `sha256`, 마지막 LF를 제외한 exact `--version` stdout `version_output`을 모두 가진다. `client_runtime_artifact`는 manifest §3.3과 같은 role/path/hash를 가지며 Claude `resolved_executable`은 resolved launcher와 같고 Codex `native_backend`는 별도 platform binary를 결속한다. `client_version`은 version 출력에서 client별 고정 parser로 얻은 값과 같아야 한다. production binary가 이 스키마를 emit하지 않고 harness가 관찰 증거로 report를 만든다. |
| client mode | `client_mode_evidence`는 모든 하위 필드를 유지한다. `plugin_state=installed_enabled|installed_disabled|not_installed|unknown`이다. `not_installed`이면 top-level `plugin_installed=false`, `plugin_version=null`, `hooks_enabled=false`, `effective_protection=OFF`; `installed_disabled`이면 `plugin_installed=true`, `hooks_enabled=false`, `effective_protection=OFF`다. Codex는 `launch_mode=normal|unknown`, `explicit_plugin_supplied=null`, `disable_all_hooks=null`, `codex_hooks_feature=enabled|disabled|unknown`이다. Claude는 `launch_mode=normal|claude_bare|claude_simple|unknown`, `explicit_plugin_supplied=true|false|null`, `disable_all_hooks=true|false|null`, `codex_hooks_feature=not_applicable`이다. `setting_evidence[]`는 높은 effective precedence부터 정렬하고 각 항목은 `source=codex_user_config|codex_project_config|claude_user_settings|claude_project_settings|claude_local_settings|claude_managed_settings`, exact `source_digest`, `claim=codex_hooks_feature_enabled|codex_hooks_feature_disabled|claude_disable_all_hooks_true|claude_disable_all_hooks_false`를 가진다. client가 다른 source/claim 또는 같은 effective precedence의 충돌 claim은 invalid다. `disable_all_hooks`와 Codex feature는 각각 첫 applicable claim과 같아야 한다. `evidence_digest`는 exact launch argv, plugin-list output과 전체 ordered setting evidence를 묶은 자체 SHA-256이다. plugin state·launch mode·explicit plugin·disableAllHooks·Codex feature 중 하나라도 unknown/null이 아닌 관찰값이면 non-null이어야 한다. Claude `disable_all_hooks=true`, bare/simple이면서 explicit plugin이 false, Codex hooks feature disabled 중 하나면 `hooks_enabled=false`, `effective_protection=OFF`; 근거가 불완전하면 둘은 `null|UNKNOWN`이다. |
| hook definition | `hook_evidence[]` 각 항목은 `source=codex_user_plugin|codex_user_config|codex_project_config|claude_user_plugin|claude_project_plugin|claude_local_plugin|claude_user_settings|claude_project_settings|claude_local_settings|claude_managed_settings`, exact 자체 SHA-256 `definition_digest`, `disposition=loaded_active|skipped`, `reason=selected_reviewed_definition|selected_enabled_source|unreviewed_definition|reviewed_digest_stale|session_predates_review|untrusted_project_source|hooks_disabled`를 모두 가진다. `heartbeat|self_test.hook_source`도 같은 enum이며 client가 다른 source는 schema-invalid다. `bundled_hook_definition_digest|reviewed_hook_definition_digest`는 검사 artifact의 bundled bytes와 마지막 제품 검토 대상 exact bytes의 자체 SHA-256이며 확인할 수 없으면 null이다. `product_hook_review=unverified|verified|stale|not_applicable`; Codex user plugin definition과 reviewed가 같을 때만 `verified`, 과거 reviewed 값과 다르면 `stale`다. Claude는 native source/enable 증거를 `hook_evidence`와 `selected_enabled_source`로 분리하고 이 Codex 전용 review 값은 `not_applicable`로 둔다. Codex 내부 trust hash로 표현하지 않는다. |
| session | `session_fixture_id`는 known session에서 필수이며 `session_state=existing_before_review|new_after_review|unknown`이다. `heartbeat|self_test.status=not_run|passed|failed|stale`, `evidence_scope=current|historical|none`이다. `passed/current`는 같은 object의 `session_fixture_id|hook_source|hook_definition_digest`가 모두 non-null이고 top-level session 및 정확히 하나의 `loaded_active` hook evidence와 일치해야 한다. `stale/historical`은 과거 non-null session/source/digest 결속을 보존하며 현재 top-level session 또는 `loaded_active` hook과 일치해서는 안 된다. `not_run/none`은 세 결속 필드가 모두 null이다. `failed`는 실패 전에 관찰한 값만 `current`로 non-null이며 그 전이면 `none`이고 fixture가 exact nullability를 고정한다. `client_trust=verified|unverified|unknown|not_applicable`, `effective_protection=VERIFIED_ACTIVE|OFF|UNKNOWN`이다. |
| test artifact | `test_profile_expected_digest`는 compile-time 값으로 필수. 입력이 없으면 supplied digest null, `rejected/profile_missing`이다. 입력이 있으면 supplied digest 필수이며 byte digest나 user-area source가 틀리면 `rejected/digest_mismatch|profile_source_untrusted`다. profile이 valid하면 `loaded`와 rejection reason null이다. 그 run의 runtime helper/argv가 모두 일치하면 `sentinel_binding_result=matched`, helper hash가 다르면 `helper_hash_mismatch`, argv가 다르면 `argv_mismatch`, loader-only이면 `not_evaluated`다. |
| production artifact | exact profile 입력을 시도한 T19-C에서는 `test_profile=not_supported`, `test_profile_expected_digest=null`, supplied digest 필수, `test_profile_rejection_reason=production_not_supported`, `sentinel_binding_result=not_evaluated`다. `artifact_inspection`은 3.2의 exact build/probe evidence를 포함한다. production binary에는 loader/rule/status constructor가 없어야 하며 모든 M0 action/event schema count는 0이다. |

`run_evidence`는 T19-A/B/C에서만 non-null이고 다른 M0 status case에서는 null이다. `object_counts`는 `HookEnvelope|M0ActionRequest|M0ActionDecision|M0Event|M0StatusReport`를 각각 세며 status count는 항상 1이다. `canonical_digests`는 자기 참조를 피하기 위해 앞의 네 object 종류만 실제 object 순서대로 담고, harness가 완성된 report의 canonical SHA-256을 별도 `status_report_digest` 결과로 반환해 다섯 번째 digest를 완성한다. `ordered_events`는 `M0Event` 배열의 순서와 같아야 한다. `observations`는 target process·marker, 사람 승인, Secure Onboard 승인 자동화와 uncorrelated result의 계측 count다.

result-bearing T19 oracle은 client별 native mapper 사실을 따른다. Claude는 correlated result HookEnvelope와 `tool_completed`를 포함하지만, Codex 0.146.0은 ambiguous empty `tool_response`를 result로 정규화하지 않아 LOW·INFO와 near-match의 result HookEnvelope/event count가 0이다.

이 Rust deterministic harness의 process·marker·approval count는 격리된 instrumented test 입력에 대한 oracle이며 실제 Claude/Codex process observer 결과를 뜻하지 않는다. native live 증거가 없거나 observer가 차단된 조합을 이 값으로 `VERIFIED` 처리하지 않는다.

`client_mode_evidence.evidence_digest`는 임의 문자열 연결이 아니다. exact bytes는 `SHA-256(ASCII("secure-onboard:m0-client-mode-evidence/v1\n") || JCS(input))`로 계산한다. `JCS`는 [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)이고 `input`은 다음 고정 key를 모두 가진다.

```json
{
  "os_string_encoding": "unix_bytes",
  "launch_argv_base64url": ["Y29kZXg="],
  "relevant_environment": [],
  "plugin_list_output_base64url": null,
  "ordered_setting_sources": [
    {
      "source": "codex_user_config",
      "source_bytes_base64url": "e30=",
      "claim": "codex_hooks_feature_enabled"
    }
  ]
}
```

모든 `*_base64url`은 raw bytes의 [RFC 4648 URL-safe base64](https://www.rfc-editor.org/rfc/rfc4648)이며 padding을 포함한다. top-level `os=macos`이면 `os_string_encoding=unix_bytes`, `os=windows`이면 `windows_utf16le`만 유효하다. macOS argv/env는 OS bytes, Windows는 UTF-16LE code unit bytes를 쓴다. `relevant_environment`의 원소는 정확히 `{ "name_base64url": string, "value_base64url": string|null }` 두 key만 가지며 decoded name 중복은 invalid다. Claude allowlist는 정확히 `CLAUDE_CODE_SIMPLE` 하나라 배열에 항상 한 항목을 넣고 unset이면 value null, set이면 raw value bytes를 넣는다. Codex allowlist는 빈 배열이다. 둘 이상으로 확장하려면 schema version을 올리며 decoded name raw bytes 오름차순으로 정렬한다. `ordered_setting_sources`는 status의 `client_mode_evidence.setting_evidence`와 길이·순서·`source`·`claim`이 byte-for-byte 같아야 하고 source 중복은 invalid다. 각 `source_bytes_base64url` decode bytes의 SHA-256은 같은 index의 `setting_evidence.source_digest`와 같아야 한다. plugin-list 명령을 지원하지 않는 client fixture는 해당 값을 null로 둔다. JCS 전후에 BOM·공백·추가 개행을 넣지 않는다.

Codex hook review case는 다음 조합으로 고정한다. `client_trust=unknown`은 native 내부 trust hash를 관찰하지 못한다는 뜻이며 제품 자체 review와 heartbeat를 대신하지 않는다.

| case | user-plugin evidence | `product_hook_review` | session | heartbeat/self-test | `effective_protection` |
|------|----------------------|-----------------------|---------|---------------------|------------------------|
| T13 | Codex user plugin `skipped/unreviewed_definition` | `unverified` | `unknown` | `not_run/not_run` | `UNKNOWN` |
| T14 | Codex user plugin `skipped/session_predates_review` | `verified` | `existing_before_review` | `not_run/not_run` | `UNKNOWN` |
| T15 | Codex user plugin `loaded_active/selected_reviewed_definition` | `verified` | `new_after_review` | 같은 session/source/digest의 `passed/passed` | `VERIFIED_ACTIVE` |
| T16 | Codex user plugin `skipped/reviewed_digest_stale` | `stale` | `unknown` | `stale/historical` digest = `reviewed_hook_definition_digest`, current skipped hook digest와는 다름 | `UNKNOWN` |

`next_checks` 허용값은 `install_plugin|enable_hooks|review_current_hook_definition|start_new_client_session|run_standalone_self_test|inspect_client_hook_status|verify_effective_cwd_binding`이다. T12처럼 `effective_protection=UNKNOWN`이면 원인을 해소할 수 있는 값이 하나 이상이어야 하고, T15의 완전한 success report는 빈 배열이다.

### 3.2 production artifact의 M0 기능 부재 증거

T19-C의 harness는 production artifact를 만든 **같은 build transaction**의 canonical component manifest와 artifact digest를 결합하고 다음 구조를 `M0StatusReport.artifact_inspection`에 넣는다.

```json
{
  "method": "bound-build-manifest-plus-black-box-profile-probe/v1",
  "build_manifest_digest": "sha256:production-build-components",
  "bound_artifact_digest": "sha256:m0-production-artifact",
  "forbidden_components": [
    "m0_test_profile_loader",
    "m0_sentinel_rules",
    "m0_status_constructor"
  ],
  "forbidden_component_count": 0,
  "black_box_profile_probe": "not_supported",
  "production_emitted_m0_schema_count": 0
}
```

canonical component manifest는 build graph가 포함한 feature/component ID의 정렬 UTF-8 목록과 산출 artifact SHA-256을 같은 원자적 build record에 넣는다. harness는 manifest의 artifact digest가 실제 production bytes와 일치하는지 확인하고 forbidden component count 0을 요구한다. 이어 exact T19-A profile path/digest를 test artifact와 같은 launch environment에 공급해 production artifact가 이를 `not_supported`로 취급하고 `m0-*` schema를 하나도 emit하지 않는지 black-box probe한다. 둘 중 하나라도 실패하면 T19-C 실패다. source-code 문자열 검색만으로 부재를 주장하지 않는다.

현재 harness의 bound build record는 canonical JSON과 마지막 LF인 `secure-onboard-bound-build-manifest/v1`이다. 필드는 정확히 `schema_version`, 실제 production file bytes의 `artifact_sha256`, 같은 artifact의 `components` probe stdout bytes를 결속한 `component_manifest_sha256`, probe에서 읽은 정렬 `components`다. `build_manifest_digest`는 이 LF를 포함한 record bytes의 SHA-256이다. constructor는 실제 artifact를 다시 읽어 hash를 비교하고, exact component probe와 `{"profile":"not_supported"}\n` profile probe를 함께 검증한다.

### 3.3 `M0FixtureManifest v1`

클라이언트·버전·OS별 M0 정적 fixture와 실행 artifact는 다음 strict schema로 결속한다. 아래 JSON은 필드 모양을 보여 주기 위해 펼친 표현이며, 체크인하는 실제 manifest bytes는 object key를 UTF-8 byte 순서로 재귀 정렬한 공백 없는 JSON 한 개와 마지막 LF 하나여야 한다.

```json
{
  "schema_version": "m0-fixture-manifest/v1",
  "client": "codex",
  "client_version": "0.146.0",
  "os": "macos",
  "architecture": "arm64",
  "client_executable": {
    "invoked_path": "/absolute/path/to/codex",
    "resolved_path": "/absolute/path/to/codex-resolved",
    "sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "version_output": "codex-cli 0.146.0"
  },
  "client_runtime_artifact": {
    "role": "native_backend",
    "absolute_path": "/absolute/path/to/codex-native-backend",
    "sha256": "sha256:9191919191919191919191919191919191919191919191919191919191919191"
  },
  "plugin_manifest": {
    "absolute_path": "/absolute/repository/root/plugins/codex-m0/.codex-plugin/plugin.json",
    "sha256": "sha256:9292929292929292929292929292929292929292929292929292929292929292"
  },
  "shipped_hooks_definition": {
    "absolute_path": "/absolute/repository/root/plugins/codex-m0/hooks/hooks.json",
    "sha256": "sha256:9393939393939393939393939393939393939393939393939393939393939393"
  },
  "product_artifact": {
    "absolute_path": "/absolute/path/to/secure-onboard-m0-hook",
    "sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "compiled_test_profile_sha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  "core_artifact": {
    "absolute_path": "/absolute/path/to/secure-onboard-m0-core",
    "sha256": "sha256:9494949494949494949494949494949494949494949494949494949494949494"
  },
  "test_profile": {
    "relative_path": "profiles/codex-0.146.0-macos-arm64.json",
    "content_sha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  "helper_fixtures": [
    {
      "role": "default",
      "relative_path": "helpers/m0-target.mjs",
      "content_sha256": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    },
    {
      "role": "failure",
      "relative_path": "helpers/m0-target-fail.mjs",
      "content_sha256": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    },
    {
      "role": "near_match",
      "relative_path": "helpers/m0-target-near-match.mjs",
      "content_sha256": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    }
  ],
  "native_fixtures": [
    {
      "role": "prompt",
      "relative_path": "native/codex-prompt.json",
      "content_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "canonical_json_sha256": "sha256:2111111111111111111111111111111111111111111111111111111111111111"
    },
    {
      "role": "pre_tool_use",
      "relative_path": "native/codex-pre.json",
      "content_sha256": "sha256:3111111111111111111111111111111111111111111111111111111111111111",
      "canonical_json_sha256": "sha256:4111111111111111111111111111111111111111111111111111111111111111"
    },
    {
      "role": "result_success",
      "relative_path": "native/codex-result-success.json",
      "content_sha256": "sha256:5111111111111111111111111111111111111111111111111111111111111111",
      "canonical_json_sha256": "sha256:6111111111111111111111111111111111111111111111111111111111111111"
    },
    {
      "role": "result_failure",
      "relative_path": "native/codex-result-failure.json",
      "content_sha256": "sha256:7111111111111111111111111111111111111111111111111111111111111111",
      "canonical_json_sha256": "sha256:8111111111111111111111111111111111111111111111111111111111111111"
    },
    {
      "role": "stop",
      "relative_path": "native/codex-stop.json",
      "content_sha256": "sha256:9111111111111111111111111111111111111111111111111111111111111111",
      "canonical_json_sha256": "sha256:a111111111111111111111111111111111111111111111111111111111111111"
    }
  ]
}
```

모든 object는 표시한 key를 정확히 한 번씩 가지며 unknown·missing·duplicate key를 거부한다. `client=claude|codex`, `os=macos|windows`, `architecture=arm64|x86_64`만 허용하고 빈 값이나 제어문자가 든 `client_version`을 거부한다. `version_output`은 Claude에서 exact `<client_version> (Claude Code)`, Codex에서 exact `codex-cli <client_version>`이다. `invoked_path`는 실제 호출 경로이고 symlink일 수 있지만 이를 해소한 physical regular file이 `resolved_path`와 같아야 하며 `sha256`은 그 resolved file bytes의 digest다. `client_runtime_artifact`는 launcher와 별도로 실제 실행되는 runtime bytes를 결속한다. Claude는 `role=resolved_executable`이며 `client_executable.resolved_path|sha256`과 같아야 한다. Codex는 `role=native_backend`이며 platform package의 native backend absolute physical path·SHA-256을 기록한다. 따라서 버전 변경 뒤 JS launcher bytes가 같아도 stale manifest를 재사용할 수 없다.

`plugin_manifest`와 `shipped_hooks_definition`은 같은 physical plugin root 아래의 non-symlink regular file이다. Claude는 각각 `plugins/claude-m0/.claude-plugin/plugin.json`, `plugins/claude-m0/hooks/hooks.json` suffix를, Codex는 각각 `plugins/codex-m0/.codex-plugin/plugin.json`, `plugins/codex-m0/hooks/hooks.json` suffix를 가져야 한다. Codex manifest가 가리키는 hooks 정의와 실제로 검증한 shipped hooks bytes를 분리해 추정하지 않는다. 각 `sha256`은 해당 raw file bytes를 결속하며 파일별 상한은 1MiB다.

`product_artifact.absolute_path`와 `core_artifact.absolute_path`는 각각 platform executable suffix를 반영한 `secure-onboard-m0-hook`, `secure-onboard-m0-core` 이름의 physical non-symlink regular file이며 같은 physical directory의 sibling이다. 각 `sha256`은 exact artifact bytes를 결속하고 파일별 상한은 64MiB다. `product_artifact.compiled_test_profile_sha256`은 `test_profile.content_sha256`과 같아야 하므로 실행 artifact가 compile-time에 결속한 profile과 검사한 profile이 달라질 수 없다. profile의 `client|client_version|os|architecture`는 manifest와 같고 profile 안 `default|failure` helper digest는 같은 role의 `helper_fixtures` digest와 같아야 한다.

`helper_fixtures`는 `default`, `failure`, `near_match` 순서로 정확히 세 개다. `native_fixtures`는 `prompt`, `pre_tool_use`, `result_success`, `result_failure`, `stop` 순서로 정확히 다섯 개다. 모든 `relative_path`는 harness가 제공한 physical fixture root 아래의 non-symlink regular file을 가리키며 absolute path, `.`, `..`를 허용하지 않는다. profile 상한은 64KiB이고 helper/native fixture 상한은 파일별 1MiB다. `content_sha256`은 마지막 LF를 포함한 raw file bytes에 적용한다. native JSON은 duplicate key와 trailing non-whitespace를 거부하고 `canonical_json_sha256`은 strict decode 뒤 재귀 key 정렬·공백 없음·추가 LF 없음인 canonical JSON bytes에 적용한다. 모든 digest는 `sha256:` 뒤 lowercase hex 64자리다. target project 밖의 profile source 신뢰와 runtime/helper argv 결속은 이 manifest 검증 뒤 §3.0 loader가 별도로 다시 검증한다.

macOS arm64 fixture manifest 생성기는 invoked symlink를 먼저 physical executable로 해소한 뒤 그 resolved path를 직접 `--version`으로 실행한다. 실행 전후 resolved file을 각각 `O_NOFOLLOW` FD로 bounded streaming hash하고 identity·metadata가 같은지 확인하며 invoked path도 다시 해소해 동일 target인지 확인한다. client executable/native backend 상한은 파일별 512MiB다. 전후 snapshot에 남은 leaf file 또는 invoked symlink 변경은 생성 실패다. 다만 subprocess가 실제 image를 여는 순간을 retained FD와 kernel-atomic하게 결속하지 않으므로, 두 snapshot 사이의 교체·복원이나 parent directory graph의 원자적 무변경까지 증명하지는 않는다.

## 4. 어댑터 입력 계약

`HookEnvelope`는 M0와 M1이 공유한다. M0는 3.1의 전용 변형으로 이어지고, 이 절의 production `ActionRequest`·fallback·durable idempotency 계약은 M1 후보다.

어댑터는 native payload를 최소한으로 검증해 `HookEnvelope`로 넘기고, 공용 코어가 `ActionRequest`를 만든다. PreToolUse ingress는 먼저 `(client, session_id, hook_event, native_tool_call_id)`를 조회한다. canonical ingress digest는 exact native payload, native session cwd와 prompt correlation을 포함하고 adapter-generated `envelope_id|action_id|occurred_at`은 제외한다. 기존 key의 같은 digest면 이미 commit된 envelope/action/result를 반환하고, 다른 digest면 새 ID나 판정을 만들지 않고 `ingress_conflict`다. key가 없을 때만 `envelope_id`와 정규화 전 `action_id`를 발급해 digest와 함께 원자적으로 commit한다. 따라서 이후 단계가 실패해도 envelope·native tool call과 failure decision을 연결할 수 있다. 정상 경로에서 어댑터가 자체 판단으로 `ActionRequest` 필드를 채우지 않는다.

어댑터가 소유하는 fallback은 `core_timeout|core_nonzero|core_schema_invalid|bridge_schema_failure|warning_delivery_failure|policy_bootstrap_failure` 고정 enum뿐이다. `bridge_schema_failure`는 제품 관리용 scan helper의 신뢰 필드·cardinality·mode schema를 native context와 결합하기 전에 거부한 경우에만 사용한다. core failure에서 보호 action은 target 내용을 재판정하지 않고 adapter-generated `action_id`와 고정 `guardrail.scan_failure` finding의 HIGH failure `ActionDecision`을 만든다. `cache_status=bypass`, `pending_action_ref=null`, `decision_source=adapter_fallback`이다. warning-delivery와 policy-bootstrap fallback도 HIGH다. adapter 자체가 실행되지 못하거나 timeout·malformed output을 낸 경우는 이 fallback을 만들 수 없는 비보장 경계이며 M0 native fault fixture로 따로 기록한다.

읽기 전용 scan helper의 같은 core 실패에서는 어댑터가 `scan_id`를 발급하고 `report_source=adapter_fallback`, `scan_status=failed`, `guardrail.scan_failure` HIGH finding, `failure.stage=core`인 `ScanReport`를 만든다. 확인하지 못한 project/target 필드는 null이고 gate decision은 없다. adapter가 local event를 쓸 수 없으면 고장 난 저장소의 영속 event를 성공 조건으로 요구하지 않는다.

### 4.1 `PromptContext v1`

```json
{
  "schema_version": "prompt-context/v1",
  "prompt_context_id": "prompt-claude-01",
  "client": "claude",
  "session_id": "session-claude-01",
  "adapter_turn_id": null,
  "created_at": "2026-07-22T00:00:00Z",
  "source_event": "user_prompt_submit",
  "source_assurance": "verified_human",
  "request_kind": "explicit_command",
  "action_hint": "install",
  "user_request_summary": "fixture package install request",
  "user_command": "npm install ./fixtures/fixture-malicious-1.0.0.tgz",
  "reconfirmation_candidate": null,
  "project_id": "hmac:project",
  "expires_at": "2026-07-22T00:10:00Z"
}
```

`source_assurance`는 `verified_human|unverified`다. `user_command`는 `verified_human`일 때만 채우며 현재 흐름과 `PendingBlock`에만 쓸 수 있다. 활동 로그·캐시에는 복사하지 않는다. Codex 예시는 별도 provenance가 증명되기 전 `source_assurance=unverified`, `request_kind=unknown`, `user_command=null`이어야 한다.

`reconfirmation_candidate`는 기본 null이다. verified-human prompt raw bytes가 제품이 직전 HIGH 응답에 안내한 exact grammar `<SHORT_REF> 명령을 직접 실행하겠습니다`와 일치할 때만 prompt 어댑터의 결정론적 parser가 다음 transient 값을 채운다.

```json
{
  "short_ref": "A1B2",
  "intent": "manual_execution_despite_risk",
  "parser_version": "reconfirm-ko/v1"
}
```

secret 포함 여부와 무관하게 같은 grammar를 사용하며 별도 secret count 필드는 없다. 모델은 candidate를 만들거나 수정하지 못하며 token·문구가 다르거나 부가 지시가 섞여도 null이다. 지원 언어별 exact grammar는 별도 parser version과 fixture를 가진다. Codex에서는 PromptContext의 candidate를 사용하지 않고 제품 소유 local-confirmation record가 같은 값을 만들며 session·action·short ref·context fingerprint·TTL과 함께 검증된다.

### 4.2 `HookEnvelope v1`

PreToolUse 예시:

```json
{
  "schema_version": "hook-envelope/v1",
  "envelope_id": "envelope-01",
  "hook_event": "pre_tool_use",
  "occurred_at": "2026-07-22T00:00:00Z",
  "client": "codex",
  "session_id": "session-01",
  "adapter_turn_id": "turn-01",
  "native_tool_call_id": "tool-call-01",
  "prompt_context_id": null,
  "native_tool_name": "Bash",
  "native_tool_input": {"command": "npm install ./fixtures/fixture-malicious-1.0.0.tgz"},
  "tool_name": "shell_exec",
  "tool_input": {"command_text": "npm install ./fixtures/fixture-malicious-1.0.0.tgz"},
  "native_session_cwd": "/example/project",
  "physical_cwd": "/example/project",
  "cwd_assurance": "verified",
  "cwd_resolution_source": "m0_effective_cwd_binding"
}
```

결과 훅 예시:

```json
{
  "schema_version": "hook-envelope/v1",
  "envelope_id": "envelope-02",
  "hook_event": "tool_result",
  "occurred_at": "2026-07-22T00:00:01Z",
  "client": "codex",
  "session_id": "session-01",
  "adapter_turn_id": "turn-01",
  "native_tool_call_id": "tool-call-01",
  "prompt_context_id": null,
  "native_tool_response": {"M0_FIXED_SHAPE": true},
  "outcome": "failure",
  "exit_code": 1
}
```

Stop 훅 예시:

```json
{
  "schema_version": "hook-envelope/v1",
  "envelope_id": "envelope-03",
  "hook_event": "assistant_stop",
  "occurred_at": "2026-07-22T00:01:01Z",
  "client": "codex",
  "session_id": "session-01",
  "adapter_turn_id": "turn-02",
  "native_tool_call_id": null,
  "prompt_context_id": null,
  "last_assistant_message": "rendered response"
}
```

이벤트별 필수 필드는 다음과 같다.

| `hook_event` | 필수 필드 |
|--------------|-----------|
| `pre_tool_use` | `native_tool_call_id`, `native_tool_name`, `native_tool_input`, `tool_name`, `tool_input`, `native_session_cwd`, `physical_cwd`, `cwd_assurance`, `cwd_resolution_source` |
| `tool_result` | `native_tool_call_id`, `native_tool_response`, `outcome`; Claude 성공/실패 훅과 Codex 결과 훅을 M0에서 고정한 mapper로 정규화 |
| `assistant_stop` | `last_assistant_message`; assistant 응답 원문 확인을 지원하는 클라이언트에서만 사용 |

`cwd_assurance`는 `verified|unverified`이고 `cwd_resolution_source`는 `native_effective_cwd|m0_effective_cwd_binding|unavailable`다. `native_session_cwd`는 native common payload의 exact 값, `physical_cwd`는 action의 effective cwd로 검증된 값이다. unverified/unavailable envelope에서는 `physical_cwd=null`이며 M1 `ActionRequest`를 만들 수 없다.

`prompt_context_id`는 검증된 prompt correlation이 없으면 null이다. 이 경우 ActionRequest의 `request_kind`와 `command_origin`은 `unknown`이다. Codex의 `adapter_turn_id`는 native `turn_id`와 byte-for-byte 같아야 하며 continuation 분석 전에 폐기하지 않는다. `native_tool_name`·`native_tool_input`은 정확한 wire 값을 transient하게 보존하고 `tool_name`·`tool_input`은 내부 canonical 값이다. Codex의 현재 공식 shell mapping 후보는 `Bash/command → shell_exec/command_text`이며 실제 지원 client version별 bytes를 M0 fixture로 고정한다. Codex common `cwd`는 session cwd이므로 곧바로 action의 effective cwd라고 가정하지 않는다. M0에서 해당 native path의 모든 지원 호출이 session cwd와 같은 effective cwd를 쓴다는 결합을 증명할 수 있을 때만 `cwd_resolution_source=m0_effective_cwd_binding`으로 `physical_cwd`를 채운다. per-call workdir 사용 여부나 effective cwd를 신뢰 입력에서 식별·재검증할 수 없으면 개별 호출만 골라낼 수 없으므로 해당 native path·client version 전체를 coverage에서 제외한다. 이미 포함된 entry의 runtime cwd assurance가 깨지면 `guardrail.state_failure` HIGH다. Codex `PostToolUse.tool_response`도 native opaque 값에서 `outcome`·nullable `exit_code`로 변환하는 mapper fixture가 생기기 전에는 구조를 추정하지 않는다.

원문 `native_tool_input`, `tool_input`, `native_tool_response`, `physical_cwd`, `last_assistant_message`는 판정·상관 확인 뒤 폐기한다. M0에서 클라이언트별 native ID, 결과 훅과 Stop payload의 exact bytes를 fixture로 고정한다.

## 5. 공용 코어 요청

### 5.1 `ActionRequest v1`

```json
{
  "schema_version": "action-request/v1",
  "action_id": "action-01",
  "envelope_id": "envelope-01",
  "client": "codex",
  "session_id": "session-01",
  "adapter_turn_id": "turn-01",
  "native_tool_call_id": "tool-call-01",
  "prompt_context_id": null,
  "request_kind": "unknown",
  "action_kind": "install",
  "command_origin": "unknown",
  "commands": {
    "user_command": null,
    "ai_expected_command": null,
    "planned_command": "npm install ./fixtures/fixture-malicious-1.0.0.tgz"
  },
  "tool_name": "shell_exec",
  "invocation": {
    "kind": "shell_text",
    "shell_executable": "/bin/zsh",
    "shell_flags": ["-lc"],
    "dialect": "posix_sh",
    "command_text": "npm install ./fixtures/fixture-malicious-1.0.0.tgz",
    "shell_resolution_source": "m0_runtime_probe",
    "shell_resolution_fingerprint": "sha256:effective-shell"
  },
  "physical_cwd": "/example/project",
  "cwd_assurance": "verified",
  "cwd_resolution_source": "m0_effective_cwd_binding",
  "project_id": "hmac:project",
  "target_refs": ["./fixtures/fixture-malicious-1.0.0.tgz"],
  "target_fingerprint": "sha256:fixture-tarball",
  "context_fingerprint": "hmac:context",
  "context_assurance": "verified",
  "analysis_profile_digest": "sha256:analysis-profile",
  "gate_policy_digest": "sha256:gate-policy"
}
```

허용 enum:

- `request_kind`: `explicit_command|intent|unknown`
- `action_kind`: `execute|open|install|update|remove|build|test|configure|permission|other`
- `command_origin`: `user_explicit|ai_derived|ai_transformed|target_derived|unknown`

`prompt_context_id`는 검증된 correlation이 없으면 null이며 이때 `request_kind=unknown`, `command_origin=unknown`, `commands.user_command=null`로 고정한다. correlation miss는 실제 tool input의 게이트를 생략하는 이유가 아니다. M1 ActionRequest의 `physical_cwd`, `cwd_assurance=verified`, `cwd_resolution_source`는 필수이며 source enum은 HookEnvelope와 같다.

`invocation`은 다음 tagged union 중 정확히 하나다.

```json
{"kind":"direct_argv","executable":"/usr/bin/open","argv":["/example/project/sample.txt"]}
```

```json
{"kind":"shell_text","shell_executable":"/bin/zsh","shell_flags":["-lc"],"dialect":"posix_sh","command_text":"npm install ./fixture.tgz","shell_resolution_source":"m0_runtime_probe","shell_resolution_fingerprint":"sha256:effective-shell"}
```

`direct_argv.executable`과 `argv`는 native 호출의 exact 값이며 implicit shell을 허용하지 않는다. `shell_text`에는 `shell_executable`, `shell_flags`, `dialect`, `command_text`, `shell_resolution_source`, `shell_resolution_fingerprint`가 모두 필수다. `dialect`는 M0에서 검증한 `posix_sh|cmd|powershell` allow-list, `shell_resolution_source`는 M1에서 `native_effective_shell|m0_runtime_probe`만 허용한다. Codex native hook은 shell executable·flags·dialect나 per-call effective cwd를 제공하지 않으므로 이 값들은 공식 wire에서 추정하지 않는다. M0가 지원 client/version/OS에서 실제 host process와 effective shell을 관찰해 resolver와 fingerprint를 고정하고, action마다 재검증한 경우에만 `shell_resolution_source=m0_runtime_probe`와 verified 값을 채운다. effective cwd는 해당 native path 전체에 대해 session cwd와의 결합 또는 별도 신뢰 필드를 증명한 coverage entry에서만 verified로 채운다. 그런 coverage entry가 없으면 해당 native path/client version을 지원하지 않으며, entry는 있으나 runtime 재검증이 실패하면 `guardrail.state_failure` HIGH다. wrapper·pipe·redirect·cwd를 평탄화해 잃지 않는다. 먼저 coarse `action_kind`를 분류해 M1 밖이면 `NOT_COVERED`로 끝낸다. install/file-open entry 후보인데 client/tool schema, dialect 또는 단일 target grammar를 해석할 수 없으면 fail-closed normalization HIGH다. context만 확정할 수 없으면 action cache를 bypass한다.

관련 환경의 **값 원문은 저장하지 않고**, 공용 HMAC 키로 계산한 effective key/value·package-manager config·resolved executable fingerprint를 `context_fingerprint`에 포함한다. `context_assurance`는 `verified|unverified`이며 unverified이면 action cache를 bypass한다. correlation miss는 게이트를 건너뛰는 이유가 아니다. 실제 tool input으로 action을 판정하되 사용자 출처만 `unknown`으로 낮춘다.

### 5.2 `ScanBridgeEnvelope v1`

```json
{
  "schema_version": "scan-bridge-envelope/v1",
  "bridge_call_id": "scan-call-01",
  "client": "claude",
  "session_id": "session-01",
  "prompt_context_id": "prompt-01",
  "physical_cwd": "/example/project",
  "target_arguments": ["sample.txt"],
  "target_origin": "user_explicit",
  "mode": "read_only"
}
```

이 envelope는 모든 prompt에서 자동 생성하지 않는다. 사용자가 명시적으로 scan/check를 요청해 제품 관리용 scan helper가 호출될 때만 어댑터가 만든다. M1 alpha의 `target_arguments`와 `target_refs` cardinality는 정확히 1이다. 모델은 구조화된 target 후보 하나만 제공하고 `client`, `session_id`, `prompt_context_id`, `physical_cwd`, `mode`는 어댑터가 native context에서 주입한다. 대상 텍스트·프로젝트 파일·tool output은 이 필드를 덮어쓸 수 없다.

### 5.3 `ScanRequest v1`

```json
{
  "schema_version": "scan-request/v1",
  "scan_id": "scan-01",
  "bridge_call_id": "scan-call-01",
  "client": "claude",
  "session_id": "session-01",
  "prompt_context_id": "prompt-01",
  "project_id": "hmac:project",
  "target_refs": ["sample.txt"],
  "physical_cwd": "/example/project",
  "target_origin": "user_explicit",
  "resolution_assurance": "verified",
  "target_fingerprint": "sha256:target",
  "analysis_profile_digest": "sha256:analysis-profile",
  "mode": "read_only"
}
```

공용 코어가 `physical_cwd`를 기준으로 exact local target을 resolve하고 project escape·symlink·permission을 검증한 뒤에만 `ScanRequest`를 만든다. `target_origin`은 `user_explicit|ai_derived|unknown`, `resolution_assurance`는 M1에서 `verified`만 허용한다. target이 모호하거나 resolve·재관찰할 수 없으면 `ScanRequest`를 만들지 않고 `bridge_call_id`에 연결된 failure `ScanReport`를 반환한다. 명시적 검사 경로는 대상 코드를 실행하거나 OS 기본 앱으로 열지 않는다.

공용 코어는 bridge ingress에서 `scan_id`를 먼저 발급한다. 따라서 target resolution 전에 실패해도 `bridge_call_id`·`scan_id`로 결과와 event를 연결할 수 있다.

## 6. 판정 결과

### 6.1 `Finding v1`

```json
{
  "schema_version": "finding/v1",
  "finding_id": "finding-01",
  "rule_id": "npm.confirmed_malicious_fixture",
  "severity": "HIGH",
  "category": "malicious-package",
  "summary": "fixed malicious fixture matched",
  "finding_scope": "target",
  "impact": "installing can run untrusted lifecycle code",
  "counter_evidence": ["local development fixture can be an intentional test"],
  "safer_alternatives": ["inspect the fixed package artifact without installing it"],
  "deterministic": true,
  "confidence": "confirmed"
}
```

`category`는 `malicious-package|install-hook|secret|exfiltration|obfuscation|file-signature|guardrail-failure|other`, `confidence`는 `confirmed|probable|possible`, `finding_scope`는 `target|context|action` 중 하나다. summary·impact·counter evidence·alternative는 비밀값·소스 원문·절대 경로를 제외한 표시 가능 값이어야 한다. M1은 `deterministic=true` finding만 실행 게이트에 사용한다. AI assessment 계약은 M2다.

### 6.2 `ActionDecision v1`

다음은 7.x의 verified-human Claude 흐름에 연결되는 M1 후보 예시다. 앞의 Codex `ActionRequest` 예시와 같은 action이 아니다.

```json
{
  "schema_version": "action-decision/v1",
  "decision_id": "decision-claude-01",
  "action_id": "action-claude-01",
  "envelope_id": "envelope-claude-01",
  "native_tool_call_id": "tool-call-claude-01",
  "decision_source": "core",
  "severity": "HIGH",
  "gate_decision": "deny",
  "state": "HIGH_BLOCKED",
  "disclosure_eligible": true,
  "risk_segments": [
    {
      "command_field": "invocation.command_text",
      "start": 0,
      "end": 50,
      "rule_id": "npm.confirmed_malicious_fixture"
    }
  ],
  "findings": [
    {
      "schema_version": "finding/v1",
      "finding_id": "finding-claude-01",
      "rule_id": "npm.confirmed_malicious_fixture",
      "severity": "HIGH",
      "category": "malicious-package",
      "summary": "fixed malicious fixture matched",
      "finding_scope": "target",
      "impact": "installing can run untrusted lifecycle code",
      "counter_evidence": ["local development fixture can be an intentional test"],
      "safer_alternatives": ["inspect the fixed package artifact without installing it"],
      "deterministic": true,
      "confidence": "confirmed"
    }
  ],
  "pending_action_ref": "A1B2",
  "failure": null,
  "cache_status": "miss",
  "core_version": "0.1.0",
  "rule_version": "sha256:rule-bundle",
  "limitations": ["hook guardrail is not an OS enforcement boundary"]
}
```

유효 조합은 정확히 세 가지다.

| severity | gate_decision | state |
|----------|---------------|-------|
| `HIGH` | `deny` | `HIGH_BLOCKED` |
| `LOW` | `continue` | `LOW_WARNING_REQUIRED` |
| `INFO` | `continue` | `INFO_ALLOWED` |

`decision_source`는 `core|adapter_fallback`이다. `continue`는 클라이언트 고유 sandbox·approval을 승인하거나 우회한다는 뜻이 아니다. LOW의 `LOW_WARNING_REQUIRED`는 adapter가 native continue를 반환하기 전에 지원 버전의 계약에 맞는 경고 출력을 동기식으로 생성·stdout에 써야 한다는 요구다. 성공한 뒤에만 `warned_low` event를 만들 수 있으나 command hook에는 host parse·표시 ACK가 없으므로 사용자 열람이나 client 표시 완료를 뜻하지 않는다. 출력 생성·write 실패 시 이 후보를 terminal decision으로 기록하지 않고 같은 action ID의 `guardrail.warning_failure` HIGH adapter fallback으로 대체한다. 실제 표시 능력은 M0 terminal fixture가 지원 client/version/OS별로 증명한다. `findings`에는 UI를 재구성할 수 있는 redacted `Finding`을 포함한다. `risk_segments`는 transient command의 UTF-8 byte offset이며 로그·캐시에는 복사하지 않는다. production `ActionDecision.cache_status`는 `hit|miss|bypass` 중 하나다. 3.1의 별도 `M0ActionDecision.cache_status`는 항상 `bypass`다. scan과 command disclosure는 `ActionDecision`이 아니다.

모든 ActionDecision은 예시의 top-level 필드를 유지한다. 다만 정규화 전 또는 adapter fallback에서는 확인하지 못한 값을 꾸며내지 않고 `risk_segments=[]`, `core_version=null`, `rule_version=null`을 허용한다. fallback `findings`는 해당 `guardrail.*` rule 하나의 redacted `Finding`이며 `category=guardrail-failure`, `finding_scope=action`, `deterministic=true`로 고정한다.

`failure.code` 허용값은 다음 고정 enum이다.

- normalization/parser/scanner: `normalization_schema_invalid|unsupported_complexity|parser_timeout|scanner_timeout|scanner_error|remote_artifact_unbound`
- state/rules/runtime assurance: `registry_unreadable|registry_invalid|registry_integrity_mismatch|rule_bundle_unreadable|rule_bundle_invalid|rule_bundle_digest_mismatch|cwd_assurance_failed|shell_resolution_failed`
- log/warning: `log_write_failed|warning_delivery_failed`
- bootstrap: `policy_unreadable|policy_invalid|policy_integrity_mismatch|coverage_manifest_unreadable|coverage_manifest_invalid|coverage_manifest_integrity_mismatch|coverage_manifest_digest_mismatch`
- core: `core_timeout|core_nonzero|core_schema_invalid`

policy/manifest를 읽지 못한 fallback은 rule bundle을 확인하지 못했으므로 version을 추측하지 않는다.

policy bootstrap fallback의 완전한 형태는 다음과 같다.

```json
{
  "schema_version": "action-decision/v1",
  "decision_id": "decision-bootstrap-01",
  "action_id": "action-bootstrap-01",
  "envelope_id": "envelope-bootstrap-01",
  "native_tool_call_id": "tool-call-bootstrap-01",
  "decision_source": "adapter_fallback",
  "severity": "HIGH",
  "gate_decision": "deny",
  "state": "HIGH_BLOCKED",
  "disclosure_eligible": false,
  "risk_segments": [],
  "findings": [
    {
      "schema_version": "finding/v1",
      "finding_id": "finding-bootstrap-01",
      "rule_id": "guardrail.policy_bootstrap_failure",
      "severity": "HIGH",
      "category": "guardrail-failure",
      "summary": "the local gate policy could not be verified",
      "finding_scope": "action",
      "impact": "the action cannot be classified against the configured protection rules",
      "counter_evidence": [],
      "safer_alternatives": ["repair the local policy state and request the action again"],
      "deterministic": true,
      "confidence": "confirmed"
    }
  ],
  "pending_action_ref": null,
  "failure": {
    "stage": "policy_bootstrap",
    "code": "coverage_manifest_invalid"
  },
  "cache_status": "bypass",
  "core_version": null,
  "rule_version": null,
  "limitations": ["this is a bootstrap fallback, not a normal coverage classification"]
}
```

`failure`는 정상 판정에서 null이고 operational failure에서는 `{ "stage": "normalization|parser|scanner|state|log|warning_delivery|policy_bootstrap|core", "code": "고정된 redacted enum" }`이다. 정규화 전에 실패하면 유효한 `ActionRequest` 없이도 ingress에서 발급한 `action_id`, `envelope_id`, `native_tool_call_id`에 직접 연결할 수 있다. 모든 operational failure는 HIGH deny다. `warning_delivery`는 `guardrail.warning_failure`, `policy_bootstrap`은 built-in `guardrail.policy_bootstrap_failure` adapter fallback이며 전달되지 않은 LOW를 `warned_low` event로 표현하지 않는다.

`failure != null`인 ActionDecision과 모든 adapter fallback은 `cache_status=bypass`이며 action decision cache를 읽거나 쓰지 않는다. 실패 결과를 allow/deny cache로 재사용하지 않는다.

`pending_action_ref`는 `disclosure_eligible=true`인 HIGH에만 필수다. PreToolUse에서 exact blocked invocation을 관찰해 identity HMAC을 만들고, 원문 representation과 재검증 가능한 pending state를 만들며 최초 HIGH 안내를 전달할 수 있는 경우만 true다. 이를 충족하는 operational HIGH도 공개할 수 있지만, 하나라도 신뢰할 수 없으면 false·ref null이며 명령을 추측하지 않는다. production `guardrail.warning_failure`와 LOW·INFO는 `disclosure_eligible=false`, `pending_action_ref=null`이다. 3.1의 별도 `M0ActionDecision`에는 `disclosure_eligible` 필드와 공개 흐름이 없고 모든 severity에서 `pending_action_ref=null`이다.

### 6.3 `ScanReport v1`

```json
{
  "schema_version": "scan-report/v1",
  "scan_id": "scan-01",
  "bridge_call_id": "scan-call-01",
  "report_source": "core",
  "client": "claude",
  "session_id": "session-01",
  "prompt_context_id": "prompt-01",
  "project_id": "hmac:project",
  "target_id": "hmac:target",
  "target_fingerprint": "sha256:target",
  "started_at": "2026-07-22T00:00:00Z",
  "completed_at": "2026-07-22T00:00:01Z",
  "scan_status": "complete",
  "state": "SCAN_REPORTED",
  "max_finding_severity": "HIGH",
  "failure": null,
  "findings": [
    {
      "schema_version": "finding/v1",
      "finding_id": "finding-01",
      "rule_id": "file.eicar_test_signature",
      "severity": "HIGH",
      "category": "file-signature",
      "summary": "EICAR test signature matched",
      "finding_scope": "target",
      "impact": "security software can quarantine this test artifact",
      "counter_evidence": ["EICAR is a standard non-malicious AV test program, not production malware"],
      "safer_alternatives": ["inspect only in an isolated opt-in fixture directory"],
      "deterministic": true,
      "confidence": "confirmed"
    }
  ],
  "cache_status": "miss",
  "core_version": "0.1.0",
  "rule_version": "sha256:rule-bundle",
  "security_data_version": null,
  "limitations": ["read-only static checks only"]
}
```

`report_source`는 `core|adapter_fallback`, M1 v1의 `scan_status`는 `complete|failed` 중 하나다. `ScanReport`에는 `gate_decision`이 없다. 검사 실패·timeout은 `guardrail.scan_failure` HIGH finding으로 보고한다. 후속 설치·열기·실행은 별도 `ActionRequest`와 `ActionDecision`을 만든다.

`scan_status=failed` 또는 `report_source=adapter_fallback`이면 `cache_status=bypass`이고 evidence cache를 읽거나 쓰지 않는다. M1 v1은 부분 결과를 반환하거나 캐시하지 않는다.

모든 report에서 `scan_id`, `bridge_call_id`, `client`, `session_id`, `prompt_context_id`, `started_at`, `completed_at`, `scan_status`, `state`, `max_finding_severity`, `findings`, `cache_status`, `limitations`는 필수다. `complete`는 finding을 최소 하나 포함하며 경고 근거가 없으면 INFO `action.no_warning_finding`을 넣는다. `max_finding_severity`는 findings의 최댓값이다. failure report는 HIGH `guardrail.*` finding을 최소 하나 포함하고 다음 단계별 nullability를 따른다.

| failure stage | report source | project | target ID/fingerprint | core/rule version | 고정 결과 |
|---------------|---------------|---------|-----------------------|-------------------|-----------|
| `bridge_schema` | `adapter_fallback` | null | null | null/null | failed, bypass |
| `target_resolution` | `core` | 필수 | null | 필수/필수 | failed, bypass |
| `core` | `adapter_fallback` | null | null | null/null | failed, bypass |
| `scanner` | `core` | 필수 | 필수 | 필수/필수 | failed, bypass |
| `state` | `core` | null | null | 필수/null | failed, bypass |
| `log` | `core` | nullable | nullable | nullable/nullable | failed, bypass |
| `policy_bootstrap` | `adapter_fallback` | null | null | null/null | failed, bypass |

`failure`는 `{stage, code}`의 고정 redacted enum이며 정상 complete report에서만 null이다. scan failure code는 `bridge_schema_invalid|target_ambiguous|target_not_found|target_outside_project|target_symlink_invalid|target_reobservation_failed|scanner_timeout|scanner_error|registry_unreadable|registry_invalid|registry_integrity_mismatch|rule_bundle_unreadable|rule_bundle_invalid|rule_bundle_digest_mismatch|log_write_failed|policy_unreadable|policy_invalid|policy_integrity_mismatch|coverage_manifest_unreadable|coverage_manifest_invalid|coverage_manifest_integrity_mismatch|coverage_manifest_digest_mismatch|core_timeout|core_nonzero|core_schema_invalid` 중 하나다. `stage=log`이면 실패 전에 검증을 끝낸 project/target/version 필드만 유지하고 나머지는 null로 둔다. 존재하지 않거나 확인하지 못한 값을 꾸며내지 않는다. `security_data_version`은 데이터팩이 없는 M1에서 항상 null이다.

### 6.4 `CoverageResult v1`

```json
{
  "schema_version": "coverage-result/v1",
  "envelope_id": "envelope-coverage-01",
  "client": "codex",
  "session_id": "session-01",
  "native_tool_call_id": "tool-call-coverage-01",
  "action_id": "action-coverage-01",
  "coverage": "NOT_COVERED",
  "behavior": "pass_through",
  "reason": "action_kind_outside_m1"
}
```

훅이 관찰했지만 현재 지원 grammar 밖인 호출에만 사용한다. 모든 PreToolUse ingress처럼 `action_id`를 발급하되 `ActionRequest`·`ActionDecision`·cache record는 만들지 않는다. severity·finding·gate decision이 없으며 native sandbox·approval 흐름을 그대로 유지한다. 지원 grammar 후보의 parse failure를 이 결과로 낮추지 않는다. hook이 관찰하지 않은 호출에는 `CoverageResult`도 만들 수 없다. coverage event 기록 실패는 범위 밖 action을 보호 action으로 바꾸지 않으며 standalone status 진단 대상으로 남긴다.

## 7. HIGH 재확인과 공개

### 7.1 `PendingBlock v1`

다음 7.x 예시는 앞의 Codex wire 예시와 별개인, `verified_human` prompt provenance를 제공하는 Claude adapter의 단일 흐름이다. Codex는 같은 상태 전이를 사용하되 모델 transcript 대신 Secure Onboard 소유 local-confirmation record를 source로 사용하며, 그 exact transport fixture가 없는 client/version/OS는 HIGH 명령 공개 coverage에서 제외한다.

```json
{
  "schema_version": "pending-block/v1",
  "action_id": "action-claude-01",
  "short_ref": "A1B2",
  "client": "claude",
  "session_id": "session-claude-01",
  "native_tool_call_id": "tool-call-claude-01",
  "prompt_context_id": "prompt-claude-01",
  "created_at": "2026-07-22T00:00:00Z",
  "expires_at": "2026-07-22T00:10:00Z",
  "command_origin": "user_explicit",
  "display_commands": {
    "user_command": "npm install ./fixtures/fixture-malicious-1.0.0.tgz",
    "ai_expected_command": null,
    "planned_command": "npm install ./fixtures/fixture-malicious-1.0.0.tgz",
    "blocked_command": "npm install ./fixtures/fixture-malicious-1.0.0.tgz"
  },
  "blocked_invocation": {
    "kind": "shell_text",
    "shell_executable": "/bin/zsh",
    "shell_flags": ["-lc"],
    "dialect": "posix_sh",
    "command_text": "npm install ./fixtures/fixture-malicious-1.0.0.tgz",
    "shell_resolution_source": "m0_runtime_probe",
    "shell_resolution_fingerprint": "sha256:effective-shell"
  },
  "display_projection": {
    "dialect": "posix_sh",
    "round_trip_fixture_digest": "sha256:display-round-trip"
  },
  "secret_spans": [],
  "blocked_invocation_hmac": "hmac:exact-blocked-invocation",
  "disclosure_mode": "literal_command",
  "recheck_inputs": {
    "physical_cwd": "/example/project",
    "target_refs": ["./fixtures/fixture-malicious-1.0.0.tgz"],
    "resolved_executable": "/example/bin/npm",
    "relevant_env_names": ["PATH"],
    "config_sources": []
  },
  "project_id": "hmac:project",
  "directory_id": "hmac:directory",
  "target_fingerprint": "sha256:fixture-tarball",
  "context_fingerprint": "hmac:context",
  "analysis_profile_digest": "sha256:analysis-profile",
  "gate_policy_digest": "sha256:gate-policy",
  "decision_digest": "sha256:decision",
  "verification_nonce": "nonce:random-per-action",
  "explanation_snapshot": {
    "action_summary": "fixture package install",
    "findings": [
      {
        "rule_id": "npm.confirmed_malicious_fixture",
        "severity": "HIGH",
        "summary": "fixed malicious fixture matched",
        "impact": "installing can run untrusted lifecycle code",
        "counter_evidence": ["local development fixture can be an intentional test"],
        "safer_alternatives": ["inspect the fixed package artifact without installing it"]
      }
    ],
    "limitations": ["manual terminal execution is outside observation"]
  },
  "status": "blocked",
  "display_digest": null
}
```

M1 HIGH pending은 실제 PreToolUse의 exact `ActionRequest.invocation`을 deny한 경우에만 만든다. deny transaction이 그 source bytes로 `blocked_invocation_hmac`, 단기 exact `blocked_invocation`과 `display_commands.blocked_command`를 파생하며 `disclosure_mode`는 `literal_command|display_safe_reference` 중 하나다. tool call 없는 `user_command|ai_expected_command`만으로 PendingBlock을 만들지 않고 사전 `ActionRequest`에는 `blocked_command`를 두지 않는다. secret은 provenance와 무관하게 치환·정규화하지 않는다. 제어문자는 §1.3에 따라 안전 표현으로 바꾸며 변환이 하나라도 적용되면 `disclosure_mode=display_safe_reference`다. `explanation_snapshot`은 재확인 턴에서 대화 기억에 의존하지 않고 영향·반대 근거·대안을 다시 설명하기 위한 redacted decision 자료이며 `decision_digest`에 포함한다.

`blocked_invocation`은 `ActionRequest.invocation`과 같은 필드를 가진 `shell_text|direct_argv` tagged union이다. shell resolution 필드를 생략하지 않으며 `direct_argv`는 exact executable·argv 배열을 유지한다. 표시 dialect와 quoting oracle은 union 밖 `display_projection`에 두고 `blocked_command` 문자열은 이 구조의 검증된 표시 projection으로만 만든다. argv를 공백으로 단순 결합하지 않으며 direct-argv quoting·round-trip이 client/version/OS별 fixture로 검증되지 않으면 literal 공개를 지원하지 않는다. projection은 구조 표현에 필요한 quoting 외에 source argument bytes를 바꾸지 않으며 secret transformation을 허용하지 않는다. 제어문자 안전 변환은 projection이 끝난 뒤 표시 단계에서만 적용하고 그 사실을 `transformations`에 기록한다.

따라서 파이프라인은 `blocked_invocation`(exact bytes) → `display_projection`(quoting만) → 제어문자 안전 변환(표시 단계) 순서다. `round_trip_fixture_digest`는 **제어문자 변환 이전**, 즉 projection 직후 bytes를 묶는다. 이 digest의 목적은 "구조를 문자열로 폈다가 다시 파싱해도 같은 invocation이 나오는가"를 증명하는 것이므로 표시 전용 변환을 포함하면 의미가 깨진다. 반대로 `DisclosurePayload.rendered_commands[].text`와 `display_digest`는 변환 **이후** 값을 기준으로 계산한다. 두 digest는 제어문자가 없는 명령에서만 같은 bytes를 대상으로 하며, 있는 명령에서는 서로 다른 값이고 이는 정상이다. fixture는 제어문자 없는 case와 있는 case를 각각 고정해 두 digest의 관계를 함께 검증한다.

`secret_spans` 항목은 다음 필드를 가진다.

```json
{
  "span_id": "secret-01",
  "source_command_field": "blocked_invocation.command_text",
  "display_command_field": "display_commands.blocked_command",
  "source_start_byte": 12,
  "source_end_byte": 20,
  "provenance": "ai_or_unknown",
  "storage": "literal",
  "replacement": null
}
```

offset은 exact source field의 UTF-8 byte 기준, end-exclusive다. `source_command_field`는 exact invocation의 `command_text`, `executable` 또는 특정 `argv[n]` path이고, `display_command_field`는 PendingBlock의 해당 표시 필드다. `provenance`는 `verified_user|ai_or_unknown`이며 secret 출처 설명에만 사용한다. `storage`는 항상 `literal`, `replacement`는 항상 null이다. 모든 secret span은 provenance와 무관하게 최대 10분 원문으로 보관·표시하며 span metadata를 활동 로그·캐시에 복사하지 않는다. span은 겹칠 수 없고 source/display command field·offset 범위를 벗어나면 pending 생성을 실패시킨다.

`recheck_inputs`는 disclose 직전에 cwd·target·resolved executable·effective env/config를 다시 관찰하기 위한 사용자 전용 locator다. 새 fingerprint가 다르거나 재관찰할 수 없으면 `cancelled(reason=context_changed)`로 종료하고 공개하지 않으며 새 판정을 요구한다. 사용자 전용 권한과 원자적 쓰기를 사용하고 응답 포함 확인·취소·context 변경·만료·격리 때 삭제한다. `status`는 `blocked|reconfirmed|prepared|response_verified|cancelled|expired|quarantined`다.

한 session에 여러 `PendingBlock`을 둘 수 있지만 live `short_ref`는 session 안에서 유일해야 한다. `(client, session_id, native_tool_call_id)`가 같은 duplicate PreToolUse는 새 pending을 만들지 않는다. 각 pending은 하나의 유효한 reconfirmation만 소비하며 terminal 상태에서 다시 공개할 수 없다.

### 7.2 `Reconfirmation v1`

```json
{
  "schema_version": "reconfirmation/v1",
  "reconfirmation_id": "reconfirm-01",
  "action_id": "action-claude-01",
  "short_ref": "A1B2",
  "client": "claude",
  "session_id": "session-claude-01",
  "prompt_context_id": "prompt-claude-02",
  "local_confirmation_id": null,
  "source_event": "user_prompt_submit",
  "source_assurance": "verified_human",
  "intent": "manual_execution_despite_risk",
  "created_at": "2026-07-22T00:01:00Z",
  "expires_at": "2026-07-22T00:10:00Z",
  "pending_context_fingerprint": "hmac:context",
  "status": "pending",
  "consumed_by_prepare_call_id": null,
  "consumed_at": null,
  "closed_at": null,
  "close_reason": null
}
```

공용 코어는 같은 session에서 ref가 정확히 일치하는 유효한 미소비 pending 하나와 직접 실행 의사가 담긴 검증된 인간 입력을 확인한다. Claude는 `source_event=user_prompt_submit`, Codex는 `source_event=local_confirmation`을 사용한다. 두 source에 따라 `prompt_context_id`와 `local_confirmation_id` 중 정확히 하나만 non-null이어야 한다. Codex local confirmation은 모델 transcript와 분리되고 session·action·short ref·context fingerprint·TTL에 결합돼야 한다. “네”, 자동 continuation, 대상 문서, assistant·tool output은 유효하지 않다. stale·다른 session·없는 ref·둘 이상에 매칭되는 ref는 모두 거부한다. 검증된 입력 수락 transaction은 PendingBlock `blocked→reconfirmed`, `status=pending` Reconfirmation 생성과 `user_reconfirmed` outbox를 원자적으로 commit한다. `Reconfirmation.status`는 `pending|consumed|closed`다. prepare transaction이 성공할 때만 `consumed`, exact `consumed_by_prepare_call_id`와 `consumed_at`을 함께 commit한다. 미소비 상태에서 pending이 취소·context 변경·만료·격리되면 같은 terminal transaction에서 `closed_at`과 `close_reason`을 채워 `closed`로 바꾼다.

### 7.3 공개 확인

모델이 제품 관리용 prepare-disclosure helper를 호출할 때 action/ref 인자는 받지 않는다. 어댑터는 다음 envelope를 모델 인자와 분리해 만든다.

```json
{
  "schema_version": "disclosure-prepare-envelope/v1",
  "prepare_call_id": "prepare-call-01",
  "occurred_at": "2026-07-22T00:01:00Z",
  "client": "claude",
  "session_id": "session-claude-01",
  "prompt_context_id": "prompt-claude-02",
  "local_confirmation_id": null,
  "reconfirmation_candidate": {
    "short_ref": "A1B2",
    "intent": "manual_execution_despite_risk",
    "source_event": "user_prompt_submit",
    "parser_version": "reconfirm-ko/v1"
  }
}
```

`prepare_call_id`는 같은 신뢰 입력의 helper retry에서 안정적인 adapter idempotency key다. Claude candidate는 해당 `PromptContext`의 결정론적 parser output과 byte-for-byte 같고 `prompt_context_id`만 non-null이어야 한다. Codex candidate는 별도 local-confirmation record와 같고 `source_event=local_confirmation`, `local_confirmation_id`만 non-null이어야 한다. 공용 코어가 정확히 하나의 pending과 미소비 reconfirmation을 resolve해 내부 `action_id`·`reconfirmation_id`를 결합한다. 모델이 short ref·내부 ID·다른 session context를 선택하는 인터페이스는 제공하지 않는다. 코어는 지문과 TTL을 다시 확인한 뒤에만 `DisclosurePayload`를 반환하며 대상 명령을 실행하지 않는다.

payload 공개는 다음 순서의 durable transaction을 따른다.

1. pending·reconfirmation·live context를 검증하고 명령을 메모리에서 렌더한다.
2. pending `reconfirmed→prepared`, reconfirmation `pending→consumed`, 기존 nonce와 새 display digest, `prepare_call_id`로 조회 가능한 durable prepare result와 `high_command_prepared` outbox를 한 원자적 state transaction으로 commit한다.
3. 최초 commit 확인 또는 같은 `prepare_call_id`의 recovery read가 성공한 뒤에만 동일 payload를 helper caller에게 반환한다.

명확한 pre-commit 실패에서는 payload를 반환하지 않고 reconfirmation을 미소비 상태로 유지해 같은 exact prompt context의 idempotent retry만 허용한다. commit ACK가 유실되거나 결과가 불명확하면 즉시 `cancelled`로 덮어쓰지 않고 `prepare_call_id`로 recovery read한다. valid committed result가 있으면 같은 payload를 idempotent하게 반환하고 outbox는 한 번만 반영한다. 명시적으로 미커밋임을 확인하면 pre-commit 실패처럼 처리한다. state/result/outbox integrity 자체를 읽을 수 없으면 payload를 반환하지 않고 해당 pending을 quarantine해 재사용하지 않으며, 상태 복구 뒤 새 HIGH gate를 요구한다. 이 경우 존재 여부를 확인하지 못한 과거 outbox event를 없었다고 주장하지 않는다. 이 관리 경로는 fail-open하지 않는다. raw command를 durable prepare result·outbox나 활동 로그에 복사하지 않고, payload는 pending의 표시 필드에서 재구성한다.

```json
{
  "schema_version": "disclosure-payload/v1",
  "client": "claude",
  "session_id": "session-claude-01",
  "action_id": "action-claude-01",
  "reconfirmation_id": "reconfirm-01",
  "short_ref": "A1B2",
  "verification_nonce": "nonce:random-per-action",
  "marker": "secure-onboard:A1B2:random-per-action",
  "display_digest": "sha256:display",
  "explanation_snapshot": {
    "action_summary": "fixture package install",
    "findings": [
      {
        "rule_id": "npm.confirmed_malicious_fixture",
        "severity": "HIGH",
        "summary": "fixed malicious fixture matched",
        "impact": "installing can run untrusted lifecycle code",
        "counter_evidence": ["local development fixture can be an intentional test"],
        "safer_alternatives": ["inspect the fixed package artifact without installing it"]
      }
    ],
    "limitations": ["manual terminal execution is outside observation"]
  },
  "rendered_commands": [
    {
      "label": "blocked_command",
      "text": "npm install ./fixtures/fixture-malicious-1.0.0.tgz",
      "rendering": "literal",
      "transformations": []
    }
  ],
  "expires_at": "2026-07-22T00:10:00Z"
}
```

`label`은 `user_command|ai_expected_command|planned_command|blocked_command` source 필드 식별자다. `rendering`의 유효값은 `literal|display_safe_reference`다. 제어문자 변환이 하나도 없으면 `literal`이고 `transformations`는 빈 배열이며, command segment의 raw bytes·길이·digest가 PendingBlock의 표시 projection과 같아야 한다. 제어문자 변환이 있으면 `display_safe_reference`이고 각 변환을 `{type: "control_escape", source_start_byte, source_end_byte, rendered_text}`로 기록하며, 이 경우 bytes·digest 대조는 변환 후 값을 기준으로 한다. 어느 경우에도 secret redaction, Unicode normalization과 줄바꿈 변환은 허용하지 않는다. `display_safe_reference` payload는 shell 언어 fence나 runnable 명령 UI를 쓰지 않고 `text` 참고 블록과 “복사 실행 시 제어문자가 제거된 형태임” 문구를 필수로 한다.

`verification_nonce`는 pending마다 새로 생성한다. `display_digest`는 canonical schema version·client/session/action/reconfirmation ID·short ref·nonce·redacted explanation snapshot·rendered commands를 모두 묶고 marker·digest footer 자체만 제외한다. Stop 어댑터는 응답 속 marker에서 ref·nonce를 추출하고 command/explanation을 같은 방식으로 canonicalize해 다시 계산한다. 같은 ref·동일 명령이어도 다른 action의 nonce·ID와 digest는 일치하지 않는다.

`expires_at`은 block 생성부터 최대 10분인 hard deadline이며 prepare로 연장하지 않는다. Stop transaction은 digest를 확인하기 전에 fixed clock의 `now < expires_at`을 검사한다. deadline 이상이면 원자적 CAS에서 `expired`가 우선해 raw state를 삭제하고, 늦은 Stop은 tombstone의 기존 expired 결과만 반환하며 `high_command_response_verified`를 만들지 않는다.

1. helper 반환 전에 durable outbox에 `high_command_prepared`를 commit하고, 활동 로그 writer가 이를 idempotent하게 반영한다.
2. assistant가 action marker와 display digest가 포함된 명령 블록을 사용자에게 표시한다.
3. 지원되는 Stop 훅이 `last_assistant_message`의 marker·digest를 확인한 경우에만 `high_command_response_verified`를 기록한다.
4. 이 event는 마지막 assistant 응답 원문에 payload가 포함됐다는 뜻이며 UI 전달·렌더 완료·사용자 열람을 뜻하지 않는다.
5. 확인할 수 없으면 응답 포함을 추정하지 않고 `prepared`까지만 남긴다.
6. response verification·취소·context 변경·만료 뒤 pending 원문을 삭제한다. context 변경은 `cancelled(reason=context_changed)`다.

response verification·취소·context 변경·만료·격리는 tombstone upsert, terminal event outbox, pending의 raw command·secret 제거를 하나의 복구 가능한 terminal transaction으로 처리한다. response verification은 `high_command_response_verified`, 취소·context 변경·만료·격리는 `high_command_closed`와 정확한 `terminal_state`를 쓴다. 파일 기반 저장소에서 물리 삭제를 같은 commit에 묶을 수 없으면 raw 필드는 pending별 data key로 암호화하고 terminal transaction에서 key를 먼저 비가역 폐기한 뒤 background compaction으로 ciphertext를 제거한다. commit 뒤에는 raw 값을 복구할 수 없어야 하며, 재시작 시 미완료 transaction을 replay해 terminal event만 보이고 raw 값이 남거나 raw 값만 사라지고 tombstone이 없는 상태를 허용하지 않는다.

terminal 전 동일 `prepare_call_id`가 재전송되면 기존 payload를 idempotent하게 반환한다. terminal 뒤 prepare replay는 tombstone 기반 `already_terminal`과 terminal state만 반환하고 명령 payload는 반환하지 않는다. Stop replay는 이전 verification 결과만 반환하며 `high_command_prepared`·`high_command_response_verified`를 두 번 기록하지 않는다. marker가 같아도 digest가 다르면 verification은 실패한다. pending 원문 삭제 뒤에도 `(session_id, action_id, nonce HMAC, terminal_state)` redacted tombstone을 활동 기록 보존 기간 동안 유지해 과거 Stop replay가 새 action에 적용되지 않게 한다.

따라서 “AI tool/process 0”이 아니라 **차단 대상 tool handler 실행과 target command process start 0**을 보장 대상으로 삼는다. PreToolUse lifecycle dispatch 자체와 scanner·hook adapter·제품 관리용 disclose helper 프로세스는 이 수치에서 제외한다.

### 7.4 `TerminalDisclosureTombstone v1`

```json
{
  "schema_version": "terminal-disclosure-tombstone/v1",
  "client": "claude",
  "session_id_hmac": "hmac:session",
  "action_id": "action-claude-01",
  "prepare_call_id_hmac": "hmac:prepare-call-01",
  "short_ref_hmac": "hmac:A1B2",
  "verification_nonce_hmac": "hmac:nonce",
  "display_digest_hmac": "hmac:display",
  "terminal_state": "response_verified",
  "terminal_at": "2026-07-22T00:01:01Z",
  "expires_at": "2026-08-21T00:01:01Z"
}
```

`terminal_state`는 `response_verified|cancelled|expired|quarantined`다. `prepare_call_id_hmac`은 prepare 전 terminal이면 null, prepare가 commit된 뒤 terminal이면 필수다. `verification_nonce_hmac`은 항상 필수지만, prepare 전에 cancel/expire/quarantine되어 raw `display_digest`가 없으면 `display_digest_hmac=null`이다. 원문 명령·raw prepare-call ID·raw nonce·raw display digest를 저장하지 않으며 30일 또는 최근 1,000 tombstones 중 먼저 도달하는 한도로 정리한다. prepare 전 terminal replay는 `(client, session_id_hmac, short_ref_hmac)`으로, prepare 뒤 동일-call replay는 `prepare_call_id_hmac`까지 결합해 tombstone을 찾고 payload 없는 `already_terminal`만 반환한다. 같은 session의 short ref는 tombstone 보존 중 재사용하지 않는다. Stop verification은 active pending 또는 일치하는 tombstone에만 idempotent하게 적용하고, tombstone은 새 action을 terminal로 바꾸지 않는다.

## 8. `LocalEvent v1`

모든 event는 다음 공통 필드를 가진다.

```json
{
  "schema_version": "local-event/v1",
  "event_id": "event-01",
  "timestamp": "2026-07-22T00:00:00Z",
  "event_type": "high_blocked",
  "client": "codex",
  "session_id_hmac": "hmac:session",
  "project_id": "hmac:project",
  "directory_id": "hmac:directory",
  "core_version": "0.1.0"
}
```

`session_id_hmac`는 standalone scope/status event에서만 null일 수 있다. `project_id`와 `directory_id`는 확인 가능한 scoped event에 넣고 global event 또는 resolution 전 failure에서는 null일 수 있다. `directory_id`는 정규화된 물리 디렉터리의 사용자별 HMAC이며 raw `session_id`와 절대 경로는 durable event에 저장하지 않는다. `core_version`은 정상 core decision/report에는 필수이며 pre-core failure 또는 `decision_source=adapter_fallback` event에서는 null이다. event별 payload의 필수 필드는 다음과 같다. 표에 없는 원문 명령·비밀값·절대 경로는 금지한다. scan의 project/target resolution 또는 state failure에서는 아직 확인하지 못한 `project_id`·`target_id`를 null로 둘 수 있다.

| event type | 필수 추가 필드 |
|------------|----------------|
| `scope_enabled`, `scope_disabled` | `scope=ON\|OFF`, `project_id\|null`, `effective_state=VERIFIED_ACTIVE\|OFF\|UNKNOWN`, `reason` |
| `protection_status_unknown` | `action_id`, `native_tool_call_id`, `unknown_reasons`, `observed_action_gated=true`; 세션 전체 보호 주장 금지 |
| `scan_started`, `scan_reported` | `scan_id`, `bridge_call_id`, `project_id`; resolution 전에는 `target_id=null`; reported는 `max_finding_severity`, `rule_ids`, nullable `failure_stage` 추가 |
| `cache_hit`, `cache_miss` | `cache_kind`, `cache_key_hmac`; action 또는 scan ID 중 하나 |
| `coverage_not_supported` | `native_tool_call_id`, `action_id`, `tool_kind_hmac`, `coverage_reason`; severity·gate_decision 없음 |
| `allowed_info`, `warned_low`, `high_detected`, `high_blocked` | 항상 `action_id`, `native_tool_call_id`, `severity`, `rule_ids`, `decision_source`; 정규화 뒤에는 `project_id`, `target_id`, `action_kind`, `command_origin`, `command_hmac`, `cache_status`; 정규화 전 failure는 이 필드를 null로 두고 `failure_stage`, `failure_code` 필수 |
| `user_reconfirmed` | `action_id`, `reconfirmation_id`, source에 따라 `prompt_context_id` 또는 `local_confirmation_id` 중 정확히 하나 |
| `high_command_prepared`, `high_command_response_verified` | `action_id`, `display_digest_hmac`, `verification_nonce_hmac`; verified는 `verification=assistant_stop` 추가 |
| `high_command_closed` | `action_id`, `terminal_state=cancelled|expired|quarantined`, `reason=user_cancelled|context_changed|ttl_expired|state_quarantined` |
| `tool_completed`, `tool_failed` | `action_id`, `native_tool_call_id`, `outcome` |
| `ingress_conflict` | `ingress_kind`, `idempotency_key_hmac`, `first_payload_digest`, `conflicting_payload_digest` |
| `orphan_result` | `native_tool_call_id_hmac`, `outcome`, `reason=unknown_action|unsupported_outcome` |

`high_blocked`는 공용 코어 또는 고정 adapter fallback이 HIGH를 정하고 어댑터가 클라이언트 문서에 맞는 deny 응답을 반환했다는 뜻이다. OS 전역 차단이나 sibling hook 무부작용을 뜻하지 않는다. 실제 target process start 0은 클라이언트별 수용 테스트로 검증한다.

`warned_low`는 adapter가 지원 버전의 계약에 맞는 경고 출력을 동기식으로 썼다는 뜻이다. command hook에는 host parse·표시 ACK가 없으므로 사용자에게 표시됐거나 읽혔다는 증거로 사용하지 않는다.

`tool_completed`·`tool_failed`는 result hook이 관찰한 LOW·INFO action에만 허용한다. HIGH, 일반 터미널 실행, 단순 명령 공개에는 만들지 않는다. native approval 취소 등 result hook이 오지 않으면 결과 event를 추정하지 않는다. `executed` event는 사용하지 않는다.

`coverage_not_supported`는 훅이 관찰했지만 현재 M1 지원 grammar 밖인 action을 통과시켰다는 coverage 진단이지 `INFO` 보안 판정이 아니다. hook 경로 밖 호출에는 이 event조차 만들 수 없다. `cache_status=bypass`는 `ActionDecision`·`ScanReport`가 정본이며 별도 cache lifecycle event를 만들지 않는다.

`protection_status_unknown`은 현재 action의 PreToolUse가 실제 도착해 gate됐다는 사실만 기록한다. 다른 action·tool·session까지 active였다는 증거로 사용하지 않는다.

보호 action의 필수 로그 쓰기 실패는 `guardrail.log_failure` HIGH deny다. read-only scan의 필수 로그 실패는 gate 없이 같은 rule의 HIGH finding을 담은 failed `ScanReport`로 보고한다. 어느 쪽이든 고장 난 로그에 failure event까지 영속됐다고 요구하지 않으며, 캡처한 decision/report와 `status` 진단을 oracle로 삼는다.

native hook·result·helper·Stop 전달은 at-least-once일 수 있다고 가정한다. Pre/result는 `(client, session_id, hook_event, native_tool_call_id)`, prompt는 `prompt_context_id`, scan helper는 `bridge_call_id`, disclosure helper는 `prepare_call_id`를 사용한다. Stop은 nullable tool call ID를 쓰지 않고 `(client, session_id, action_id, verification_nonce_hmac, display_digest, stop_payload_digest)`를 사용한다. 같은 key의 동일 payload는 상태 전이와 event를 한 번만 적용한다. 충돌 payload가 key를 재사용하면 처리하지 않고 `ingress_conflict`를 기록한다. result가 알려진 action과 연결되지 않거나 outcome을 정규화할 수 없으면 action 상태를 추정하지 않고 `orphan_result` 진단만 남긴다.

## 9. 캐시 계약

캐시는 target repo 밖 사용자 영역에 두며 두 종류를 섞지 않는다.

### 9.1 `EvidenceCacheRecord v1`

```json
{
  "schema_version": "evidence-cache/v1",
  "cache_key": "sha256:evidence",
  "key_id": "local-key-01",
  "created_at": "2026-07-22T00:00:00Z",
  "expires_at": "2026-07-23T00:00:00Z",
  "project_id": "hmac:project",
  "directory_id": "hmac:directory",
  "target_fingerprint": "sha256:target",
  "core_version": "0.1.0",
  "rule_version": "sha256:rule-bundle",
  "security_data_version": null,
  "analysis_profile_digest": "sha256:analysis-profile",
  "findings": [
    {
      "schema_version": "finding/v1",
      "finding_id": "finding-02",
      "rule_id": "file.format_mismatch",
      "severity": "LOW",
      "category": "other",
      "summary": "the file extension and detected format differ",
      "finding_scope": "target",
      "impact": "the default application can handle the file differently than expected",
      "counter_evidence": ["no executable path was found in the M1 checks"],
      "safer_alternatives": ["inspect the file as plain bytes before opening it"],
      "deterministic": true,
      "confidence": "possible"
    }
  ],
  "integrity_hmac": "hmac:evidence-cache-record"
}
```

### 9.2 `ActionDecisionCacheRecord v1`

```json
{
  "schema_version": "action-cache/v1",
  "cache_key": "sha256:action",
  "key_id": "local-key-01",
  "created_at": "2026-07-22T00:00:00Z",
  "expires_at": "2026-07-22T00:10:00Z",
  "project_id": "hmac:project",
  "directory_id": "hmac:directory",
  "evidence_cache_key": "sha256:evidence",
  "action_fingerprint": "hmac:action",
  "context_fingerprint": "hmac:context",
  "gate_policy_digest": "sha256:gate-policy",
  "severity": "LOW",
  "findings": [
    {
      "schema_version": "finding/v1",
      "finding_id": "finding-02",
      "rule_id": "file.format_mismatch",
      "severity": "LOW",
      "category": "other",
      "summary": "the file extension and detected format differ",
      "finding_scope": "target",
      "impact": "the default application can handle the file differently than expected",
      "counter_evidence": ["no executable path was found in the M1 checks"],
      "safer_alternatives": ["inspect the file as plain bytes before opening it"],
      "deterministic": true,
      "confidence": "possible"
    }
  ],
  "integrity_hmac": "hmac:action-cache-record"
}
```

- evidence key: target content·권한·symlink fingerprint + core/rule-bundle/security-data version + analysis-profile digest
- action key: evidence key + exact tool/command HMAC + physical cwd/resolved-executable/effective-env/config HMAC + gate-policy digest
- evidence cache에는 `finding_scope=target`인 redacted finding만 저장한다. 환경·명령에서 유래한 `context|action` finding은 action cache에만 저장한다.
- target·context·analysis profile·gate policy·version이 바뀌면 miss다.
- M1 remote registry npm install은 실제 설치 bytes를 immutable하게 묶기 전까지 HIGH deny, `cache_status=bypass`다. exact local artifact와 context가 검증된 경우만 action cache를 허용한다.
- cache read·MAC·schema 실패는 폐기 후 fresh scan한다. writeback만 실패하면 fresh decision을 유지하고 bypass하며 stale allow를 사용하지 않는다.
- hit여도 HIGH 차단·LOW 경고·새 event는 반복한다.
- M1 실행 게이트에는 AI assessment를 사용·캐시하지 않는다. M2에서 session·turn·model·prompt·action correlation과 stale/spoof 검증 계약을 별도로 추가한다.

두 cache record는 `integrity_hmac`을 제외한 canonical bytes를 `key_id`의 키로 검증한 뒤에만 사용한다. 권장 기본값은 evidence TTL 24시간, action TTL 10분, 종류별 최대 10,000 records 또는 256 MiB 중 먼저 도달한 한도다. canonical encoding·HMAC algorithm·키 저장·손실·회전 계약은 durable storage 결정과 함께 M1 fixture에서 최종 고정한다. 그 전에는 cache 구현을 시작하지 않는다.

## 10. 정책·활성 registry와 상태

### 10.1 `GatePolicy v1`

```json
{
  "schema_version": "gate-policy/v1",
  "policy_version": 1,
  "failure_mode": "fail_closed",
  "alpha_scope": "npm_open_scan",
  "secret_rendering": "literal_all",
  "warning_delivery_failure": "deny",
  "policy_bootstrap_failure": "deny",
  "coverage_manifest_digest": "sha256:coverage-manifest",
  "rule_bundle_digest": "sha256:rule-bundle",
  "created_at": "2026-07-22T00:00:00Z",
  "integrity_hmac": "hmac:gate-policy"
}
```

M1 policy 값은 `failure_mode=fail_closed`, `alpha_scope=npm_open_scan`, `secret_rendering=literal_all`, `warning_delivery_failure=deny`, `policy_bootstrap_failure=deny`로 확정한다. secret redaction 분기와 fail-open·scan 유예 분기는 active schema에서 허용하지 않는다. 제어문자 안전 변환은 정책 선택지가 아니라 §1.3의 고정 불변식이므로 `secret_rendering` 값과 무관하게 항상 적용하며 GatePolicy에 별도 스위치를 두지 않는다. `coverage_manifest_digest`는 client/version/OS별 exact native tool mapping·executable/subcommand/option/shell grammar와 case applicability manifest를 묶는다.

`gate_policy_digest`는 `integrity_hmac`을 제외한 canonical policy bytes의 digest다. policy 또는 참조한 CoverageManifest를 읽지 못하거나 schema·canonical decoding·integrity·고정 enum/digest 검증이 실패하면 지원 grammar를 알 수 없으므로 stale/부분 값을 사용하지 않는다. 유효한 registry로 scope `OFF`임을 확인했다면 사용자 비활성화가 우선하며 target-tool을 게이트하거나 보호 event를 만들지 않는다. 그 외 상태에서 실제 도착한 target-tool PreToolUse는 normal coverage 분류를 하지 않고 전부 내장 `guardrail.policy_bootstrap_failure` HIGH deny, `disclosure_eligible=false`, `cache_status=bypass`로 끝내며 action cache를 읽거나 쓰지 않는다. 이는 정상 지원 coverage 판정이 아니라 policy 복구 전 비상 fallback이다. scan helper가 실제 호출된 경우에는 gate 없이 같은 rule의 HIGH failed `ScanReport`를 반환한다. 이 bootstrap matcher와 제품 관리 경로 제외 목록은 어댑터에 고정하고 client별 fixture로 검증한다.

policy와 HMAC key도 같은 사용자 권한으로 수정될 수 있으므로 중앙 관리·변조 방지 경계는 아니다.

### 10.2 `CoverageManifest v1`

```json
{
  "schema_version": "coverage-manifest/v1",
  "manifest_version": 1,
  "m0_matrix_digest": "sha256:m0-client-version-os-fixtures",
  "entries": [
    {
      "entry_id": "codex-macos-npm-install",
      "client": "codex",
      "client_version": "M0_FIXED_VERSION",
      "os": "macos",
      "native_tool_name": "Bash",
      "native_command_field": "command",
      "tool_name": "shell_exec",
      "invocation_kind": "shell_text",
      "dialect": "posix_sh",
      "cwd_policy": "m0_bound_effective_cwd",
      "action_kind": "install",
      "executable_allowlist": ["npm"],
      "subcommand_allowlist": ["install", "i"],
      "option_allowlist": ["--save-exact"],
      "package_spec_allowlist": ["local_tarball"],
      "max_targets": 1,
      "compound_policy": "deny_high_unsupported_complexity",
      "fixture_manifest_digest": "sha256:entry-fixtures"
    }
  ],
  "unsupported_action_behavior": "NOT_COVERED",
  "supported_candidate_parse_failure": "deny_high_normalization_schema_invalid",
  "integrity_hmac": "hmac:coverage-manifest"
}
```

각 entry는 M0에서 확인한 exact client version·OS·native tool/field mapping·invocation kind·shell dialect·effective-cwd binding에 묶인다. `cwd_policy=m0_bound_effective_cwd`는 T18이 해당 native path 전체에서 effective cwd를 재검증할 수 있음을 증명한 경우에만 허용한다. 분류 순서는 `coarse action_kind → matching support entry → exact grammar`로 고정한다. build/test/configure처럼 action kind 자체가 M1 밖이면 option 파싱 전에 `NOT_COVERED`다. install/file-open entry 후보에서 pipe, redirect, subshell, command substitution, compound separator, wrapper, 다중 target 또는 허용되지 않은 executable/subcommand/option이 나오면 `failure.code=unsupported_complexity`, `guardrail.scan_failure` HIGH다. 그 밖의 지원 후보 schema/grammar parse 실패는 `failure.code=normalization_schema_invalid`, 같은 HIGH다. M1 정상 grammar는 exact local tarball의 npm install 또는 platform file-open의 **단일 simple invocation·단일 target**만 허용한다.

위 예시의 `M0_FIXED_VERSION`은 실제 지원값이 아니다. M0 fixture에서 얻은 exact version·macOS/Windows opener·Claude/Codex tool entry와 모든 option을 manifest에 채우고 digest를 GatePolicy에 결합하기 전에는 M1을 시작하지 않는다. entry가 없는 client/version/OS는 지원으로 표시하지 않는다.

### 10.3 `ActivationRegistry v1`

```json
{
  "schema_version": "activation-registry/v1",
  "registry_version": 1,
  "global_scope": "OFF",
  "projects": [
    {
      "project_id": "hmac:project",
      "directory_id": "hmac:directory",
      "path_depth": 4,
      "scope": "ON"
    }
  ],
  "updated_at": "2026-07-22T00:00:00Z",
  "integrity_hmac": "hmac:registry"
}
```

`global_scope`와 project `scope`는 `ON|OFF`다. `project_id`는 활성화 대상 논리 프로젝트, `directory_id`는 그 정규화된 물리 root의 사용자별 HMAC이다. 현재 physical path와 ancestor HMAC을 계산해 가장 깊은 일치 항목을 사용한다. 같은 canonical physical project가 둘 이상 있거나 같은 depth에서 서로 다른 scope가 충돌하면 registry 전체를 invalid로 처리하고 추정하지 않는다. macOS는 symlink를 해소한 physical real path와 실제 volume의 case behavior를, Windows는 final path와 volume/file identity를 기준으로 중복을 판정한다. 대상 repo의 경로·환경·문서는 registry 위치나 내용을 지정할 수 없다. schema·integrity·canonical decoding 실패 시 scope를 추정하지 않는다.

### 10.4 `StatusReport v1`

```json
{
  "schema_version": "status-report/v1",
  "client": "codex",
  "client_version": "M0_FIXED_VERSION",
  "os": "macos",
  "coverage_entry_id": null,
  "project_id": "hmac:project",
  "configured_scope": "ON",
  "effective_protection": "UNKNOWN",
  "evidence": {
    "plugin_installed": true,
    "hooks_enabled": true,
    "session_heartbeat_at": null,
    "self_test": "not_run",
    "client_trust": "unknown",
    "gate_policy": "valid",
    "coverage_manifest": "valid"
  },
  "reasons": ["current session hook trust is not machine-readable"],
  "core_version": "0.1.0",
  "registry_version": 1,
  "gate_policy_digest": "sha256:gate-policy"
}
```

`client_version`과 `os`는 probe가 관찰한 exact 값이며 확인하지 못하면 null이다. `coverage_entry_id`는 현재 client/version/OS에 정확히 일치하는 valid manifest entry가 하나일 때만 그 ID이고 그 밖에는 null이다. `configured_scope`는 성공적으로 계산하면 `ON|OFF`, registry를 읽거나 검증할 수 없으면 null이다. 이때 `project_id`와 `registry_version`도 null일 수 있다. `effective_protection`은 `VERIFIED_ACTIVE|OFF|UNKNOWN`이다. `self_test`는 `not_run|passed|failed|stale`, `client_trust`는 `verified|unverified|unknown|not_applicable`, `gate_policy`는 `valid|invalid|unreadable`, `coverage_manifest`는 `valid|invalid|unreadable|not_evaluated`다. GatePolicy를 읽거나 검증하지 못해 참조 manifest를 확정할 수 없으면 `coverage_manifest=not_evaluated`이고 `gate_policy_digest=null`이다. GatePolicy는 valid지만 manifest가 실패하면 digest는 valid policy의 값이고 manifest 상태만 invalid/unreadable이다. evidence의 값은 `true|false|null` 또는 명시된 enum이며 추정값을 넣지 않는다.

GatePolicy·CoverageManifest가 valid인 상태에서 registry만 실패하면 standalone status는 `UNKNOWN`이며 실제 관찰된 보호 action에는 `guardrail.state_failure` HIGH를 적용한다. registry가 valid `OFF`이면 GatePolicy/manifest 진단 값과 무관하게 effective protection은 `OFF`이고 target-tool을 게이트하지 않는다. scope가 OFF로 확인되지 않은 상태에서 GatePolicy 또는 그가 참조한 CoverageManifest가 invalid/unreadable이면 registry 상태와 무관하게 standalone status는 `UNKNOWN`이고 실제 관찰 target-tool action에는 built-in policy bootstrap HIGH를 우선 적용한다. client trust/heartbeat만 unknown이고 registry·GatePolicy·CoverageManifest가 모두 valid이면 실제 도착한 지원 action은 정상 gate하되 전체 세션 보호를 주장하지 않는다.

## 11. 로컬 저장 기본값

- 대상 저장소 밖 사용자 소유 application-data 디렉터리
- POSIX 디렉터리 `0700`, 파일 `0600`; Windows는 현재 사용자 전용 ACL
- 심볼릭 링크·하드링크를 따라 쓰지 않고 임시 파일 뒤 원자적 교체
- 활동 event와 terminal tombstone 기본 보존: 종류별로 30일 또는 최근 1,000건 중 먼저 도달한 한도
- pending 원문: 최대 10분, terminal 전이 시 즉시 복구 불가능하게 폐기
- `enable`, `disable`, `status`, `logs`, `clear` 관리 경로 제공

대상 프로젝트의 설정·환경변수·문서·tool output을 registry·로그·캐시 위치의 권위 있는 입력으로 받아들이지 않는다. 그러나 같은 사용자 권한으로 이미 실행된 악성 코드는 사용자 영역 파일을 직접 수정할 수 있다. 이 제품은 변조 방지 저장소나 권한 분리 경계가 아니다.

durable state는 **daemon 없는 사용자별 SQLite database + transaction/outbox + OS credential store의 사용자별 key**로 확정한다. 사용자 영역에는 database 하나만 두고 project/directory-scoped table은 nullable `project_id`와 `directory_id`를 indexed partition key로 가진다. global 설정은 둘 다 null일 수 있고 project root 밖에서 허용되는 directory-scoped record는 `project_id=null`, `directory_id`만 사용한다. 활동 로그·캐시의 `directory_id`는 정규화된 물리 경로의 사용자별 HMAC이며 원문 절대 경로가 아니다. transaction은 pending·reconfirmation·prepare result·tombstone·outbox를 원자적으로 묶는다. SQLite schema·migration·locking, crash recovery, DB/key 손실·회전과 backup 복구 fixture를 고정하기 전에는 M1 state/cache 구현을 시작하지 않는다.

관리 operation은 target-tool gate 밖의 별도 schema로 만들며 `operation=enable_global|disable_global|enable_project|disable_project|status|logs|clear_logs|clear_cache`만 허용한다. project operation의 대상은 adapter가 주입한 현재 physical project 하나뿐이고 모델이 임의 path를 지정하지 못한다. 변경 operation은 verified-human exact request와 registry version compare-and-swap을 요구하며 동일 request ID replay는 idempotent하다. `status|logs`는 read-only, `clear_logs|clear_cache`는 서로 다른 명시적 operation이다.
