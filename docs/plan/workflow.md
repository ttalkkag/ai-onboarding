# AI CLI 실행 게이트 플로우

> 상태: **M0 검증 뒤 잠글 M1 상태 전이 초안**. 실행 oracle의 정본은 `use-cases.md`다.

## 전체 상태기계

```text
OFF

ON
  → REQUEST_OBSERVED
      ├─ explicit read-only scan → SCAN_BRIDGE → READ_ONLY_SCAN → SCAN_REPORTED → END
      └─ protected action
  → ACTION_PLANNED
  → PRE_TOOL_GATE
  → CACHE_LOOKUP ─ miss → ACTION_SCAN ─┐
                 └ hit ────────────────┤
                                       ▼
                                  DECISION
              ┌─────────────────┼────────────────┐
              ▼                 ▼                ▼
            INFO               LOW              HIGH
              │                 │                │
        local log        warn + local log   local log + deny
              │                 │                │
        native client      native client      disclosure eligible?
       approval/run       approval/run        ├─ no → explain limitation → END
              │                 │              └─ yes → WAIT_RECONFIRM
              │                 │                         ├─ cancel/change/expire → END
              │                 │                         └─ explicit reconfirm
        result hook        result hook                  │
              └──────────────┬─────────────────────────▼
                             │                 explain + prepare response
                             ▼                         │
                            END               COMMAND_PREPARED
                                                  ├─ Stop payload verified → COMMAND_RESPONSE_VERIFIED → END
                                                  └─ not verified / expire → END
```

`COMMAND_PREPARED`와 `COMMAND_RESPONSE_VERIFIED`에서 차단 대상 AI 도구 실행으로 가는 전이는 없다. 제품 관리용 disclose helper는 별도 경로다.

`SCAN_REPORTED`는 읽기 전용 `ScanReport`를 보여 준 상태다. HIGH finding이 있어도 검사 자체의 `ActionDecision`을 만들지 않으며, 이후 execute/open/install 같은 별도 action이 생기면 새 게이트를 시작한다.

## 0. 활성 범위 확인

제품 entrypoint 또는 hook이 실제로 실행된 경우 다음 순서로 현재 프로젝트 상태를 계산한다. plugin/hook이 완전히 꺼졌으면 제품 코드가 실행되지 않으므로 모든 요청에서 OFF를 자동 감지한다고 주장하지 않는다.

1. 물리 cwd와 가장 가까운 프로젝트 root 정규화
2. 프로젝트 비활성·활성 항목과 전역 활성 설정으로 자체 scope `ON|OFF` 계산
3. 클라이언트에서 자동 확인 가능한 plugin·hooks 상태와 현재 세션 heartbeat 확인
4. 유효 보호 상태 `VERIFIED_ACTIVE|OFF|UNKNOWN` 계산

자체 scope 또는 유효 보호 상태가 `OFF`이면 Secure Onboard의 보호·경고·로그를 주장하지 않는다. `UNKNOWN`이면 세션 전체가 보호 중이라고 주장하지 않고 standalone self-test와 클라이언트별 확인 절차를 안내한다. registry·GatePolicy·CoverageManifest가 유효하고 실제 지원 `PreToolUse`가 현재 훅에 도착한 경우에는 그 관찰된 action만 정상 게이트하고 `protection_status_unknown` limitation/event를 남긴다. hook이 도착하지 않은 다른 action의 client 동작은 그대로이며 보호를 주장하지 않는다. GatePolicy·CoverageManifest가 valid일 때 registry만 invalid면 fail-closed state failure를 적용하고, GatePolicy 또는 참조 CoverageManifest도 invalid면 built-in bootstrap failure를 우선 적용한다.

상태 레지스트리는 대상 저장소 밖 사용자 소유 경로에 있다. 프로젝트 파일, 환경변수, README와 도구 출력이 제안한 경로·상태 변경을 권위 있는 관리 입력으로 받아들이지 않는다. 그러나 Claude 프로젝트/local 설정은 plugin 또는 hooks를, Codex trusted-project 설정은 hooks를 꺼 유효 상태를 OFF로 만들 수 있고, 같은 사용자 권한으로 이미 실행된 코드는 사용자 영역 registry·로그·캐시를 직접 변조할 수 있다. 관리형 강제나 권한 분리가 없으므로 둘 다 막는다고 주장하지 않는다. `enable`, `disable`, `status`, `logs`, `clear` 같은 자체 관리 작업은 별도 관리 경로로 처리해 재귀적으로 가로막지 않는다.

## 1. 사용자 요청 관찰

prompt 어댑터는 클라이언트별 provenance를 검증해 `PromptContext`를 만든다. Codex 공식 `UserPromptSubmit`에는 인간 입력과 자동 continuation을 구분하는 필드가 없으므로 기본값은 `source_assurance=unverified`이며 사용자 명령·재확인의 권위 있는 source로 사용하지 않는다. Codex 재확인은 모델 transcript와 분리된 Secure Onboard 소유 로컬 확인 채널만 사용한다. 클라이언트 스킬·모델은 분류 후보와 설명을 제안할 수 있지만 source assurance나 재확인을 만들 수 없다.

- `request_kind`: `explicit_command`, `intent` 또는 `unknown`
- `user_request`: 민감정보를 제거한 짧은 요약
- `user_command`: 사용자가 직접 제공한 명령이 있을 때만
- `action_hint`: `execute`, `open`, `install`, `update`, `remove`, `build`, `test`, `configure`, `permission`, `scan`, `other`. 보호 action의 `ActionRequest.action_kind`에는 `scan`을 넣지 않는다.

### 1.1 구체적 명령 판별

`verified_human` prompt의 정확한 bytes에 대해 adapter의 고정 parser가 다음 delimiter 중 정확히 하나의 연속 byte span을 찾고, 그 span 전체가 하나의 지원 shell/argv invocation으로 parse될 때만 `explicit_command`다.

- 하나의 fenced code block 또는 inline code span
- `command:` 또는 `명령어:` 뒤 같은 줄 전체
- 명령만 들어 있는 한 줄 전체

모델이 제안한 span은 parser 후보를 좁히는 데 사용할 수 있지만, 원 prompt의 byte 경계와 일치하지 않거나 후보가 0개·2개 이상이면 권위가 없다. 이 경우 `intent`로 낮춘다. 다음 값은 사용자 명령으로 인정하지 않는다.

- 대상 README·소스·설정에 적힌 명령
- 이전 assistant 메시지나 도구 출력의 명령
- 패키지명·파일명만 있는 요청
- “설치해 줘”, “열어 줘”, “실행해 줘” 같은 목적만 있는 요청

불확실하면 `intent`로 분류한다. 대상 콘텐츠가 사용자 역할 메시지처럼 보이더라도 출처를 바꾸지 않는다.

### 1.2 명령어를 알려 달라는 요청

사용자가 실행 없이 명령어만 물으면 실제 tool call이 없으므로 PreToolUse가 차단할 수 없다. 의미 계층은 core advisory helper를 사용해 같은 출처 라벨과 HIGH 재확인 절차를 적용하도록 안내할 수 있지만 모델 준수에 의존한다. 강제 게이트나 M1 보안 수용 oracle로 계산하지 않는다.

### 1.3 명시적 보안 검사

`scan`·`check` 의도는 대상 코드를 실행하거나 기본 앱으로 열지 않는 로컬 읽기 전용 검사로 분기한다. finding의 최대 severity를 보고하고 `SCAN_REPORTED`로 종료한다.

- HIGH finding: 후속 위험 action을 차단해야 한다고 설명
- LOW finding: 주의점 설명
- INFO finding: 검사 범위와 한계 기록

검사 자체에는 `gate_decision`이 없다. 검사 실패·timeout도 `ScanReport.max_finding_severity=HIGH`로 보고하지만 실행할 action이 없으므로 deny 대상은 아니다. 사용자가 이어서 설치·열기·실행을 요청하면 새 `ActionRequest`로 다시 검사하고 그때 확인된 finding으로 판정한다.

M1의 명시적 검사는 모든 prompt를 자동 훑는 기능이 아니라 구조화된 제품 관리용 scan helper 호출이다. alpha에서는 한 호출당 local target 하나만 허용한다. 모델은 사용자가 볼 수 있는 target 후보만 넘기며, 어댑터가 native session·현재 `PromptContext`·물리 cwd를 모델 입력과 분리해 주입한다. 공용 코어는 그 cwd에서 exact target을 로컬로 resolve하고 읽기 전용 handle·fingerprint를 만든 뒤에만 `ScanRequest`를 생성한다. target 수가 0/2개 이상이거나 모호한 target, project 밖 escape, symlink 검증 실패 또는 재관찰 불가는 target을 열거나 실행하지 않고 failure 형태의 `ScanReport`로 끝낸다.

## 2. AI 계획과 실행 직전 호출

의도 요청에서 AI가 후보를 만들면 `ai_expected_command`로 표시한다. AI가 실제 로컬 tool call을 만들면 클라이언트 어댑터는 `PreToolUse` 입력에서 다음 값을 정규화한다.

- `tool_name`
- `shell` 또는 구조화된 실행 파일·argv
- `planned_command`
- 물리 `cwd`
- 관련 환경의 값 없는 이름과 HMAC 지문
- target·project fingerprint
- session·native tool call ID와 nullable adapter turn ID

실제 tool input이 가장 권위 있는 판정 입력이다. `planned_command`, 실행 파일·argv, cwd와 관련 context가 사용자 요청과 모두 같을 때만 `command_origin=user_explicit`이다. 명령·옵션·wrapper·cwd·관련 환경 중 하나라도 AI가 바꾸면 `ai_transformed`가 우선한다. 의도에서 생성했으면 `ai_derived`, 대상 텍스트에서만 유래했으면 `target_derived`, 유효한 prompt correlation이 없으면 `unknown`이다.

AI가 사용자 명령을 변경한 경우 보고서에 두 값을 모두 표시하고 다음 차이 중 해당 항목을 설명한다.

- 실행 파일·패키지 관리자 변경
- 옵션·버전·경로 추가 또는 제거
- shell wrapper·pipe·redirect·복합 명령 추가
- cwd·권한·환경 변수 사용 변경

다음 coverage 분류는 유효한 GatePolicy와 그가 참조한 CoverageManifest를 모두 확인한 뒤에만 수행한다. 둘 중 하나가 invalid/unreadable이고 유효한 registry로 scope `OFF`임을 확인하지 못한 상태에서 `PreToolUse`가 실제 도착하면 정상 grammar나 `NOT_COVERED`를 추정하지 않는다. 어댑터의 내장 bootstrap matcher가 관찰된 target-tool 호출 전부를 `guardrail.policy_bootstrap_failure` HIGH로 deny한다. 이 비상 fallback은 지원 coverage 주장이 아니며 `status|clear|scope off` 같은 제품 관리 경로는 target-tool 게이트 밖에 둔다. 실제 scan helper 호출은 실행 gate 없이 같은 rule의 failed `ScanReport`로 끝낸다.

정상 상태에서는 정규화 전에 M1 coverage를 먼저 분류한다.

1. native tool 입력에서 coarse `action_kind`를 먼저 분류한다.
2. build/test/configure처럼 M1 action kind 밖이면 세부 option 파싱보다 먼저 `NOT_COVERED`로 통과시키고 redacted `coverage_not_supported` event만 남긴다. `INFO` 판정이나 보호 성공으로 표시하지 않는다.
3. install/file-open 지원 entry 후보면 exact schema·shell dialect·단일 target grammar를 검사한다. 해석할 수 없으면 fail-closed operational HIGH다.
4. M1 지원 grammar에 해당하면 정상 `ActionRequest`를 만든다.
5. 훅이 관찰하지 않은 호출은 제품 코드가 event를 만들 수 없으며 범위 밖이다.

## 3. 캐시 확인과 검사

### 3.1 캐시 키

1. 증거 키: target content/permission/symlink fingerprint + core/rule-bundle/security-data version + analysis-profile digest
2. 작업 키: 증거 키 + exact tool/command + physical cwd + resolved executable + effective env/config fingerprint + gate-policy digest

경로 또는 mtime만으로 hit를 만들지 않는다. 캐시 레코드가 손상됐거나 MAC·스키마가 다르면 폐기하고 fresh scan한다. fresh scan이 실패한 보호 action은 fail-closed HIGH다. writeback만 실패하면 fresh decision을 유지하고 `bypass`로 기록한다.

### 3.2 캐시 hit

유효한 hit이면 중복 정적 분석만 생략한다. 다음은 생략하지 않는다.

- 매 시도의 target fingerprint 재확인
- HIGH 차단과 사용자 재확인
- LOW 실행 전 경고
- INFO/LOW/HIGH 이벤트 기록

### 3.3 검사 순서

1. command·target·context 정규화
2. 요청한 작업과 target의 M1 범위 내 정적 근거 확인
3. 결정론적 규칙 실행
4. 가장 높은 등급으로 `ActionDecision` 생성
5. 실행 직전 target fingerprint 재확인

한 바이트, symlink target, 실행 권한, 명령, cwd, resolved 실행 파일, effective 환경·package-manager 설정, 규칙·데이터·analysis profile·gate policy가 바뀌면 관련 cache miss로 다시 검사한다. M1 remote registry npm install은 실제 설치 bytes를 immutable하게 결합하지 못하므로 `guardrail.scan_failure` HIGH로 deny하고 action cache를 bypass한다. context를 입증할 수 없는 다른 tool도 bypass한다. 일반 파일시스템 경쟁 상태를 완전히 제거할 수 없으므로 남은 TOCTOU는 결과에 한계로 표시한다. AI assessment 병합은 M2다.

## 4. 판정

### INFO

1. `allowed_info`를 로컬에 기록한다.
2. 별도 보안 경고를 표시하지 않는다.
3. 클라이언트의 기존 sandbox·permission·approval 흐름을 유지한다.
4. 실제 tool call 뒤 클라이언트 결과 훅이 관찰되면 `tool_completed` 또는 `tool_failed`를 기록한다.

사용자가 native approval을 취소하거나 result hook이 오지 않으면 결과 event를 추정하지 않고 해당 흐름을 종료한다.

### LOW

1. adapter가 실행 전에 위험과 오탐 가능성을 쉬운 말로 담은 client별 유효 경고 출력을 동기식으로 쓴다.
2. output write 성공 뒤 `warned_low`를 로컬에 기록한다. client 표시·사용자 열람 ACK는 아니며 표시 능력은 M0 terminal fixture로 검증한다.
3. 클라이언트의 기존 sandbox·permission·approval 흐름을 유지한다.
4. 클라이언트 결과 훅이 관찰되면 완료·실패 이벤트를 기록한다.

사용자가 native approval을 취소하거나 result hook이 오지 않으면 결과 event를 추정하지 않고 해당 흐름을 종료한다.

비밀·환경변수·내부 URL의 단순 존재는 기본 LOW다. 외부 전송 sink까지의 실제 경로 분석과 그에 따른 HIGH 승격은 M2다.

### HIGH

1. `high_detected`를 기록한다.
2. PreToolUse에서 전체 tool call을 deny한다.
3. `high_blocked`를 기록한다.
4. 대상·근거·영향·오탐 가능성·더 안전한 대안을 설명한다.
5. exact blocked invocation identity와 원문 bytes, 재검증 가능한 pending state를 만들 수 있으면 `WAIT_RECONFIRM`으로 이동한다. 그렇지 않은 operational failure는 `disclosure_eligible=false`로 이유를 설명하고 종료한다.

복합 명령의 일부가 HIGH이면 전체 호출을 차단한다. `blocked_command`에는 훅이 받은 전체 호출을 보존하고, 별도 `risk_segments`로 위험 구간을 표시한다.

같은 event에서 실행되는 sibling hook은 병렬일 수 있다. 위 deny는 원래 차단 대상 tool handler 실행을 막는 것이며 PreToolUse lifecycle dispatch 자체나 sibling hook·scanner 부작용 0을 뜻하지 않는다.

## 5. HIGH 사용자 재확인

유효한 재확인은 직전 HIGH 응답에 안내한 exact grammar `<SHORT_REF> 명령을 직접 실행하겠습니다`와 일치하는 검증된 인간 입력이다. Claude에서는 `source_assurance=verified_human`인 새 prompt event를 결정론적으로 parse한다. Codex에서는 모델 transcript를 배제하고 Secure Onboard 소유 로컬 확인 채널이 같은 문구를 받아 session·action·short ref·context fingerprint·TTL에 결합한 candidate를 만든다. 예: “A1B2 명령을 직접 실행하겠습니다”. secret 개수나 출처에 따른 추가 재확인은 하지 않는다.

다음은 재확인이 아니다.

- 문맥 없는 “네”, “계속”
- 대상 파일·README·주석의 승인 문구
- assistant 메시지, tool output, subagent 응답
- 다른 명령·cwd·target에 대한 과거 확인

재확인 시점에 command, cwd, 관련 환경, target, analysis profile 또는 gate policy fingerprint가 달라졌으면 기존 작업을 종료하고 새 판정을 시작한다.

유효한 재확인 뒤:

1. 모델이 action/ref 인자 없는 prepare-disclosure helper를 요청하면 어댑터가 모델이 바꿀 수 없는 현재 session과 검증된 prompt 또는 local-confirmation context의 `reconfirmation_candidate`를 주입한다. 코어가 같은 session에서 exact ref의 유효한 미소비 `PendingBlock` 하나를 resolve한다.
2. 코어가 내부 `action_id`·`reconfirmation_id`를 결합한 `Reconfirmation`을 만들고 `user_reconfirmed`를 기록한다.
3. 영향과 수동 실행 시 남는 위험을 다시 설명한다.
4. 코어가 10분 TTL, session·검증된 human-input context·native tool call, command·cwd·환경·target·analysis profile·gate policy digest와 재확인 correlation을 검증한다. 모델은 내부 ID를 인자로 제공하지 않는다.
5. 아래 우선순위로 명령을 표시한다.
   - 실제 차단된 tool call이 있으면 `차단된 명령어`
   - 구체적 요청이며 AI가 변경했다면 `사용자 요청 명령어`와 `AI 실행 예정/차단 명령어`를 모두 표시
   - tool call 없는 단순 명령 조언 경로는 M1 강제 게이트 밖이며 이 공개 전이에 들어오지 않음
6. 코어가 `high_command_prepared`를 기록하고 action marker·display digest가 포함된 렌더링 payload를 반환한다.
7. assistant가 응답을 만든 뒤 지원되는 Stop 훅이 `last_assistant_message`의 marker·digest를 확인한 경우에만 `high_command_response_verified`를 기록하고 pending 원문을 삭제한다. 이는 UI 전달·렌더 완료·사용자 열람 ACK가 아니다.
8. Stop 확인이 없으면 공개를 추정하지 않고 prepared 상태를 TTL까지 유지한다.

AI는 명령을 tool call로 다시 보내지 않는다. 사용자가 같은 대화에서 다시 AI 실행을 요구해도 새로운 PreToolUse 호출은 다시 HIGH로 차단한다.

PendingBlock은 활동 로그·캐시가 아니다. 사용자 전용 권한으로 저장하고 응답 포함 확인·취소·context 변경·만료·격리 시 삭제한다. 지문이 달라진 action은 `cancelled(reason=context_changed)`, TTL을 넘긴 action은 `expired`로 종료하고 새 판정을 요구한다. 여러 HIGH가 병렬로 생기면 live session에서 short ref를 유일하게 발급하고 정확히 하나만 resolve한다. terminal 전 같은 `prepare_call_id` 재전송은 동일 payload를 반환한다. terminal 뒤 helper replay는 tombstone의 `already_terminal`만 반환하고 명령 payload는 반환하지 않으며, Stop replay는 이전 검증 결과만 idempotent하게 반환한다.

## 6. 명령 렌더링

화면의 명령과 로컬 로그를 분리한다.

다음은 확정된 M1 화면 정책이다. M0는 명령 공개를 구현하지 않는다.

### 화면

- exact blocked command의 bytes와 개행·shell quoting을 보존
- 비밀값은 출처와 무관하게 치환하지 않음
- ANSI/OSC, 양방향 제어문자, NUL과 코드펜스 탈출은 터미널에서 동작시키지 않고 가시적인 dialect별 안전 표현으로 변환. 변환이 하나라도 있으면 `rendering=display_safe_reference`이며 exact/runnable 값이라고 주장하지 않음
- 비밀 노출 가능성과 제어문자 변환 사실을 영향 설명에 알리고, 검증은 시각적 렌더링이 아니라 응답의 command segment bytes·길이·digest로 수행. 변환된 segment는 변환 후 값을 기준으로 대조

### 로컬 로그

- 원문 명령, 비밀값, 소스 원문, 절대 경로 저장 금지
- command HMAC, action kind, origin, severity, rule ID, project/target HMAC, version, timestamp만 기록

## 7. 오류 처리

보호 action의 공용 코어와 live 어댑터가 실행됐지만 다음 문제가 생기면 명시적 HIGH deny를 반환한다.

- parser·scanner 오류 또는 timeout
- tool input 정규화 실패
- 필수 로그·상태 파일 쓰기 실패
- 손상 캐시 뒤 재검사 실패

core timeout·nonzero exit·schema-invalid output에서는 어댑터가 target을 재분석하지 않는다. 보호 action은 고정 `guardrail.scan_failure` fallback decision을 만들고 M0에서는 `cache_status=bypass`, pending command 공개 없음이다. read-only scan은 adapter-generated scan ID, `report_source=adapter_fallback`, `scan_status=failed`, HIGH finding의 `ScanReport`를 만든다. adapter event 저장까지 실패했다면 고장 난 저장소에 event가 남았다고 요구하지 않는다.

명령 공개 가능성은 신뢰 가능한 exact invocation이 남았는지로 정한다. exact blocked bytes·safe rendering·pending state를 만들고 재검증할 수 있으면 operational HIGH도 같은 재확인 절차를 사용할 수 있다. 정규화·state 실패로 이를 신뢰할 수 없으면 `disclosure_eligible=false`이며 명령을 추측해 만들지 않는다.

읽기 전용 scan의 같은 오류는 HIGH finding을 담은 `ScanReport`로 끝나며 scan 자체에 deny를 만들지 않는다. 후속 보호 action은 새로 판정한다.

adapter 자체의 미실행·timeout·일반 nonzero exit·malformed output은 클라이언트가 계속 실행할 수 있는 비보장 경계다. M0는 core child 실패를 live adapter가 유효 deny로 변환하는 case와 adapter 자체 실패 case를 분리해 관찰 결과를 기록한다.

클라이언트가 hook을 로드하지 않았거나 사용자가 비활성화한 경우에는 코어가 deny할 수 없다. `status`는 제품 entrypoint가 실행되거나 사용자가 standalone self-test를 요청했을 때 다음을 최선의 노력으로 보여 준다.

- 공통: plugin installed/configured, 자체 scope `ON|OFF`, 유효 보호 `VERIFIED_ACTIVE|OFF|UNKNOWN`, 현재 세션 heartbeat, 마지막 standalone self-test
- Codex: hooks feature 상태와 확인 가능한 설정, exact bundled hook definition의 제품 자체 digest·heartbeat; Codex 내부 trust hash 값은 `unknown — Codex /hooks에서 정의와 trust 상태 확인 필요`
- Claude Code: `claude plugin list --json`의 설치·enable 상태, 설정 계층의 `disableAllHooks`, `--bare` 또는 `CLAUDE_CODE_SIMPLE=1`, `/hooks`의 hook source, `/status`의 setting sources, 제품 heartbeat/self-test; 기계 판독 근거가 없으면 `UNKNOWN`
- 현재 프로젝트 scope와 유효 보호 상태의 적용 근거
- core/rule/cache schema version
- 마지막 in-session self-check 결과

## 8. 일반 터미널과 실행 결과

HIGH 명령 제공 뒤 사용자가 일반 터미널에서 실행하는 것은 제품 범위 밖이다.

- 실행 여부, exit code, 출력과 부작용을 알 수 없음
- `executed`, `tool_completed`, `tool_failed`를 만들지 않음
- “이 판정은 명령을 표시한 시점의 cwd·환경·대상 상태에만 해당한다”고 안내

LOW·INFO에서 result hook으로 관찰한 작업만 결과 이벤트를 기록한다. Claude Code는 성공 `PostToolUse`와 실패 `PostToolUseFailure`, Codex는 `PostToolUse`의 결과를 어댑터가 공통 outcome으로 변환한다. 결과 훅은 실행 전 차단 수단으로 사용하지 않는다.
