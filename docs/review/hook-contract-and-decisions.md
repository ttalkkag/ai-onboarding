# 훅 계약 독립 검증과 사용자 확정 결정

- 작성일: 2026-07-26
- 범위: `docs/plan/*.md`, `docs/research/*.md`, 루트 `README.md`·`CONTEXT.md`
- 방법: 공식 문서 직접 대조(Claude Code hooks/plugins/settings, Codex hooks/plugins) + 저장소 기계 점검 + 사용자 확인
- 성격: 이 문서는 **검증 기록과 사용자 결정의 원본**이다. 제품 계약 정본은 `../plan/`이다.

> 주의: 이 검토를 수행하는 동안 다른 에이전트 세션이 같은 `docs/plan/*.md`를 동시에 개정했다. 아래 "정본 반영 상태"는 2026-07-26 17:30 KST 시점 기준이며, 그 이후 개정에서는 다시 대조해야 한다.

## A. 사용자가 확정한 결정 (4건)

이 절은 사용자에게 실제로 제시된 선택지와 답변을 그대로 남긴다. 이후 문서 개정에서 재논의를 막기 위한 근거다.

### A1. M1 정책 3종

| 항목 | 최종 확정 내용 |
|------|-----------|
| P01 비밀값 표시 | **`P01-B` (literal-all).** 출처와 무관하게 exact blocked command의 secret 원문 bytes를 치환·정규화 없이 제공. 최초 답변은 `P01-A`였으나 A1-X의 충돌 확인 뒤 사용자가 `P01-B`로 확정 |
| P02 검사 실패 | **`P02-A`.** 보호 action의 필수 검사·상태·로그 실패는 fail-closed HIGH deny. read-only scan의 같은 실패는 HIGH finding report |
| P03 alpha 범위 | **`P03-A`.** npm 설치 + 로컬 파일 열기 + 두 대상의 명시적 read-only scan |

여기에 A1-Y의 별도 결정이 겹친다: **터미널 제어문자 안전 변환은 secret 정책과 무관하게 항상 적용한다.** 즉 최종 표시 정책은 "secret은 literal, 제어문자는 안전 변환"의 하이브리드다.

정본 반영 상태: **세 항목 모두 반영 완료.**

### A1-X. P01 정책 충돌 — 해결됨

2026-07-26 17:26~17:31 KST 사이 다른 에이전트 세션이 `decisions.md` D13과 `use-cases.md` §8을 **P01-B(literal-all)로 재작성**했다. 거의 같은 시각 사용자는 이 세션에 P01-A를 답했고, `report-template.md`는 아직 P01-A를 규정하고 있어 정본이 내부 모순 상태였다.

사용자에게 충돌을 제시한 결과 **P01-B가 맞다**는 답을 받았다. 이후 다른 세션이 `report-template.md`까지 literal-all로 전파해 secret 정책은 현재 전 문서에서 일관된다(`secret_rendering=literal_all`, `secret_spans[].storage=literal`, `replacement=null`).

**교훈으로 남길 것:** 같은 저장소를 여러 에이전트 세션이 동시에 편집하면 정본이 몇 분 단위로 자기모순 상태를 지난다. 정책을 바꿀 때는 그 정책이 걸쳐 있는 모든 문서를 한 번에 옮기거나, 옮기는 중임을 문서에 표시해야 한다.

### A1-Y. 제어문자 안전 변환 제거 — 회귀, 복원 완료

위 재작성은 secret 정책만 바꾼 것이 아니라 **터미널 제어문자 안전 변환까지 함께 제거**했다. `use-cases.md` §8 S05는 "escape·정규화 0"이 됐고 S09는 escape하면 payload를 거부하도록 뒤집혔으며, 같은 서술이 `proposal.md`·`workflow.md`·`report-template.md`·루트 `README.md`로 전파됐다.

이 변경을 회귀로 판단한 근거는 다음 세 가지다.

1. **사용자에게 제시된 적이 없다.** P01-A·P01-B 어느 선택지도 제어문자 처리를 건드리지 않았다. 두 안의 공통 불변식이었다.
2. **공격 표면을 새로 연다.** 위험 명령 원문은 정의상 신뢰할 수 없는 대상에서 유래할 수 있다. 그 bytes를 그대로 터미널에 출력하면 ANSI/OSC 시퀀스로 화면을 조작해 사용자가 보는 명령과 실제 복사되는 명령을 다르게 만들 수 있다. 양방향 제어문자(Trojan Source 계열)도 같다. 이는 "사용자가 위험을 이해한 상태에서 선택하게 한다"는 제품 목적을 정면으로 무력화한다.
3. **secret 정책과 독립이다.** P01-B를 택해도 제어문자 안전 변환은 유지할 수 있다.

**사용자가 복원을 지시했고 다음과 같이 복원했다.**

| 파일 | 복원 내용 |
|------|-----------|
| `decisions.md` D7·D13.2 | secret은 literal, 제어문자는 예외로 항상 안전 표현 변환. 이유(화면-실제 불일치)를 함께 기재 |
| `use-cases.md` §8 | intro를 하이브리드로 정정. S05를 `display_safe_reference` 기대값으로 복원. S09를 S09-A(secret 치환 시 거부)/S09-B(제어문자 raw 방출 시 거부)로 분리 |
| `report-template.md` §1.2·§1.3·§7.1·§7.3·§10.1 | `rendering`·`disclosure_mode` enum에 `display_safe_reference` 복원, `transformations`에 `control_escape` 복원, GatePolicy에는 스위치를 두지 않고 고정 불변식으로 명시 |
| `proposal.md` §5.3·§10 | 같은 예외를 반영 |
| `workflow.md` §6 화면 | escape 금지 서술을 변환 요구로 되돌림 |
| `README.md` | 사용자 대상 문구 정정 |

복원 뒤 `escape 없이`·`escape·정규화 0` 계열 서술은 정본에 남아 있지 않으며, 6개 문서 전부가 같은 규칙을 기술한다.

### A2. HIGH 종단 설계 — 현행 유지

**결정: 현행 D7 유지. `continue:false` 도입하지 않음.**

제시한 대안은 HIGH 차단 시 `continue:false`+`stopReason`으로 턴 자체를 종료해 같은 턴의 변형 명령 재시도를 원천 차단하고, 모델이 바꿀 수 없는 메시지를 표시하는 것이었다. 사용자는 현행 설계를 택했다.

따라서 다음 두 한계는 **수용된 설계 특성**이며 결함으로 재기재하지 않는다.

- HIGH는 "제품이 관측할 수 있는 AI 실행"을 막을 뿐, 사용자가 일반 터미널에서 수행하는 수동 실행으로 이어질 수 있다. 기획서 §1이 정의한 비기술 사용자에게 이는 `차단됨` → `무관측 실행`의 전환이다.
- 같은 턴 내 변형 명령 재시도는 매 `PreToolUse`마다 다시 차단하는 방식으로만 처리된다(C08).

덧붙여 검증 결과 `continue:false`·`stopReason`은 **Claude Code 전용**이다. Codex 공식 문서는 이 두 필드를 `permissionDecision:"ask"`, `decision:"approve"`, `suppressOutput`과 함께 "parsed but not supported yet"으로 명시한다. 즉 이 대안은 애초에 두 클라이언트 대칭으로 구현할 수 없었다.

### A3. 배포 모델 — 개인 opt-in 유지

**결정: 관리형(관리자 강제) 배포를 채택하지 않는다. D0·D2 현행 유지.**

검증 결과 두 CLI 모두 관리자 강제 수단이 실재한다.

- Claude Code: managed settings의 `enabledPlugins` 강제 활성화, `allowManagedHooksOnly`, `disableAllHooks`
- Codex: `requirements.toml`로 관리자가 `[features] hooks` 상태를 강제

기획서 §1의 문제 정의가 "내부 사용자"라는 조직 상황임에도 개인 opt-in을 유지한다는 것은, **설치한 사람이 언제든 끌 수 있다**는 한계를 조직 차원 문제 해결의 비용으로 수용한다는 뜻이다. 이 선택은 확정이며, 문서 곳곳의 "강제 보안 통제가 아니다"라는 서술과 일관된다.

### A4. `systemMessage` 채택 — M0 실측 후 확정

**결정: 계약을 지금 잠그지 않고 M0 tracer-bullet에서 실제 렌더링을 측정한 뒤 확정한다.**

측정해야 할 것은 "필드가 존재하는가"가 아니라(존재는 아래 B절에서 확인됨) **두 CLI가 실제 터미널에서 이 값을 사용자에게 어떻게 보여 주는가**이다. 특히 다음을 M0 케이스로 고정해야 한다.

1. `permissionDecision:"deny"`와 `systemMessage`를 같은 응답에 넣었을 때 경고가 실제로 표시되는가, deny 경로에서 무시되지는 않는가
2. LOW에서 permission decision 없이 `systemMessage`만 반환했을 때 **대상 도구가 실행되기 전에** 표시되는가
3. 표시되는 최대 길이·개행·서식 제약 — 짧은 ref와 재확인 문구가 잘리지 않는가
4. Codex에서 `systemMessage`가 "UI 또는 event stream 중 어디로" 가는지, 대화형 터미널 세션에서 사용자 눈에 보이는가

## B. 공식 문서로 확인한 사실

아래는 이번 검토에서 공식 문서를 직접 조회해 확인한 값이다. 모든 인용 URL은 조회 시점에 HTTP 200이다.

### B1. 사용자 표시 채널

| 사실 | 확인 내용 |
|------|-----------|
| `permissionDecisionReason`의 도달 지점 | Claude Code 문서는 이 값을 "shown to Claude as a system reminder"로 규정한다. **사용자가 아니라 모델에게** 간다 |
| `systemMessage` (Claude Code) | top-level 출력 필드, "Warning message shown to the user" |
| `systemMessage` (Codex) | 공통 출력 필드, "Surfaced as a warning in the UI or event stream". `PreToolUse`를 포함한 여러 이벤트에 적용 |
| 훅의 직접 터미널 출력 | 불가. Claude Code 문서는 `terminalSequence` 설명에서 "Use this instead of writing to `/dev/tty`, which is unavailable to hooks"라고 명시한다 |

**함의:** `systemMessage` 없이는 제품의 모든 사용자 표시가 모델의 성실한 전달에 의존한다. 이는 LOW 경고 전달 보장뿐 아니라 **짧은 ref와 exact 재확인 문구**에도 적용된다. 모델이 요약·의역하면 재확인 grammar가 사용자에게 정확히 전달되지 않아 HIGH 공개 경로 자체가 성립하지 않는다.

### B2. 판정 출력 형식

| 사실 | 확인 내용 |
|------|-----------|
| Claude Code deny | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}` |
| `permissionDecision` 허용값 (Claude) | `allow`, `deny`, `ask`, `defer` |
| `permissionDecision` 허용값 (Codex) | `allow`, `deny`만 유효. `ask`는 "parsed but not supported yet" |
| Codex 미지원 필드 | `permissionDecision:"ask"`, `decision:"approve"`, `continue:false`, `stopReason`, `suppressOutput` |

**함의:** `ask`(사용자에게 승인 요청 위임)와 `continue:false`(턴 종료)는 두 클라이언트 대칭 설계의 기본 도구로 쓸 수 없다.

### B3. 실패·타임아웃 시맨틱 — fail-open 경계

| 사실 | 확인 내용 |
|------|-----------|
| Claude Code exit 0 | stdout의 JSON을 파싱. JSON 출력은 exit 0에서만 처리 |
| Claude Code exit 2 | 차단. stdout·JSON 무시, stderr가 모델에 전달 |
| Claude Code 기타 non-zero | **비차단 오류. 도구 호출은 그대로 진행** |
| Codex 기타 non-zero·timeout | hook failure로 보고하되 **실행은 계속** |
| 기본 timeout | 두 CLI 모두 대부분 훅 600초. Claude는 `UserPromptSubmit` 30초, `MessageDisplay` 10초로 낮춤. Codex는 `SessionEnd` 1초(최대 3초) |
| 훅 병렬성 | Codex: "Multiple matching command hooks for the same event are launched concurrently, so one hook can't prevent another matching hook from starting" |

**함의 1:** fail-closed는 **어댑터가 살아서 유효한 deny를 반환하는 경우에만** 성립한다. 어댑터가 죽거나 멈추거나 exit 1로 끝나면 두 CLI 모두 실행을 계속한다. 정본은 이미 이를 반영했다(`workflow.md` §7 말미, `use-cases.md` T05-F/J/K, 리뷰 blocker #2).

**함의 2 (미반영):** 훅 선언의 `timeout` 값을 명시하지 않으면 기본값이 600초다. 어댑터가 멈추면 사용자 세션이 최대 10분 정지한다. `hooks.json`에 제품이 감당할 수 있는 작은 명시적 timeout을 넣는 것은 구현 세부가 아니라 **UX와 fail-open 노출 시간을 동시에 결정하는 값**이므로 M0에서 고정해야 한다.

### B4. 배포·신뢰 경계

| 사실 | 확인 내용 |
|------|-----------|
| Claude Code 플러그인 구성요소 | `hooks/hooks.json` 포함. 훅을 실을 수 있음 |
| Claude Code 설치 scope | user / project / local / managed. project scope는 `.claude/settings.json`에 기록 |
| Claude Code 플러그인 훅 신뢰 | **훅 단위 신뢰 절차 없음.** 설치 경고 문구와 설치 전 구성요소 목록 표시가 전부 |
| Codex 플러그인 훅 신뢰 | **설치·활성화만으로 신뢰되지 않음.** 검토·신뢰 전까지 번들 훅은 skip. 훅의 현재 hash에 대해 신뢰가 기록되고 변경 시 재검토 필요 |
| Codex 훅 설정 위치 | `~/.codex/hooks.json`·`config.toml`(사용자), `<repo>/.codex/hooks.json`·`config.toml`(프로젝트, 해당 `.codex/` 레이어가 신뢰된 경우에만 로드) |
| Codex 훅 비활성 | `config.toml`의 `[features] hooks = false`. 관리자는 `requirements.toml`로 강제 |
| Codex 공식 성격 규정 | "Treat tool hooks as a useful guardrail, not a complete enforcement boundary" |
| Claude Code 훅 비활성 | `disableAllHooks`(user/project/local/managed), managed 전용 `allowManagedHooksOnly` |

**함의:** Codex에서는 **설치 완료 ≠ 보호 활성**이다. 사용자가 `/hooks`에서 명시적으로 신뢰해야 하며, 제품 업데이트로 훅 정의가 바뀌면 다시 신뢰해야 한다. 설치 안내와 `VERIFIED_ACTIVE` 판정이 이 단계를 반드시 포함해야 한다.

### B5. 이벤트·payload 사실 (기존 서술 검증)

기획서가 이미 주장하던 다음 항목은 **모두 사실로 확인**됐다.

- Claude Code `Stop` 훅의 `last_assistant_message` 존재. 문서는 "Hooks that need the final assistant text of the current turn should use `last_assistant_message` on Stop and SubagentStop instead of reading the transcript"라며 transcript 읽기보다 이 필드를 권장한다
- **Codex `Stop`에도 `last_assistant_message` 존재** — 응답 원문 확인이 한쪽 클라이언트 전용이 아니다
- Claude Code에 성공 `PostToolUse`와 실패 `PostToolUseFailure`가 **별도 이벤트로 존재**
- Codex는 단일 `PostToolUse`가 "also runs after commands that exit with a non-zero status" — 실패까지 포함. 따라서 어댑터의 공통 outcome 정규화 설계가 맞다
- Codex `PreToolUse`에 `tool_use_id`와 `turn_id` 존재
- 두 CLI 모두 `UserPromptSubmit` 존재 (Claude는 `user_prompt`, Codex는 `prompt` 필드)
- `PermissionRequest`가 두 CLI에 존재하며, 승인 요청이 발생하지 않는 호출은 놓칠 수 있으므로 1차 게이트로 부적합하다는 판단이 타당
- `disableAllHooks` 실재

### B6. 인용 URL 상태

`decisions.md` D1이 인용한 4개 URL은 모두 HTTP 200이다. 참고로 `developers.openai.com/codex/plugins`는 `learn.chatgpt.com/docs/plugins`로 308 리다이렉트되며, 플러그인의 `hooks.json`과 번들 훅 신뢰 규칙은 후자에 기술돼 있다.

## C. 정본에 아직 반영되지 않은 항목

아래 5건은 이 검토에서 식별하고 **모두 정본에 반영 완료**했다. 목록은 감사 추적을 위해 남긴다.

| # | 항목 | 반영 위치 | 근거 |
|---|------|-----------|------|
| C1 | 제어문자 변환 파이프라인 순서와 digest 경계 정의. `blocked_invocation`(exact) → `display_projection`(quoting만) → 제어문자 변환(표시 단계) 순서이며, `round_trip_fixture_digest`는 **변환 이전** projection 직후 bytes를, `rendered_commands[].text`·`display_digest`는 **변환 이후** 값을 묶는다. 제어문자가 있는 명령에서 두 digest가 다른 것은 정상이며 fixture는 있는 case와 없는 case를 각각 고정한다 | `report-template.md` §7.1 | A1-Y로 계약을 넓히면서 이 검토가 새로 만든 구멍을 닫음 |
| C2 | `systemMessage` 실제 렌더링 측정 case `T20-A~D` 추가. deny 경로 동봉 표시, LOW의 target 실행 전 표시, ref·재확인 문구 무손실 여부, Codex의 UI/event-stream 구분 | `use-cases.md` §2 | A4의 4개 측정 항목 |
| C3 | 배포 `hooks.json`의 명시적 `timeout` 선언을 M0 고정 대상으로 추가. 기본값 600초를 그대로 두면 어댑터 정지 시 세션이 최대 10분 멈춤 | `use-cases.md` §2 manifest, `proposal.md` §7.1 | B3 함의 2 |
| C4 | 조직 관리 설정에 의한 훅 배제와 Codex 미신뢰 훅을 비보장 목록에 추가 | `decisions.md` D1 | B4 |
| C5 | Codex "설치 ≠ 보호 시작" 단계를 설치·업데이트 안내와 상태 판정에 명시 | `proposal.md` §9.1 | B4 함의 |

## D. 사용자가 채택하지 않은 대안 (재논의 방지)

아래는 검토했고 사용자가 명시적으로 택하지 않은 안이다. 새로운 근거 없이 다시 제안하지 않는다.

- `continue:false`+`stopReason` 기반 HIGH 턴 종료 (A2) — 더불어 Codex 미지원
- 관리자 강제 배포로의 전환 또는 후속 마일스톤 추가 (A3)
- HIGH에서 명령 원문을 아예 제공하지 않는 축소안 (A2)
- `systemMessage`를 M0 측정 없이 즉시 1차 채널로 계약에 고정 (A4)

## E. 기계 점검 결과

| 항목 | 결과 |
|------|------|
| 코드펜스 균형 (`docs/**` 전체 99개 md + 루트) | 이상 없음 |
| 내부 상대 링크 | 48개, 실질 깨짐 0. 검출된 2건은 `docs-generator/references/templates.md`의 **코드펜스 안 README 템플릿 예시**(`./docs/api/README.md` 등)로 실제 링크가 아님 |
| UTF-8 BOM | 0 |
| `git diff --check` | 통과 |
| `decisions.md` D9 필수 이벤트 ↔ `report-template.md` §8 이벤트 표 | 17개 전부 일치 |
| rule ID 표기 | `npm.*`·`file.*`·`secret.*`·`action.*`·`guardrail.*` 문서 간 불일치 없음 |
| 인용 외부 URL | 전부 200 |

## F. 저장소 위생 (문서 밖 지적)

- **`.gitignore` 부재 → 해결.** 작업 트리의 `.DS_Store`가 `git add -A` 한 번으로 커밋될 수 있었다. `.gitignore`를 추가했다.
- **업스트림 라이선스 고지 부재 → 해결.** `docs/draft/reverse-skill/`은 [`zhaoxuya520/reverse-skill` @ `fe2e2de`](https://github.com/zhaoxuya520/reverse-skill/commit/fe2e2def5ec21dbda9d84f69c1ef8b20d53fc269)의 MIT 저작물을 번역·재구성한 것이고, MIT는 저작권·허가 고지를 사본에 포함할 것을 요구한다. 해당 commit의 `LICENSE` 원문을 확인해 `docs/draft/reverse-skill/LICENSE`로 추가했다(`Copyright (c) 2026 zhaoxuya520ya520`, 원본은 BOM 포함이나 저장 시 제거).
- **저장소 자체 `LICENSE` — 미해결, 사용자 결정 사항.** 이 저장소 고유 저작물에 어떤 라이선스를 적용할지는 소유자가 정할 문제이므로 임의로 선택하지 않았다. 공개 전에 정해야 하며, 정하기 전까지는 기본적으로 “모든 권리 유보” 상태로 취급된다. 파일별 provenance(어떤 문서가 업스트림 파생이고 어떤 문서가 자체 저작인지) 정리도 함께 필요하다.

## G. 관찰: 계약 규모

`report-template.md`는 이번 개정으로 1,279줄이 됐고, 스키마는 15종을 넘는다. 아직 제품 코드는 한 줄도 없으며 M1 alpha의 지원 흐름은 3개다. 저장소 `AGENTS.md`는 "최소 코드", "단일 사용처에 추상화 금지", "200줄로 쓴 것이 50줄이면 다시 써라"를 원칙으로 명시한다.

이는 오류가 아니라 트레이드오프다. 계약을 먼저 고정하면 M0/M1의 expected JSON을 기계적으로 검증할 수 있고, 실제로 이번 개정에서 durable transaction·tombstone·replay 같은 어려운 실패 모드가 문서 단계에서 드러났다. 다만 다음 두 가지는 실측 전 계약 확장의 위험 신호로 남긴다.

- M0가 아직 native payload를 하나도 확보하지 못한 상태에서 스키마 세부가 계속 늘고 있다. M0 결과가 가정과 다르면 되돌릴 문서량이 그만큼 커진다.
- `use-cases.md` M1 착수 조건이 요구하는 fixture·expected JSON 총량(C·N·F·R·O·A·K·L·S 계열 전체 × client/version/OS)은 3개 흐름 alpha치고 매우 크다. M0 종료 시점에 이 목록을 **줄이는 방향으로** 한 번 재검토할 것을 권한다.

## H. 구현 착수 판정

- **M0 hook tracer-bullet: GO.** 이번 검증은 M0가 전제한 훅 사실(Stop `last_assistant_message`, `PostToolUseFailure`, Codex 단일 `PostToolUse`, `tool_use_id`, deny 출력 형식, 훅 신뢰 절차)이 모두 공식 문서와 일치함을 확인했다. M0를 막는 사실 오류는 발견되지 않았다.
- **전체 M1 제품 구현: NO-GO.** P01/P02/P03과 D13 네 항목이 모두 닫혔지만, `use-cases.md` §12 착수 조건 1·3·5·6은 정의상 **M0 실행 결과가 있어야 닫힌다**. 즉 지금 문서를 더 고쳐서 M1 GO로 만들 수 있는 상태가 아니며, 다음 관문은 문서 작업이 아니라 M0 실행이다.
- **M2: NO-GO.**

### 문서 검토 관점의 완료 판정

이 검토 기준으로 **문서에 남은 사실 오류·내부 모순·미정의 스키마는 없다.** C1–C5를 모두 반영했고, secret·제어문자 정책이 9개 문서에서 일치하며, 인용 URL·상대 링크·코드펜스·BOM 점검이 모두 통과한다.

남은 것은 문서 결함이 아니라 성격이 다른 두 가지다.

1. **M0 실행으로만 얻을 수 있는 값** — native payload bytes, `systemMessage` 실제 렌더링(T20), 훅 선언 timeout, Codex/Claude 버전별 fault 동작. 문서에는 "무엇을 측정할지"까지 고정돼 있고 "측정값"만 비어 있다.
2. **사용자 결정 1건** — 저장소 자체 라이선스(F절).

따라서 다음 단계는 **M0 tracer-bullet 구현 착수**이며, 문서 측 선행 작업은 없다.

## I. 구현 프롬프트 검증 (2026-07-26)

`docs/user-prompt.md`·`docs/system-prompt.md`를 정본 5개 축(decisions, use-cases, report-template, workflow+proposal, 루트/리뷰)과 각각 독립 대조하고, 발견마다 별도 검증자가 현재 파일 bytes로 반박을 시도하는 2단계 검증을 수행했다(finder 6 + verifier 5, 총 11 에이전트).

**완결성:** 12개 파이프라인 항목(정본 읽기 순서 → 시작 전 조사 → runtime 선택 → M0 → M1 계약 → 코어/설치/scan/공개 구현 → 7종 검증 → 완료 게이트 → 최종 보고 → 금지사항 → 부트스트랩 → 자율 실행)이 전부 “명시됨”으로 판정됐다. user-prompt 복사 블록은 467자로 §7.2의 1,500자 제한을 충족하고, 참조 경로는 모두 실존한다.

**확정된 결함과 수정 (전부 system-prompt.md, 반영 완료):**

| # | 결함 | 수정 |
|---|------|------|
| 1 | §6.6 “control bytes를 그대로 보존·반환” — A1-Y 복원 불변식 및 자체 §3과 자기모순 | secret literal / 제어문자 변환 분리로 재서술 |
| 2 | §6.6 “literal-all 검증… 제품 출력 계약은 raw bytes 유지” — 복원 이전 전제 | 변환 후 bytes 기준 대조·이중 fixture로 교체 |
| 3 | §7.2 “display-safe 과거 후보가 남지 않음” 검사 — 그대로 실행하면 복원된 계약을 제거 대상으로 오판(A1-Y 회귀 재발 경로) | secret redaction 잔재만 검사, `display_safe_reference`·`control_escape`는 보호 대상으로 명시 |
| 4 | §7.5 “control bytes byte-for-byte 동일” oracle — 정본 준수 구현이 반드시 실패 | secret span 동일 + 제어문자 raw 방출 0으로 분리 |
| 5 | §1 “NO-GO는 작업 목록” — D12의 ‘허용 작업은 M0뿐’·M0 후 재판정 관문 미기재 | M0 증거 체크인 → 리뷰 판정 갱신 후에만 M1 진입, 불일치 시 범위 축소·NO-GO 유지 명시 |
| 6 | §6.1 M0 목록 누락: T20 systemMessage 실측, hooks.json timeout, sandbox/approval control run, effective shell/cwd 결합, sibling hook 관찰(D12) | 5개 항목 추가 |
| 7 | §6.4 Codex `/hooks` 검토·신뢰 단계 누락(proposal §9.1) | 설치·업데이트 안내 항목 추가 |
| 8 | §3 라벨 literal `표시 안전 변환본`이 D7/D13의 `표시 안전 변환`과 상이 | 정본 위임으로 교체(개념 라벨은 D7, 사용자 라벨은 report-template §1.2) |
| 9 | §3 “C 목록(아직 반영되지 않은 항목)” + 리뷰 인덱스의 같은 구식 문구 | 반영 완료 기록으로 정정(양쪽) |
| 10 | §2 읽기 순서 vs 충돌 우선순위 모호, AGENTS.md “불확실하면 질문” 충돌 미해소 | 읽기 순서/우선순위 구분 명시, §4 자율 원칙이 해당 지침을 대체함을 명시 |

**반박되어 수정하지 않은 주장:** user-prompt의 “전체 구현·최종 검증 완료” 지시 자체(같은 문장의 게이트 통과 조건이 해소, #5 수정으로 근거 완성), §7.5 replay ‘payload 0’과 idempotent 재전송의 충돌(§7.4가 duplicate/replay 계약 테스트를 별도 보유), NO-GO 재해석 자체(정본도 작업 목록으로 서술).
