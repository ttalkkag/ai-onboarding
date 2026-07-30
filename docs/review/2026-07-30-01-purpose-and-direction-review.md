# 목적과 방향 리뷰 (2026-07-30)

> 상태: 리뷰 기록 (비계약 문서). 기준일 2026-07-30.
> 함께 읽기: `2026-07-30-00-project-overview.md`
> 파일명은 이번 작업 지시가 지정한 `YYYY-MM-DD-NN-주제` 형식을 따랐다. 기존 `docs/review/README.md` 인덱스 등록은 기존 문서 수정에 해당하므로 이번 작업에서 수행하지 않았고, `05` 문서의 즉시 조치 항목으로 남겼다.
> `Critical`/`High`/`Medium`/`Low`는 리뷰 findings 우선순위이며 제품 판정 등급 `HIGH`/`LOW`/`INFO`와 무관하다.

## 1. 문서에서 확인되는 공식 목적

| # | 목적 서술 | 근거 |
|---|---|---|
| P1 | Claude Code CLI·Codex CLI의 로컬 도구 호출을 실행 직전(`PreToolUse`)에 점검하는 **선택형** 가드레일 | `README.md:5-7`, `decisions.md` D0 |
| P2 | 판정은 `HIGH`(차단) / `LOW`(경고 후 계속) / `INFO`(기록만) 3등급이며 HIGH만 deny | `README.md:19-27`, `decisions.md` D4 |
| P3 | 결정론적 HIGH를 AI가 강등할 수 없다. AI에 의한 승격은 M2 이후 | `decisions.md` D5 |
| P4 | 사용자 영역에 1회 설치하고 프로젝트별로 활성화한다. 프로젝트별 제품 설치는 제공하지 않는다 | `decisions.md` D2, D13.1, `proposal.md` §9.1 |
| P5 | 관찰하지 못한 조합은 지원으로 표시하지 않는다(증거 없는 coverage 금지) | `decisions.md` D12, `docs/review/README.md` |
| P6 | M1 범위는 `npm 패키지 설치`·`로컬 파일 열기`·`명시적 읽기 전용 검사`의 fixture 기반 alpha. 그 밖은 `NOT_COVERED`로 통과시키고 성공으로 표시하지 않는다 | `README.md:54`, `decisions.md` D11, `use-cases.md` §3 |

(확실성: 확인됨 — 해당 문서 직접 확인)

## 2. 코드에서 추론되는 실제 목적

코드가 실제로 최적화하고 있는 대상은 "가드레일 제품"이 아니라 **한 번의 호환성 관찰을 위조 불가능하게 봉인하는 것**이다.

근거(모두 직접 확인):

1. **제품 기능은 feature 게이트 뒤에 있고 production 산출물은 비어 있다.** `src/lib.rs:1-25`는 `strict_json`을 제외한 12개 모듈 전부에 `#[cfg(feature = "m0-test-profile")]`를 붙인다. `Cargo.toml:8`의 `default = []`이므로 기본 빌드에는 포함되지 않는다. `src/bin/secure-onboard.rs`(36행)는 `use secure_onboard::` import가 하나도 없고 `probe-profile`/`components`에 상수 바이트만 출력한다.
2. **검증기가 코드베이스의 과반이다.** `m0_observation_matrix.rs`(1,914행) + `m0_status.rs`(1,442행) + `m0_fixture_manifest.rs`(671행) + `m0_status_harness.rs`(422행) = 4,449행으로 `src/` 8,160행의 약 54%다. 이 4개 모듈은 실행 경로에서 호출되지 않고 테스트만 소비한다.
3. **coverage 0이 코드 계약이다.** `m0_observation_matrix.rs:475-480`은 `verified_count != 0 || included_count != 0`이면 `Err(Contract)`를 반환한다. 관찰 결과를 "검증됨"으로 바꾸는 순간 라이브러리가 실패한다.
4. **제품 도메인 어휘가 타입으로 존재하지 않는다.** `CONTEXT.md`가 정의한 명령 출처 4종·짧은 ref·명령 준비/제공·검사 캐시·활성화 registry·`NOT_COVERED` 중 `src/`에 타입이 있는 것은 판정 등급(`Severity`)뿐이다. `m0.rs:64-74`의 `Invocation`은 `ShellText` 단일 variant이고, `m0.rs:387`은 `cache_status != "bypass"`이거나 `pending_action_ref`가 있으면 계약 위반으로 거부한다.
5. **관찰 스냅샷이 소스에 고정되어 있다.** `m0_observation_matrix.rs:1010-1015`는 `assessed_at == "2026-07-29"`, `host.os == "macos"`, `os_version == "26.5.2"`, `os_build == "25F84"`, `architecture == "arm64"`를 등호 비교한다. `m0_adapter.rs:269-273`은 클라이언트 버전·OS·아키텍처를, `bin/secure-onboard-m0-hook.rs:31-33`은 Node 버전과 셸 sha256을 상수로 담는다.

즉 코드가 표현하는 목적은 **"2026-07-29 macOS 26.5.2 arm64 호스트에서 Claude 2.1.220 / Codex 0.146.0을 상대로 수행한 46×2 관찰이 이후에도 그대로 재현·검증되도록 잠근다"**이다. 이는 문서가 선언한 방향(M0 tracer-bullet, 증거 없는 주장 금지)과 **모순되지 않는다** — 오히려 문서의 규율을 코드로 강제한 결과다. 다만 문서가 서술하는 "제품 구조"(rules/cache/log 계층, 명령 출처, 활성화 registry)는 코드에 아직 존재하지 않는다.

## 3. 주요 사용자와 사용 시나리오

| 시나리오 | 문서 정의 | 현재 코드로 가능한지 |
|---|---|---|
| (a) 사용자가 구체적 명령 실행을 요청 | `proposal.md` §5.1, `workflow.md` §1 | sentinel 4토큰 명령에 한해 Claude 경로에서만 가능 (`m0_profile.rs:487-509`가 그 외 문법 전면 거부) |
| (b) 사용자가 의도만 말하고 AI가 명령을 만든다 | `proposal.md` §5.2 | 불가 — action kind·명령 정규화가 없음 |
| (c) HIGH 차단 후 재확인 → 명령 텍스트 제공 | `proposal.md` §5.3, `decisions.md` D8 | 불가 — pending 저장소·재확인 채널 없음 |
| (d) 명시적 읽기 전용 검사 | `use-cases.md` §5 | 불가 — scan 경로 미구현 |

(확실성: 확인됨 — 코드 측 부재는 해당 타입·상수를 직접 확인)

## 4. 핵심 가치

문서 기준 핵심 가치는 "비전문 사용자가 AI에게 위임한 실행을, 실행 직전에 결정론적으로 한 번 막아준다"이다. 현재 코드가 실제로 제공하는 가치는 그 가치의 **전제 조건 검증**이다: 두 CLI의 훅 경계가 (1) 실행을 실제로 차단할 수 있는지, (2) 결과를 신뢰할 수 있는지, (3) 무엇을 관찰할 수 없는지를 증거와 함께 확정했다. `docs/review/README.md`는 이 결과로 M1을 NO-GO 처리했다.

이 판단은 프로젝트 목적에 **부합한다**. 관찰 결과가 부정적일 때 제품을 진행하지 않는 것이 P5(증거 없는 지원 표시 금지)의 직접적 귀결이다.

## 5. 현재 범위와 제외 범위

| 구분 | 내용 | 근거 |
|---|---|---|
| 현재 구현 범위 | Claude `UserPromptSubmit`/`PreToolUse`/`PostToolUse`/`PostToolUseFailure`/`Stop` 훅 어댑터, sentinel 판정, fail-closed, 상관·증거 기록, 프로필·파일 무결성, 46×2 관찰 행렬과 상태 보고서 검증 | `src/**`, `tests/**` |
| 의도적 제외 (문서) | Finder·OS GUI 실행, 일반 터미널 명령, 다른 IDE·에이전트, 관리자 강제 통제·중앙 감사, DLP, 동적 sandbox·detonation | `decisions.md:24-27`, `proposal.md` §3·§4.3 |
| 사실상 제외 (코드) | Codex의 실질 판정(항상 중립), Codex 결과 처리(항상 거부), Windows·Linux, 실제 위험 규칙, 캐시, 배포·설치 | `native.rs:273-274,295-296`, `m0_adapter.rs:272-273` |

## 6. 현재 구현이 향하는 방향

- 단기(문서 기준): M0 관찰 결과를 근거로 M1 native 경계를 닫거나 지원 범위를 축소한 뒤에야 M1 계약을 잠근다(`decisions.md:256`).
- 단기(코드 기준): M1 진입은 **라이브러리 수정을 선행 조건으로 갖는다.** `m0_observation_matrix.rs:475-480`의 coverage 0 강제, `m0_status.rs:1210-1234`의 T19 케이스별 기대값 하드코딩, `m0_adapter.rs:269-273`의 버전 등호 비교를 모두 손대야 한다. 이 선행 조건은 어떤 문서에도 기록되어 있지 않다. (코드: 확인됨 / 영향: 추론)
- 장기(문서 기준): M2 심층 분석 → M3 배포(Windows·macOS 패키징) → M4 평판 데이터(`proposal.md` §12).

## 7. 문서와 코드의 방향 일치 여부

| 항목 | 문서상 정의 | 코드상 확인 결과 | 일치 여부 | 평가 |
|---|---|---|---|---|
| 해결하려는 문제 | 비전문 사용자의 무검토 설치·실행 사고 방지 (`proposal.md` §1) | 문제 해결 로직 없음. 훅 경계 관측 가능성만 확정 (`src/m0.rs`는 sentinel→등급 1:1 표) | 방향 일치, 구현 미도달 | 대체로 적절 (M0 선언과 부합) |
| 주요 사용자 | AI 도구를 쓰는 비전문 내부 사용자 (`proposal.md` §1) | 실사용자는 관찰 실험 실행자. 하네스·manifest가 개인 홈 절대 경로에 결속 (`tests/fixtures/m0/manifests/*.json`) | 현 단계 한정 불일치 | 대체로 적절 |
| 핵심 기능 | 실행 직전 HIGH 차단 + 결과 기록 + 캐시 + 활성화 registry (`README.md`, `report-template.md` §9-§10) | HIGH 차단·결과 상관은 있음. 캐시는 상수 `"bypass"`, 활성화 registry·상태 수집기는 없음 (`m0.rs:387`, `m0_status.rs`는 검증만) | 부분 불일치 | 부분적으로 부적절 |
| 운영 방식 | 사용자 영역 1회 설치 + 프로젝트 활성화, 30일/1,000건 보존, 원자적 쓰기 (`decisions.md` D9, `report-template.md:1489-1492`) | 설치 산출물·보존·정리 코드 없음. 증거는 내용 주소 파일로 누적 | 불일치 | 부분적으로 부적절 |
| 확장 방향 | M1 → M2 → M3 → M4 단계 확장 (`proposal.md` §12) | 확장 지점이 `src/`의 리터럴 테이블에 고정되어 각 단계가 라이브러리 수정을 요구 | 방향 일치, 구조적 마찰 존재 | 부분적으로 부적절 |

## 8. 불명확하거나 충돌하는 방향

### [High] README의 M0 Windows 검증 주장이 다른 근거와 충돌한다

- 관련 문서: `README.md:54` — "M0에서는 고정 sentinel만으로 Windows·macOS의 Claude Code CLI와 Codex CLI hook 경계를 검증한다".
- 반대 근거: `src/m0_observation_matrix.rs:1012-1015`가 `host.os == "macos"`, `os_version == "26.5.2"`, `os_build == "25F84"`를 등호 검사한다. `src/m0_adapter.rs:272-273`은 `expected_os: "macos"`, `expected_architecture: "arm64"`다. 체크인된 관찰 파일은 `tests/fixtures/m0/observations/macos-arm64.json` 하나뿐이고, `tests/m0_checked_host_manifests.rs:2`와 `tests/m0_fixture_manifest_generator.rs:2`는 `#![cfg(all(target_os = "macos", target_arch = "aarch64"))]`로 macOS arm64에서만 컴파일된다.
- 영향: 저장소에서 가장 먼저 읽히는 문서가 미검증 플랫폼을 완료형으로 서술한다. 이는 P5(증거 없는 지원 표시 금지)와 직접 충돌하며, 프로젝트 자신의 핵심 규율 위반 사례로 인용될 수 있다.
- 권장 조치: 해당 문장을 macOS arm64 단일 호스트 관찰로 축소하고, Windows는 M3 항목으로 표기.
- 확실성: 확인됨 (문서·코드 양쪽 직접 확인)

### [High] M1 진입의 코드 선행 조건이 문서화되어 있지 않다

- 관련 코드: `src/m0_observation_matrix.rs:475-480`, `src/m0_status.rs:1210-1234`, `src/m0_adapter.rs:269-273`.
- 확인 내용: 관찰이 `Verified`가 되거나 coverage에 `Included`되면 검증기가 실패한다. T19 케이스별 기대 객체 수·이벤트 순서가 라이브러리 소스에 배열 리터럴로 있다.
- 문제점: 문서(`decisions.md` D12, `docs/review/README.md`)는 M1 blocker를 native 경계 관점으로만 열거하고, "M1을 시작하면 검증기 코드를 먼저 고쳐야 한다"는 사실을 남기지 않았다.
- 영향: 다음 담당자가 M1에 착수하면 이유를 모른 채 검증 실패를 만난다. 검증기를 우회하는 방향으로 손댈 위험이 있다.
- 권장 조치: `docs/review/README.md`의 M1 blocker 목록에 "검증기 coverage 0 강제 해제와 케이스 테이블 외부화"를 선행 작업으로 추가.
- 확실성: 확인됨(코드) / 추론(다음 담당자 영향)

### [Medium] Codex는 문서상 지원 클라이언트지만 코드상 상시 중립이다

- 관련 코드: `src/native.rs:273-274`가 `CwdBinding::UnsupportedPerCallWorkdir`를 하드코딩하고, `src/m0_adapter.rs:303-305`가 cwd 미검증이면 즉시 중립 응답을 반환한다. `src/native.rs:295-296`은 Codex `PostToolUse`를 무조건 거부한다.
- 문서 대조: `README.md`와 `docs/review/README.md`는 "Codex는 effective cwd와 result outcome을 신뢰할 수 없어 제외"라고 서술한다 — 이 부분은 일치한다.
- 남는 문제: `plugins/codex-m0/hooks/hooks.json`은 여전히 `PostToolUse` 훅을 등록한다. 매핑이 항상 실패하므로 훅 프로세스는 매번 실패로 종료된다(`src/bin/secure-onboard-m0-hook.rs:36-68`의 non-pre 경로).
- 영향: "제외"가 문서상 제외에 그치지 않고 실행 시 반복 오류로 나타난다.
- 확실성: 확인됨(코드·플러그인 정의) / 실제 CLI 표면 노출 형태는 추가 확인 필요

### [Medium] 사용자 프롬프트 단독 사용 시 게이트를 놓칠 수 있다

- 관련 문서: `docs/user-prompt.md`(7행)는 제품 범위 전체 구현과 최종 검증 완료를 지시하며 `AGENTS.md`·`docs/system-prompt.md` 선독에 의존한다. D12(착수 가능 작업은 M0뿐)는 `system-prompt.md`에만 있다.
- 영향: 프롬프트만 복사해 사용하는 경로에서 M1 무단 착수 유인이 남는다.
- 확실성: 확인됨(문서 구성) / 실제 오용 가능성은 추론

## 9. 프로젝트가 집중해야 할 핵심 영역

우선순위 근거는 "목적 달성에 필요한 최소 경로"다.

1. **관찰 결과를 다음 결정으로 전환하는 문서 갱신.** M1 blocker에 코드 선행 조건을 포함시키고, README의 Windows 문구를 실측 범위로 축소한다. 코드 변경 없이 신뢰도를 회복하는 유일한 항목이다.
2. **재현 절차 문서화.** 빌드·테스트 명령(feature 포함), 하네스 실행 조건, 증거 파일 위치를 활성 문서에 남긴다. 현재 이 정보는 `Cargo.toml`·`tests/**`·`.mjs`를 읽어야만 알 수 있다.
3. **검증기와 실행 경로의 분리 축 정리.** 케이스 테이블·호스트 값·coverage 정책을 데이터(fixture)로 옮겨 M1 진입 시 라이브러리 수정을 최소화한다.
4. **증거 보존 정책 확정.** 원문 payload를 영속하는 현재 구현과 문서의 보존·폐기 계약 사이 경계를 명시한다(상세는 `04` 문서).

M1 기능 구현(action kind, 캐시, registry)은 위 4개가 정리된 뒤의 작업이다. 현재 상태에서 기능부터 붙이면 검증기와 계약이 동시에 흔들린다.

## 10. 종합 평가

| 관점 | 등급 | 근거 |
|---|---|---|
| 목적과 방향의 명확성 | 적절 | D0-D13이 범위·비범위·비보장·우선순위를 성문화. 판정 3등급과 fail-closed가 코드에 그대로 반영 |
| 목적 대비 현재 구현의 정직성 | 적절 | coverage 0·M1 NO-GO를 문서와 코드가 함께 강제. 미검증을 성공으로 위장하는 경로를 찾지 못했다 |
| 목적 대비 구현 비중 | 부분적으로 부적절 | 검증기 약 54% 대 실행 경로 약 46%. 제품 규칙은 타입조차 없음 |
| 방향 전환(M1) 준비도 | 부분적으로 부적절 | 코드 선행 조건이 문서화되지 않았고 확장 지점이 소스 리터럴에 고정 |
| 사용자 관점 가치 전달 | 판단 보류 | 현재 사용자에게 제공되는 기능이 없다. M0 선언과는 모순되지 않으므로 결함으로 단정하지 않음 |

프로젝트 목적 자체는 임의로 하나로 확정할 필요가 없다. 문서와 코드는 **같은 목적의 서로 다른 단계**를 표현하고 있으며(문서=제품 목표, 코드=전제 검증), 이 관계가 문서에 명시되어 있다는 점이 이 저장소의 강점이다. 위험은 목적 불일치가 아니라 **단계 전환 비용이 문서에 기록되지 않았다는 점**이다.
