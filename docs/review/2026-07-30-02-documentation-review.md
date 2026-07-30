# 문서 리뷰 (2026-07-30)

> 상태: 리뷰 기록 (비계약 문서). 기준일 2026-07-30.
> 근거 표기 규칙: `직접 확인` = 이번 리뷰에서 해당 파일·라인을 읽어 대조함. `스카우트 보고(미검증)` = 병렬 조사 결과를 인용했으나 이번 리뷰에서 재확인하지 않음.
> `Critical`/`High`/`Medium`/`Low`는 리뷰 findings 우선순위이며 제품 판정 등급 `HIGH`/`LOW`/`INFO`와 무관하다.

## 1. 문서 목록과 역할

| 문서 | 행수 | 역할 | 계약 지위 |
|---|---|---|---|
| `README.md` | 68 | 제품 경계·판정표·구현 구조·상태 선언 | 활성 (검증 대상 11개 중 하나) |
| `CONTEXT.md` | 117 | 제품 용어집 | 활성 |
| `docs/system-prompt.md` | 326 | 자율 구현 시스템 프롬프트, 정본 읽기 순서·충돌 우선순위 | 활성 |
| `docs/user-prompt.md` | 7 | 실행 입력(1,500자 상한) | 활성 |
| `docs/plan/decisions.md` | 267 | 정책 정본 D0-D13 | 활성 (최우선 정본) |
| `docs/plan/proposal.md` | 277 | 기획서(문제·목표·범위·마일스톤) | 활성 |
| `docs/plan/workflow.md` | 275 | 상태 전이 정본 | 활성 |
| `docs/plan/report-template.md` | 1,499 | 필드·스키마·직렬화 정본 | 활성 |
| `docs/plan/use-cases.md` | 343 | 테스트 oracle 정본 | 활성 |
| `docs/review/README.md` | 144 | 게이트 판정·blocker·리뷰 인덱스 | 활성 |
| `docs/review/hook-contract-and-decisions.md` | 253 | 훅 공식문서 검증 기록·사용자 결정 원본 | 활성 |
| `docs/review/plan-research-review.md` | 394 | 과거 리뷰 (역사 배너) | 비계약 |
| `docs/review/core-reverse-engineering-review.md` | 291 | 과거 리뷰 | 비계약 |
| `docs/review/security-modules-review.md` | 240 | 과거 리뷰 | 비계약 |
| `docs/review/runtime-modules-review.md` | 204 | 과거 리뷰 | 비계약 |
| `docs/research/**` | — | 탐지 근거·후보 카탈로그 | 비계약 (자기 선언) |
| `docs/draft/**` | — | 폐기 설계·업스트림 참고 코퍼스 | 비계약 (자기 선언) |
| `AGENTS.md` / `CLAUDE.md` | 각 2,525바이트 | LLM 코딩 행동 지침 | 비계약 |

`docs/research/` + `docs/draft/`의 Markdown은 총 78개다(`find` 실측). 활성 문서 11개 목록은 `scripts/validate-docs:14-26`의 `ACTIVE_MARKDOWN`과 일치한다. (직접 확인)

## 2. 문서 구조 평가 — `대체로 적절`

강점(직접 확인):

- 4계층 구조가 명시적이다: 진입(`README`/`CONTEXT`) → 계약 정본(`docs/plan/`) → 판정·감사(`docs/review/`) → 비계약 자료(`docs/research/`, `docs/draft/`).
- 충돌 우선순위가 성문화되어 있다: `docs/system-prompt.md` §2가 `decisions.md` > `report-template.md`(필드) > `workflow.md`(전이) > `use-cases.md`(oracle) 순서를 정한다.
- 비계약 자료가 자기 선언 배너를 갖는다(`docs/research/README.md`, `docs/draft/README.md`, 과거 리뷰 4종 상단).
- **문서 계약이 기계로 강제된다.** `scripts/validate-docs`(1,018행)가 활성 11개 문서에 readiness marker, severity enum, 폐기 후보 어휘, 제어문자 정책 어휘, 프로젝트별 설치 주장 금지, 로컬 링크·앵커·경로 대소문자, `user-prompt` 1,500자, `report-template`의 M0 스키마 예제 key 집합을 검사하고, 저장소 전체 Markdown에 대해 fenced JSON 엄격 파싱(중복 키 거부)을 적용한다. `tests/docs_contract.rs`가 이 스크립트를 호출하고 문서 예제를 실제 Rust 타입으로 역직렬화한다.

약점: 동일 정책이 6-8개 문서에 산문으로 재서술된다(§6 참조). 문서 계약 검증은 특정 어휘 축만 덮고 플랫폼 지원 주장·문서 기준일·수치 서술은 사람 검토에 의존한다.

## 3. 정확성 평가 — `부분적으로 부적절`

기계 검증은 통과하지만(§04 문서 §4의 `validate-docs` 결과), 검증기가 덮지 않는 축에서 실측과 다른 서술이 남아 있다. 아래 §5·§7의 High 2건과 Medium 3건이 근거다.

정확한 것으로 확인된 주장(반증 없음, 직접 확인):

- "46 case × 2 client = 92 cell" ↔ `src/m0_observation_matrix.rs:12`의 `M0_CASE_IDS: [&str; 46]`.
- "verified=0, coverage included=0" ↔ 같은 파일 `:475-480`이 0이 아니면 실패시킨다.
- "production 빌드에 test profile 파서·규칙·상태 생성기가 없다" ↔ `src/bin/secure-onboard.rs`가 상수 2종만 출력하고 `tests/production_negative.rs`·`tests/production_artifact_contract.rs`가 이를 검사한다.
- "Codex 0.146.0은 success와 failure가 모두 `tool_response=""`" ↔ `tests/fixtures/m0/native/codex-0.146.0-macos-arm64-post-{success,failure}.json`, `decisions.md:86`. (fixture 파일 존재와 코드의 거부 분기는 직접 확인. 두 fixture의 바이트 동일성은 스카우트 보고(미검증))
- "hook timeout 5초" ↔ `plugins/*/hooks/hooks.json`의 `"timeout": 5`.

## 4. 완전성 평가 — `부분적으로 부적절`

| 항목 | 상태 | 근거 |
|---|---|---|
| 제품 개념·도메인 설명 | 충분 | `CONTEXT.md`, `decisions.md`, `proposal.md` |
| 제약·비보장 명시 | 충분 | `decisions.md` D1, `proposal.md` §3, 여러 문서의 fail-open 한계 서술 |
| 판정·필드·상태 전이 계약 | 충분(과할 정도로 상세) | `report-template.md` 1,499행 |
| 테스트 oracle | 충분 | `use-cases.md` |
| **설치 방법** | 없음 | 설치 스크립트·패키징 산출물이 저장소에 없다(`scripts/`에는 `validate-docs`, `generate-m0-fixture-manifests` 2개뿐) |
| **빌드·테스트·검증 실행 방법** | 없음 | 활성 문서 어디에도 `cargo`, `m0-test-profile`, `python3 scripts/validate-docs`, 하네스 실행 절차가 없다 |
| **증거 재현 절차** | 없음 | 관찰 행렬·harness summary 파일 경로가 문서에 없다 |
| 외부 의존성 설명 | 부분 | 지원 CLI 버전은 문서화. Node 버전·셸 지문·OS build 고정은 문서에 없다 |
| 운영·장애 대응 | 없음 | 현 단계(M0)에서는 과도한 요구가 아니므로 결함으로 분류하지 않되, 설치 문서 부재와 함께 §8에 기록 |

## 5. 코드와 문서의 불일치

### [High] README의 M0 Windows 검증 주장이 실측 범위를 넘는다

- 관련 문서: `README.md:54`
- 관련 코드: `src/m0_observation_matrix.rs:1012-1015`, `src/m0_adapter.rs:272-273`, `tests/m0_checked_host_manifests.rs:2`, `tests/fixtures/m0/observations/macos-arm64.json`
- 확인 내용: README는 "M0에서는 고정 sentinel만으로 Windows·macOS의 Claude Code CLI와 Codex CLI hook 경계를 검증한다"고 쓴다. 코드는 `host.os == "macos"`, `os_version == "26.5.2"`, `os_build == "25F84"`, `architecture == "arm64"`를 등호 검사하고, 관찰 파일은 macOS arm64 1종뿐이다.
- 문제점: 가장 먼저 읽히는 문서가 미검증 플랫폼을 완료형으로 서술한다.
- 프로젝트에 미치는 영향: "증거 없는 조합은 지원으로 표시하지 않는다"는 자체 원칙(D12)과 충돌해 문서 전체의 신뢰도를 떨어뜨린다. `validate-docs`도 이 문장을 잡지 못한다.
- 권장 조치: 문장을 macOS arm64 단일 호스트 관찰로 축소. Windows는 M3 항목으로 명시.
- 확실성: 확인됨 (직접 확인)

### [High] 빌드·테스트·재현 절차가 어떤 활성 문서에도 없다

- 관련 문서: `README.md`, `docs/**` 전체
- 관련 코드·설정: `Cargo.toml:7-9`(`default = []`, `m0-test-profile`), `Cargo.toml:29-39`(m0 바이너리의 `required-features`), `tests/**`의 14개 파일 첫 줄 `#![cfg(feature = "m0-test-profile")]`, `scripts/validate-docs`
- 확인 내용: 기본 `cargo test`는 5개 테스트만 실행한다(`cargo test -- --list` 실측: `plugin_manifest_contract` 2개, `production_artifact_contract` 1개, `production_negative` 2개). 나머지 핵심 계약 테스트는 `--features m0-test-profile` 없이는 컴파일조차 되지 않는다. 이 사실이 문서에 없다.
- 문제점: 신규 담당자가 기본 명령으로 "전부 통과"를 보고 회귀를 놓칠 수 있다. `.claude/hookify.require-tests.local.md:23`의 Rust 안내도 `cargo test`뿐이고 규칙 자체가 `enabled: false`다.
- 프로젝트에 미치는 영향: GO/NO-GO 판정 전체가 이 테스트·증거에 의존하는데 제3자 재현 경로가 없다. 인수인계·운영 위험.
- 권장 조치: `README.md`(또는 신설 `docs/development.md`)에 (1) `cargo test --locked --offline --features m0-test-profile`, (2) `python3 scripts/validate-docs`, (3) 하네스 실행 전제(macOS arm64, 로컬 CLI 경로, 환경 변수), (4) 관찰 증거 파일 경로를 기록.
- 확실성: 확인됨 (직접 확인)

### [Medium] `hook-contract-and-decisions.md`의 저장소 위생 "해결" 표기가 실제 상태를 앞선다

- 관련 문서: `docs/review/hook-contract-and-decisions.md:202` — "`.gitignore` 부재 → 해결. 작업 트리의 `.DS_Store`가 `git add -A` 한 번으로 커밋될 수 있었다. `.gitignore`를 추가했다."
- 관련 설정: `.gitignore`(5행: `/target/`, `/dist/`, `/.secure-onboard-test/`, `__pycache__/`, `*.py[cod]`)
- 확인 내용: `.DS_Store` 패턴이 없다. 작업 트리에 `./.DS_Store`, `docs/.DS_Store`, `docs/draft/.DS_Store` 3개가 존재한다(`find` 실측).
- 문제점: 해결 표기가 남아 있어 재점검 유인이 사라진다.
- 영향: 실수 커밋 가능성이 유지된다. 영향 범위는 작지만 이 문서가 "현재 리뷰"로 색인되어 있어 오해 소지가 있다.
- 권장 조치: `.gitignore`에 `.DS_Store`(및 `.tmp*`, §03 문서 참조) 추가 후 해당 문장을 실제 상태로 정정.
- 확실성: 확인됨 (직접 확인)

### [Medium] `decisions.md` 기준일이 본문 근거보다 이르다

- 관련 문서: `docs/plan/decisions.md:6` — `기준일: 2026-07-26`
- 확인 내용: 같은 문서 `:86`은 "Codex CLI 0.146.0에서는 success와 exit 23 failure가 모두 `tool_response=""`로 관찰됐으므로"를, `:256`은 "M0 결과로 native fixture와 46 case × 2 client coverage matrix를 만들었지만 `verified=0`"을 인용한다. 이 실측은 `src/m0_observation_matrix.rs:1011`이 `assessed_at == "2026-07-29"`로 고정한 관찰이다.
- 문제점: 헤더 기준일과 본문 근거 시점이 어긋나 최신성 판단이 흐려진다. `proposal.md`·`docs/review/README.md`는 2026-07-29 기준이다.
- 영향: 정본 우선순위 1위 문서의 최신성이 불명확해진다.
- 권장 조치: 기준일을 본문이 인용하는 실측일로 갱신.
- 확실성: 확인됨 (직접 확인)

### [Medium] `docs/research/README.md` R5가 이미 확정된 결정을 미결로 남긴다

- 관련 문서: `docs/research/README.md:38` — "실제 프로젝트별 plugin/package 설치까지 제공할지는 M1 전 사용자 확인 사항이다."
- 반대 근거: `docs/plan/decisions.md:49` — "실제 프로젝트별 package/plugin 설치는 제공하지 않으며 실행 코드와 상태를 대상 저장소에 체크인하지 않는다." `docs/plan/proposal.md:214`도 동일.
- 문제점: research가 비계약임을 선언하고 `validate-docs`의 프로젝트 설치 정책 검사도 활성 11개 문서에만 적용되므로 기계 검증에 걸리지 않는다. 미결 질문 형태로 남아 재논의를 유발할 수 있다.
- 권장 조치: R5 마지막 문장을 "D2에서 미제공으로 확정"으로 갱신하거나 결정 링크를 추가.
- 확실성: 확인됨 (직접 확인)

### [Medium] `hook-contract-and-decisions.md` E절의 이벤트 수치가 낡았다

- 관련 문서: `docs/review/hook-contract-and-decisions.md:196` — "`decisions.md` D9 필수 이벤트 ↔ `report-template.md` §8 이벤트 표 | 17개 전부 일치"
- 확인 내용: 현재 `decisions.md` D9 절에서 backtick으로 표기된 이벤트 이름은 20종이다(`scope_enabled`, `scope_disabled`, `protection_status_unknown`, `scan_started`, `scan_reported`, `cache_hit`, `cache_miss`, `coverage_not_supported`, `allowed_info`, `warned_low`, `high_detected`, `high_blocked`, `user_reconfirmed`, `high_command_prepared`, `high_command_response_verified`, `high_command_closed`, `tool_completed`, `tool_failed`, `ingress_conflict`, `orphan_result`).
- 문제점: 계약 자체가 깨진 것은 아니고 **감사 기록의 수치가 낡았다**. 이 문서는 활성 문서이자 "현재 리뷰"로 색인된다.
- 영향: 감사 기록을 근거로 재검증할 때 잘못된 기준값을 재사용할 위험.
- 권장 조치: 수치를 현재 값으로 갱신하거나 "당시 기준" 표기 추가.
- 확실성: D9의 20종은 확인됨. `report-template.md` §8 표의 현재 행수 일치 여부는 스카우트 보고(20개, 미검증).

### [Low] `.claude/hookify.sync-docs.local.md`가 존재하지 않는 경로를 지시한다

- 관련 파일: `.claude/hookify.sync-docs.local.md:20-21` — `docs/plans/`, `docs/report.md`
- 확인 내용: 실제 경로는 `docs/plan/`이고 `docs/report.md`는 없다. 규칙은 `enabled: false`(:3)다.
- 영향: 즉시 영향 없음. 활성화 시 잘못된 안내.
- 확실성: 확인됨 (직접 확인)

## 6. 중복되거나 충돌하는 문서

| # | 내용 | 근거 | 등급 |
|---|---|---|---|
| 1 | `AGENTS.md`와 `CLAUDE.md`가 바이트 단위로 동일하다(각 2,525바이트, `cmp -s` 일치). `docs/user-prompt.md`는 `AGENTS.md`만 지목한다. | 직접 확인 | Medium |
| 2 | 동일 정책이 활성 6-8개 문서에 산문으로 재서술된다(예: 비밀 처리와 제어문자 안전 변환 규칙). 실제 회귀 이력이 문서에 남아 있다 — `hook-contract-and-decisions.md` A1-Y는 한 세션이 정책 1건을 바꾸다 다른 정책을 6개 문서에서 함께 제거한 사고를 기록한다. 현재 `validate-docs`의 제어문자 정책 검사만 이 축을 방어한다. | 스카우트 보고(문서 위치)·`validate-docs` 존재는 직접 확인 | Medium |
| 3 | `CONTEXT.md`만 상태·기준일 헤더가 없다. 다른 정본은 모두 헤더를 갖는다. | 직접 확인 (`CONTEXT.md:1-4`) | Low |
| 4 | 훅 정의가 배포본(`plugins/*/hooks/hooks.json`)과 하네스 합성 정의(`run-adapter-fault-observations.mjs`, `run-prompt-observations.mjs`)에 각각 존재하고 실행 형태가 다르다. 어느 쪽이 계약인지 문서에 없다. | 스카우트 보고(미검증). `.codex/hooks.json` 복사 경로와 `plugins = false` 설정은 직접 확인 | Medium |

## 7. 오래되었을 가능성이 있는 문서

- `docs/review/hook-contract-and-decisions.md`: 2026-07-26 기준. E절 수치(§5)와 F절 위생 주장(§5)이 현재 상태와 어긋난다. 그런데 `docs/review/README.md`에서 "현재 리뷰"로 색인된다. → **역사 문서로 재분류하거나 갱신** 필요.
- `docs/plan/decisions.md`: 헤더 기준일이 본문 근거보다 이르다(§5).
- `docs/research/README.md` R5: 확정된 결정을 미결로 표기(§5).
- 과거 리뷰 4종(`plan-research-review`, `core-reverse-engineering-review`, `security-modules-review`, `runtime-modules-review`): 상단 역사 배너가 있어 지위는 명확하다. 문제 없음.

## 8. 부족한 문서

프로젝트 목적과 현재 단계에 실제로 필요한 것만 제안한다.

| 제안 | 이유 | 필요성 |
|---|---|---|
| 개발·재현 문서 1개 (`docs/development.md` 또는 README 절 추가) | 빌드/테스트/문서검증/하네스 실행/증거 경로가 어디에도 없음. GO/NO-GO 판정이 이 증거에 의존 | 높음 |
| M1 착수 선행 조건 목록 보강 (`docs/review/README.md`의 blocker 절) | coverage 0 강제 해제와 케이스 테이블 외부화가 코드 선행 조건인데 미기록 | 높음 |
| 증거 보존·정리 정책 절 (`decisions.md` D9 보강) | M0 증거가 원문 payload를 영속하는데 보존·삭제 계약과의 관계가 미기술 (§04 문서 참조) | 중간 |

다음 문서는 **제안하지 않는다**: 아키텍처 개요 문서(이미 `README.md` + `report-template.md`로 충분), API 명세(외부 API 없음), 운영 런북(배포 대상이 없는 현 단계에서는 과도), ADR 디렉터리(`decisions.md`가 같은 역할을 이미 수행).

## 9. 삭제 또는 보관을 검토할 문서

- `CLAUDE.md`: `AGENTS.md`와 동일 내용. 한쪽만 수정되면 조용히 갈라진다. 심볼릭 링크화 또는 한쪽을 포인터 문서로 축소하는 방안 검토. (판단: Medium, 단 도구 호환성 요구가 있을 수 있어 삭제 전 확인 필요)
- `docs/draft/**`(reverse-skill 코퍼스 다수): 지위·사용 금지 규칙이 `docs/draft/README.md`에 명확하므로 즉시 삭제 필요는 없다. 다만 저장소 자체 LICENSE가 없고 `docs/draft/reverse-skill/LICENSE`(업스트림)만 존재하므로, 공개 전 provenance 정리는 문서가 이미 지적한 대로 유효한 미결 항목이다. (LICENSE 파일 위치: 스카우트 보고(미검증))

## 10. 권장 문서 구조

현재 구조를 크게 바꿀 필요는 없다. 다음 3개 변경만 권장한다.

1. `docs/review/hook-contract-and-decisions.md`를 "현재 리뷰"에서 "역사 기록"으로 이동하거나 E·F절을 갱신한다.
2. 개발·재현 절차를 활성 문서 1곳에 추가하고, `scripts/validate-docs`의 `ACTIVE_MARKDOWN`에 포함시켜 링크·경로 검증 대상으로 만든다.
3. `CONTEXT.md`에 다른 정본과 동일한 상태·기준일 헤더를 추가한다.

새 디렉터리 신설이나 문서 대량 추가는 권장하지 않는다. 현재 문서량(활성 11개, 3,700여 행)은 이미 프로젝트 규모 대비 큰 편이며, 중복 서술이 회귀 사고를 만든 이력이 있다.

## 11. 문서 개선 우선순위

| 순서 | 등급 | 항목 | 근거 | 난이도 |
|---|---|---|---|---|
| 1 | High | `README.md:54` Windows 문구 정정 | 자체 원칙 위반, 최상단 문서 | 낮음 |
| 2 | High | 개발·재현 문서 추가 | 재현·인수인계 불가 | 낮음 |
| 3 | High | M1 blocker에 코드 선행 조건 추가 | 다음 단계에서 검증 실패 발생 | 낮음 |
| 4 | Medium | `hook-contract-and-decisions.md` E·F절 갱신 또는 재분류 | 활성 문서의 낡은 수치·해결 표기 | 낮음 |
| 5 | Medium | `decisions.md` 기준일 갱신 | 정본 최신성 | 낮음 |
| 6 | Medium | `research/README.md` R5 정정 | 확정 결정과 충돌 | 낮음 |
| 7 | Medium | `CLAUDE.md` 중복 해소 | 드리프트 위험 | 낮음 |
| 8 | Low | `CONTEXT.md` 헤더 추가, hookify 규칙 경로 정정 | 일관성 | 낮음 |
