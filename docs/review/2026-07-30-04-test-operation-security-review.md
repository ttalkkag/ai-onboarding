# 테스트·운영·보안 리뷰 (2026-07-30)

> 상태: 리뷰 기록 (비계약 문서). 기준일 2026-07-30.
> `Critical`/`High`/`Medium`/`Low`는 리뷰 findings 우선순위이며 제품 판정 등급 `HIGH`/`LOW`/`INFO`와 무관하다.
> 근거 표기: `확인됨` = 직접 읽거나 명령으로 실측. `추론` = 확인된 근거로 판단. `추가 확인 필요` = 저장소만으로 판정 불가.

## 1. 테스트

### 1.1 구성

| 항목 | 값 | 근거 |
|---|---|---|
| 통합 테스트 파일 | 18개 / 7,380행 | `wc -l tests/*.rs` |
| `m0-test-profile` feature 게이트 파일 | 14개 (파일 첫 줄 `#![cfg(feature = "m0-test-profile")]`) | `grep` 실측 |
| 기본 feature에서 실행되는 테스트 | **5개** (`plugin_manifest_contract` 2, `production_artifact_contract` 1, `production_negative` 2) | `cargo test -- --list` 실측 |
| feature 포함 시 실행되는 테스트 | **159 passed / 2 ignored / 0 failed** | 아래 §4 실행 결과 |
| 기본 무시(ignored) 테스트 | 2개 | `#[ignore]` 실측 |
| 플랫폼 한정 테스트 | `m0_secure_fs_contract`(`unix`), `m0_checked_host_manifests`·`m0_fixture_manifest_generator`(`macos` + `aarch64`) | 파일 첫 줄 |
| 라이브 관찰 하네스 | `tests/native-harness/*.mjs` 5개 / 3,520행. `cargo test`가 호출하지 않음 | 파일 목록·`wc -l` |

### 1.2 핵심 기능의 테스트 여부 — `대체로 적절`

계약 테스트의 밀도는 프로젝트 규모 대비 높다. 확인된 방어 지점:

- 엄격 JSON: 중복 키, 미지 필드, nullable 키 부재, 후행 데이터 (`m0_contract_validation`, `native_adapter_contract`).
- 판정·이벤트 상관: 결정과 이벤트의 대응, 중복 배달, 병렬 out-of-order, 상관 충돌 (`m0_adapter_integration` 7개).
- 프로세스 격리: 타임아웃 상한, 대용량 stdin, 손자 프로세스 종료, spawn 실패는 폴백 불가 (`adapter_runtime_contract` 6개).
- 훅 프로세스 계약: fail-closed deny, 증거 preflight 실패, stdout 실패, 배달 충돌, 권한 (`m0_hook_cli` 7개).
- production 누출 방지: 별도 target에서 clean release 빌드 후 M0 문자열·fixture·바이너리 부재 검사 (`production_artifact_contract`).
- 문서 계약: `validate-docs` 호출 + 문서 JSON 예제를 실제 Rust 타입으로 역직렬화 (`docs_contract` 19개).
- 상태 보고서 스키마: 32개 케이스 (`m0_status_contract`).

### 1.3 누락된 주요 시나리오

| 누락 | 근거 | 등급 |
|---|---|---|
| Codex 어댑터의 종단 계약 | `m0_adapter_integration`·`m0_hook_cli`가 Claude 경로만 사용한다는 스카우트 보고(미검증). Codex는 payload 매핑 단위 테스트(`native_adapter_contract`)와 macOS 로컬 하네스로만 검증 | Medium |
| 실제 호스트 결속 검증 | `tests/m0_checked_host_manifests.rs:14` `#[ignore = "requires the exact pinned local Claude and Codex executables"]` (확인됨) | Medium |
| 최종 harness source 수용 검증 | `tests/m0_observation_matrix_contract.rs:585` `#[ignore = "requires five final native harness summary paths"]` (확인됨) | Medium |
| 비-Unix 프로세스 트리 종료 | `adapter_runtime`의 non-Unix 경로가 no-op이라는 스카우트 보고(미검증). Windows·Linux 호스트 미보유로 실행 불가 | Medium |
| `.hooks/*.sh` 5종 자체 테스트 | 해당 스크립트 이름을 참조하는 테스트가 없다는 스카우트 보고(미검증) | Low |
| 사설 저장소 경쟁 조건·하드링크 | `m0_secure_fs_contract`는 2개 테스트(권한·심볼릭 링크)만 실행(확인됨: 2 passed) | Medium |

**[Medium] 실제 호스트·최종 증거를 검증하는 두 테스트가 항상 무시된다.** 이 2개는 "체크인된 관찰이 지금 설치된 CLI와 실제 하네스 출력에 여전히 결속되는지"를 확인하는 유일한 경로다. 기본·CI 경로에서 실행되지 않으므로 일반 스위트는 체크인된 증거의 **내부 무결성**만 보장하고 **현실과의 일치**는 보장하지 않는다. `-- --include-ignored`와 필요한 환경 변수·경로를 문서에 남기는 것이 권장 조치다. (확실성: 확인됨 / 영향 판단은 추론)

### 1.4 테스트 실행 가능성 — `부분적으로 부적절`

**[High] 기본 `cargo test`가 핵심 계약을 실행하지 않는다.**
`Cargo.toml:8`의 `default = []`이고 14개 테스트 파일이 `m0-test-profile`을 요구하므로, 기본 명령은 5개만 실행한다(실측). 저장소에 CI가 없고(`.github/` 부재), `.claude/hookify.require-tests.local.md`는 `enabled: false`(:3)이며 안내 명령도 `cargo test`뿐(:23)이다. 어떤 활성 문서에도 feature 포함 명령이 없다. → 회귀가 "전부 통과"로 보일 수 있다. (확실성: 확인됨)

**[Medium] feature 포함 스위트가 기본(debug) 프로필에서 실용적이지 않다.**
`cargo test --locked --offline --features m0-test-profile`(debug)를 실행하면 `m0_observation_matrix_contract` 단일 바이너리가 100% CPU로 20분 이상 지속되어 이번 리뷰 시간 내 완주를 확인하지 못했다(클린 실행 1회 관찰 후 취소). 동일 스위트를 release 프로필로 실행하면 같은 바이너리가 93.38초, 전체가 109초에 끝난다(실측). `Cargo.toml`에는 `[profile.release]`만 있고 `[profile.dev]`/`[profile.test]` 최적화 설정이 없다(확인됨).

- 영향: 개발자가 기본 명령으로 스위트를 돌리기 어려워지고, 이는 §1.4 High(기본 명령이 핵심을 건너뜀)를 실질적으로 고착시킨다.
- 권장 조치: `[profile.test]`에 `opt-level = 2`(또는 `[profile.dev.package.sha2] opt-level = 3`)를 추가하거나, release 실행을 공식 검증 명령으로 문서화.
- 확실성: 확인됨(release 실측·debug 클린 실행 1회 미완주) / debug 지연의 정확한 원인(해시 비용 추정)은 추가 확인 필요

### 1.5 테스트 신뢰성과 요구사항 일치

- 대부분의 테스트가 관찰 가능한 계약(바이트, exit code, 파일 권한, 이벤트 순서)을 검증한다. 구현 세부에 결합된 테스트는 두드러지지 않았다.
- 다만 `tests/production_negative.rs` 2개는 production 바이너리가 출력하는 **상수를 상수와 비교**한다(`src/bin/secure-onboard.rs`가 리터럴만 출력하므로). 회귀 탐지력은 제한적이다. 실질 방어는 `production_artifact_contract`의 부정 계약이 담당한다. (확실성: 확인됨)
- `use-cases.md`의 케이스 ID와 실제 테스트 함수의 1:1 매핑은 이번 리뷰에서 전수 대조하지 않았다(추가 확인 필요).

## 2. 운영

### 2.1 환경별 설정 — `판단 보류`

배포 대상이 없으므로 dev/stage/prod 구분 자체가 성립하지 않는다. 현재 존재하는 "환경"은 (a) 기본 feature(production 스텁), (b) `m0-test-profile`(관찰용) 두 가지이며 이 구분은 `Cargo.toml`과 `src/lib.rs`로 명확히 강제된다.

### 2.2 빌드와 배포 — `부적절`

| 항목 | 상태 |
|---|---|
| 재현 가능한 빌드 | 부분적으로 가능. `Cargo.lock` 존재, `--locked --offline` 사용. 단 `rust-toolchain.toml`이 없어 툴체인 고정이 없다(확인됨) |
| CI/CD | 없음 (`.github/` 부재, 다른 CI 설정 파일도 발견하지 못함) |
| 설치·패키징 산출물 | 없음. `plugins/**`은 `bin/`이 없고 placeholder가 미치환 상태(확인됨) |
| 서명·SBOM·의존성 취약점 점검 | 없음 |
| 마이그레이션·롤백 | 대상 데이터 스토어가 없어 해당 없음 |

README가 M3(배포) 미구현을 명시하므로 현 단계 선언과 모순되지는 않는다. 다만 아래 Critical 항목은 단계와 무관한 위험이다.

### 2.3 [Critical] 프로젝트의 유일한 산출물이 버전 관리되지 않는다

- 확인 내용: `git ls-files | wc -l` = 111이고, 추적 대상은 전부 문서·에이전트 설정이다. `git status --porcelain` 기준으로 `Cargo.toml`, `Cargo.lock`, `src/`, `tests/`, `plugins/`, `scripts/`, `.gitignore`, `docs/system-prompt.md`, `docs/user-prompt.md`가 모두 **untracked**다. 아울러 추적 중인 문서 8개(`README.md`, `docs/plan/` 5개, `docs/review/` 2개)가 미커밋 수정(M) 상태이며, 그 mtime은 2026-07-29~30 새벽으로 이번 리뷰 이전에 이뤄진 변경이다(stat 실측). 최신 커밋은 `9d3f101 docs: 구현 계획 검토 및 정합성 보완`이다.
- 문제점: M0 관찰 증거(`tests/fixtures/m0/**`)와 그것을 검증하는 코드 전체가 이 작업 트리 한 곳에만 존재한다. 이 증거는 특정 호스트(macOS 26.5.2 arm64, Claude 2.1.220, Codex 0.146.0, Node v26.5.0)와 46×2 실행에 결속되어 있어 유실 시 동일하게 재생성하기 어렵다. 미커밋 수정 중인 추적 문서 8개의 최신 정본 변경분도 이력에 없다.
- 프로젝트 목적에 미치는 영향: GO/NO-GO 판정 전체가 이 증거에 근거한다. 유실되면 프로젝트의 핵심 자산과 판정 근거가 함께 사라진다. 또한 문서(`docs/review/README.md`)가 증거 경로를 인용하지만 그 경로는 저장소 이력에 존재하지 않아 제3자가 검증할 수 없다.
- 발생 가능성: 중간. 디스크 장애, 실수 삭제, 잘못된 정리 명령 한 번으로 충분하다.
- 수정 난이도: 낮음 — 로컬 커밋만으로 대부분 해소된다. `.hooks/block_git_origin_push.sh`가 `git push`를 차단하므로 원격 공개는 별도 결정 사항이지만, 로컬 커밋은 차단되지 않는다(확인됨).
- 선행 조건: `.gitignore`에 `.DS_Store`·`.tmp*` 추가(§03 참조)와 LICENSE·provenance 결정(문서가 이미 미결로 기록). 개인 절대 경로가 담긴 `tests/fixtures/m0/manifests/*.json`을 공개 이력에 넣을지 판단 필요.
- 조치하지 않을 때 예상 결과: 단일 지점 유실로 M0 결과 전체 재실행이 필요해지고, 그 재실행은 동일 호스트·동일 CLI 버전 확보에 의존한다.
- 확실성: 확인됨(사실) / 미커밋이 의도적인지는 추가 확인 필요

### 2.4 로그·모니터링·장애 대응 — `부적절`(단계 감안 시 `판단 보류`)

- 훅 실패 시 출력은 stderr 고정 한 줄 `Secure Onboard M0 hook failed`와 exit code뿐이다(`src/bin/secure-onboard-m0-hook.rs:36-68`, `map_err(|_| ())` 32회). 실패 원인을 구분할 수 없다.
- 증거·상태는 파일로 누적되며 보존·정리 코드를 찾지 못했다. 문서(`docs/plan/report-template.md:1489-1492`)는 종류별 30일 또는 최근 1,000건 보존과 pending 원문 10분 폐기를 규정한다 — 구현은 없다.
- 플러그인 훅이 고정 `--observed-at 2026-07-22T00:00:00Z`를 넘기므로 활동 기록에 시간 축이 없다(확인됨). 현재 데이터로는 보존 정책을 적용할 수 없다.
- 외부 서비스 의존이 없어 장애 전파 경로는 없다.

## 3. 보안

### 3.1 제품 코드 — `대체로 적절`

강점(확인됨):

- 입력 검증: stdin 1 MiB 상한, 엄격 JSON, `deny_unknown_fields`, 4토큰 ASCII 문법(셸 메타문자·제어문자 전면 거부).
- 명령 실행: 셸을 경유하지 않고 실행 파일 + 고정 인자. `env_clear`로 환경 차단. 별도 프로세스 그룹 + 그룹 종료.
- 파일 처리: 절대 물리 경로 요구, 경로 구성요소별 심볼릭 링크 거절, 소유자 UID·0700/0600 검사, `create_new`, `O_NOFOLLOW` 열기와 열기 전후 메타데이터 동등성 재확인.
- fail-closed: 판정 불가 시 허용이 아니라 차단. Spawn/IO 실패는 폴백 판정을 만들 수 없다.
- 응답 인코딩이 `allow`/`ask`/`continue:false`를 만들 수 없고 계약 테스트가 바이트 단위로 이를 고정한다.

### 3.2 [Medium] M0 증거가 원문 payload를 영속하는데 보존·폐기 경계가 문서에 없다

- 관련 경로: `src/bin/secure-onboard-m0-hook.rs`의 증거 기록 경로(내용 주소 `.bin` 파일), `tests/m0_hook_cli.rs`가 raw `native-input` 증거 존재를 계약으로 요구한다는 스카우트 보고(미검증).
- 대조 문서: `docs/plan/report-template.md:1489-1492`(보존 한도·원자적 쓰기·심볼릭 링크 비추종), `docs/plan/decisions.md` D9(활동 기록에 원문 명령·비밀·절대 경로 비저장).
- 확인 내용: 증거 저장 자체는 0700/0600 사설 디렉터리에 이뤄지고 파일명이 내용 해시다. 정리·보존 코드는 발견하지 못했다.
- 판단: 문서의 보존 정책은 **제품 활동 기록·캐시**를 대상으로 하고 M0 증거는 시험 산출물이므로 즉시 "정책 위반"으로 단정하지 않는다. 그러나 native payload에는 프롬프트·명령 원문·cwd·도구 응답이 포함될 수 있고, 이 tracer를 실제 세션에 붙이면 해당 내용이 기한 없이 남는다. 예외 여부·저장 위치·삭제 절차가 어디에도 기술되지 않은 것이 문제다.
- 권장 조치: `decisions.md` D9에 "M0 증거는 시험용 예외이며 위치·기본 비활성·삭제 방법은 다음과 같다"를 1개 문단으로 명시.
- 확실성: 코드의 증거 저장·권한 강제는 확인됨. raw 원문 포함 범위와 테스트 계약화는 스카우트 보고(미검증).

### 3.3 [High] 저장소에 커밋된 개발 환경 설정이 승인 우회와 광범위 네트워크 허용을 기본값으로 둔다

- 관련 경로:
  - `.claude/settings.json:34` `"defaultMode": "bypassPermissions"`, `:138` `"skipDangerousModePermissionPrompt": true`
  - `.codex/config.toml:137` `approval_policy = "never"`, `:499-507` `[permissions.workspace.network]` `enabled = true` + `[permissions.workspace.network.domains]` `"*" = "allow"`, `:192` `cli_auth_credentials_store = "file"`
- 완화 요소(확인됨): 같은 파일들에 비밀 파일 읽기 거부 목록이 있다(`.codex/config.toml:490-497`의 `**/.docker/config.json`, `**/credentials.json`, `**/.netrc`, `**/.npmrc`, `**/.git-credentials`, `**/.kube/config`, `**/.gnupg/**` 등). `.claude/settings.json`과 `.codex/hooks.json`이 `.hooks/*.sh` 5종을 `PreToolUse`에 등록한다.
- 문제점: 이 설정은 저장소를 여는 모든 기여자에게 적용된다. 방어 수단은 정규식 문자열 탐지 셸 스크립트(`.hooks/pre_tool_use_common.sh`가 `jq` → `tr` → `sed` → `grep -E`)이므로 의미상 동등한 우회(변수 조합, 인터프리터 경유, alias 등)를 포괄하지 못한다. 승인 프롬프트가 꺼진 상태에서 이 스크립트가 유일한 게이트다.
- 프로젝트 목적과의 관계: 이 프로젝트는 "AI가 위험한 로컬 실행을 하지 않도록 승인·차단하는 제품"이다. 그 제품의 저장소가 승인을 끄고 전 도메인 네트워크를 허용한다는 점은 설계 의도와 긴장 관계에 있다. 또한 제품 자신이 T17에서 "프로젝트 로컬 훅"을 사칭 위험으로 규정하는데(스카우트 보고, 미검증) 저장소는 `.codex/hooks.json`으로 그 레이어를 사용한다(파일 존재는 확인됨).
- 권장 조치: 이 설정이 제품 계약이 아니라 개발 편의 설정임을 `.claude/`·`.codex/` 안에 1행으로 명시하고, `bypassPermissions`를 개인 설정으로 옮길지 결정. 훅 스크립트를 보안 경계로 문서화하지 않는다.
- 확실성: 설정 값은 확인됨 / 실제 우회 성공 여부는 재현하지 않았으므로 추가 확인 필요

### 3.4 인증·인가, 데이터 접근 제어

- 제품에 사용자 인증·인가 개념이 없다. 접근 제어는 파일시스템 권한(소유자 UID + 0700/0600)으로만 구현되며 이는 로컬 단일 사용자 도구라는 설계와 일치한다. (확인됨)
- 하드코딩된 비밀은 발견하지 못했다. 코드에 있는 상수 해시는 셸·프로필 지문이며 비밀이 아니다. (확인됨)
- 민감 정보 로깅: 훅은 고정 문구만 stderr에 쓴다. 다만 §3.2의 증거 파일이 실질적인 민감 정보 저장소다.

### 3.5 위험한 기본 설정

| 항목 | 판단 |
|---|---|
| 제품 기본값 | 안전. 기본 feature에는 어떤 훅·판정 기능도 포함되지 않는다 |
| 개발 환경 기본값 | 위험 방향. §3.3 참조 |
| Codex 자격 증명 저장 | `cli_auth_credentials_store = "file"`은 OS 키체인보다 약한 기본값. 파일 권한은 이 저장소에서 검증하지 않는다(추가 확인 필요) |

## 4. 실행 검증 결과

| 검증 항목 | 실행 명령 | 결과 | 주요 내용 | 비고 |
|---|---|---|---|---|
| 의존성 확인 | `Cargo.lock` 존재 확인 + `--locked --offline` 사용 | 성공 | lockfile로 정확한 해석 고정. 별도 설치 절차 없음 | `rust-toolchain` 파일 없음 |
| 문서 계약 검증 | `python3 scripts/validate-docs --root .` | **성공** | `docs contract: ok (11 active Markdown files, 39 fenced JSON examples, 15 local links, user prompt 648/1500 characters)` | 1.15초 |
| 린트 | `cargo clippy --locked --offline --all-targets --all-features -- -D warnings` | **성공** | 경고 0 | 3.44초 |
| 타입 검사 | 별도 명령 없음 (Rust는 컴파일이 타입 검사) | 해당 없음 | 위 clippy·test 빌드가 대체 | — |
| 기본 테스트 | `cargo test --locked --offline` | **성공** | 5 passed (실행 대상이 5개뿐) | 22.24초 / 40.78초(2회) |
| 기본 테스트 목록 | `cargo test --locked --offline -- --list` | 성공 | 실행 대상 5개 이름 확인 | `plugin_manifest_contract` 2, `production_artifact_contract` 1, `production_negative` 2 |
| M0 스위트 (debug) | `cargo test --locked --offline --features m0-test-profile` | **미완주** | 클린 실행에서 `m0_observation_matrix_contract` 바이너리가 100% CPU로 20분 이상 지속. 취소함 | 환경 문제 아님. debug 프로필 성능 특성으로 판단(§1.4) |
| M0 스위트 (release) | `CARGO_TARGET_DIR=target/rel cargo test --locked --offline --release --features m0-test-profile` | **성공** | **159 passed / 0 failed / 2 ignored**. `m0_observation_matrix_contract` 93.38초, `production_artifact_contract` 8.47초, 전체 109초 | 무시된 2건: 실제 호스트 실행 파일 요구, 최종 harness summary 5경로 요구 |
| 릴리스 빌드 | `cargo build --locked --offline --release --no-default-features` | **성공** | production 산출물 빌드 확인 | 0.20초(캐시) |
| 문서 빌드 | 해당 없음 | — | 정적 사이트 생성기·문서 빌드 설정이 없다 | — |
| 설정 파일 유효성 | `.codex/config.toml`·`.claude/settings.json`·`plugins/**/*.json` 직접 확인 | 성공 | 구조·키 확인. 스키마 검증기는 저장소에 없음 | `validate-docs`가 문서 내 JSON 예제만 검증 |
| 심볼 참조 분석 | LSP(`rust-analyzer`) | **실패** | `rust-analyzer` 미설치 | 환경 문제. `grep`·직접 읽기로 대체 |
| 라이브 관찰 하네스 | `tests/native-harness/*.mjs` | **미실행** | 실제 Claude/Codex 프로세스와 개인 절대 경로·mock API를 요구. 외부 도구 실행은 이번 리뷰 범위 밖 | 의도적 미실행 |
| 배포 | 없음 | **미실행** | 배포 대상·스크립트가 없고, 작업 지시가 운영 배포를 금지 | — |

실행하지 못한 항목과 이유를 위 표에 모두 남겼다. 실패 2건 중 `rust-analyzer`는 환경 문제, M0 debug 스위트 미완주는 코드·설정 특성(debug 프로필 최적화 부재) 문제로 판단한다.

## 5. 영역별 종합 평가

| 영역 | 등급 | 근거 요약 |
|---|---|---|
| 테스트 구성·품질 | 대체로 적절 | 계약 밀도가 높고 release 기준 159개 전부 통과 |
| 테스트 실행 가능성 | 부분적으로 부적절 | 기본 명령이 5개만 실행, debug 스위트 실용성 낮음, CI 없음 |
| 테스트 커버리지 범위 | 부분적으로 부적절 | Codex 종단 경로·비-Unix·실제 호스트 결속이 비어 있거나 무시됨 |
| 빌드 재현성 | 대체로 적절 | lockfile + `--locked --offline`. 툴체인 고정 없음 |
| 배포·운영 | 부적절 | CI·설치·보존·모니터링 부재. 단계 선언과는 모순되지 않음 |
| 버전 관리·자산 보존 | 부적절 | 구현·증거 전체가 untracked (§2.3 Critical) |
| 제품 코드 보안 | 대체로 적절 | fail-closed·엄격 파싱·경로 검증. 증거 보존 경계 미기술 |
| 개발 환경 보안 | 부분적으로 부적절 | 승인 우회·전 도메인 허용이 커밋되어 있고 방어는 정규식 훅 |
| 관측 가능성 | 부적절 | 실패 원인 구분 불가, 시간 축 없음 |
