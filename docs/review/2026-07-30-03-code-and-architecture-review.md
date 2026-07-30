# 코드와 아키텍처 리뷰 (2026-07-30)

> 상태: 리뷰 기록 (비계약 문서). 기준일 2026-07-30.
> 근거 표기: `확인됨` = 이번 리뷰에서 해당 파일·라인을 직접 읽거나 명령으로 실측함. `추론` = 확인된 근거들로 판단했으나 명시적으로 확인되지 않음. `추가 확인 필요` = 저장소만으로 판단 불가.
> `Critical`/`High`/`Medium`/`Low`는 리뷰 findings 우선순위이며 제품 판정 등급 `HIGH`/`LOW`/`INFO`와 무관하다.

## 1. 현재 아키텍처 개요

저장소는 성격이 다른 두 덩어리로 나뉜다.

| 덩어리 | 구성 | 행수 | 소비자 |
|---|---|---|---|
| A. 훅 실행 경로 | `m0`, `contracts`, `native`, `m0_profile`, `m0_adapter`, `adapter_runtime`, `m0_secure_fs`, `m0_physical_file`, `strict_json` + 3개 bin | 약 3,686 | 실제 훅 프로세스 |
| B. 오프라인 검증기 | `m0_fixture_manifest`, `m0_observation_matrix`, `m0_status`, `m0_status_harness` | 4,449 | 테스트만 |

B가 A를 호출하지 않고 A도 B를 호출하지 않는다. B의 유일한 라이브러리 내부 연결은 `m0_observation_matrix` → `m0_fixture_manifest` 한 방향이다. 즉 이 저장소는 가드레일 제품이 아니라 **한 번의 호환성 관찰을 재현 가능하게 봉인한 증거 아카이브 + 그 관찰을 만든 훅 어댑터**다. (확인됨 — `wc -l` 실측 및 호출처 확인)

## 2. 주요 실행 흐름 (`pre` 모드)

1. `main`(`src/bin/secure-onboard-m0-hook.rs:36`)이 fail-closed 판단을 위해 argv를 먼저 훑는다(`is_pre_tool_mode`:72, `pre_tool_client`:76).
2. `run_pre`가 플래그를 파싱하고 stdin을 1 MiB 상한으로 읽는다. 식별자는 native payload sha256에 결속한다(`--id-binding native-sha256`).
3. `m0_adapter::handle_pre_tool_use`(`src/m0_adapter.rs:249-375`)가 순서대로 수행한다: native 매핑 → `HookEnvelope` 검증 → `load_profile`(digest·소유자·권한·헬퍼/셸/런타임 전수 검증) → cwd 미검증이면 즉시 중립 반환 → 4토큰 argv 정확 매칭 → `M0ActionRequest` 조립 → `run_core_child` → 실패 시 폴백 판정 → 응답 인코딩.
4. `run_core_child`(`src/adapter_runtime.rs:71`)가 `env_clear` + 별도 프로세스 그룹 + 3스레드 I/O + 데드라인으로 `secure-onboard-m0-core`를 실행한다. 코어는 `m0::evaluate`를 수행한다.
5. 증거 preflight → stdout 응답 → 증거 커밋 → `mark_delivered` 순서로 진행한다. 응답 전달에 실패하면 상관 정보를 배달하지 않는다.
6. 어댑터 오류 시 `main`이 아직 응답을 쓰지 않았다면 HIGH deny를 대신 출력하고 exit 0, 이미 썼다면 exit 2로 종료한다.

(확인됨)

## 3. 모듈 및 계층별 책임

| 계층 | 모듈 | 책임 | 판정 |
|---|---|---|---|
| 공통 | `strict_json` | 중복 키·후행 데이터 거부, canonical bytes/sha256 | 적절 (139행, 단일 책임) |
| 도메인 | `m0` | sentinel → severity/gate/event, fallback, 계약 검증 | 적절 (I/O 의존 0) |
| 도메인 경계 | `contracts` | `HookEnvelope` 정규화·검증 | 적절 |
| 어댑터 | `native` | 클라이언트 방언 매핑, 응답 인코딩 | 대체로 적절 (payload 구조체가 파일 절반) |
| 어댑터 | `m0_profile` | 프로필 로드, argv 정확 매칭 | 적절 |
| 어댑터 | `m0_adapter` | 오케스트레이션, 상관 저장소 | 부분적으로 부적절 (단일 함수 비대) |
| 인프라 | `adapter_runtime` | 자식 프로세스 격리·타임아웃 | 적절 |
| 인프라 | `m0_secure_fs`, `m0_physical_file` | 경로·권한·무결성 | 적절 |
| 검증기 | `m0_fixture_manifest`, `m0_observation_matrix`, `m0_status`, `m0_status_harness` | 증거·상태 전수 검증 | 부분적으로 부적절 (테스트 계획을 소스에 인코딩) |

## 4. 의존성 방향과 도메인·인프라 분리

- 의존은 단방향이고 순환이 없다: `bin` → `m0_adapter` → {`native`, `m0_profile`, `adapter_runtime`} → {`contracts`, `m0`} → `strict_json`, 인프라는 `m0_secure_fs`/`m0_physical_file`로 격리.
- `src/m0.rs`(515행)는 파일·프로세스·시계 의존이 없는 순수 규칙 계층이다. `tests/m0_core_contract.rs`와 `tests/m0_contract_validation.rs`가 이를 직접 검증한다.
- 인프라 관심사(0700/0600 강제, `O_NOFOLLOW` 열기, 프로세스 그룹 관리, 상한 있는 리더)가 전용 모듈에 모여 있다.

판정: `적절`. 현재 규모에 과하지 않고 도메인 순수성이 실제로 지켜진다. (확인됨)

## 5. 구조적 장점

1. **fail-closed가 타입 수준에서 강제된다.** `CoreChildError::fallback_failure`(`src/adapter_runtime.rs:59-68`)가 폴백 가능한 장애를 timeout/nonzero/schema로 한정하고 Spawn/Io는 `None`을 반환해 폴백 판정을 만들 수 없게 한다. `m0::fallback`은 항상 HIGH deny + `guardrail.scan_failure`를 만들고, `m0::validate_decision`(`:380-421`)의 화이트리스트가 그 외 조합을 계약 위반으로 거부한다. 조용한 허용 경로를 찾지 못했다.
2. **증거 기록이 2단계 프로토콜이다.** preflight → 응답 → 커밋 → `mark_delivered` 순서라 관찰 불가능한 결정이 durable 상태로 남지 않는다. 증거 파일명은 내용 주소(sha256)이며 같은 이름에 다른 내용이면 실패한다.
3. **자식 프로세스 관리가 견실하다.** `env_clear`, 프로세스 그룹 분리 후 그룹 단위 종료, 상한 있는 stdout/stderr 리더, 데드라인 폴링. 손자 프로세스가 파이프를 붙잡는 회귀를 실제 테스트가 방어한다(`tests/adapter_runtime_contract.rs`).
4. **엄격 파싱이 일관된다.** `strict_json::from_slice`가 중복 키와 후행 데이터를 거부하고, 도메인 구조체는 `deny_unknown_fields` + nullable 필드에 키 존재 강제(`required_nullable`)를 적용한다. 호스트 payload 변경이 조용히 통과하지 않는다.
5. **공격면을 좁힌 명령 문법.** `m0_profile`의 정확 4토큰 ASCII 매칭이 비-ASCII·제어문자·셸 메타문자를 전면 거부한다. M0 sentinel 목적에 정확히 맞는 선택이며, 범용 파서를 만들지 않은 판단이 옳다.
6. **production 누출 방지가 실제 부정 계약으로 존재한다.** `tests/production_artifact_contract.rs`는 별도 임시 target에서 `--locked --offline --release --no-default-features` 빌드를 수행하고 M0 문자열·fixture·바이너리 부재를 검사한다. 이는 상수 대조가 아닌 진짜 회귀 방어다.

(모두 확인됨)

## 6. 발견 사항

Critical 없음. 근거: 현재 산출물은 `README.md:1`과 코드(`Cargo.toml:7`의 `default = []`)가 함께 test-only로 못박은 M0 tracer이며, 배포·설치 경로가 존재하지 않아 사용자 데이터·운영을 위협하는 경로가 성립하지 않는다. 미구현 자체를 Critical로 올리지 않았다.

### [High] 확장 지점이 라이브러리 소스의 리터럴 테이블에 고정되어 M1 진입이 코드 수정을 강제한다

- 관련 경로:
  - `src/m0_observation_matrix.rs:475-480` (`verified_count != 0 || included_count != 0` → `Err(Contract)`)
  - `src/m0_observation_matrix.rs:12-59` (`M0_CASE_IDS: [&str; 46]`), `:1010-1015` (`assessed_at`/`os_version`/`os_build`/`architecture` 등호 검사)
  - `src/m0_status.rs:1210-1234` (`("T19-A-HIGH", _) => ([1,1,1,2], vec![HighDetected, HighBlocked], [0,0,0])` 형태의 케이스별 기대값), `:1012-1014` (클라이언트 버전 리터럴)
  - `src/m0_adapter.rs:269-273` (버전·OS·아키텍처 리터럴)
- 확인 내용: 관찰 1건이라도 `Verified`가 되면 검증기가 실패한다. 케이스 추가·클라이언트 버전 변경·호스트 변경은 모두 `src/` 수정을 요구한다.
- 문제점: 테스트 계획과 관찰 스냅샷이 데이터가 아니라 코드다.
- 프로젝트 목적과의 관계: M0 단계에서는 "위조 불가능한 봉인"이라는 장점이지만, M1 진입은 문서에 기록되지 않은 코드 선행 작업을 요구한다.
- 예상 영향: 다음 단계에서 검증 실패를 만나고, 우회하려는 수정이 봉인 자체를 약화시킬 수 있다.
- 권장 조치: coverage 정책·케이스 목록·호스트 기대값을 fixture(JSON)로 외부화하고, 검증기는 "선언된 정책과 관찰이 일치하는지"만 검사하도록 좁힌다.
- 수정 난이도: 높음
- 확실성: 확인됨(코드) / 추론(다음 단계 영향)

### [High] 배포 표면 `plugins/**`은 그대로는 동작할 수 없는 껍데기다

- 관련 경로: `plugins/claude-m0/{hooks/hooks.json,.claude-plugin/plugin.json}`, `plugins/codex-m0/{hooks/hooks.json,.codex-plugin/plugin.json}`
- 확인 내용: `plugins/**` 실제 파일은 위 4개뿐이고 `bin/` 디렉터리가 없다(glob 실측). 훅 커맨드는 `${CLAUDE_PLUGIN_ROOT}/bin/secure-onboard-m0-hook`(Claude) / `"$PLUGIN_ROOT/bin/secure-onboard-m0-hook"`(Codex)를 가리키고, 인자에는 `__SECURE_ONBOARD_M0_{TRUSTED,TARGET,STATE,EVIDENCE}_ROOT__` 리터럴 placeholder가 남아 있다. 치환과 바이너리 주입은 테스트 하네스(`tests/native-harness/*.mjs`)만 수행한다.
- 문제점: 이 디렉터리를 실제 플러그인으로 설치하면 훅 spawn이 실패한다. 문서가 서술한 훅 실패 시 비차단 동작이 적용되면 "설치했지만 보호 0" 상태가 조용히 성립한다.
- 프로젝트 목적과의 관계: 제품의 핵심 가치가 "설치하면 실행 직전에 막아준다"인데, 현재 배포 표면은 그 가치를 제공할 수 없는 상태로 저장소에 존재한다.
- 예상 영향: 사용자·리뷰어가 `plugins/`를 설치 가능한 산출물로 오해할 수 있다. 설치 스크립트가 없어 실제 유통되지는 않는다.
- 권장 조치: `plugins/README` 또는 각 `plugin.json` 설명에 "하네스 전용 템플릿"임을 명시하거나, placeholder 치환을 수행하는 설치 스크립트를 M3 작업으로 등록.
- 수정 난이도: 낮음(표기) / 보통(설치 경로 구현)
- 확실성: 확인됨(파일 구성·하네스 치환) / 훅 실패 시 호스트 동작은 추가 확인 필요

### [High] 호스트 값 등호 비교로 인해 환경이 조금만 달라지면 모든 Bash 호출이 차단된다

- 관련 경로: `src/bin/secure-onboard-m0-hook.rs:31-33`(`RUNTIME_VERSION = "v26.5.0"`, `SHELL_FINGERPRINT = "sha256:4323..."`), `src/m0_adapter.rs:269-273`, `src/m0_profile.rs`의 프로필 검증
- 확인 내용: 프로필 검증은 클라이언트 버전·OS·아키텍처·런타임 버전·셸 지문을 등호 비교한다. 불일치 시 어댑터가 오류를 반환하고, `pre` 모드에서는 `main`의 fail-closed 경로가 HIGH deny를 출력한다.
- 문제점: 안전 방향의 실패지만 사용자 관점에서는 무차별 세션 마비다. Claude 패치 업그레이드, Node 업그레이드, 셸 변경만으로 발생한다.
- 프로젝트 목적과의 관계: "선택형 가드레일"의 사용성 전제(정상 작업을 방해하지 않음)와 충돌한다.
- 예상 영향: 현재는 test profile 전용이라 실사용 영향이 없다. M1에서 동일 패턴을 유지하면 지원 버전 갱신 지연이 곧 전면 차단으로 이어진다.
- 권장 조치: 지원 목록을 데이터로 분리하고, 미지원 호스트는 HIGH deny가 아니라 `protection_status_unknown` 계열의 관측 가능한 비활성 상태로 처리하는 방안 검토(문서에 해당 이벤트가 이미 정의되어 있다).
- 수정 난이도: 보통
- 확실성: 확인됨(코드 경로) / 실제 CLI 표면 노출 형태는 추가 확인 필요

### [High] Codex 결과 훅이 등록되어 있으나 매핑이 항상 실패한다

- 관련 경로: `src/native.rs:295-296`(`CodexPost` 파싱 후 무조건 `Err(UnverifiedCodexResult)`), `plugins/codex-m0/hooks/hooks.json`의 `PostToolUse` 항목, `src/bin/secure-onboard-m0-hook.rs:36-68`
- 확인 내용: Codex `PostToolUse`는 설계상 거부된다(근거: success/failure 모두 `tool_response=""`). 그런데 플러그인 정의는 여전히 `PostToolUse`에 result 훅을 등록하므로 `run_result`가 오류를 반환하고 훅 프로세스가 비정상 종료한다.
- 문제점: "coverage에서 제외"라는 결정이 실행 시 반복 실패로 나타난다. 등록만 제거하면 되는데 남아 있다.
- 예상 영향: 도구 호출마다 훅 실패 이벤트가 발생한다. 상태 판정을 오염시킬 가능성.
- 권장 조치: Codex 플러그인 정의에서 `PostToolUse` 항목을 제거하거나, 매핑 거부를 오류가 아닌 명시적 "관측 제외" 중립 응답으로 처리.
- 수정 난이도: 낮음
- 확실성: 확인됨(코드·플러그인 정의) / 호스트 UI 노출 형태는 추가 확인 필요

### [Medium] 동일 개념이 계층마다 별도 타입으로 중복 정의된다

- 관련 경로:
  - `Client`(`src/m0.rs:7`) vs `M0ProfileClient`(`src/m0_profile.rs:20`)
  - `Sentinel`(`src/m0.rs:14`) vs `M0Sentinel`(`src/m0_profile.rs:27`)
  - `BindingResult`(`src/m0_profile.rs:34`) vs `SentinelBinding`(`src/m0_adapter.rs:24`) vs `SentinelBindingResult`(`src/m0_status.rs:194`)
  - `OperatingSystem` 2곳(`src/m0_status.rs:13`, `src/m0_fixture_manifest.rs:21`), `Architecture` 2곳(`:19`, `:27`)
- 확인 내용: `grep 'pub enum'` 실측 결과 위와 같다. 봉합용 변환 함수가 `src/m0_adapter.rs`에 존재한다.
- 문제점: 값 추가 시 여러 곳을 함께 고쳐야 하고 누락이 컴파일 오류로 잡히지 않는 조합이 있다.
- 프로젝트 목적과의 관계: 지원 클라이언트·OS 확장이 M1-M3의 핵심 작업이므로 이 중복이 곧 확장 비용이다.
- 권장 조치: 도메인 enum 1개를 정본으로 두고 검증기는 `serde` 표현만 별도 유지하거나, 변환을 `From` 구현으로 모아 누락을 컴파일 시점에 드러낸다.
- 수정 난이도: 보통
- 확실성: 확인됨

### [Medium] 저수준 해시·경로 헬퍼가 3-5중 복제되어 있다

- 관련 경로: `is_sha256_label` 3곳(`src/m0_profile.rs:563`, `src/m0_status.rs:1379`, `src/m0_fixture_manifest.rs:659`) + 동일 로직의 `is_sha256`(`src/m0_observation_matrix.rs:1881`), `sha256_label` 3곳(같은 파일들) + `sha256_bytes`(`src/m0_status_harness.rs:259`)
- 확인 내용: `grep 'fn is_sha256\|fn sha256_'` 실측.
- 문제점: 각 검증기가 자기 오류 타입을 위해 헬퍼를 복사했다. 판정 기준이 갈라지면 발견이 어렵다.
- 권장 조치: `strict_json`(이미 canonical/sha256 담당) 또는 신설 내부 모듈로 통합. 오류 타입은 호출부에서 변환.
- 수정 난이도: 낮음
- 확실성: 확인됨

### [Medium] 훅 CLI가 모든 진단 정보를 버린다

- 관련 경로: `src/bin/secure-onboard-m0-hook.rs` — `Result<(), ()>` 서명과 `map_err(|_| ())` 32회(실측), 실패 시 stderr는 고정 한 줄 `Secure Onboard M0 hook failed`
- 확인 내용: 라이브러리는 `thiserror` 계층(`M0AdapterError`, `ProfileError`, `StatusError` 등)을, core 바이너리는 64/65/70/74 exit code 체계를 갖는다. 정보가 마지막 계층에서만 소실된다.
- 문제점: 프로필 digest 불일치인지, 상태 저장소 충돌인지, 코어 spawn 실패인지 운영에서 구분할 수 없다.
- 프로젝트 목적과의 관계: 문서가 정의한 `protection_status_unknown` 같은 상태 구분을 실제로 만들 수 없다.
- 권장 조치: 실패 원인을 안정적인 코드(enum)로 stderr 또는 로컬 로그에 남기고, 원문·비밀은 담지 않는다.
- 수정 난이도: 낮음
- 확실성: 확인됨

### [Medium] `handle_pre_tool_use`가 127행 단일 함수다

- 관련 경로: `src/m0_adapter.rs:249-375`
- 확인 내용: 매핑, 프로필 로드, 클라이언트 일치, cwd 판정, sentinel 바인딩, 요청 조립, 자식 실행, 폴백, 응답 인코딩이 한 함수에 있다.
- 문제점: M1의 action kind·캐시·NOT_COVERED 분기가 모두 이 지점에 들어온다.
- 권장 조치: 현재 규모에서 무리한 추상화는 권장하지 않는다. M1 착수 시 "판정 입력 조립"과 "판정 실행·응답"으로 2분할하는 선에서 충분하다.
- 수정 난이도: 보통
- 확실성: 확인됨

### [Medium] argv를 두 파서로 이중 해석해 fail-closed가 조용히 비활성화될 수 있다

- 관련 경로: `src/bin/secure-onboard-m0-hook.rs:72-93`(`is_pre_tool_mode`, `pre_tool_client`) vs `run_pre`가 쓰는 정식 파서
- 확인 내용: `pre_tool_client`는 `--` 접두 검사 없이 key/value 쌍만 훑고 홀수 argv면 `None`을 반환한다. 정식 파서는 `--` 접두와 중복 키를 거부한다.
- 문제점: 두 파서의 수용 문법이 어긋나면 fail-closed 판단이 클라이언트를 못 찾아 무력화될 수 있다.
- 예상 영향: 인자 형식을 바꾸는 변경에서 조용한 회귀가 발생할 수 있다.
- 권장 조치: 정식 파서를 먼저 호출하고 그 결과를 fail-closed 경로가 재사용하도록 단일화.
- 수정 난이도: 낮음
- 확실성: 확인됨(코드) / 실제 회귀 발생 가능성은 추론

### [Medium] 증거 쓰기 실패 시 LOW 경고를 표시한 채 실행이 차단된다

- 관련 경로: `tests/m0_hook_cli.rs:457-496` (`evidence_failure_after_low_stdout_blocks_and_never_delivers_correlation`), `src/bin/secure-onboard-m0-hook.rs:36-68`
- 확인 내용: 이 테스트는 `--post-response-fault evidence-write`로 증거 쓰기 실패를 주입한다. 그 결과 stdout에는 `{"systemMessage":"Secure Onboard M0: LOW warning."}`, stderr에는 `Secure Onboard M0 hook failed`, exit code는 2이며 대상 marker가 생성되지 않는다(=실행되지 않음).
- 인과 구분: LOW 등급 자체가 deny인 것이 아니다(`docs/plan/decisions.md` D4의 "HIGH만 deny"는 유효하다). LOW 응답을 stdout에 쓴 **뒤** 증거 커밋이 실패해 훅이 실패 경로로 빠지고, 그 실패가 exit 2로 표현되어 결과적으로 도구 호출이 차단된다.
- 문제점: 사용자에게 표시되는 메시지("경고 후 진행")와 실제 결과(차단)가 어긋난다. 차단 사유가 stderr 고정 문구 한 줄뿐이어서 원인을 구분할 수 없다(§6 훅 CLI 진단 소실 항목과 동일 원인).
- 프로젝트 목적과의 관계: 안전 방향의 실패이므로 보호 목적에는 부합한다. 다만 "표시된 판정과 실제 결과가 일치한다"는 사용자 신뢰 전제가 이 경로에서 깨진다.
- 권장 조치: 이 조합을 문서의 오류 처리 절에 명시하고, 실패 사유를 구분 가능한 코드로 노출한다. 응답 출력 이후 실패를 표시로 되돌릴 수 없다는 제약 자체는 현재 순서 설계상 타당하다.
- 수정 난이도: 낮음(문서·진단) / 보통(표시 일관성)
- 확실성: 확인됨(테스트 단언 직접 확인) / Claude가 exit 2를 차단으로 해석한다는 점은 문서 서술 기반이며 호스트 실측은 추가 확인 필요

### [Medium] 테스트가 저장소 내부에 임시 디렉터리를 만들고 `.gitignore`가 이를 덮지 않는다

- 관련 경로: `tests/m0_observation_matrix_contract.rs:43-45`(`TempDir::new_in(repository_root())`), 같은 파일 `:763`(`TempDir::new_in(tests/fixtures/m0)`), `.gitignore`(5행)
- 확인 내용: 실행 중 `./.tmpXXXXXX/bad.json`과 `tests/fixtures/m0/.tmpXXXXXX/fake-manifest.json`이 실제로 생성되는 것을 확인했다. `.gitignore`에는 `.tmp*` 패턴이 없다.
- 문제점: 정상 종료 시에는 정리되지만 패닉·강제 종료 시 작업 트리에 잔재가 남고 추적 대상이 된다.
- 예상 영향: 실수 커밋 위험. 리뷰 시 무엇이 산출물인지 혼동.
- 권장 조치: `.gitignore`에 `.tmp*` 추가(1행)가 가장 저렴하다. 또는 시스템 temp 디렉터리를 사용하도록 테스트를 변경.
- 수정 난이도: 낮음
- 확실성: 확인됨(코드·`.gitignore`·실행 중 관찰) / 커밋 사고 발생 가능성은 추론

### [Medium] 플러그인 훅 정의가 고정 식별자와 고정 시각을 넘긴다

- 관련 경로: `plugins/claude-m0/hooks/hooks.json:44-59` (`--test-case T-LIVE`, `--action-id action-live`, `--decision-id decision-live`, `--observed-at 2026-07-22T00:00:00Z`), `plugins/codex-m0/hooks/hooks.json`
- 확인 내용: `--id-binding native-sha256`이 식별자에 payload 해시를 결속해 충돌은 완화하지만, `observed_at`은 결속 대상이 아니라 모든 이벤트가 동일한 고정 시각을 갖는다.
- 문제점: 활동 기록에 시간 축이 없다. 문서가 정의한 30일/1,000건 보존 정책을 이 데이터로는 적용할 수 없다.
- 권장 조치: 현재는 test tracer이므로 시급하지 않다. M1에서 시각을 호출 시점으로 대체하는 것을 선행 조건으로 등록.
- 수정 난이도: 낮음
- 확실성: 확인됨

### [Medium] 손으로 만든 TOML 부분 파서가 실제 설정에서 오작동한다

- 관련 경로: `src/m0_status.rs:625-654` (`derive_codex_hooks_claim`)
- 확인 내용: `[features]` 섹션 안에서 `line.strip_prefix("hooks")?`를 사용한다. `?`는 `None`을 조기 반환하므로 `[features]` 아래에 `hooks` 외 키가 하나라도 있으면 전체가 `None`이 된다. dotted key(`features.hooks = true`), 인라인 테이블, 따옴표 키, 값 뒤 주석도 지원하지 않는다.
- 대조: 실제 하네스 config는 `[features]` 아래에 `plugins = false`, `remote_plugin = false` 등 다수 키를 둔다(`tests/native-harness/run-codex-m0.mjs:693-700`).
- 문제점: Codex 훅 기능 활성 여부 판정이 조용히 "판단 불가"로 떨어질 수 있다.
- 권장 조치: 상태 수집을 실제로 구현하는 시점에 TOML 파서를 도입하거나, 파싱 실패와 키 부재를 구분해 반환.
- 수정 난이도: 낮음
- 확실성: 확인됨(코드 형태·하네스 config) / 실제 오판 발생 경로는 상태 수집기가 없어 추가 확인 필요

### [Low] 사용되지 않는 payload 구조체가 파일 절반을 차지한다

- 관련 경로: `src/native.rs`의 클라이언트 원시 payload 구조체들(`#[allow(dead_code)]` + `deny_unknown_fields`)
- 확인 내용: 스키마 고정 목적의 의도적 설계다. 다만 필드 대부분이 읽히지 않아 계약인지 잔재인지 코드만으로 구분되지 않는다.
- 권장 조치: 모듈 상단 주석 1-2줄로 "스키마 드리프트 감지용"임을 명시.
- 수정 난이도: 낮음
- 확실성: 확인됨(스카우트 보고 기반, `#[allow(dead_code)]` 존재는 직접 확인)

### [Low] `canonical_bytes`가 객체마다 전체 트리를 한 번 더 복제한다

- 관련 경로: `src/strict_json.rs`의 `canonical_bytes`(`to_value` → `to_vec` 2단계), 훅 경로의 preflight/record가 같은 객체에 각각 적용
- 문제점: envelope·request·decision·event마다 직렬화와 해시가 2회 발생한다.
- 프로젝트 목적과의 관계: 훅은 5초 timeout 안에서 동작해야 하므로 무의미한 비용은 아니지만, 현재 payload 크기(1 MiB 상한)에서 병목으로 관측되지 않았다.
- 권장 조치: 지금은 조치 불필요. 성능 문제가 관측될 때 preflight 결과를 재사용.
- 수정 난이도: 낮음
- 확실성: 확인됨(코드) / 성능 영향은 추가 확인 필요(측정하지 않음)

## 7. 확장 시 예상되는 병목

| 병목 | 위치 | M1에서 발생하는 형태 |
|---|---|---|
| coverage 0 강제 | `src/m0_observation_matrix.rs:475-480` | 관찰을 검증됨으로 표시하는 순간 검증 실패 |
| 케이스별 기대값 테이블 | `src/m0_status.rs:1210-1234` | 케이스 추가마다 라이브러리 수정 |
| 호스트·버전 등호 비교 | `src/m0_adapter.rs:269-273`, `src/bin/secure-onboard-m0-hook.rs:31-33` | 지원 버전 확대마다 코드 수정, 미지원 시 전면 차단 |
| 단일 판정 함수 | `src/m0_adapter.rs:249-375` | action kind·캐시·NOT_COVERED 분기 집중 |
| 개념 타입 중복 | §6 Medium 1 | 지원 OS·클라이언트 추가 시 다중 수정 |
| Codex 경로 하드코딩 | `src/native.rs:273-274` | Codex 지원을 살리려면 cwd 결속 재설계 필요 |

## 8. 코드 일관성

| 축 | 상태 | 근거 |
|---|---|---|
| JSON 파싱·직렬화 | 일관 | 전 도메인 구조체가 `strict_json` + `deny_unknown_fields` |
| 판정 결과 구조 | 일관 | `M0ActionDecision`/`M0Event` 단일 스키마, 화이트리스트 검증 |
| 오류 처리 | 불일관 | 라이브러리 `thiserror` / core bin exit code 체계 / 훅 bin `Result<(), ()>` 3종 공존 |
| 설정 접근 | 일관 | 환경 변수 대신 명시 인자. `env_clear`로 자식 환경 차단 |
| 로깅 | 사실상 없음 | 훅 실패 시 고정 stderr 1줄 |
| 추상화 수준 | 영역 간 격차 큼 | 순수 도메인 515행 대 검증기 1,914행. 검증기는 절차적 대형 함수 위주 |

## 9. 주요 기술 부채와 불필요·중복 코드

- 테스트 계획·호스트 스냅샷의 소스 인코딩(§6 High 1) — 가장 비용이 큰 부채.
- 개념 타입·해시 헬퍼 중복(§6 Medium 1·2).
- 배포 표면과 하네스 조립 로직의 이원화(§6 High 2). 훅 정의가 배포본과 하네스 합성 정의로 나뉘어 있다는 스카우트 보고가 있으나 각 하네스 파일의 정의 내용은 이번 리뷰에서 재확인하지 않았다(미검증).
- 폐기 코드는 발견하지 못했다. `#[allow(dead_code)]` payload 구조체는 스키마 고정이라는 목적이 있다.

## 10. 프로젝트 목적에 대한 코드 적합성 — 종합

| 관점 | 등급 | 근거 |
|---|---|---|
| 목적 적합성(M0 단계) | 적절 | 훅 경계 관측·증거 봉인·fail-closed가 M0 목표를 정확히 구현. 미검증을 성공으로 위장하는 경로 없음 |
| 현재 규모 적합성 | 부분적으로 부적절 | 단일 스냅샷 검증을 위해 4,449행을 유지. `AGENTS.md`의 단순성 원칙과 긴장 관계 |
| 유지보수 가능성 | 부분적으로 부적절 | 개념·헬퍼 중복과 진단 정보 소실이 변경·조사 비용을 높인다 |
| 확장 가능성 | 부분적으로 부적절 | §7의 6개 병목이 모두 라이브러리 수정을 요구 |
| 안정성 | 대체로 적절 | fail-closed·격리·엄격 파싱이 두터움. LOW 표시/차단 불일치와 이중 파서가 예외 |
| 도메인·인프라 분리 | 적절 | 순환 없음, 순수 도메인 유지 |
| 테스트 가능성 | 적절 | 순수 도메인과 프로세스 계약이 분리되어 실제로 테스트됨 |

핵심 결론: **아키텍처는 M0 목적에 잘 맞고, 문제는 "다음 단계로 넘어가는 비용"에 집중되어 있다.** 지금 필요한 것은 대규모 재설계가 아니라 (1) 확장 지점을 데이터로 옮기기, (2) 중복 타입·헬퍼 정리, (3) 훅 실패 진단 노출, (4) 배포 표면의 지위 명시다.
