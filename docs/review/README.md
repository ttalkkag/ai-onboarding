# 문서 검토 및 구현 준비도

- 최신 검토일: 2026-07-29
- 기준 문서: 루트 `README.md`, `CONTEXT.md`, `docs/plan/*.md`
- 판정: **M0 구현·관찰 완료-with-exclusions / 검증된 보호 coverage 0 / 전체 M1 NO-GO**

## 최신 검토 결론

2026-07-22 이전 문서는 별도 설치 전 검사기, 공용 저장소 스킬, 프로젝트 단위 `안전/위험`, `HIGH/MED/INFO`, AI의 대상 원문 접근 금지를 전제로 했다. 2026-07-26 공식 문서 재검증과 독립 계약 감사를 거쳐 정본을 다음 모델로 갱신했다.

| 항목 | 현재 계약 |
|------|-----------|
| 제품 | 개인 컴퓨터의 Claude Code·Codex CLI용 선택형 실행 가드레일 |
| 배포 | 사용자 영역 공용 코어 + 클라이언트별 plugin/hook adapter |
| 활성 범위 | 사용자 scope `ON\|OFF`와 유효 보호 `VERIFIED_ACTIVE\|OFF\|UNKNOWN` 분리, 프로젝트 비활성화 우선 |
| 판정 단위 | 프로젝트가 아니라 실행 직전 보호 action |
| 등급 | `HIGH`, `LOW`, `INFO`; HIGH만 deny |
| read-only scan | `ScanReport`만 생성; HIGH finding이어도 scan 자체 `ActionDecision` 없음 |
| HIGH 재확인 | Claude의 검증된 user prompt 또는 Codex의 제품 소유 local confirmation으로 action을 재확인한 뒤 명령 준비·표시, AI의 target tool 실행 없음 |
| 명령 출처 | 사용자 요청, AI 예상, AI 실행 예정, 실제 차단 명령 분리 |
| 기록 | 준비와 assistant 응답 원문 포함 확인을 분리; UI 전달·열람과 일반 터미널 실행은 기록하지 않음 |
| 중복 검사 | evidence/action cache 분리, remote npm은 HIGH deny·cache bypass |
| 데이터 | 외부 프로젝트 AI 처리는 허용; 공급자 데이터 정책은 각 CLI를 따름 |
| M1 성격 | 일반 탐지 제품이 아니라 npm 설치·파일 열기·명시적 read-only scan을 고정 fixture로 관통하는 end-to-end alpha |

## M0 실측 증거와 M1 재판정

2026-07-29 macOS 26.5.2(build 25F84) arm64에서 로컬 mock API와 외부 egress trap만 사용해 native probe를 실행했다. 실행 파일, test profile, helper, native fixture, plugin/hook definition과 M0 hook/core release artifact의 결합은 `tests/fixtures/m0/manifests/`의 canonical manifest 두 개로 고정한다. 관찰 행렬은 46 case × 2 client를 분류하지만 현재 `verified=0`, coverage `included=0`이다.

| client | exact 실행 파일 | 실측 결과 | M0 coverage |
|--------|-----------------|-----------|-------------|
| Claude Code 2.1.220 | `/Users/kimchanhyung98/.local/share/claude/versions/2.1.220`, `sha256:8addc857f3fe64d5a0368af9ee50321b50afb4a6918ba3ef018ab84f5dbbe081` | HIGH marker 부재, LOW warning stream 수신 뒤 marker 생성, INFO marker 생성, success/failure result correlation과 Stop exact message를 관찰했다. core timeout/nonzero/schema failure는 adapter가 HIGH deny로 변환했다. `/bin/ps`가 권한 오류여서 target process start는 모두 null이다. | 실제 marker·native payload 관찰은 보존하지만 process·승인 경계가 미검증이므로 모든 protection coverage 제외 |
| Codex CLI 0.146.0 | `/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js`, `sha256:134063e133f0b4244fa3b251acf973d4fe4b4aeeacbdc135211bf480f59f1477` | hook은 호출되지만 per-call `workdir`를 native payload에서 신뢰할 수 없어 HIGH sentinel을 활성화하지 않았다. success와 exit 23 failure의 `PostToolUse.tool_response`가 모두 exact empty string이라 outcome을 구분할 수 없었다. `systemMessage` 전달도 관찰되지 않았다. | 이 exact version의 shell action/result path 전체 제외 |

- Claude·Codex adapter 자체 미실행, timeout, 일반 nonzero, malformed output에서는 target marker가 생성돼 native fail-open 경계를 관찰했다. exit 2 fault의 marker는 없었지만 process observer와 실제 승인 경계가 없으므로 이를 보호 성공으로 세지 않는다.
- plugin/hooks OFF control은 격리된 임시 cwd에서 target 실행과 제품 event 0을 확인했다. 저장소 자체 hook이 섞이지 않도록 control cwd를 별도로 검증한다.
- 같은 Claude `PreToolUse`의 sibling hook은 원래 HIGH target 차단 뒤에도 marker를 기록했다. sibling 부작용 0은 보장하지 않는다.
- kernel network confinement는 `sandbox-exec` 권한 오류로 사용할 수 없었다. localhost mock API 외 요청은 proxy trap으로 관찰했고 격리 수정 뒤 egress 시도 0이었다.
- interactive operator approval은 실행하지 않았다. bypass mode의 target reachability만 관찰했으며 native approval 안전성 성공으로 표시하지 않는다.
- Codex 자동 continuation probe에서는 최초 인간 prompt의 `UserPromptSubmit` 1개와 같은 turn의 Stop 2개(`stop_hook_active=false → true`)를 관찰했다. continuation은 두 번째 local API 요청의 `<hook_prompt>`였고 두 번째 `UserPromptSubmit`은 없었으므로 provenance는 계속 `unverified`다.
- `codex exec --json`에서 `systemMessage`가 보이지 않은 사실만 확인했다. 대화형 terminal UI 렌더링은 실행하지 않아 T20 사용자 표시 계약은 미검증이다.
- Codex의 effective cwd와 result outcome이 정본 가정과 달랐으므로 D12에 따라 M1 착수 조건은 닫히지 않았다. M1 구현 범위를 추측해 진행하지 않고 전체 M1 판정을 `NO-GO`로 유지한다.

## 제거한 오류·모순

- 공용 저장소 skill/symlink를 제품 배포 방식으로 사용한다는 주장
- Finder·일반 터미널까지 보호한다는 범위 확대
- `MED`, `안전/위험`, scan의 `not_applicable ActionDecision`
- 최초 HIGH 차단 응답에서 AI가 runnable command를 새로 제공하는 흐름
- 사용자 prompt, native tool call, result hook과 재확인을 연결할 ID가 없는 계약
- command helper가 payload를 반환한 사실을 실제 사용자 표시로 기록하는 오류
- Claude success/failure 결과 훅과 Codex 결과 훅을 같은 native event로 표현한 오류
- 프로젝트가 사용자 영역 상태를 절대 변조할 수 있다는 과도한 보장
- AI assessment를 스키마·spoof 방지 없이 M1 deny에 반영하는 계획
- install-hook sink·secret exfiltration 같은 심층 M2 규칙을 M1 fixture와 섞은 계획

연구·초안·과거 리뷰는 역사 자료로 표시했다. `docs/draft/scan.sh`는 참고 구현이며 제품 엔진이나 판정기로 사용하지 않는다.

## 현재 완성된 부분

- 사용자 확인 사항: local AI CLI 전용, global/project/OFF, HIGH/LOW/INFO, HIGH만 차단
- 구체적 명령과 의도 요청, 네 command 필드와 출처 라벨
- HIGH deny → 검증된 사용자 재확인 → 영향 설명 → 명령 준비 → assistant 응답 원문 포함 확인 → 종료
- 일반 터미널·Finder·hook OFF·hosted/special tool·interactive follow-up의 비보장 경계
- PromptContext → HookEnvelope → ActionRequest → ActionDecision 실행 게이트 경계
- ScanBridgeEnvelope → ScanRequest → ScanReport 분리와 resolution failure 형태
- Reconfirmation·PendingBlock·Stop 응답 원문 확인 경계
- event별 필드와 evidence/action cache 분리
- M1의 AI assessment 제거와 M2 유예
- M0/M1/M2 단계 분리
- trusted scan helper와 short-ref disclosure transport
- 범위 밖 `NOT_COVERED`, 정규화 전 failure, 중복·병렬 호출의 idempotency 계약
- operational fail-closed와 npm/open/scan 범위, literal-all HIGH 명령 공개 정책 확정
- action kind 우선 coverage 분류, terminal replay·quarantine·HMAC 로그 식별자 계약
- remote npm과 local immutable artifact 경계, EICAR 단일 파일 fixture

## M1을 막는 항목

다음은 구현 중 정하면 되는 사소한 세부가 아니라 M1 expected output 또는 지원 범위를 바꾸므로 먼저 닫아야 한다.

1. Claude Code·Codex의 지원 exact version·OS별 native prompt/pre/result/Stop bytes, deny·continue 응답과 관찰 가능한 독립 process observer로 확인한 HIGH 뒤 target process start 0 증거
2. core child 실패를 valid deny로 변환하는 경우와 adapter 자체 미실행·timeout·malformed output의 native fail-open 가능성을 분리한 fixture
3. client-native plugin/hooks OFF, Codex hook-definition trust, Claude workspace/plugin/bare 상태의 확인 가능 범위
4. 공식 provenance 필드가 없는 Codex에서 제품 소유 local confirmation을 action에 결합하는 exact transport fixture
5. 사용자별 SQLite의 schema·migration·locking, project/directory partition, transaction·outbox·crash recovery와 management operation의 원자성 계약
6. canonical encoding, parser/scanner resource limit, cache TTL·용량, HMAC key 보관·손실·회전 계약
7. OS별 physical path canonicalization, 중복 registry 충돌, short-ref collision·clock rollback 처리
8. 각 M1 case의 exact bytes·path·permission·prompt·tool payload·clock·timeout·expected JSON, 실제 CoverageManifest 값과 case×client/version×OS 적용 행렬
9. exact local npm artifact와 실제 실행 bytes 결합, Node/npm version·effective config fixture
10. stale/cross-session/wrong-ref, near-miss identity, digest mismatch, replay·병렬 HIGH의 negative fixture

## 다음 작업

M0 test-only tracer, strict profile/manifest, adapter/core, native harness, status·observation contract와 production 음성 검사는 구현돼 있다. 다음 지원 확대 작업은 새 기능을 추측해 만드는 것이 아니라 현재 제외된 경계를 실제 증거로 닫는 일이다.

- 독립 process observer가 가능한 환경에서 Claude HIGH와 fault exit 2의 target process start를 다시 측정
- 두 CLI의 실제 대화형 승인 절차를 사람이 수행해 LOW·INFO와 adapter fault가 native approval을 우회하지 않는지 확인
- 실제 대화형 terminal에서 `systemMessage` 표시·시각·개행·잘림을 측정
- Codex에서 effective per-call cwd와 success/failure result outcome을 신뢰할 공식·관찰 가능 필드가 생긴 exact version만 새 matrix entry로 추가
- 위 증거가 없는 동안 coverage는 0으로 유지하고 설치 가능 제품·M1 보호로 설명하지 않음

M0에서는 npm/EICAR 분석기, 캐시, 재확인 UI, SQLite와 AI 판정 bridge를 구현하지 않는다. M1은 이 문서의 blocker와 exact fixture 계약을 닫고 별도 GO 판정을 갱신하기 전까지 시작하지 않는다.

## 확정한 제품 정책

- 필수 검사·상태·로그 실패는 보호 action에서 HIGH deny, read-only scan에서 HIGH finding이다.
- M1 alpha는 npm 설치, 로컬 파일 열기와 명시적 read-only scan을 포함한다.
- fail-open과 scan 유예는 active 후보 계약에서 제거했다.
- HIGH 명령은 secret 출처와 무관하게 원문 bytes를 그대로 제공하되, 터미널 표시를 조작하는 제어문자만 항상 가시적인 안전 표현으로 바꾼다. 활동 로그·캐시에는 원문을 저장하지 않는다.
- 공용 코어와 adapter는 사용자 영역에 한 번 설치하고 프로젝트별 활성화 상태만 관리한다.
- Codex 재확인은 모델 transcript와 분리된 제품 소유 local confirmation을 사용한다.
- durable state는 project/directory를 구분하는 daemonless 사용자별 SQLite + transaction/outbox + OS credential store key를 사용한다.

## 확정된 고영향 구조 결정

아래 선택은 M0를 막지 않았으며 M1의 고정 정책으로 확정됐다.

1. **프로젝트 모드:** 사용자 영역 공용 코어 1회 설치 + 프로젝트별 활성화.
2. **HIGH 명령 표시:** exact blocked command의 secret bytes를 출처와 무관하게 literal로 제공. ANSI/OSC·양방향 제어문자·NUL은 예외로 항상 안전 표현으로 변환하며, 이는 정책 스위치가 아닌 고정 불변식이다.
3. **Codex 재확인:** 모델 transcript와 분리된 제품 소유 로컬 확인 채널.
4. **durable state:** project/directory를 구분하는 daemon 없는 사용자별 SQLite + transaction/outbox + OS credential store key.

## 아직 주장 불가

- 전체 M1 구현 착수 가능 또는 v0.1 배포 준비 완료
- 모든 로컬 실행 보호
- 같은 event의 sibling hook 부작용 차단
- project 또는 같은 사용자 권한 악성 코드에 대한 상태 변조 방지
- 중앙 감사·강제 보안 통제

## 현재 리뷰

- [hook-contract-and-decisions.md](hook-contract-and-decisions.md): 2026-07-26 훅 계약 공식 문서 독립 검증과 사용자 확정 결정의 원본 기록. 사용자에게 제시된 선택지 원문, 채택하지 않은 대안, 발견 항목 C1–C5의 정본 반영 기록(전부 반영 완료)을 담는다.

## 과거 리뷰

아래 문서는 2026-07-22 이전 설계의 사실 검증·참고 코퍼스 리뷰다. 최신 제품 정책이나 구현 준비도는 이 인덱스와 `../plan/`이 우선한다.

- [plan-research-review.md](plan-research-review.md)
- [core-reverse-engineering-review.md](core-reverse-engineering-review.md)
- [security-modules-review.md](security-modules-review.md)
- [runtime-modules-review.md](runtime-modules-review.md)

과거 리뷰의 도구 API·보안 주의·라이선스 검토는 해당 참고 자료를 실제 제품에 채택할 때 다시 확인한다. 저장소를 공개·배포하기 전 `docs/draft/reverse-skill/`의 업스트림 라이선스와 파일별 provenance를 정리해야 한다는 지적은 여전히 유효하다.
