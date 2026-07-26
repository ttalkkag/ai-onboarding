# 문서 검토 및 구현 준비도

- 최신 검토일: 2026-07-26
- 기준 문서: 루트 `README.md`, `CONTEXT.md`, `docs/plan/*.md`
- 판정: **M0 hook tracer-bullet GO / 전체 M1 NO-GO**

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

1. Claude Code·Codex의 지원 exact version·OS별 native prompt/pre/result/Stop bytes, deny·continue 응답과 HIGH 뒤 target process start 0 증거
2. core child 실패를 valid deny로 변환하는 경우와 adapter 자체 미실행·timeout·malformed output의 native fail-open 가능성을 분리한 fixture
3. client-native plugin/hooks OFF, Codex hook-definition trust, Claude workspace/plugin/bare 상태의 확인 가능 범위
4. 공식 provenance 필드가 없는 Codex에서 제품 소유 local confirmation을 action에 결합하는 exact transport fixture
5. 사용자별 SQLite의 schema·migration·locking, project/directory partition, transaction·outbox·crash recovery와 management operation의 원자성 계약
6. canonical encoding, parser/scanner resource limit, cache TTL·용량, HMAC key 보관·손실·회전 계약
7. OS별 physical path canonicalization, 중복 registry 충돌, short-ref collision·clock rollback 처리
8. 각 M1 case의 exact bytes·path·permission·prompt·tool payload·clock·timeout·expected JSON, 실제 CoverageManifest 값과 case×client/version×OS 적용 행렬
9. exact local npm artifact와 실제 실행 bytes 결합, Node/npm version·effective config fixture
10. stale/cross-session/wrong-ref, near-miss identity, digest mismatch, replay·병렬 HIGH의 negative fixture

## 다음 구현 작업

**진행 가능:** 고정 HIGH/LOW/INFO sentinel을 사용하는 M0 hook tracer-bullet.

M0는 다음을 산출해야 한다.

- Claude·Codex plugin manifest와 native hook payload fixture
- `HookEnvelope → M0ActionRequest → M0ActionDecision` 최소 변환과 production LocalEvent/Status와 분리된 M0Event/M0StatusReport
- documented HIGH deny, LOW/INFO continue와 native approval 유지 증거
- parallel native tool call/result correlation
- live adapter의 core child timeout·exit·schema failure deny와 adapter 자체 fault의 native 결과를 분리한 증거
- plugin/hooks OFF와 client별 standalone status/self-test
- 공식 Stop `last_assistant_message`의 nullable 조건·exact bytes·marker/digest fidelity
- Codex native `Bash/command/tool_use_id`와 내부 canonical field의 변환 fixture
- Codex exact bundled hook definition bytes·제품 자체 digest·새 session trust 행동·heartbeat. 내부 trust hash 값은 추정하지 않음
- effective shell과 effective cwd 결합, per-call workdir을 식별하지 못하는 native path 전체의 coverage 제외
- sandbox mode·approval policy·approvals reviewer를 포함한 native control run
- M0 test build에 compile-time으로 결합된 exact profile bytes/digest와 production artifact의 loader·sentinel rule 부재, Codex unsupported output exact bytes 결과

2026-07-26 현재 이 장비의 첫 probe 후보는 `codex-cli 0.145.0`, `Claude Code 2.1.220`이다. 이는 설치된 버전 기록일 뿐 최소 지원 버전 선언이 아니며, M0 결과와 함께 실행 파일 hash·OS·shell·permission mode까지 묶어야 한다.

M0에서는 npm/EICAR 분석기, 캐시, 재확인 UI, AI 판정 bridge를 구현하지 않는다. M0 증거와 남은 M1 구조 계약이 닫히면 `use-cases.md`의 manifest를 작성하고 M1 alpha GO/NO-GO를 다시 판정한다.

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
