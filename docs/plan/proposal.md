# Secure Onboard 기획서

- 문서 상태: **M0 hook tracer-bullet GO / 전체 M1 NO-GO**
- 기준일: 2026-07-26
- 제품: Claude Code·Codex 로컬 CLI용 선택형 실행 가드레일
- 구현 상태: 미착수. 첫 단계는 두 클라이언트의 `PreToolUse` tracer-bullet이다.
- 정책 정본: `decisions.md`
- 상태 전이 정본: `workflow.md`
- 출력·필드 정본: `report-template.md`

## 1. 문제와 사용자

내부 사용자는 AI나 코딩에 익숙하지 않아 외부에서 받은 프로젝트·코드·파일을 충분히 확인하지 않고 AI에 설치·실행하도록 요청한다. 이 과정에서 패키지 설치 훅, 위장 파일, 비정상 스크립트, 권한 변경, 비밀정보 노출로 보안 사고가 발생한다.

Secure Onboard는 AI가 실제 로컬 작업을 수행하기 직전에 위험을 쉬운 말로 설명한다. 중대한 위험은 AI 자동 실행을 막되, 로컬 개발 중인 파일과 오탐 가능성을 고려해 사용자가 위험을 다시 확인하면 원래 명령을 직접 판단할 수 있도록 보여 준다.

## 2. 제품 목표

1. 실행·설치·열기·설정·권한 변경·보안 검사 요청을 Claude Code CLI와 Codex CLI에서 식별한다.
2. 실제 로컬 도구 호출 직전에 같은 공용 규칙으로 `HIGH`, `LOW`, `INFO`를 판정한다.
3. HIGH는 AI 자동 실행을 차단하고, LOW는 실행 전 경고하며, INFO는 로컬 기록만 남긴다.
4. 구체적 명령과 의도 요청, 사용자 원문과 AI 생성 명령을 혼동하지 않는다.
5. 로컬 캐시로 같은 대상·작업의 중복 검사를 줄인다.
6. 개인 컴퓨터에서 전역 또는 프로젝트별로 활성화하고 언제든 비활성화할 수 있다.

## 3. 제품이 아닌 것

- Finder·파일 탐색기 또는 OS 전역 실행 차단기
- 일반 터미널 감시기
- 관리자가 강제하는 보안 정책이나 중앙 감사 시스템
- 프로젝트 전체의 영구적인 안전 인증
- Claude Code·Codex의 데이터 전송을 막는 DLP
- 동적 악성코드 sandbox, DAST, detonation, 디버거·후킹 도구

## 4. 지원 범위

### 4.1 지원 클라이언트

- Claude Code CLI
- Codex CLI

각 클라이언트는 별도 plugin manifest와 얇은 hook adapter를 가진다. 공용 규칙·캐시·로그·상태 관리는 하나의 로컬 코어가 담당한다. 저장소 스킬 심볼릭 링크는 제품 배포 구조로 사용하지 않는다.

현재 저장소의 `.skills/sample`과 세 skills symlink는 예제 자산으로만 유지한다. M1 제품 코드를 `.skills/secure-onboard`에 만들거나 이 링크를 설치 방식으로 재사용하지 않는다.

### 4.2 단계별 작업 범위

| 단계 | 범위 | 완료 증거 |
|------|------|-----------|
| M0 hook tracer-bullet | Claude·Codex의 shell/exec `PreToolUse`, 고정 sentinel의 HIGH deny·LOW/INFO continue, result·Stop hook, 상태 진단 | 실제 native payload fixture, 차단 대상 tool handler·process 0, native approval 유지 |
| M1 fixture-backed alpha | npm 설치, 로컬 파일 열기, 명시적 읽기 전용 검사, 결정론적 규칙, 명령 출처·재확인·표시, scope·로그·캐시 | 확정 fixture manifest와 expected JSON 통과 |
| M2 심층 분석 | install hook→sink, secret source→외부 sink, container·실행 경로 분석, 검증된 AI 승격, 추가 MCP/file-edit coverage | 별도 스키마와 회귀 oracle 통과 |

빌드·테스트·설정·권한 변경은 의미 트리거와 탐지 카탈로그에 포함하지만 M1 지원 grammar는 아니다. 훅이 관찰한 범위 밖 호출은 `NOT_COVERED`로 통과시키고 coverage 진단만 남기며 `INFO` 판정이나 보호 성공으로 표현하지 않는다. native file write/edit·일반 MCP는 M2에서 별도 coverage test와 case를 만든 뒤 지원으로 표시한다. hook이 관찰하지 않는 경로에는 event도 만들 수 없다.

명시적 보안 검사는 대상을 실행하지 않는 읽기 전용 작업이다. HIGH finding을 발견해도 검사 자체는 끝까지 수행하고 별도 `ScanReport`로 알린다. 같은 대상을 설치·열기·실행하는 후속 action은 새 `ActionDecision`으로 게이트한다. scan은 어댑터가 native session·prompt·물리 cwd를 주입하는 구조화 helper로만 시작하며 모델이 내부 context를 정하지 않는다.

### 4.3 범위 밖 실행

- 일반 터미널에 붙여 넣은 HIGH 명령
- Finder·파일 탐색기에서 연 파일
- 플러그인·훅이 꺼졌거나 신뢰되지 않은 세션
- 훅이 관찰하지 않는 hosted·특수 도구
- 이미 시작된 대화형 프로세스의 후속 입력
- `--bare` 또는 `CLAUDE_CODE_SIMPLE=1`로 시작하고 Secure Onboard plugin을 명시적으로 전달하지 않은 Claude Code 세션

## 5. 사용자 경험

### 5.1 구체적 명령 요청

```text
사용자: `npm install adsf` 실행해 줘

판정: HIGH — AI 자동 실행 차단
요청 유형: 구체적 명령어
명령 출처: 사용자가 직접 제공
작업 요약: adsf npm 패키지 설치
명령 상태: 실행되지 않음 — 재확인 전 원문을 다시 제공하지 않음
```

### 5.2 의도 요청

```text
사용자: adsf 패키지를 설치해 줘

판정: HIGH — AI 자동 실행 차단
요청 유형: 의도 기반 요청
사용자 요청: adsf 패키지를 설치해 줘
명령 출처: AI가 의도에서 생성
작업 요약: adsf npm 패키지 설치
명령 상태: 실행되지 않음 — 재확인 전 예상 명령 원문을 제공하지 않음
```

AI가 사용자 명령을 변경했다면 최초 차단 시에는 변경 종류만 설명하고, 사용자가 재확인한 뒤 `사용자 요청 명령어`, `AI 실행 예정 명령어`, `차단된 명령어`를 함께 표시한다.

### 5.3 HIGH 재확인

최초 HIGH 응답은 짧은 ref와 exact 재확인 문구(예: `A1B2 명령을 직접 실행하겠습니다`)를 안내한다. Claude는 검증된 인간 prompt를, Codex는 모델 transcript와 분리된 Secure Onboard 소유 로컬 확인 채널을 사용한다. 유효한 재확인 뒤 AI는 영향을 다시 설명하고, 비밀값을 포함한 위험 명령 원문 bytes를 치환 없이 출처 라벨과 함께 처음으로 제공한다. 터미널 표시를 조작하는 제어문자만 예외로 가시적인 안전 표현으로 바꾸고 `표시 안전 변환본`으로 라벨링한다. 존재하는 출처만 표시하며 구체적 요청은 사용자 요청·AI 실행 예정·차단 명령을, 의도 요청은 AI 예상·AI 실행 예정·차단 명령을 구분한다. 이 단계는 실행 승인이 아니다. AI는 같은 명령이나 대체 도구를 호출하지 않고 `COMMAND_PREPARED`, Stop 원문 확인이 가능하면 `COMMAND_RESPONSE_VERIFIED`로 끝낸다.

사용자가 일반 터미널에서 실행했는지는 관찰할 수 없으므로 Secure Onboard는 실행 성공·실패를 기록하지 않는다.

## 6. 동작 불변식

### G1. 실제 도구 호출이 권위 있는 입력

의미 트리거와 AI 예상 명령은 사용자 설명에 사용한다. 실제 차단 판정은 `PreToolUse`의 도구 이름, shell/argv, cwd와 입력을 기준으로 한다.

### G2. HIGH만 차단

- HIGH: deny
- LOW: 실행 전 경고 후 클라이언트의 기존 approval 흐름으로 계속
- INFO: 로컬 기록 후 클라이언트의 기존 approval 흐름으로 계속

LOW·INFO를 허용할 때 Claude Code·Codex 자체 sandbox·권한 요청을 자동 승인하거나 우회하지 않는다.

### G3. HIGH 제공 뒤 AI 실행 없음

사용자 재확인은 텍스트 명령 제공만 허용한다. `COMMAND_PREPARED`·`COMMAND_RESPONSE_VERIFIED`에서 차단 대상 AI 도구 실행으로 가는 상태 전이는 없다. hook·scanner·제품 관리용 disclose helper는 별도 경로다.

### G4. 명령 출처 보존

사용자 메시지, AI 후보, 실제 tool input을 별도로 보존한다. 대상 파일 속 지시와 도구 출력은 사용자 명령이나 재확인으로 취급하지 않는다.

### G5. 실패 시 활성 작업 차단

보호 action의 검사 코어 오류, timeout, 상태·정규화·필수 로그 실패는 HIGH로 deny한다. LOW 경고 출력을 adapter가 유효하게 생성·방출하지 못한 실패와 GatePolicy 자체를 읽을 수 없는 bootstrap 실패도 HIGH deny다. command hook에는 client의 표시 ACK가 없으므로 실제 경고 표시 능력은 M0 fixture로 검증한다. read-only scan의 같은 검사 오류는 HIGH finding으로 보고하되 scan 자체를 deny하지 않는다. 훅 자체가 비활성·미신뢰·skip되거나 adapter 프로세스가 실행되지 못한 경우에는 코어가 유효한 deny를 반환할 기회가 없으므로 완전한 차단을 보장하지 않는다.

### G6. 캐시 hit도 사용자 절차 유지

캐시는 분석 비용만 줄인다. HIGH 차단과 재확인, LOW 경고, 매 시도 이벤트 기록은 항상 다시 수행한다.

## 7. 아키텍처

```text
[Prompt event]
      │
      ├─ adapter: client별 human provenance 검증 뒤 PromptContext 기록
      └─ skill/model: 분류·표현 보조, source 확정 권한 없음
      │
      ▼
[Claude Code / Codex가 tool call 계획]
      │
      ▼
[client PreToolUse adapter]
      │  native payload → HookEnvelope v1
      ▼
[shared local core]
      ├─ HookEnvelope → ActionRequest
      ├─ activation registry
      ├─ command/action normalizer
      ├─ deterministic rules
      ├─ validated AI assessment (M2)
      ├─ short-lived pending HIGH state + disclose formatter
      ├─ evidence/action cache
      └─ local activity history
      │
      ▼
[ActionDecision v1]
      ├─ HIGH: client-specific deny
      └─ LOW/INFO: native client approval 흐름 유지
```

### 7.1 클라이언트 어댑터

- 클라이언트별 native hook 입력을 공통 `HookEnvelope`로 변환한다. 공용 코어가 이를 `ActionRequest`로 정규화한다.
- 공용 코어의 `HIGH`를 해당 클라이언트의 올바른 deny 출력으로 변환한다.
- malformed output이 실행 계속으로 이어질 수 있으므로 scanner child 오류를 어댑터가 명시적 deny로 변환한다.
- core timeout·exit·schema failure에는 target을 재판정하지 않는다. 보호 action은 고정 `guardrail.scan_failure` adapter fallback decision, read-only scan은 gate 없는 failed fallback `ScanReport`를 사용한다.
- Claude Code 동기식 command hook에서 HIGH는 exit 0의 유효 JSON `{"systemMessage":"<사용자용 경고>","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"<차단 사유>"}}`로 변환한다. LOW는 top-level `systemMessage`로 경고하되 permission decision을 생략하고, INFO도 명시적 allow 없이 기존 permission 흐름을 유지한다. async hook은 실행 게이트에 사용하지 않는다.
- Codex HIGH deny, LOW 경고와 INFO continue는 공식 hook 응답 형식을 사용하며 unsupported 필드를 반환하지 않는다. client별 exact 출력 bytes와 terminal에서의 경고 관찰 결과를 M0 fixture로 고정한다.
- 여러 훅의 실행 순서에 의존하지 않는다.
- 배포하는 `hooks.json`에 명시적 `timeout`을 선언한다. 두 CLI의 기본값은 대부분 600초여서, 선언하지 않으면 어댑터가 멈췄을 때 사용자 세션이 최대 10분 정지한다. 이 값은 어댑터 정상 경로의 실측 지연과 fail-open 노출 시간을 함께 보고 M0에서 고정한다.
- plugin/hooks 설치·활성과 self-test를 `status`에 노출한다. 사용자 scope `ON|OFF`와 유효 보호 `VERIFIED_ACTIVE|OFF|UNKNOWN`을 분리하고, Codex hash trust와 Claude workspace/plugin 상태를 클라이언트별로 구분한다.

### 7.2 공용 코어

공용 코어는 클라이언트 UI 문구가 아니라 다음 순수 계약을 담당한다.

- 활성 범위 판정
- command origin과 action kind 정규화
- 대상·명령·환경 지문 생성
- 결정론적 finding 생성. 검증된 AI assessment 병합은 M2
- cache hit/miss와 무효화
- `HIGH|LOW|INFO` 판정
- redacted local event 기록

HIGH 원명령은 활동 로그나 캐시에 넣지 않는다. 명령 제공을 위해 exact invocation identity HMAC과 원문 invocation/display를 사용자 전용 `PendingBlock`에 최대 10분 보관한다. secret 출처에 따른 치환이나 terminal control escape는 하지 않는다. 모델은 action/ref 인자 없는 helper만 호출하고, 어댑터가 신뢰된 session·재확인 context를 주입하면 코어가 내부 ID와 single-use pending을 resolve한다. Stop 훅이 action-bound nonce·marker·digest를 마지막 assistant 응답 원문에서 확인한 뒤에만 `high_command_response_verified`로 기록한다. UI 전달·렌더 완료·사용자 열람은 증명하지 않는다.

정규화된 필드와 enum은 `report-template.md`를 따른다.

## 8. 판정 정책

### 8.1 기본 규칙

| 단계 | 근거 | 기본 판정 |
|------|------|-----------|
| M1 | 고정 악성 테스트 시그니처·package artifact 정확히 일치 | HIGH |
| M1 | 보호 action의 검사 불완전, timeout, 정규화·필수 로그 실패 | HIGH |
| M1 | 비밀·환경변수·내부 URL의 단순 존재 | LOW |
| M1 | 고정 fixture의 확장자·형식 불일치 같은 단독 신호 | LOW |
| M1 | 지원 검사가 끝났고 경고할 근거 없음 | INFO |
| M2 | 설치·실행 진입점에서 외부 코드 실행·비밀 유출 sink까지 확인 | HIGH |

설치 훅이나 스크립트 존재만으로 무조건 HIGH로 만들지 않는다. 현재 요청한 작업에서 실제 도달 가능한지, sink와 연결되는지, 확정 악성 데이터가 있는지를 종합한다. 결정론적 HIGH는 AI가 낮추지 못한다. AI 상관분석에 의한 승격은 M2에서 검증된 assessment 계약을 추가한 뒤 활성화한다.

### 8.2 안전 보증 금지

INFO는 검사 범위에서 경고 근거를 찾지 못했다는 뜻이다. 미래 버전, 바뀐 원격 패키지, scan-to-use 사이 변경과 알려지지 않은 공격까지 안전하다고 보증하지 않는다.

## 9. 설치·상태·데이터

### 9.1 설치와 활성화

플러그인 adapter와 공용 코어는 사용자 소유 영역에 한 번 설치하고 프로젝트 모드는 local registry의 활성화 상태로 관리한다. 실제 프로젝트별 package/plugin 설치는 제공하지 않는다.

**Codex에서는 설치·활성화만으로 보호가 시작되지 않는다.** Codex는 번들 훅 정의의 현재 hash에 대해 사용자가 검토·신뢰하기 전까지 그 훅을 skip한다. 따라서 설치 안내는 `/hooks`에서 정의를 검토·신뢰하는 단계와, 신뢰 이후 새 세션이 필요한지 여부를 반드시 포함한다. 제품 업데이트로 훅 정의가 바뀌면 신뢰가 만료되므로 업데이트 안내에도 같은 단계를 넣는다. 신뢰 전 상태는 `VERIFIED_ACTIVE`가 아니라 `UNKNOWN`이며 보호 중이라고 표시하지 않는다. Claude Code에는 이에 대응하는 훅 단위 신뢰 절차가 없어 두 클라이언트의 설치 흐름이 비대칭이다. 프로젝트 설정·환경변수·대상 파일·도구 출력이 제안하는 위치나 상태 변경을 권위 있는 관리 입력으로 받아들이지 않는다. 다만 같은 사용자 권한으로 이미 실행된 코드는 사용자 영역 파일을 직접 변조할 수 있으므로 권한 분리나 변조 방지를 보장하지 않는다.

프로젝트 비활성화는 전역 활성화보다 우선한다. 비활성화는 다음 작업부터 적용되고, 대상 파일의 자연어 지시나 AI 도구 출력은 Secure Onboard 자체 registry 변경 요청으로 인정하지 않는다. Claude 프로젝트/local 설정은 plugin 또는 hooks를 비활성화할 수 있고 Codex의 trusted project 설정은 hooks를 끌 수 있으므로 유효 보호 상태를 `OFF`로 만들 수 있다. Codex의 project-scoped plugin enable은 공식 기능으로 가정하지 않는다. 현재 세션을 확인할 근거가 부족하면 `UNKNOWN`이며 scope ON을 보호 활성으로 오인하지 않는다. 다만 실제 지원 PreToolUse가 도착한 action 하나는 정상 게이트하되 다른 action까지 보호됐다고 확장하지 않는다.

### 9.2 로컬 활동 기록

기본 보존은 30일 또는 최근 1,000건이다. 원문 명령·비밀값·절대 경로 대신 사용자별 HMAC ID, 등급, action kind, rule ID, 상태, 버전과 시각을 저장한다. 사용자는 조회·삭제할 수 있으며 로그 완전성이나 변조 방지를 주장하지 않는다.

### 9.3 검사 캐시

증거 캐시와 작업 판정 캐시를 분리한다.

- 증거 캐시 키: 대상 콘텐츠·권한·심볼릭 링크 지문 + 코어·규칙 bundle·보안 데이터 버전 + analysis profile digest
- 작업 판정 캐시 키: 증거 지문 + exact tool/command + 물리 cwd·resolved 실행 파일·effective 환경/설정 지문 + gate policy digest

경로와 mtime만으로 재사용하지 않는다. M1 remote registry npm install은 HIGH deny하고 action cache를 bypass한다. effective executable·환경을 입증하지 못한 다른 tool도 action cache를 bypass한다. cache 오류는 stale allow 대신 fresh scan으로 복구하며 writeback만 실패하면 fresh decision을 유지하고 bypass한다. 마지막 접근 시각은 지문과 보존 보장에 포함하지 않는다. AI assessment cache는 M2 계약 전에는 만들지 않는다.

M1 검사 코어는 별도 registry lookup이나 artifact download를 하지 않고 exact local `.tgz` 같은 immutable artifact만 권위 입력으로 사용한다. lockfile이나 npm cache만으로 remote install의 실제 bytes를 검증했다고 주장하지 않는다. remote registry install은 artifact-to-execution 결합을 구현하기 전까지 HIGH로 deny하고 action cache를 bypass한다. online resolve는 데이터 전송·proxy/auth·오류 정책을 별도 고지한 후속 opt-in 기능이다.

## 10. 데이터·보안 경계

- 외부 프로젝트를 Claude Code·Codex가 읽고 분석하는 것은 허용한다.
- 해당 코드와 프롬프트의 공급자 전송·보존은 각 CLI와 계정 정책을 따른다.
- Secure Onboard는 별도 제3자 분석 서비스에 원문을 자동 업로드하지 않는다.
- 로그·캐시·hook output에는 원문 비밀을 남기지 않는다.
- 위험 명령은 명시적 재확인 뒤 출처 라벨과 함께 보여 준다. 비밀값의 출처와 무관하게 secret 원문 bytes를 치환 없이 제공하며 그 노출 가능성을 영향 설명에 포함한다. ANSI/OSC·양방향 제어문자·NUL은 예외로 항상 가시적인 안전 표현으로 바꾼다.
- 프로젝트 내부 설정, ignore, 실행 파일과 환경 주입을 검사 규칙·로그·캐시 위치의 신뢰 기반으로 사용하지 않는다. Claude 프로젝트/local 설정이 plugin/hooks를, Codex trusted-project 설정이 hooks를 끌 수 있다는 비보장은 별도다.

## 11. 검증 전략

실행 oracle의 정본은 `use-cases.md` 하나다. M0는 native hook payload·deny·continue·result·Stop·status를 먼저 고정하고, M1은 그 fixture 위에 제품 규칙과 사용자 흐름을 추가한다. EICAR는 격리된 opt-in 테스트에서 고정 commit의 `standard/eicar.com.txt` 단일 68-byte artifact만 signature/cache fixture로 사용한다. install hook 도달성·secret 흐름·prompt injection·권한은 M2 합성 fixture다.

## 12. 마일스톤

1. **M0 — hook tracer-bullet:** 두 CLI의 native payload·deny/continue·result/Stop·status와 고정 sentinel 규칙
2. **M1 — fixture-backed end-to-end alpha:** npm 설치·파일 열기·읽기 전용 검사, 결정론적 규칙, 명령 출처·재확인·공개, scope·로그·캐시
3. **M2 — 심층 분석:** 설치 훅 도달성, 스크립트·난독화·비밀 유출 경로, 검증된 AI 승격, 추가 tool coverage
4. **M3 — 배포:** Windows·macOS 패키징, 설치·업데이트·상태·삭제, 지원 버전 matrix
5. **M4 — 평판 데이터·범위 확장:** 고정·검증된 MAL/OSV 데이터팩, 다른 생태계, 선택 정적 분석기

## 13. 구현 착수 판정

판정은 다음과 같다.

- **M0 hook tracer-bullet: GO**
- **전체 M1 제품 구현: NO-GO**
- **M2 심층 분석: NO-GO**

M1은 다음 조건을 모두 충족한 뒤 시작한다.

1. 두 CLI의 native hook payload와 deny·continue·result·Stop 동작을 fixture로 고정
2. HIGH deny 뒤 차단 대상 tool handler 실행·target command process start 0 증명
3. 클라이언트별 plugin/hooks OFF·self-test·확인 불가 상태 표시 정의
4. 모든 필수 M1 fixture의 정확한 bytes·path·permission·prompt·tool payload·expected JSON 고정
5. 사용자별 SQLite의 schema·migration·locking·transaction/outbox·crash recovery와 canonical encoding, HMAC key 손실·보관·회전, TTL·용량·resource limit fixture 확정
6. short-ref disclosure helper와 구조화 scan helper의 신뢰 transport·single-use/idempotency fixture 고정
7. `NOT_COVERED`와 지원 grammar parse failure의 구분, case×client/version×OS 적용 행렬 고정
8. Codex 모델 transcript는 재확인 source로 사용하지 않고 제품 소유 로컬 확인 채널의 action-bound fixture를 고정

M0는 실제 npm/EICAR 분석기나 캐시·재확인 UI를 만들지 않고 고정 sentinel로 hook 경계만 증명한다. 이 증거 전에는 “M1 구현 완료”, “배포 준비 완료”, “모든 실행 보호”, “강제 보안 통제”라고 표시하지 않는다.
