---
name: js-reverse
description: 프론트엔드 JavaScript 분석에서 서명 로직 위치 지정, 페이지 관찰·포렌식, 런타임 샘플링, 로컬 환경 재현과 증거 출력에 사용합니다. MCP를 사용하는 경우 서버가 실제로 공개한 도구 이름과 스키마를 먼저 확인합니다.
---

# MCP 프론트엔드 JS 리버스 엔지니어링 사양

## 적용 범위

이 기술은 작업이 다음 시나리오에 해당할 때 먼저 사용됩니다.

- 인터페이스 서명, 암호화 매개변수 및 위험 제어 필드를 찾습니다.
- 페이지 요청 링크 및 스크립트 소스 관찰
- 런타임 시 함수를 참여 반환 값으로 가져옵니다.
- 특정 XHR/Fetch/WebSocket의 트리거 포인트를 추적합니다.
- 로컬 재생 및 환경 개선을 위해 페이지 증거를 다시 Node로 가져옵니다.

대상이 바이너리, APK, PE, ELF, DLL, SO인 경우 대신 `ida-reverse`, `radare2` 또는 `reverse-engineering`를 사용하세요.

## 클라이언트별 도구 매핑

아래 `js-reverse_*` 이름은 이 문서가 작성될 때 사용한 클라이언트 별칭입니다. 현재 큐레이션에는 MCP 서버 구성이나 해당 이름의 도구가 포함되어 있지 않습니다. 먼저 MCP 클라이언트가 실제로 공개한 도구 목록을 확인하고, 이름과 입력 스키마가 일치할 때만 호출하세요.

현재 작업에서 `jshookmcp`, `JS hook`, `CDP`, 브라우저 중단점, 네트워크 차단, SourceMap 또는 AST 난독화 해제를 언급해도 이 방법론을 사용합니다. jshookmcp가 등록·활성화되어 있다면 실제 공개된 기능을 우선 확인하고, 없으면 정적 분석과 로컬 재현 경로를 사용하세요.

전제 조건: `jshookmcp`는 로컬 베어 명령 도구가 아니라 먼저 다운로드/등록/활성화해야 하는 MCP 서버입니다. Claude MCP 구성에서 액세스하고 활성화한 후에만 관련 도구 인터페이스가 실제로 호출될 수 있습니다.

레거시 매핑 참고:

- `list_scripts` -> `js-reverse_list_scripts`
- `get_script_source` -> `js-reverse_get_script_source`
- `search_in_sources` -> `js-reverse_search_in_sources`
- `break_on_xhr` -> `js-reverse_break_on_xhr`
- `evaluate_script` -> `js-reverse_evaluate_script`
- `get_paused_info` -> `js-reverse_get_paused_info`
- `set_breakpoint_on_text` -> `js-reverse_set_breakpoint_on_text`
- `list_network_requests` -> `js-reverse_list_network_requests`
- `get_request_initiator` -> `js-reverse_get_request_initiator`
- `get_websocket_messages` -> `js-reverse_get_websocket_messages`
- `take_screenshot` -> `js-reverse_take_screenshot`
- `new_page` -> `js-reverse_new_page`
- `navigate_page` -> `js-reverse_navigate_page`
- `select_page` -> `js-reverse_select_page`
- `select_frame` -> `js-reverse_select_frame`
- `pause/resume` -> `js-reverse_pause_or_resume`

나중에 도구 이름 접두사가 변경되면 이 섹션을 먼저 업데이트하고 실행 중에 임시 추측을 하지 마십시오.

### jshookmcp의 위치 지정

- 역할: 독립적인 마스터 제어가 아닌 `js-reverse`의 실행 측면 강화
- 적합 대상: 브라우저 자동화, CDP 디버깅, JS Hook, 네트워크 차단, SourceMap 재구성, AST 이해 지원
- 호출 전제 조건: 먼저 `@jshookmcp/jshook`을 다운로드하여 MCP 클라이언트 구성에 등록한 다음 서버가 활성화되어 있는지 확인하세요.
- 권장 항목: `Observe → Capture → Rebuild`를 눌러 실행하되 `Observe/Capture` 단계에서 jshookmcp의 브라우저 및 후크 기능 호출에 우선순위를 둡니다.
- 무엇이든 분석기와의 관계: 둘 다 브라우저/네트워크 측 포렌식을 수행할 수 있습니다. everything-analyzer는 패킷 캡처 및 HTTP 분석에 더 중점을 두는 반면, jshookmcp는 JS 런타임, CDP, Hook 및 소스 코드 이해에 더 중점을 둡니다.

## 핵심 원칙

- `Observe-first`
- `Hook-preferred`
- `Breakpoint-last`
- `Rebuild-oriented`
- `Evidence-first`

먼저 페이지를 관찰한 후 샘플링을 최소화하고 로컬에서 환경을 보완합니다. 증거 수집을 건너뛰지 말고 직접적으로 환경을 추측해 보세요.

## 5단계 워크플로

### 1. Observe

대상: 환경을 추측하지 않고 먼저 대상 요청, 관련 스크립트, 후보 기능을 확인합니다.

기본 동작:

- `js-reverse_new_page` 또는 `js-reverse_navigate_page`를 사용하여 대상 페이지를 엽니다.
- `js-reverse_list_network_requests`를 사용하여 대상 요청을 찾으세요.
- `js-reverse_get_request_initiator`를 사용하여 호출 소스를 역추적하세요.
- `js-reverse_list_scripts`, `js-reverse_search_in_sources`를 사용하여 스크립트 범위를 좁힙니다.

다음을 생산해야 합니다.

- 대상 요청 URL 또는 특성
- 개시자 단서
- 의심스러운 스크립트 URL
- 초기 작업 기록

### 2. Capture

목표: 대상 요청을 최소한으로 방해하는 샘플링을 수행하고 매개변수 샘플, 호출 시퀀스 및 런타임 증거를 얻습니다.

규칙:

- 우선순위 `js-reverse_break_on_xhr`
- 우선순위 `js-reverse_evaluate_script` 간단한 런타임 관찰 수행
- `js-reverse_get_paused_info` 치고 나서 먼저 보세요
- 필요할 때 다시 사용하세요 `js-reverse_set_breakpoint_on_text`

### 3. Rebuild

목표: 페이지 증거를 로컬 반복 가능한 노드 재생 자료로 구성합니다.

규칙:

- 로컬 보충 환경은 페이지 관찰 증거를 기반으로 해야 합니다.
- 판타지 보완은 불가 `window/document/navigator/crypto/storage`
- 한 번에 하나의 최소 원인 패치 결정만 기록됩니다.

### 4. Patch

목표: 로컬 스크립트가 대상 매개변수를 안정적으로 실행할 때까지 오류 보고 및 첫 번째 분기 드라이버에 따라 환경을 보완합니다.

규칙:

- 먼저 부족한 부분을 살펴보고 부족한 부분을 채워보세요.
- 한 번에 하나의 최소 패치 결정만 내립니다.
- 각 패치 후 즉시 다시 테스트
- 각 패치는 작업 기록에 기록됩니다.

### 5. DeepDive

목표: 로컬 실행 후 난독화 해제, 제어 흐름 복원 및 비즈니스 로직 정화.

규칙:

- 현재 작업이 서명 발행만 하는 것이라면 이 단계를 다운그레이드할 수 있습니다.
- 알고리즘 링크를 장기간 재사용하려면 이 단계를 반드시 수행해야 합니다.

## 구현 요구 사항

- 모든 중요한 단계는 로컬 작업 아티팩트에 기록됩니다.
- 도구가 호출되는 이유를 설명할 수 없으면 호출하지 마세요.
- 증거를 직접 확보하려면 `js-reverse_*` 또는 jshookmcp의 기성 MCP 기능을 우선적으로 사용하세요. 먼저 기능을 다시 생성하는 스크립트를 작성하지 마십시오.
- 실패한 경우 `references/fallbacks.md`를 눌러 돌아가세요.
- 출력은 다음과 같습니다 `references/output-contract.md`

## 꼭 읽어야 할 인용문

- 자동화 입구:`references/automation-entry.md`
- 매개변수 기본값: `references/tool-defaults.md`
- 작업 입력 템플릿: `references/task-input-template.md`
- MCP 전용 작업 배치: `references/mcp-task-template.md`
- 과제 제품: `references/task-artifacts.md`
- 국소 재발: `references/local-rebuild.md`
- 보충 환경: `references/env-patching.md`
- 노드 재발: `references/node-env-rebuild.md`
- 계측:`references/instrumentation.md`
- AST 난독화 해제: `references/ast-deobfuscation.md`
- 대체: `references/fallbacks.md`
- 출력 계약:`references/output-contract.md`

---

## 라우팅 컨텍스트

**상류 입구**: `../../SKILL.md`(마스터 제어), `../../routing.md`
**업스트림 대안**:
- everything-analyzer MCP(포트 23816)용 브라우저 도구를 대안으로 또는 추가로 사용할 수 있습니다.
- jshookmcp는 더 강력한 브라우저/CDP/Hook/Network/SourceMap/AST 실행 표면 역할을 합니다.
- `../reverse-engineering/methodology.md` (대상이 프런트엔드 JS가 아닌 경우)

**다운스트림 내보내기**:
- 환경보완 필요 → `references/env-patching.md`
- 로컬에서 재현 필요 → `references/local-rebuild.md` / `references/node-env-rebuild.md`
- 헷갈릴 필요가 있어요 → `references/ast-deobfuscation.md`
- 길이 없을 때 돌아가기 → `references/fallbacks.md`

**형제 연관 모듈**: everything-analyzer MCP(브라우저 자동화 및 HTTP 캡처 기능은 서로 보완할 수 있음)

---

## 주문형 부트스트랩

현재 큐레이션에는 MCP 자동 등록 스크립트가 포함되어 있지 않습니다. 아래 항목은 외부 도구를 별도로 구성할 때의 경계입니다.

### 자동화 기능 경계

| 능력| 자동으로 등록할 수 있습니다| 방법| 설명|
|------|-----------|------|------|
| jshookmcp | ✗ | MCP 클라이언트에 별도 등록 | Node.js 22.12 이상 또는 24.x 필요 |
| everything-analyzer | ✗ | 별도 프로젝트와 서비스 구성 필요 | 이 저장소에 포함되지 않음 |
| Node.js | ✗ | 공식 배포판 또는 패키지 관리자로 설치 | 런타임 종속성 |

### jshookmcp 등록 예

```json
{
  "command": "npx",
  "args": ["-y", "@jshookmcp/jshook@0.3.3"]
}
```

### 주의할 점

- `jshookmcp` 등록 후에도 AI 클라이언트에서 MCP 서버를 호출하려면 **활성화**해야 합니다.
- 예시는 2026-07-14에 검토한 `0.3.3`을 의도적으로 고정합니다. npm의 2026-07-15 최신 릴리스는 `0.3.4`이므로, 업그레이드할 때는 릴리스 노트·도구 스키마·보안 권고를 다시 검토하세요.
- `everything-analyzer`는 pnpm 및 별도 프로젝트 소스 코드가 필요하며 이 저장소가 자동 설치하지 않습니다.
- jshookmcp의 현재 런타임 요구사항은 Node.js 22.12 이상 또는 24.x입니다.
