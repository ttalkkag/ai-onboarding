# secure-onboard

> 상태: **M0 hook tracer-bullet GO / 전체 M1 NO-GO** — 현재 공식 훅 계약을 기준으로 지원 버전·OS별 실제 입력, deny, result, Stop 동작을 fixture로 고정하는 구현만 착수한다.

Secure Onboard는 외부에서 받은 코드·파일·프로젝트를 다루는 **Claude Code CLI와 Codex CLI의 선택형 로컬 실행 가드레일**이다. 사용자가 AI에 실행·설치·열기·설정·권한 변경·보안 검사를 요청하면 의미를 인식하되, M1에서 실제로 게이트하는 범위는 npm 설치·로컬 파일 열기이고 명시적 읽기 전용 검사를 별도 지원한다. 설정·권한·build/test 같은 요청은 M1에서 `NOT_COVERED`다.

## 제품 경계

- 개인 컴퓨터의 사용자 영역에 공용 코어와 클라이언트 adapter를 한 번 설치하고 언제든 비활성화·삭제할 수 있다.
- 프로젝트 모드는 별도 프로젝트 설치가 아니라 사용자 로컬 registry의 활성화 상태로 관리한다. 전역 활성화 또는 선택한 프로젝트만 활성화할 수 있으며, 프로젝트 비활성화가 전역 활성화보다 우선한다.
- 활성화 상태·로그·캐시는 검사 대상 저장소가 아니라 사용자 소유 로컬 영역에 둔다.
- Claude Code·Codex의 로컬 도구 호출만 다룬다. Finder, 파일 탐색기, 일반 터미널, 다른 IDE·프로세스, 비활성화된 플러그인과 훅이 관찰하지 못하는 도구 경로는 범위 밖이다.
- 관리형 배포가 아니므로 강제 보안 통제나 완전한 실행 차단 수단이 아니다.

`로컬 AI CLI`는 도구가 로컬에서 실행된다는 뜻이지 모델이 로컬에서 실행된다는 뜻이 아니다. Claude Code·Codex가 읽은 프롬프트와 코드는 각 공급자·계정의 데이터 정책을 따른다. Secure Onboard를 끄는 것만으로 AI 전송이 차단되지는 않는다.

## 판정과 동작

| 판정 | AI 동작 | 로컬 기록 |
|------|---------|-----------|
| `HIGH` | 실행 직전 도구 호출 차단. 사용자가 다시 실행 의사를 밝히면 영향 설명과 위험 명령을 텍스트로 제공하지만 AI가 대신 실행하지 않음 | 탐지·차단·재확인·명령 제공 |
| `LOW` | 실행 전에 경고와 설명을 보여 준 뒤 클라이언트 고유 권한 확인을 유지한 채 계속 | 경고·실행 결과(관찰 가능한 경우) |
| `INFO` | 별도 보안 경고 없이 클라이언트 고유 권한 확인을 유지한 채 계속 | 판정·실행 결과(관찰 가능한 경우) |

등급은 정확히 `HIGH`, `LOW`, `INFO`만 사용하며 `HIGH`만 Secure Onboard가 차단한다. 결정론적으로 확인된 `HIGH`는 AI가 낮출 수 없다. AI가 실제 판정을 높이는 기능은 검증된 assessment 계약을 추가할 M2 범위이며, M1은 결정론적 규칙만 사용한다. 보호 작업의 필수 검사·상태·기록이 실패하면 `HIGH`로 막고, 읽기 전용 검사 실패는 `HIGH` finding으로 보고한다.

“검사해 줘”라는 읽기 전용 보안 검사 자체는 차단 대상이 아니다. 검사에서 HIGH를 발견하면 결과를 보고하고, 이후 같은 대상을 설치·열기·실행하려는 별도 작업은 당시 대상과 context를 다시 검사해 새로 판정한다.

HIGH 명령을 사용자가 일반 터미널에서 실행하면 Secure Onboard는 실행 여부와 결과를 알 수 없다. 따라서 로그에는 `executed`가 아니라 마지막 assistant 응답 원문에 명령 payload가 포함됐음을 Stop 훅으로 확인한 `high_command_response_verified`까지만 기록한다. 이는 UI 전달·렌더 완료·사용자 열람 증명이 아니다.

## 명령어 표기

- 사용자가 명령 문자열을 직접 입력했다면 `사용자 요청 명령어`로 표시한다.
- “설치해 줘”, “이 파일을 열어 줘”처럼 목적만 요청했다면 AI가 만든 값을 `AI 예상 명령어`로 표시한다.
- AI가 실제 도구 호출을 만들면 `AI 실행 예정 명령어`, 훅이 거부했다면 `차단된 명령어`를 별도로 표시한다.
- 사용자 명령과 AI 실행 예정 명령이 다르면 둘 다 보여 주고 차이를 설명한다.

위험 명령 자체는 명시적 재확인 뒤 보여 준다. 모델에는 내부 ID나 ref 선택을 맡기지 않고, 공용 코어가 현재 session·action과 정확히 연결된 명령만 반환한다. 비밀값의 출처와 무관하게 secret을 포함한 차단 명령 bytes를 치환 없이 그대로 제공하므로 비밀 노출 가능성을 영향 설명에 포함한다. 다만 ANSI/OSC·양방향 제어문자·NUL처럼 터미널 표시 자체를 조작하는 bytes는 예외로, 항상 눈에 보이는 안전 표현으로 바꾸고 `표시 안전 변환본`임을 밝힌다. 화면에서 보는 명령과 실제로 복사되는 명령이 달라지면 사용자가 위험을 이해하고 선택한다는 전제가 무너지기 때문이다. 차단 당시 exact invocation과 원문 보존을 신뢰할 수 없는 제품 장애에서는 명령을 추측해 만들지 않는다. 원문은 사용자별 단기 pending 상태에만 최대 10분 보관하며 로컬 활동 로그와 캐시에는 명령 원문이나 비밀값을 저장하지 않는다.

## 구현 구조

```text
Claude Code plugin ─┐
                    ├─ PreToolUse adapter → shared local core → rules/cache/log
Codex plugin ───────┘
```

의도 인식은 사용자 경험을 돕지만 실제 차단의 권위 있는 입력은 `PreToolUse`가 받은 실행 직전 도구 호출이다. 결과 훅은 LOW·INFO 작업의 관찰 가능한 성공·실패 기록에만 사용한다. Claude Code는 성공 `PostToolUse`와 실패 `PostToolUseFailure`, Codex는 `PostToolUse` 결과를 클라이언트 어댑터가 공통 outcome으로 정규화한다.

저장소에 남아 있는 `.skills/sample`과 `.agents/skills`·`.claude/skills`·`.codex/skills` 링크는 개발 예시이며 Secure Onboard 제품 배포물이 아니다. 제품 구현을 이 공용 스킬 링크에 추가하지 않는다.

M1 범위는 `npm 패키지 설치`, `로컬 파일 열기`, `명시적 읽기 전용 검사`를 고정 fixture로 관통하는 end-to-end alpha로 확정했다. build/test/configure 등 훅이 관찰해도 M1 action kind 밖인 호출은 먼저 `NOT_COVERED`로 통과시키며 `INFO` 판정이나 보호 성공으로 표시하지 않는다. M0에서는 고정 sentinel만으로 Windows·macOS의 Claude Code CLI와 Codex CLI hook 경계를 검증한다. OSV/MAL 데이터팩과 광범위한 생태계 분석은 후속 마일스톤이다.

## 문서 안내

- [CONTEXT.md](CONTEXT.md): 제품 용어
- [기획서](docs/plan/proposal.md): 제품 범위·아키텍처·마일스톤
- [실행 게이트 플로우](docs/plan/workflow.md): 상태 전이와 명령 출처 규칙
- [결정 레지스터](docs/plan/decisions.md): 확정 사항과 검증이 필요한 구현 가정
- [출력·로컬 기록 계약](docs/plan/report-template.md): 사용자 표시와 스키마
- [수용 기준](docs/plan/use-cases.md): 구현 테스트 oracle
- [최신 문서 검토](docs/review/README.md): 구현 착수 판정
- [AI CLI 사용자 프롬프트](docs/user-prompt.md): 1,500자 이내 실행 입력
- [전체 구현 시스템 프롬프트](docs/system-prompt.md): 자율 구현·상세 검증 지시

`docs/research/`는 탐지 근거, `docs/draft/`는 이전 설계와 참고 자료다. 두 디렉터리의 내용은 `docs/plan/`과 충돌할 때 구현 계약으로 사용하지 않는다.
