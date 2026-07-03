---
name: docs-generator
description: |
  점진적인 공개를 통해 작업 중심의 기술 문서를 작성합니다. README, API 문서, 아키텍처 문서 또는 마크다운 문서를 작성할 때 사용하세요.
  또한 리버스 엔지니어링, 침투 테스트, CTF 또는 보안 분석 작업이 끝날 때 이 완성된 기술을 사용하여 사용자 프로젝트 디렉터리에 공식 보고서를 생성합니다.
  트리거 키워드: 보고서 작성, 문서 작성, 보고서, 글쓰기, 기술 문서, 보고서, 문서.
---

# Technical Documentation

글쓰기 스타일, 어조, 음성 안내를 받으려면 **The Engineer** 페르소나와 함께 `Skill(ce:writer)`를 사용하세요.

## 보안/역업무 문서 출력

역/침투/CTF/보안 분석 작업이 완료되면 **사용자 프로젝트 디렉터리**에 정식 기술 문서를 생성하는 역할을 담당합니다.

### 트리거 시간

1. 역 작업이 완료되고 핵심 결론이 도출되었습니다(알고리즘 복원, 시그니처 크래킹, 우회 솔루션 등).
2. 침투 테스트 완료, 취약점 발견 및 검증
3. CTF 문제가 해결되어 플래그를 얻었습니다.
4. 사용자가 "보고서/문서/작성"을 명시적으로 요청했습니다.

### 템플릿 선택

| 작업 유형| 템플릿 사용|
|---------|---------|
| APK/바이너리/역방향| `references/security-report-templates.md` → 리버스 엔지니어링 보고서|
| 침투 테스트/취약점 마이닝| `references/security-report-templates.md` → 침투 테스트 보고서|
| CTF 문제 해결| `references/security-report-templates.md` → CTF 작성|
| JS/Web 시그니처 리버스|`references/security-report-templates.md` → 서명 역신고|
| 일반 기술 문서| `references/templates.md` → 읽어보기 / API 문서|

### 출력사양

- **출력 위치**: 사용자의 현재 프로젝트 디렉터리(스킬 패키지 디렉터리 아님)
- **파일 이름 형식**:`YYYY-MM-DD_[유형]-[대상약칭]-report.md`
- **프로젝트에 `docs/` 디렉토리가 있는 경우**: `docs/` 아래에 우선순위를 지정하세요.
- **인코딩**: UTF-8
- **언어**: 사용자의 대화 언어를 따릅니다. (중국어 대화는 중국어 보고서 생성, 영어 대화는 영어 보고서 생성)

### 품질 요구 사항

- 모든 코드 블록은 직접 실행 가능하거나 명확한 컨텍스트를 가지고 있어야 합니다.
- placeholder/TODO이 없습니다
- 주요 결과는 증거로 뒷받침되어야 합니다.
- 재생산 단계는 제3자가 독립적으로 재생산할 수 있어야 합니다.
- 민감한 정보(실제 토큰, 비밀번호, 내부 URL)는 자리 표시자로 대체됩니다.

### 차트 통합

보고서를 생성할 때 시각적 차트를 생성하려면 적절한 위치에서 `diagram-generator` 스킬을 호출해야 합니다.

| 보고서 유형|추천 차트| 차트 종류|
|---------|---------|---------|
| 리버스 엔지니어링 보고서| 함수 호출 다이어그램, 데이터 흐름 다이어그램| Mermaid 순서도/시퀀스 다이어그램|
| 침투 테스트 보고서| 공격 경로 맵, 네트워크 토폴로지 맵| Mermaid 흐름도/그래프비즈|
| CTF Writeup | 문제 해결 아이디어 흐름도| Mermaid flowchart |
| JS 서명 역 보고서| 요청 링크 시퀀스 다이어그램, 알고리즘 흐름도| Mermaid 시퀀스 다이어그램/흐름도|

차트는 보고서 마크다운에 Mermaid 코드 블록으로 포함되어 GitHub/GitLab에서 직접 렌더링이 가능합니다.

---

## Core Principles

### 1. Progressive Disclosure

레이어에서 정보 표시:

| Layer | Content | User Question |
|-------|---------|---------------|
| 1 | One-sentence description | 그것은 무엇입니까?|
| 2 | 빠른 시작 코드 블록| 어떻게 사용하나요?|
| 3 | 전체 API 참조|내 옵션은 무엇입니까? |
| 4 | 아키텍처 심층 분석 | 어떻게 작동하나요? |

**경고, 주요 변경 사항 및 전제 조건은 맨 위에 표시됩니다.**

### 2. Task-Oriented Writing

```markdown
<!-- Bad: Feature-oriented -->
## AuthService Class
The AuthService class provides authentication methods...

<!-- Good: Task-oriented -->
## Authenticating Users
To authenticate a user, call login() with credentials:
```

### 3. 보여주세요, 말하지 마세요

모든 개념에는 구체적인 예가 필요합니다.

## Formatting Standards

- **문장 사례 제목**: '시작하기'가 아닌 '시작하기'
- **최대 3개 제목 수준**: 깊이가 깊어질수록 문서가 분할됨을 의미합니다.
- 코드 블록에 **항상 언어 지정**
- 내부 링크의 **상대 경로**
- 3개 이상의 속성이 있는 구조화된 데이터용 **테이블**

## Quality Checklist

- [ ] 테스트되고 실행 가능한 코드 예제
- [ ] 자리 표시자 텍스트 또는 TODO 없음
- [ ] 실제 코드 동작과 일치
- [ ] 모든 내용을 읽지 않고도 스캔 가능
- [ ] 독자는 다음에 무엇을 해야 할지 알고 있습니다.

## Anti-Patterns

| Problem | Fix |
|---------|-----|
| 텍스트의 벽 | 제목, 글머리 기호, 코드, 표로 구분|
|묻혀있는 중요한 정보| Warnings/breaking TOP의 변경사항|
| 누락된 오류 문서| 무엇이 잘못될 수 있는지 항상 문서화하세요.|

## Templates

README, API 엔드포인트 및 파일 구성 템플릿은 [references/templates.md](references/templates.md)를 참조하세요.

## Related Skills

- `Skill(ce:writer)` - 글쓰기 스타일, 톤, 목소리(엔지니어 페르소나 로드)
- `Skill(ce:visualizing-with-mermaid)` - 아키텍처 및 흐름도


---

## 주문형 부트스트랩

이 기술은 외부 도구에 의존하지 않으며 순수한 텍스트를 생성합니다. 부트스트랩이 필요하지 않습니다.

차트가 포함된 보고서를 렌더링해야 하는 경우 `diagram-generator/` 기술이 호출됩니다.

---

## 라우팅 컨텍스트

**업스트림 항목**: 모든 보안/역방향 스킬은 작업이 완료된 후 자동으로 이 스킬을 호출합니다.
**트리거 방법**:
- 자동: 작업 완료 후 행동 체인의 9단계로 실행됩니다.
- 수동: 사용자가 "보고서 작성", "문서 출력", "작성"이라고 말합니다.

**동일 레벨 관련 모듈**:
- `apk-reverse/` — APK 리버스 엔지니어링이 완료된 후 리버스 엔지니어링 보고서를 생성합니다.
- `ida-reverse/` — 바이너리 분석이 완료된 후 리버스 엔지니어링 보고서 생성
- `radare2/` — CLI 분석 완료 후 역보고서 생성
- `js-reverse/` — JS 서명 리버스 엔지니어링이 완료된 후 서명 보고서 생성
- `reverse-engineering/` — 일반 리버스 엔지니어링이 완료된 후 리버스 엔지니어링 보고서를 생성합니다.
- `field-journal/` — 보고서 내용은 진화 로그의 데이터 소스 역할도 합니다.

**보안 보고서 템플릿**: `references/security-report-templates.md`
**범용 문서 템플릿**: `references/templates.md`
