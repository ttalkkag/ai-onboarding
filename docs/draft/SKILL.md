# 폐기된 공용 저장소 스킬 초안

> **참고 자료 전용:** 2026-07-22 결정으로 이 설계는 대체됐다. 의도적으로 skill frontmatter가 없으며 제품 구현·설치·판정 입력으로 사용하지 않는다.

이 파일은 Secure Onboard를 하나의 저장소 스킬로 공유하고 프로젝트 전체를 `안전/위험`으로 판정하던 이전 방향의 흔적이다. 현재 제품은 사용자 컴퓨터에 설치하는 Claude Code·Codex별 플러그인, `PreToolUse` 어댑터와 공용 로컬 코어로 구성한다.

현재 계약은 다음 문서만 따른다.

- `../plan/decisions.md`: 확정 정책
- `../plan/proposal.md`: 제품 범위와 아키텍처
- `../plan/workflow.md`: HIGH/LOW/INFO 상태 전이
- `../plan/report-template.md`: 명령 출처와 로컬 기록 필드

`reverse-skill/`과 `scan.sh`에서는 정적 탐지 아이디어와 테스트 공격면만 가져올 수 있다. 기존 MED 등급, 프로젝트 단위 최종 판정, 공용 스킬 심볼릭 링크와 자동 실행 절차는 가져오지 않는다.
