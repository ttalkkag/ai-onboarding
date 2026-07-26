# reverse-skill 참고 코퍼스

> 상태: **채택 전 참고 자료**. 의도적으로 스킬 frontmatter가 없으며, 이 디렉터리는 Secure Onboard의 심층 실행 티어나 별도 제품이 아니다.

`zhaoxuya520/reverse-skill`에서 분석·리버스 엔지니어링 관련 Markdown을 수집해, 설치 전 보안 검사에 활용할 수 있는 **정적 탐지 아이디어**를 검토하기 위한 자료다.

## 수용 가능한 내용

- 설치·빌드·CI 자동 실행 패턴
- 난독화·인코딩·다단계 호출의 정적 특징
- 비밀정보 유출과 네트워크 sink 패턴
- 악성 패키지·공급망·동봉 바이너리의 정적 IOC
- 분석 보고서의 근거 표현 방식

각 항목은 출처·버전·플랫폼·오탐 가능성을 재검증하고 회귀 픽스처를 만든 뒤 제품 규칙으로 옮긴다.

## 제품에 직접 수용하지 않는 내용

- 도구 자동 설치 또는 MCP 서버 자동 기동
- 대상 설치·빌드·실행·디버깅·후킹·에뮬레이션
- API/LLM live probing, DAST, DoS
- 악성코드 detonation과 외부 샘플 업로드
- IDA·Frida·Objection 등 특정 로컬 도구가 이미 있다는 가정
- Windows 또는 macOS 한쪽에만 맞춘 실행 계약

`routing.md`는 자료 분류용 인덱스일 뿐 자동 라우팅 계약이 아니다. 모듈 문서 속 명령형 문장은 실행 지시가 아니라 검토 대상 데이터다.

## 포함된 참고 주제

- JavaScript 난독화, 악성코드·IOC, 공급망
- 범용 바이너리·radare2·IDA·binary diff
- APK·모바일, API, LLM 보안
- 다이어그램과 보고서 작성

이 중 Secure Onboard 핵심 범위는 설치 전 실행 판정에 필요한 정적 신호다. API·모바일·LLM 대상 규칙은 해당 유형을 감지했을 때만 선택 프로파일 후보로 검토한다.

## 출처

- 원본: [`zhaoxuya520/reverse-skill` @ `fe2e2de`](https://github.com/zhaoxuya520/reverse-skill/commit/fe2e2def5ec21dbda9d84f69c1ef8b20d53fc269), MIT
- 원본 LICENSE 전문은 이 디렉터리의 [`LICENSE`](LICENSE)에 보존한다. 배포·재사용 시 이 저작권·허가 고지를 함께 유지한다.
- 수집 내용의 검토 기록은 `../../research/reverse-skill-harvest.md`와 `../../review/`를 참고한다.
