# API 보안 테스트

> REST / GraphQL을 중심으로 WebSocket / SOAP 점검 지점을 함께 다룹니다.
> 발견부터 CI/CD 통합까지 10단계 방법론

> **안전 경계:** 쓰기 요청, 인증 우회, 속도 제한 및 자원 고갈 테스트는 명시적으로 승인된 범위와 격리된 테스트 환경에서만 수행합니다. 운영 환경에서는 비파괴 확인과 구성 검토를 우선합니다.

## 적용 가능한 시나리오

- REST API 보안 테스트(OpenAPI/Swagger 기반 또는 블라인드 테스트)
- GraphQL 보안 감사(인트로스펙션, 배치 쿼리, 별칭 과부하)
- WebSocket 보안 테스트
- JWT / OAuth 2.0 인증 테스트
- BOLA/IDOR/BFLA 인증 취약점 감지
- API 속도 제한 우회 및 DoS 테스트

## 10단계 테스트 프로세스

### 1단계: API 발견 및 정찰

```text
사전에 다음을 발견하십시오.
□ Vespasian: 관찰한 브라우저/HAR 트래픽에서 OpenAPI 또는 GraphQL 사양 후보 생성
□ Entropy: 확보한 OpenAPI 사양으로 테스트 시나리오를 생성하고, 사양이 없으면 승인된 범위에서 discover/--discover로 엔드포인트 후보 확인
□ Kiterunner/ffuf: 승인된 범위에서 문서화되지 않은 엔드포인트 후보 확인
□ 공통 경로 확인: /swagger.json, /openapi.json, /graphql, /api-docs

GraphQL 인트로스펙션(응답 최소화 순서):
  1. 표준 인트로스펙션 쿼리
  2. 단순화한 인트로스펙션 쿼리
  3. { __type(name: "Query") { name } }만 확인합니다(최소 감지).
```

### 2단계: 인증 테스트

```text
JWT 분석(jwt_tool/Burp):
□ alg:none 수용 여부: 헤더를 "alg":"none"으로 수정하고 서명을 지웁니다.
□ 알고리즘 혼동: 잘못 구현된 검증기가 RS256 공개키를 HS256 대칭키로 받아들이는지 확인
□ 약한 HMAC 키 사전 대입: jwt_tool -C -d wordlist.txt
□ 만료/위조된 클레임: exp/iat/sub/role 클레임 수정
□ kid 주입: 경로/SQL/LDAP 입력으로 안전하지 않은 키 조회가 발생하는지 확인

OAuth 2.0:
□ redirect_uri 제어 → 인증 코드 유출
□ PKCE/nonce/state 중 해당 흐름에 필요한 CSRF 바인딩 검증
□ 콜백 URL의 code/state 및 브라우저 저장소의 토큰 유출
□ PKCE 강제 여부 확인

GraphQL 인증:
□ 서버가 GET mutation을 405로 거부하는지 확인하고, 위반 시 쿠키 인증/CSRF 방어도 함께 검증
□ 일괄 질의 인증 우회
```

### 3단계: 인가 테스트(BOLA/IDOR/BFLA)

```text
BOLA(객체 수준 인증 우회):
□ 숫자 ID 순회: /user/1 → /user/2 → /user/3
□ UUID 변경
□ 사용자 이름/이메일 변경
□ Burp Autorize: 듀얼 세션 재생 비교

BFLA(기능 수준 인증 우회):
□ 일반 사용자 권한으로 관리자 API 호출
□ HTTP 메소드 전환: GET → PUT → PATCH → DELETE
□ API 버전 다운그레이드: /v2/admin → /v1/admin
□ 일괄 작업 주입: {"users": [1,2,3]} → {"users": [1,2,3,admin_id]}

도구: Burp Autorize, AuthMatrix, Entropy(malicious_insider persona)
```

### 4단계: GraphQL 특화 점검

```text
인트로스펙션 결과 → 불필요한 스키마 정보 노출 여부
별칭 과부하 → 승인된 테스트 환경에서 복잡도 제한 검증
일괄 쿼리 → 승인된 테스트 환경에서 배치/자원 제한 검증
필드 중복 → __typename × 500
지시문 오버로드 → 재귀적 @skip/@include
깊이 중첩 쿼리 → 깊이/비용 제한 검증
필드 제안 → 오류 메시지 정보 유출
GraphiQL/Playground 노출 → 운영 정책, 인증 및 디버그 정보 노출 여부
GET mutation 허용 → HTTP 안전 메서드 위반 및 조건부 CSRF 위험
추적/디버그 모드 → 메타데이터 누출

도구: FireTail, Escape DAST, api.sh
```

### 5단계: REST 입력 검증

```text
□ HTTP 메소드 전환: GET→POST→PUT→DELETE→OPTIONS→PATCH
□ 콘텐츠 유형 변조: JSON→XML→multipart
□ NoSQL 주입: {"username": {"$gt": ""}}
□ URL 매개변수를 통한 SSRF: 웹훅 URL/아바타 URL/가져오기 URL
□ XML 끝점의 XXE
□ 매개변수 오염: /api?role=user&role=admin
□ 일괄 할당: 요청 본문에 is_admin: true를 추가합니다.
```

### 6단계: 비즈니스 로직 및 차등 테스트

```text
□ Entropy 비교: v1과 v2 API의 상태 코드 변경/필드 삭제/지연 회귀 확인
□ 다중 역할 워크플로 테스트: admin/user/readonly 권한 매트릭스
□ 쿠폰/포인트/가격 통제
□ 경쟁 조건: 동시 요청 테스트 TOCTOU
```

### 7단계: WebSocket 테스트

```text
□ 엔드포인트 발견
□ 메시지 주입(페이로드 주입, 프로토타입 오염)
□ 대용량 메시지 처리
□ 유형혼란
□ 사이트 간 WebSocket 하이재킹(CSWH)
```

### 8단계: 속도 제한 및 DoS

```text
사전 조건: 별도 승인, 테스트용 테넌트/환경, 요청량 상한, 중단 조건 및 모니터링 합의
□ 헤더를 통한 속도 제한 우회: X-Forwarded-For, X-Real-IP
□ 경로 변형: /api/ → /api → /Api/ → /API/
□ 슬로로리스 저대역폭 고갈
□ GraphQL 깊게 중첩된 DoS 일괄 쿼리
□ IP 교체 테스트(ProxyCat 프록시 풀)
```

### 9단계: 데이터 노출

```text
□ 응답 과다 노출: API 반환과 UI 표시 비교
□ 페이징 열거: ?page=1&limit=10000
□ 오류 메시지 정보 유출: 스택 추적/내부 경로/SQL 오류
□ GraphQL 중첩된 순회 접근 권한이 없는 데이터
□ OpenAPI 사양은 민감한 엔드포인트를 노출합니다.
```

### 10단계: CI/CD 통합

```text
□ Entropy dry-run 결과를 검토한 뒤 승인된 테스트 환경에서만 --live 실행
□ Escape DAST: 심각도 임계값에 따라 빌드를 자동으로 차단합니다.
□ 회귀 테스트로 발견 사항의 재발 여부를 확인합니다.
□ StackHawk(개발자 우선순위, ZAP 코어)
```

## 도구 체인

| 도구 | 목적 | 공식 위치 |
|------|------|------|
| Vespasian | 관찰 트래픽 → OpenAPI/GraphQL 사양 후보| GitHub: praetorian-inc/vespasian|
| Entropy | LLM 공격 시나리오 생성, 5개 페르소나| GitHub: arjinexe/entropy-chaos|
| Escape DAST | 비즈니스 로직 보안 테스트| escape.tech |
| api.sh | GraphQL/REST/WebSocket/SOAP/속도 제한을 다루는 8단계 API 보안 테스트 파이프라인| GitHub: Sharon-Needles/api|
| FireTail | GraphQL/API 보안 점검| firetail.ai |
| jwt_tool | JWT 구현 점검| GitHub: ticarpi/jwt_tool|
| Burp Autorize | 이중 세션 인증 비교| Burp BApp 스토어|

## 참고자료

- `references/rest-graphql-testing.md` — REST + GraphQL 깊이 테스트
- `references/jwt-oauth-testing.md` — JWT + OAuth 보안 테스트
