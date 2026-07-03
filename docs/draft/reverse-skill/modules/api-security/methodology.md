# API 보안 테스트

> REST / GraphQL / WebSocket / SOAP 전체 프로토콜을 다룹니다.
> 발견부터 CI/CD 통합까지 10단계 방법론

## 적용 가능한 시나리오

- REST API 보안 테스트 (OpenAPI/Swagger 운전 또는 블라인드 테스트)
- GraphQL 보안 감사(자체 검사, 일괄 쿼리, 별칭 과부하)
- WebSocket 보안 테스트
- JWT / OAuth 2.0 인증시험
- BOLA/IDOR/BFLA 인증 취약점 감지
- API 속도 제한 우회 및 DoS 테스트

## 10단계 테스트 프로세스

### 1단계: API 발견 및 정찰

```text
사전에 다음을 발견하십시오.
□ Vespasian: 헤드리스 브라우저 크롤링 → OpenAPI 3.0 / GraphQL SDL 사양 자동 생성
□ 엔트로피 --discover: robots.txt + JS 파일에서 엔드포인트 추출
□ Kiterunner/ffuf: 문서화되지 않은 엔드포인트 경로 악용
□ 공통 경로 확인: /swagger.json, /openapi.json, /graphql, /api-docs

GraphQL 성찰(레벨 3 시도):
  1. 표준 내성 쿼리
  2. 쿼리 간소화(WAF 전체 차단 우회)
  3. __schema { 유형 { 이름 } } 만 확인합니다(최소 감지).
```

### 2단계: 인증 테스트

```text
JWT 분석(jwt_tool/Burp):
□ alg:none 공격: 헤더를 "alg":"none"으로 수정하고 서명을 지웁니다.
□ 키 난독화: RS256 공개키 → HS256 대칭키
□ 약한 HMAC 키 폭발: jwt_tool -C -d wordlist.txt
□ 만료/위조된 진술: 수정 exp/iat/sub/role 진술
□ 키드 주입:../../etc/passwd → HMAC 서명 우회

OAuth 2.0：
□redirect_uri 제어 → 인증코드 유출
□ 상태 매개변수를 통한 CSRF가 누락되었습니다.
□ 리퍼러 헤더에서 토큰 유출
□ PKCE 삭제 감지

GraphQL 인증:
□ 돌연변이는 GET 요청을 통해 인증(CSRF)을 우회합니다.
□ 일괄 질의 인증 우회
```

### 3단계: 인증 테스트(BOLA/IDOR/BFLA)

```text
BOLA(객체 수준 인증 우회):
□ 트래버스 디지털 ID: /user/1 → /user/2 → /user/3
□ 트래버스 UUID
□ 사용자 이름/이메일 트래버스
□ Burp Autorize: 듀얼 세션 재생 비교

BFLA(기능 수준 인증 우회):
□ 일반 사용자 임원 관리자 API
□ HTTP 메소드 전환: GET → PUT → PATCH → DELETE
□ API 버전 다운그레이드: /v2/admin → /v1/admin
□ 일괄 작업 주입: {"users": [1,2,3]} → {"users": [1,2,3,admin_id]}

도구: Burp Autorize, AuthMatrix, Entropy(malicious_insider persona)
```

### 4단계: GraphQL 특별 프로젝트

```text
내부정보 유출 → 정보노출 탐지
별칭 과부하 → 100개 이상의 별칭 DoS
일괄 쿼리 → 10개 이상의 동시 쿼리 DoS
필드 중복 → __typename × 500
지시문 오버로드 → 재귀적 @skip/@include
루프 쿼리 → 깊이 중첩된 내성 재귀
현장 제안 → 오류 메시지 정보 유출
GraphiQL/Playground 노출 → IDE 노출 위험
GET 돌연변이 → CSRF 위험
추적/디버그 모드 → 메타데이터 누출

도구: FireTail, Escape DAST, api.sh(1~3단계)
```

### 5단계: REST 입력 확인

```text
□ HTTP 메소드 전환: GET→POST→PUT→DELETE→OPTIONS→PATCH
□ 콘텐츠 유형 변조: JSON→XML→다중 부분
□ NoSQL 주입: {"username": {"$gt": ""}}
□ URL 매개변수를 통한 SSRF: 웹훅 URL/아바타 URL/가져오기 URL
□ XML 끝점의 XXE
□ 매개변수 오염: /api?role=user&role=admin
□ 일괄 할당: 요청 본문에 is_admin: true를 추가합니다.
```

### 6단계: 비즈니스 로직 및 차등 테스트

```text
□ 엔트로피 비교: diff v1 vs v2 API → 상태 코드 변경/필드 삭제/지연 회귀
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
□ 엔트로피 --ci --watch: 사양 변경 시 자동 재실행
□ Escape DAST: 심각도 임계값에 따라 빌드를 자동으로 차단합니다.
□ 회귀 테스트를 통해 지속성을 발견합니다.
□ StackHawk(개발자 우선순위, ZAP 코어)
```

## 도구 체인

| 도구| 목적| 얻다|
|------|------|------|
| Vespasian | 흐름 → OpenAPI/GraphQL 표준| GitHub: praetorian-inc/vespasian|
| Entropy | LLM 공격 시나리오 생성, 5개 페르소나| GitHub: arjinexe/entropy-chaos|
| Escape DAST | 비즈니스 로직 보안 테스트| escape.tech |
| api.sh | 8단계 전체 프로토콜 공격 파이프라인| GitHub: Sharon-Needles/api|
| FireTail | GraphQL 12 특별시험| firetail.ai |
| jwt_tool | JWT 완전히 테스트됨| GitHub: ticarpi/jwt_tool|
| Burp Autorize | 이중 세션 인증 비교| Burp BApp 스토어|

## 참고자료

- `references/rest-graphql-testing.md` — REST + GraphQL 깊이 테스트
- `references/jwt-oauth-testing.md` — JWT + OAuth 보안 테스트
