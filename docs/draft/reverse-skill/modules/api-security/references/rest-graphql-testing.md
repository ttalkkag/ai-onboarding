# REST + GraphQL 깊이 테스트

## GraphQL 보안 테스트 전체 체크리스트

### 인트로스펙션 프로브(응답 최소화)

```graphql
 # 레벨 1 — 표준 인트로스펙션
{ __schema { queryType { name } mutationType { name } types { name fields { name type { name } } } } }

 # 레벨 2 — 단순화한 인트로스펙션
{ __schema { types { name } } }

 # 레벨 3 — 최소 탐지
{ __type(name: "Query") { name } }
```

### 자원 제한 검증

아래 쿼리는 승인된 테스트 환경에서 요청량·깊이·복잡도 상한과 중단 조건을 정한 뒤 축소된 크기로 사용합니다.

```text
 # 별칭 과부하
query { a1: __typename a2: __typename ... a100: __typename }

 # 배치 요청 형식 예시(서버가 배치를 지원하는 경우)
[
  { "query": "query { __typename }" },
  { "query": "query { __typename }" }
]

 # 순환 쿼리
query { __schema { types { fields { type { fields { type { fields { name } } } } } } } }

 # 지시문 과부하
query { __typename @skip(if: false) @include(if: true) ... }
```

### 인증 테스트

```text
 # GET mutation은 GraphQL-over-HTTP 초안에 따라 405로 거부되어야 합니다.
GET /graphql?query=mutation+{+deleteUser(id:1)+}

 # 배치 쿼리 인증 우회
[
  { "query": "query { me { id } }" },
  { "query": "mutation { deleteUser(id: 2) }" }
]
```

## REST API 심도 테스트

### 메소드 조작 매트릭스

| 엔드포인트 | GET | POST | PUT | PATCH | DELETE | OPTIONS |
|------|-----|------|-----|-------|--------|---------|
| /users | 기준 동작 확인 | 생성 인가 확인 | 일괄 변경 범위 확인 | 필드 주입 확인 | 연속 삭제 방지 확인 | 허용 메서드 정보 노출 확인 |
| /users/me | 기준 동작 확인 | — | 자기 권한 상승 확인 | 필드 추가 확인 | 자기 계정 삭제 확인 | — |

### 매개변수 주입

```text
# NoSQL 연산자 주입 후보
{"username": {"$gt": ""}, "password": {"$ne": ""}}

# 대량 할당 후보
{"email": "user@example.com", "role": "admin", "isAdmin": true}

# 매개변수 오염
GET /api/users?role=user&role=admin

# JSON 배열 주입
{"ids": [1, 2, 3]} → {"ids": ["1 UNION SELECT ..."]}
```

### API를 통한 SSRF

```text
일반적인 SSRF 매개변수: webhook_url, callback_url, Avatar_url, import_url,
                redirect_uri, file_url, proxy_url, image_url
검증: 테스트팀이 소유한 콜백 서버로 아웃바운드 요청 여부를 확인합니다.
클라우드 메타데이터·내부 주소·로컬 파일 접근은 격리된 전용 환경에서만 별도 승인 후 검증합니다.
```

## 자동화 도구 체인

### 베스파시아누스(교통 중심 사양 생성)

```bash
# 헤드리스 브라우저에서 관찰 트래픽 수집
vespasian crawl https://authorized.example -o capture.json

# Burp/HAR에서 가져오기
vespasian import har traffic.har -o capture.json

# 관찰한 트래픽에서 REST 사양 후보 생성
vespasian generate rest capture.json -o api-spec.yaml
```

### 엔트로피(LLM 공격 생성)

```bash
# 기본은 dry-run입니다. 생성된 시나리오를 먼저 검토합니다.
entropy run --spec api-spec.yaml --target https://staging.example

# 별도 승인된 테스트 환경에서만 실제 요청을 전송합니다.
entropy run --spec api-spec.yaml --target https://staging.example --live

# 5명의 동시 성격:
# - 악성 내부자: IDOR/일괄 할당/권한 에스컬레이션
# - bot_swarm: 속도 제한 우회/DoS/자동 남용
# - 침투_테스터: 주입/인증 우회
# - impatient_consumer: 경쟁 조건/오류 처리
# - 혼란스러운_사용자: 예상치 못한 입력/경계 테스트

# CI에서는 dry-run 결과를 검토 가능한 산출물로 보관하고,
# live 실행은 승인·요청량 상한·중단 조건이 있는 별도 단계로 분리합니다.
```

### api.sh

```bash
# 공식 CLI는 개별 graphql-exploit/rest-abuse 같은 하위 명령을 제공하지 않습니다.
# 한 번의 호출이 승인된 URL 목록을 대상으로 8단계 보안 테스트 파이프라인을 실행합니다.
api --target authorized-api -u urls.txt --platform hackerone
```

Source: [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), [GraphQL over HTTP draft](https://graphql.github.io/graphql-over-http/draft/), [Praetorian Vespasian](https://github.com/praetorian-inc/vespasian), [Entropy](https://github.com/arjinexe/entropy-chaos), [api.sh](https://github.com/Sharon-Needles/api)
