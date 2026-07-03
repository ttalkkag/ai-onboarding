# SBOM + SCA 방법론

## SBOM 표준 비교

| 표준| 형식| 생태학| 권장 시나리오|
|------|------|------|---------|
| SPDX | JSON/YAML/tag-value | 리눅스 재단, 욕토| 라이센스 준수 우선|
| CycloneDX | JSON/XML | OWASP, 쿠버네티스|보안 분석이 우선|
| SWID | XML | ISO 표준| 엔터프라이즈 자산 관리|

## SBOM 도구 체인 생성

```bash
# cdxgen: 소스에서 CycloneDX SBOM 생성
cdxgen -o bom.json -t cyclonedx

# Syft: 컨테이너/파일 시스템에서 생성
syft nginx:latest -o spdx-json > sbom.spdx.json

# SBOM-도구: Microsoft 도구 체인
sbom-tool generate -b ./build -bc ./src -pn MyApp -pv 1.0
```

## SCA 도구 비교

| 도구| 무료| 속도| 데이터베이스| 접근성|
|------|:--:|------|--------|:--:|
| OSV-Scanner | ✅ | 매우 빠르다| OSV.dev | ❌ |
| Trivy | ✅ | 빠르게| 여러 소스| ❌ |
| Dependency-Track | ✅ | 안으로| NVD+OSV+GitHub| ❌ (플러그인 필요)|
| Snyk | ❌ | 안으로| 독점| ✅ |
| CodeQL | ✅ | 천천히| 코드 레벨| ✅ |

## 취약점 우선순위 지정 전략

```
CVSS ≥ 9.0 + 공개 PoC + 연결 가능 → P0 즉시 수리
CVSS ≥ 7.0 + 예 PoC + 연결 가능 → P1 이번 주에 수정됨
CVSS ≥ 7.0 + 없음 PoC 또는 도달 불가능 → 다음 반복에서 P2 고정
나머지 → 일반적인 절차를 따릅니다.
```

## 수동 검증 3단계 방법

```bash
# 1. 버전을 확인하세요(SBOM 필드를 맹목적으로 신뢰하지 마세요)
# 컨테이너 내: dpkg -l | grep <패키지>
# Node: cat node_modules/<pkg>/package.json | jq .version
# Python: pip show <package>

# 2. 취약점 확인
# 검색 CVE: https://osv.dev / https://nvd.nist.gov
# 영향을 받는 버전 범위를 확인하세요.
# GitHub Advisory/oss-security 메일링 리스트 찾기

# 3. 영향 확인
# 공개 검색 PoC: GitHub/Exploit-DB
# 활용 조건 분석: 인증/로컬 접속/특정 구성 필요 여부
# 격리 환경에서 확인: docker run --rm -it 취약한 이미지 bash
```

## 지속적인 모니터링

```yaml
# 매일 SBOM 업데이트 + 스캔
schedule:
  - cron: "0 6 * * *"  # 매일 오전 6시
    steps:
      - cdxgen -o bom.json
      - osv-scanner scan --sbom bom.json
      - trivy fs --exit-code 1 --severity CRITICAL .
```

Source: OWASP CycloneDX, SPDX, Google OSV, CISA SBOM 지침
