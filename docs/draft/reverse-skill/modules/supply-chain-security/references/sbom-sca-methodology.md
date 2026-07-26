# SBOM + SCA 방법론

## SBOM 표준 비교

| 표준 | 형식 | 생태계 | 권장 시나리오 |
|------|------|------|---------|
| SPDX 3.x | JSON-LD 등 모델 직렬화| 리눅스 재단, Yocto| 라이선스·공급망 정보 교환|
| CycloneDX 1.7 | JSON/XML/Protocol Buffers | OWASP, Ecma International| 보안 분석과 BOM 확장|
| SWID | XML | ISO 표준| 엔터프라이즈 자산 관리|

## SBOM 도구 체인 생성

```bash
# cdxgen 1차 검토: 파일을 쓰거나 외부 명령을 실행하지 않고 활동 계획만 확인
cdxgen --dry-run -p .

# 검토·승인 후: 비밀 없는 일회용 격리 환경에서 자동 의존성 설치를 끄고 SBOM 생성
cdxgen-secure --no-install-deps -o bom.cdx.json .

# Syft: 검토한 컨테이너 digest에서 생성
REVIEWED_IMAGE='nginx@sha256:REPLACE_WITH_REVIEWED_SHA256_HEX'
syft "$REVIEWED_IMAGE" -o spdx-json=sbom.spdx.json

# SBOM-도구: Microsoft 도구 체인
sbom-tool generate -b ./build -bc ./src -pn MyApp -pv 1.0
```

`--dry-run`은 검토용 계획이며 최종 SBOM 파일을 저장하지 않는다. `cdxgen-secure`와
`--no-install-deps`도 악성 입력에 대한 절대적 안전 보장은 아니다. 더 풍부한 결과를 위해 외부 빌드 도구가
필요하다고 표시되면, dry-run에서 확인한 명령만 별도 승인하고 대상 읽기 전용·출력 외부화·비밀 제거·프로세스
허용 목록을 갖춘 일회용 환경에서 실행한다.

## SCA 도구 비교

| 도구 | 제공 형태 | 취약점 데이터 | 도달성 분석 |
|------|------|--------|------|
| OSV-Scanner | 오픈소스 CLI | OSV.dev | Go 지원, Rust 실험적 지원 |
| Trivy | 오픈소스 CLI | 여러 소스 | 기본 SCA 결과에는 없음 |
| Dependency-Track | 오픈소스 플랫폼 | 구성한 분석기/미러 | 별도 통합 필요 |
| Snyk Open Source | 상용 서비스 | Snyk 데이터베이스 | 지원 생태계에서 제공 |

OSV-Scanner의 Go 호출 분석은 기본 활성화되므로 정적 파일·잠금 파일 스캔만 허용하는 경로에서는
`--no-call-analysis=go`로 끕니다. Rust 호출 분석은 실험적이며 종속성의 `build.rs`를 실행할 수 있으므로
신뢰하지 않은 프로젝트에 사용하지 않습니다.

## 취약점 우선순위 지정 전략

```text
CISA KEV 등 실제 악용 확인 + 노출·도달 가능 + 중요 자산 → P0 즉시 대응
높은 EPSS/CVSS + 노출·도달 가능 → P1 단기 대응
영향 버전이나 도달 가능성이 불확실 → 검증 우선순위를 부여하고 근거를 기록
도달 불가능·완화됨 → 수용 기한과 재평가 조건을 기록
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
# 호출 경로, 배포 구성, 인증/로컬 접근 조건과 보완 통제를 검토합니다.
# 실제 악용 확인이 필요한 경우에만 별도 승인된 격리 환경에서 비파괴 검증합니다.
```

## 지속적인 모니터링

```yaml
# 전제: 아래 도구의 검토된 버전과 신뢰 설정이 매 작업 폐기되는 불변 runner 이미지에 사전 설치되어 있습니다.
name: Daily SBOM scan
on:
  schedule:
    - cron: "0 6 * * *"

permissions:
  contents: read

jobs:
  scan:
    runs-on: [self-hosted, ephemeral, hardened-supply-chain]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      # 승인된 별도 생성 파이프라인이 갱신한 SBOM을 입력으로 사용합니다.
      - run: osv-scanner scan source --config /opt/security/osv-scanner.toml --format json -L bom.cdx.json
      - run: trivy fs --exit-code 1 --severity CRITICAL .
```

위 self-hosted runner는 작업마다 폐기하며 `pull_request`의 신뢰하지 않은 코드를 받지 않는다. SBOM 생성은
앞 절의 dry-run과 승인 절차를 거친 별도 격리 파이프라인에서 수행하며, 이 모니터링 job은 기존 SBOM만 읽는다.

Source: [CycloneDX 1.7](https://cyclonedx.org/specification/overview/), [SPDX specifications](https://spdx.dev/use/specifications/), [cdxgen permissions](https://github.com/cdxgen/cdxgen/blob/master/docs/PERMISSIONS.md), [OSV-Scanner v2](https://google.github.io/osv-scanner/usage/), [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
