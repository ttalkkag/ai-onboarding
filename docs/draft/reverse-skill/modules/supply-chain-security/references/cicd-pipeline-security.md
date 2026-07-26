# CI/CD 파이프라인 보안 감사

## 파이프라인 공격 표면

```text
위협 모델(STRIDE):
□ 스푸핑: 빌드/서명/소스 위조
□ 변조(Tampering): 소스 코드/빌드 산출물/종속성 변조
□ 부인(Repudiation): 감사 로그가 없어 행위 주체가 작업을 부인할 수 있음
□ 정보 유출: 파이프라인 로그의 비밀 또는 빌드 산출물 유출
□ 서비스 거부: CI 리소스 소진/빌드 중단
□ 권한 상승: 러너 탈출/자격증명 탈취
```

## 감사 체크리스트

### 1. 코드 구성으로서의 파이프라인

```text
# GitHub Actions 감사 하이라이트
# ❌ 위험 모드
on:
  pull_request_target:  # 쓰기 토큰/비밀이 있는 컨텍스트에서 신뢰하지 않은 PR 코드를 checkout·실행하면 위험
    types: [opened]

# ❌ 스크립트 삽입
- run: echo "${{ github.event.issue.title }}"  # 사용자 입력 → 쉘

# ❌ 무제한 토큰 권한
permissions: write-all

# ✅ 포크 PR의 기본 비밀 격리(권한은 별도로 최소화)
on:
  pull_request:  # 포크 PR에는 Actions secrets가 전달되지 않음
    types: [opened]

# ✅ SHA에 고정
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

# ✅ 최소 권한
permissions:
  contents: read
```

### 2. 키 관리

```bash
# 커밋 이력의 비밀 스캔
gitleaks git --verbose .
trufflehog git file://. --only-verified

# Actions secrets 목록 확인
gh secret list
# 확인: 하드코딩된 키 없음, 정기적인 순환, 최소 권한

# 런타임 비밀 주입
# ✅ 장기 키 대신 OIDC를 사용하세요
# ✅ 비밀은 필요한 특정 단계에만 노출합니다.
```

### 3. 무결성 구축

```bash
# 추적성 구축
# SLSA에는 범용 `slsa-provenance generate` CLI가 없습니다.
# 사용 중인 빌드 플랫폼의 공식 provenance generator를 선택하고,
# SLSA Build L2에서는 호스팅 빌드 플랫폼이 서명한 provenance를 생성합니다.

# Cosign v3 blob 서명: 서명·인증서 정보를 bundle에 저장
cosign sign-blob --key cosign.key \
  --bundle artifact.sigstore.json artifact.tar.gz

# bundle로 확인
cosign verify-blob --key cosign.pub \
  --bundle artifact.sigstore.json artifact.tar.gz
```

### 4. 러너 보안

```text
□ GitHub-hosted runner는 각 표준 작업마다 새 VM을 제공하는지 확인했나요?
□ self-hosted runner는 작업마다 폐기되는 격리 VM에서 실행하나요?
□ 포크 PR의 신뢰하지 않은 코드를 self-hosted runner에서 실행하지 않나요?
□ Runner에는 네트워크 아웃바운드 제한이 있습니까?
□ 빌드 캐시가 빌드 전체에서 누출될 수 있습니까?
```

### 5. 종속성 가져오기 보안

```text
□ npm: package-lock.json을 커밋하고 CI에서 `npm ci`를 사용하나요?
□ pip: 해시가 포함된 잠금/요구사항 파일과 승인된 인덱스를 사용하나요?
□ Docker: `FROM` 이미지를 검토한 digest로 고정하나요?
□ Go: go.sum을 커밋하고 변경을 검토하나요?
□ 프라이빗 패키지: 레지스트리 인증에 단기 토큰이 사용되나요?
```

## 자동화된 검사 파이프라인

```yaml
# .github/workflows/supply-chain.yml
# 전제: cdxgen, osv-scanner, trivy, gitleaks의 검토된 버전과 신뢰 설정을
# 매 작업 폐기되는 불변 runner 이미지에 사전 설치합니다.
name: Supply Chain Security
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  sca:
    runs-on: [self-hosted, ephemeral, hardened-supply-chain]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false

      - name: SBOM read-only preflight
        run: cdxgen --dry-run -p .

      # dry-run 직후 자동 실행하는 것은 사람의 승인 게이트가 아닙니다.
      # 이 단계는 신뢰된 main 전용이며, 별도 검토가 필요하면 승인 보호된 job/workflow로 분리합니다.
      - name: SBOM generate in trusted isolated job
        run: cdxgen-secure --no-install-deps -o sbom.cdx.json .

      - name: OSV Scan
        run: osv-scanner scan source --config /opt/security/osv-scanner.toml --format sarif -L sbom.cdx.json > osv-results.sarif

      - name: Trivy Scan
        run: trivy fs --severity CRITICAL,HIGH --exit-code 1 .

      - name: Secret Scan
        run: gitleaks git --verbose .

      - name: Dependency-Track Upload
        env:
          DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
          BUILD_VERSION: ${{ github.sha }}
        run: |
          curl -X POST https://dtrack.example.com/api/v1/bom \
            -H "X-Api-Key: $DTRACK_API_KEY" \
            -F "autoCreate=true" -F "projectName=myapp" \
            -F "projectVersion=$BUILD_VERSION" -F "bom=@sbom.cdx.json"
```

비밀을 사용하는 업로드와 self-hosted runner는 신뢰된 `main` push로 제한했다. 외부 기여 PR 검사는 별도의
비밀 없는 일회용 GitHub-hosted job에서 수행하고, self-hosted job과 산출물·캐시를 공유하지 않는다.
`cdxgen-secure`는 권한을 강화하지만 악성 코드에 대한 보장은 아니다. 또한 같은 job에서 이어지는 dry-run은
승인 게이트가 아니므로, 사람이 결과를 승인해야 하는 조직은 생성 단계를 보호된 environment의 별도 job이나
수동 workflow로 분리한다. dry-run이 보고한 외부 명령은 이 기본 job에서 자동 허용하지 않는다.

Source: [SLSA v1.2](https://slsa.dev/spec/v1.2/), [Cosign sign-blob](https://github.com/sigstore/cosign/blob/main/doc/cosign_sign-blob.md), [Cosign verify-blob](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-blob.md), [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use), [cdxgen permissions](https://github.com/cdxgen/cdxgen/blob/master/docs/PERMISSIONS.md)
