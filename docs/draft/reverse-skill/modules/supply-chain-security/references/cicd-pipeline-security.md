# CI/CD 파이프라인 안전 감사

## 파이프 공격 표면

```text
위협 모델(STRIDE):
□ 스푸핑: 빌드/서명/소스 위조
□ 변조(Tampering): 소스 코드 수정/제품 빌드/종속성
□ 거부: 감사 로그가 없는 악의적인 작업
□ 정보 유출: 파이프라인 로그/빌드 제품 유출 키
□ 서비스 거부: CI 리소스 소진/빌드 중단
□ 권한 상승: 주자의 탈출/열쇠 도난
```

## 감사 체크리스트

### 1. 코드 구성으로서의 파이프라인

```yaml
# GitHub Actions 감사 하이라이트
# ❌ 위험 모드
on:
  pull_request_target:  # 접근 가능한 비밀에 대한 PR 트리거
    types: [opened]

# ❌ 스크립트 삽입
- run: echo "${{ github.event.issue.title }}"  # 사용자 입력 → 쉘

# ❌ 무제한 토큰 권한
permissions: write-all

# ✅ 안전 모드
on:
  pull_request:  # 비밀에 액세스할 수 없음
    types: [opened]

# ✅ SHA에 고정
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

# ✅ 최소 권한
permissions:
  contents: read
```

### 2. 키 관리

```bash
# 키에 대한 기록 커밋 스캔
gitleaks detect --source . --verbose
trufflehog git file://. --only-verified

# 작업 비밀 사용량 확인
gh secret list
# 확인: 하드코딩된 키 없음, 정기적인 순환, 최소 권한

# 런타임 키 삽입
# ✅ 장기 키 대신 OIDC를 사용하세요
# ✅ 비밀은 필요한 경우에만 특정 단계에 노출됩니다.
```

### 3. 무결성 구축

```bash
# 추적성 구축
# 변경할 수 없는 빌드 레코드 생성(SLSA L2+)
slsa-provenance generate --source . --output provenance.json

# 제품 서명
cosign sign-blob --key cosign.key artifact.tar.gz

# 확인
cosign verify-blob --key cosign.pub --signature artifact.tar.gz.sig artifact.tar.gz
```

### 4. 러너 안전

```text
□ GitHub에서 호스팅되는 Runner를 사용하시나요? (권장, 매번 새로운 환경)
□ 자체 호스팅 실행기: 격리된 VM/컨테이너에서 실행 중이신가요?
□ 포크홍보를 해본 적이 있나요? (자체 호스팅 러너는 매우 위험합니다)
□ Runner에는 네트워크 아웃바운드 제한이 있습니까?
□ 빌드 캐시가 빌드 전체에서 누출될 수 있습니까?
```

### 5. 풀 보안에 의존

```text
□ npm: package-lock.json 제출하시겠습니까? 금지 --force / --legacy-peer-deps
□ pip: 요구 사항.txt 버전이 고정되어 있나요? pip 설치 비활성화 <확인되지 않은 소스>
□ Docker: FROM은 고정 다이제스트인가요? 최신 태그 비활성화
□ 가기: go.sum 제출하시겠습니까?
□ 프라이빗 패키지: 레지스트리 인증에 단기 토큰이 사용되나요?
```

## 자동화된 검사 파이프라인

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SBOM Generate
        run: |
          npm install -g @cyclonedx/cdxgen
          cdxgen -o sbom.json

      - name: OSV Scan
        run: |
          go install github.com/google/osv-scanner/cmd/osv-scanner@latest
          osv-scanner scan --sbom sbom.json --format sarif > osv-results.sarif

      - name: Trivy Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Secret Scan
        run: |
          docker run --rm -v $PWD:/src ghcr.io/gitleaks/gitleaks:latest \
            detect --source /src --verbose

      - name: Dependency-Track Upload
        run: |
          curl -X POST https://dtrack.example.com/api/v1/bom \
            -H "X-Api-Key: ${{ secrets.DTRACK_API_KEY }}" \
            -F "autoCreate=true" -F "project=myapp" -F "bom=@sbom.json"
```

Source: SLSA 프레임워크, OWASP CI/CD 상위 10위, GitHub 보안 연구소
