# 공급망 보안 테스트

> SBOM / SCA / CI/CD 파이프라인 / 종속성 추적성
> 규제 중심: 미국 행정 명령 SBOM, 중국 국가 표준, EU CRA

## 적용 가능한 시나리오

- 소프트웨어 공급망 보안 평가
- 오픈소스 종속성 취약점 스캔 및 검증
- CI/CD 파이프라인 안전 감사
- 컨테이너 이미지 보안 분석
- 타사 구성요소 규정 준수 검토
- 제품 추적성 및 무결성 검증 구축

## 6계층 공급망 거버넌스 프레임워크

```text
Layer 1: 소스코드 신뢰도 평가 → 업스트림 저장소/유지관리자/출시 이력 검토
레이어 2: 파이프라인 통합 구축 → CI/CD 보안 접근 제어, 서명 확인
레이어 3: 아티팩트 배포 무결성 → 서명, 체크섬, SBOM 추가
레이어 4: 런타임 보호 → 컨테이너 검색, 승인 제어
Layer 5: 지속적인 모니터링 → CVE 실시간 추적, 취약점 접근성 분석
레이어 6: 사고 대응 → 공급망 공격 비상 상황 및 롤백 전략
```

## 작업흐름

### 1. SBOM 생성 및 감사

```text
SBOM 생성:
□ CycloneDX 형식: cdxgen → bom.json
□ SPDX 형식: sbom-tool generate
□ Syft: syft <image|dir> -o spdx-json

감사 포인트:
□ 알 수 없거나 승인되지 않은 종속성이 있습니까?
□ 유지보수가 중단되거나 중단된 패키지가 있습니까?
□ 라이센스 충돌 감지
□ 직접 종속성 vs 전이적 종속성 목록
□ 각 컴포넌트의 릴리즈 타임라인 및 유지관리자 현황
```

### 2. 소프트웨어 구성 분석(SCA)

```bash
# OSV-Scanner(무료, Google에서 유지관리)
osv-scanner scan -r . --format json

# OWASP 종속성 추적(엔터프라이즈 수준 연속 모니터링)
docker run -p 8080:8080 dependencytrack/apiserver
# → 업로드 SBOM → 자동 매칭 NVD/OSV/GitHub Advisory

# Snyk(상용)
snyk test --all-projects
snyk monitor  # 지속적인 모니터링

# Trivy(컨테이너 + 종속성 + IaC)
trivy fs .          # 파일 시스템 검사
trivy image nginx   # 컨테이너 이미지
trivy config .      # IaC 구성
```

### 3. 취약점 도달성 검증

```text
SCA 경고 ≠ 실제 위험! 대부분의 SCA 도구에는 실제로 도달할 수 있는 경고의 최대 15%만 있습니다.

확인 단계:
1. CVE 목록을 얻으려면 종속성 추적 또는 Trivy를 사용하십시오.
2. 취약점 선별 CVSS ≥ 7.0
3. PoC를 사용하여 CVE에 대한 도달 가능성 분석을 수행합니다.
   - 코드 속성 그래프 슬라이스: 취약한 함수에 대한 사용자 입력 경로 추적
   - DEPTEX 방식: EPD(Execution Path Dominance) + LLM 의미 검증
4. 격리된 환경에서 PoC 확인
5. 실제 영향에 따라 접근 가능한 취약점의 수정 우선순위를 정합니다.
```

도구 참조:
- CodeQL: GitHub 코드 쿼리 → 데이터 흐름 분석
- Snyk 코드: 도달성 마커
- DEPTEX: LLM 상황 인식 위험 평가 지원

### 4. CI/CD 파이프라인 안전

```text
보안 검색대:
□ 코드 제출 → pre-commit Hook: gitleaks(키 스캐닝)
□ 홍보단계 → SCA 스캔 (Trivy/OSV-Scanner)
□ 구축 단계 → 아티팩트 서명(공동 서명)
□ 푸시 단계 → SBOM 연결(syft + attest)
□ 배포단계 → 출입통제(OPA/Kyverno + 이미지 스캔)
□ Runtime → 지속적인 취약점 모니터링(Dependency-Track)

파이프라인 안전:
□ 코드형 파이프라인 감사(GitHub Actions / GitLab CI 구성 주입)
□ 러너 격리(악성 빌드가 컨테이너를 뚫는 것을 방지하기 위해)
□ 키 관리(Actions Secrets/Vault, 하드코딩 금지)
□ 제3자 조치 검토(잠금 커밋 SHA, 태그 없음)
```

### 5. 컨테이너 이미지 보안

```bash
# Dockerfile 감사
hadolint Dockerfile

# 이미지 스캐닝(다층: OS + 애플리케이션 종속성 + 구성)
trivy image --severity HIGH,CRITICAL nginx:latest

# 최소 기본 이미지
# 우선순위: distroless → alpine → slim → 최신 피하기
docker scout quickview nginx:latest

# 이미지 서명
cosign sign --key cosign.key myimage:tag
cosign verify --key cosign.pub myimage:tag
```

### 6. 타사 종속성 검토

```text
새 종속성 체크리스트 추가:
□ 유지상태: 최근 6개월 이내 제출되었나요? 유지관리자 활동?
□ 보안 이력: 과거에 악성코드가 심어진 적이 있었나요?
□ 종속성 트리: 도입 후 몇 개의 전이적 종속성이 추가됩니까?
□ 라이선스: 프로젝트 라이선스와 호환되나요?
□ 대안: 더 안전한 대안이 있습니까(Snyk Advisor/Socket.dev 등급)?

위험 평가 매트릭스:
  높은 유지 관리 × 낮은 종속성 × 호환 라이센스 → 낮은 위험
  낮은 유지 관리 × 많은 종속성 × 라이센스 충돌 → 높은 위험
```

## 도구 체인

| 도구| 목적| 얻다|
|------|------|------|
| OWASP Dependency-Track | 엔터프라이즈급 연속 SCA| `docker pull dependencytrack/apiserver` |
| OSV-Scanner | 무료 SCA (OSV.dev 생태계)| `go install github.com/google/osv-scanner` |
| Trivy | 이미지 + 종속성 + IaC 스캔| `apt install trivy` |
| Syft | SBOM 생성됨| `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh` |
| cdxgen | CycloneDX SBOM 생성됨| `npm install -g @cyclonedx/cdxgen` |
| Cosign | 컨테이너 서명| `go install github.com/sigstore/cosign/v2/cmd/cosign` |
| Gitleaks | 키/자격증명 스캔| `go install github.com/gitleaks/gitleaks/v8` |
| Snyk | 상용 SCA + 접근성| `npm install -g snyk` |
| CodeQL | 코드 쿼리 + 데이터 흐름| GitHub Actions 내장|

## 참고자료

- `references/sbom-sca-methodology.md` — SBOM + SCA 방법론
- `references/cicd-pipeline-security.md` — CI/CD 파이프라인 안전 감사
