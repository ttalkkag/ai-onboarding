# 공급망 보안 테스트

> SBOM / SCA / CI/CD 파이프라인 / 종속성 추적성
> 규제 참고: 미국 EO 14028에 따른 NTIA SBOM 최소 요소, 중국 SBOM 데이터 형식 국가표준 프로젝트, EU Cyber Resilience Act

> **안전 경계:** 기본 분석은 저장소 파일과 잠금 파일을 읽는 정적 스캔으로 제한합니다. 대상 프로젝트의 빌드·설치 스크립트나 OSV-Scanner `fix`를 실행하지 않습니다. 동적 검증은 별도 승인된 격리 환경에서만 수행합니다.

## 적용 가능한 시나리오

- 소프트웨어 공급망 보안 평가
- 오픈소스 종속성 취약점 스캔 및 검증
- CI/CD 파이프라인 안전 감사
- 컨테이너 이미지 보안 분석
- 타사 구성요소 규정 준수 검토
- 제품 추적성 및 무결성 검증 구축

## 6계층 공급망 거버넌스 프레임워크

```text
계층 1: 소스 코드 신뢰도 평가 → 업스트림 저장소/유지관리자/릴리스 이력 검토
계층 2: 빌드 파이프라인 무결성 → CI/CD 접근 제어, 출처 증명과 서명 검증
계층 3: 아티팩트 배포 무결성 → 서명, 체크섬, SBOM 연결
계층 4: 런타임 보호 → 컨테이너 스캔, 승인 제어
계층 5: 지속적인 모니터링 → CVE 추적, 취약점 도달성 분석
계층 6: 사고 대응 → 공급망 침해 대응 및 롤백 전략
```

## 작업흐름

### 1. SBOM 생성 및 감사

```text
SBOM 생성:
□ CycloneDX 형식: cdxgen `--dry-run`으로 활동 검토 → 승인된 격리 환경에서 bom.json 생성
□ SPDX 형식: sbom-tool generate
□ Syft: syft <image|dir> -o spdx-json

감사 포인트:
□ 알 수 없거나 승인되지 않은 종속성이 있습니까?
□ 유지보수가 중단된 패키지가 있습니까?
□ 라이선스 충돌 감지
□ 직접 종속성 vs 전이적 종속성 목록
□ 각 컴포넌트의 릴리즈 타임라인 및 유지관리자 현황
```

### 2. 소프트웨어 구성 분석(SCA)

```bash
# OSV-Scanner v2(Go call analysis도 끈 정적 종속성 스캔)
osv-scanner scan source -r . --no-call-analysis=go --format json

# OWASP Dependency-Track(검토한 이미지 digest로 고정)
DTRACK_IMAGE='dependencytrack/apiserver@sha256:REPLACE_WITH_REVIEWED_SHA256_HEX'
docker run -p 8080:8080 "$DTRACK_IMAGE"
# → SBOM 업로드 후 구성한 취약점 인텔리전스 소스와 매칭

# Snyk(상용)
snyk test --all-projects
snyk monitor  # 지속적인 모니터링

# Trivy(컨테이너 + 종속성 + IaC)
REVIEWED_IMAGE='nginx@sha256:REPLACE_WITH_REVIEWED_SHA256_HEX'
trivy fs .          # 파일 시스템 검사
trivy image "$REVIEWED_IMAGE"  # 검토한 digest로 고정한 이미지
trivy config .      # IaC 구성
```

### 3. 취약점 도달성 검증

```text
SCA 경고만으로 실제 악용 가능성을 확정할 수 없습니다. 자산 중요도, 배포 구성, 호출 경로와 기존 완화책을 함께 검토합니다.

확인 단계:
1. CVE 목록은 Dependency-Track, OSV-Scanner 또는 Trivy로 수집합니다.
2. CISA KEV, EPSS, CVSS, 자산 중요도와 노출도를 함께 사용해 선별합니다.
3. 코드와 구성으로 도달 가능성 분석을 수행합니다.
   - 코드 속성 그래프 슬라이스: 취약한 함수에 대한 사용자 입력 경로 추적
   - 연구 참고: DEPTEX 프리프린트의 EPD(Execution Path Dominance) + LLM 의미 검증
4. 실제 악용 확인이 꼭 필요하면 별도 승인된 격리 환경에서 비파괴 검증을 수행합니다.
5. 실제 영향에 따라 접근 가능한 취약점의 수정 우선순위를 정합니다.
```

도구 참조:
- CodeQL: GitHub 코드 쿼리 → 데이터 흐름 분석
- Snyk Open Source: 지원 생태계의 도달성 분석
- DEPTEX: 2026년 프리프린트 단계의 연구 제안이며 검증된 표준 도구로 취급하지 않음

### 4. CI/CD 파이프라인 보안

```text
보안 검사 지점:
□ 코드 제출 → pre-commit hook: gitleaks(비밀 스캔)
□ PR 단계 → SCA 스캔(Trivy/OSV-Scanner)
□ 빌드 단계 → 아티팩트 서명(Cosign)
□ 게시 단계 → SBOM 연결(Syft + attest)
□ 배포 단계 → 승인 제어(OPA/Kyverno + 이미지 스캔)
□ 런타임 → 지속적인 취약점 모니터링(Dependency-Track)

파이프라인 안전:
□ 코드형 파이프라인 감사(GitHub Actions / GitLab CI의 입력 주입)
□ 러너 격리(신뢰하지 않은 빌드와 내부망·비밀 분리)
□ 비밀 관리(Actions Secrets/Vault, 하드코딩 금지)
□ 제3자 액션 검토(검토한 전체 커밋 SHA로 고정)
```

### 5. 컨테이너 이미지 보안

```bash
# Dockerfile 감사
hadolint Dockerfile

# 이미지 스캐닝(다층: OS + 애플리케이션 종속성 + 구성)
REVIEWED_DIGEST='REPLACE_WITH_REVIEWED_SHA256_HEX'
REVIEWED_IMAGE="nginx@sha256:$REVIEWED_DIGEST"
trivy image --severity HIGH,CRITICAL "$REVIEWED_IMAGE"

# 목적에 맞는 최소 이미지를 선택하고 태그 대신 검토한 digest로 고정
docker scout quickview "nginx@sha256:$REVIEWED_DIGEST"

# 이미지 서명 및 검증도 불변 digest를 대상으로 수행
IMAGE_REF="registry.example.com/myimage@sha256:$REVIEWED_DIGEST"
cosign sign --key cosign.key "$IMAGE_REF"
cosign verify --key cosign.pub "$IMAGE_REF"
```

### 6. 타사 종속성 검토

```text
새 종속성 체크리스트 추가:
□ 유지 상태: 최근 6개월 이내 릴리스/커밋과 유지관리자 활동이 있나요?
□ 보안 이력: 과거에 악성코드가 심어진 적이 있었나요?
□ 종속성 트리: 도입 후 몇 개의 전이적 종속성이 추가됩니까?
□ 라이선스: 프로젝트 라이선스와 호환되나요?
□ 대안: 더 안전한 대안이 있습니까(Snyk Advisor/Socket.dev 등급)?

위험 평가 매트릭스:
  높은 유지 관리 × 낮은 종속성 × 호환 라이선스 → 낮은 위험
  낮은 유지 관리 × 많은 종속성 × 라이선스 충돌 → 높은 위험
```

## 도구 체인

| 도구 | 목적 | 공식 문서 |
|------|------|------|
| OWASP Dependency-Track | 엔터프라이즈급 연속 SCA| [공식 문서](https://docs.dependencytrack.org/) |
| OSV-Scanner | 무료 SCA (OSV.dev 생태계)| [v2 설치 문서](https://google.github.io/osv-scanner/installation/) |
| Trivy | 이미지 + 종속성 + IaC 스캔| [공식 문서](https://trivy.dev/docs/latest/) |
| Syft | SBOM 생성| [공식 저장소](https://github.com/anchore/syft) |
| cdxgen | CycloneDX SBOM 생성| [공식 저장소](https://github.com/cdxgen/cdxgen) |
| Cosign | 컨테이너 서명| [공식 문서](https://docs.sigstore.dev/cosign/) |
| Gitleaks | 비밀/자격증명 스캔| [공식 저장소](https://github.com/gitleaks/gitleaks) |
| Snyk | 상용 SCA + 도달성 분석| [공식 문서](https://docs.snyk.io/) |
| CodeQL | 코드 쿼리 + 데이터 흐름| [공식 문서](https://codeql.github.com/docs/) |

## 참고자료

- `references/sbom-sca-methodology.md` — SBOM + SCA 방법론
- `references/cicd-pipeline-security.md` — CI/CD 파이프라인 안전 감사

Source: [NTIA SBOM Minimum Elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom), [중국 국가표준 프로젝트 20243686-T-469](https://std.samr.gov.cn/gb/search/gbDetailed?id=11DC846DDBE169A8E06397BE0A0A53ED), [EU Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2847/oj), [OSV-Scanner v2](https://google.github.io/osv-scanner/usage/)
