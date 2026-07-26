# 보안 관련 모듈 최종 리뷰

> **역사적 참고 코퍼스 리뷰:** 2026-07-22의 플러그인 작업 게이트, HIGH/LOW/INFO와 HIGH 명령 제공 결정이 이 문서의 이전 제품 경계를 대체한다. 최신 정책은 `README.md`와 `../plan/`을 우선한다.

- 검토일: 2026-07-15, 결정 반영 재검증 2026-07-18
- 범위: `api-security`, `llm-security`, `supply-chain-security`, `malware-analysis`, `docs-generator` 아래 Markdown 17개
- 방법: 전 파일 수동 검토, 프로젝트 실행 정책 대조, 공식 문서·표준·RFC·원 논문 우선 검증

## 결론

17개 파일을 모두 검토하고 명백한 사실·명령·번역·Markdown 오류를 직접 수정했다. 특히 실제 CLI와 맞지 않던 Vespasian, Entropy, api.sh, jwt_tool, garak, OSV-Scanner, Cosign, cdxgen, YARA, Sigma, Promptfoo, PyRIT 예제를 현재 공식 문서에 맞췄고, ASD Azul을 샌드박스로 오인한 설명과 근거 없는 통계도 바로잡았다. 최종 교차 검증에서는 Promptfoo 원격 전용 경로의 데이터 반출, OSV-Scanner 호출 분석, cdxgen의 외부 도구·자동 설치 경계와 self-hosted CI의 신뢰 경계를 추가로 명시했다.

후속 결정에서 Secure Onboard는 대상 설치·빌드·실행과 live DAST·detonation을 승인 여부와 관계없이 제품 범위에서 제외했다. 따라서 아래 1·2번은 제품 코어에서는 해결됐고, 해당 문서를 별도 보안 테스트 절차로 재사용할 때의 채택 조건으로 남는다. 3·5번도 참고 자료의 유지보수 조건이다. 4번의 로컬 보고서 저장·마스킹 원칙은 확정됐지만 정확한 JSON 스키마와 보존·독자 정책은 아직 미결이다.

## 상위 설계 이슈

### 1. 해결됨(제품 코어) — 실행 권한 경계가 문서 경고에만 의존했음

**영향**

API 자원 고갈 테스트, 실제 요청을 보내는 DAST, 패키지·도구 설치, 악성코드 detonation이 동일한 방법론 안에 섞여 있다. 에이전트가 문장을 잘못 해석하면 운영 서비스 장애, 데이터 변경, 외부 유출 또는 호스트 감염으로 이어질 수 있다.

**근거**

- 현재 [제안서](../plan/proposal.md)는 대상 설치·빌드·실행을 판정 전후 모두 금지하며, 동적 분석을 승인 후 단계로도 제공하지 않는다.
- Entropy는 기본 dry-run과 실제 요청을 보내는 `--live`를 구분한다: [Entropy 공식 저장소](https://github.com/arjinexe/entropy-chaos)
- OSV-Scanner는 신뢰하지 않은 프로젝트에서 `fix`가 패키지 관리자 스크립트와 외부 레지스트리를 실행할 수 있다고 경고한다: [OSV-Scanner v2 Usage](https://google.github.io/osv-scanner/usage/)
- cdxgen은 일반 모드에서 일부 프로젝트의 의존성을 자동 설치할 수 있고 외부 빌드 도구를 호출한다. 공식 dry-run은 쓰기·child process·임시 디렉터리·clone·제출을 차단하지만 결과가 불완전할 수 있으며, secure mode 자체도 악성 코드에 대한 안전 보장은 아니다: [cdxgen README](https://github.com/cdxgen/cdxgen), [cdxgen permissions](https://github.com/cdxgen/cdxgen/blob/master/docs/PERMISSIONS.md)
- CAPE는 악성 파일을 격리 환경에서 실행하는 샌드박스이며 네트워크 라우팅도 별도 통제가 필요하다: [CAPE 개요](https://github.com/kevoreilly/CAPEv2), [CAPE 라우팅](https://capev2.readthedocs.io/en/latest/installation/host/routing.html)
- NIST는 보안 테스트 전에 실행 권한과 제약을 Rules of Engagement로 정하도록 정의한다: [NIST ROE 정의](https://csrc.nist.gov/glossary/term/rules_of_engagement)

**참고 자료를 별도 동적 테스트 절차로 채택할 때의 조건**

상위 라우터와 각 모듈 front matter에 다음을 명시하고 실행 전에 강제한다.

- `execution_tier`: `static`, `active`, `detonation`
- `requires_explicit_authorization`
- `requires_isolated_environment`
- `network_policy`: `none`, `sink-only`, `approved-target-only`
- `side_effect_budget`와 즉시 중단 조건
- 기본 경로에서는 `active`와 `detonation` 단계를 설명만 하고 실행하지 않는 규칙
- SBOM 생성도 무조건 `static`으로 분류하지 않는다. cdxgen은 먼저 `--dry-run`으로 계획을 검토하고, 실제 생성은
  `--no-install-deps`·검증된 버전·신뢰 설정·대상 읽기 전용·외부 출력·비밀 없는 일회용 runner를 강제한다.
  외부 도구 권한이 필요하면 dry-run이 보고한 명령별로 다시 승인한다.

**제품 코어의 현재 처리와 향후 채택 기준**

제품 코어에서는 live DAST, DoS, 샘플 제출과 대상 설치·빌드 명령으로 향하는 라우팅 자체가 없어야 한다. 향후 별도 제품이나 절차로 채택한다면 승인 정보가 없는 호출 차단과 미신뢰 PR의 self-hosted runner·비밀 접근 차단을 픽스처로 입증해야 한다.

### 2. 해결됨(제품 코어) — 모듈 이름과 실제 커버리지 사이의 계약이 불명확했음

**영향**

`api-security`의 심층 절차는 REST·GraphQL 중심이며 WebSocket·SOAP은 점검 지점만 언급한다. `AgentThreatBench`는 ASI 전체가 아니라 현재 3개 과제와 ASI01·ASI06만 다룬다. 안티분석 문서의 대표 관점은 실무 선별용이고, 원 논문의 정확한 9개 범주·94개 기법 수는 별도 분류표에 명시했다. 이 경계를 놓치면 “전체 테스트 완료”라는 잘못된 보증이 생긴다.

**근거**

- GraphQL-over-HTTP 문서는 아직 Stage 2 draft이며 GET mutation을 405로 거부하도록 요구한다: [GraphQL over HTTP draft](https://graphql.github.io/graphql-over-http/draft/)
- AgentThreatBench의 공식 페이지는 3개 데이터셋과 ASI01·ASI06 범위를 명시한다: [UK AISI AgentThreatBench](https://ukgovernmentbeis.github.io/inspect_evals/evals/agent_threat_bench/index.html)
- 안티분석 원 논문은 94개 기법, 9개 범주와 82개 규칙의 평가를 설명한다: [JCP 원 논문](https://doi.org/10.3390/jcp6020069)

**권고**

각 방법론 첫머리에 `지원`, `체크리스트만 제공`, `미지원`의 3단계 커버리지 표를 둔다. WebSocket·SOAP을 실제 지원하려면 전용 테스트 절차와 검증 근거를 추가하고, 그렇지 않으면 모듈 범위를 REST·GraphQL 중심으로 좁힌다.

현재 결정 레지스터는 WebSocket·SOAP처럼 검증 절차가 없는 영역을 지원한다고 표시하지 않도록 확정했다. 해당 방법론 파일은 제품 기능이 아니라 참고 코퍼스이므로 이 항목은 코어 차단 이슈가 아니다.

### 3. P1 — 빠르게 변하는 CLI·사양의 버전 기준이 없음

**영향**

현재 교정한 명령도 향후 릴리스에서 다시 낡을 수 있다. 특히 CAPE는 rolling 방식으로 유지되고, Promptfoo는 2026-07-11에도 전략 이름을 변경했으며, CycloneDX 최신 버전도 진화한다. 버전 기준 없이 “실행 가능한 예제”를 보장할 수 없다.

**근거**

- Promptfoo의 기존 `prompt-injection` 전략은 `jailbreak-templates`로 변경되었다: [Promptfoo migration note](https://www.promptfoo.dev/docs/red-team/strategies/prompt-injection/)
- CAPE 설치 문서는 rolling 업데이트와 운영자의 지속적 갱신 책임을 명시한다: [CAPE installation](https://capev2.readthedocs.io/en/latest/installation/host/installation.html)
- CycloneDX 공식 사양 페이지는 현재 버전과 지원 직렬화를 공개한다: [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- OSV-Scanner v2는 v1과 명령 구조가 다르다: [OSV-Scanner migration guide](https://google.github.io/osv-scanner/migration-guide.html)

**권고**

각 도구 표에 `검증 버전/commit`, `last_verified`, `공식 문서 URL`을 추가한다. 코드 펜스는 가능한 경우 fixture와 함께 구문·`--help` 스냅샷 검사를 CI에서 실행한다. 버전이 없는 rolling 프로젝트는 검증 commit을 기록한다.

### 4. P1 — 보고서 생성 권한과 민감 증거 배포 정책이 상위에서 강제되지 않음

**영향**

자동 문서 생성은 사용자가 요청하지 않은 파일 변경이 될 수 있고, 침투 테스트 재현 단계·요청/응답·내부 URL·샘플 해시는 민감 정보가 될 수 있다. 템플릿만으로는 저장 위치, 독자, 보존 기간과 공유 범위를 통제하지 못한다.

**근거**

- 이번 수정에서 `docs-generator`의 자동 호출 문구를 제거하고 명시적 사용자 요청을 조건으로 바꿨다.
- NIST SP 800-115는 테스트 계획, 수행, 결과 분석과 보고를 하나의 통제된 평가 프로세스로 다룬다: [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)

**권고**

상위 라우터가 파일 쓰기 전에 출력 경로와 문서 생성을 승인받도록 한다. 보고서에는 `classification`, `intended_audience`, `retention`, `redaction_status`를 필수 메타데이터로 두고, 원본 증거와 배포용 보고서를 분리한다.

### 5. P1 — 연구 결과와 운영 표준의 성숙도 표시가 부족함

**영향**

특정 실험의 공격 성공률이나 최신 프리프린트의 방법을 일반적인 운영 사실처럼 적용할 수 있다. 그러면 우선순위와 탐지 기대치가 왜곡되고 재현되지 않은 기법에 과도하게 의존한다.

**근거**

- PoisonedRAG의 90% 수치는 “대상 질문마다 악성 텍스트 5개”를 넣은 특정 실험 결과다: [USENIX Security 2025 논문 페이지](https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag)
- DEPTEX의 EPD는 2026년 프리프린트에서 제안된 방법이다: [DEPTEX arXiv](https://arxiv.org/abs/2605.00179)
- 안티분석 YARA 연구의 42개 규칙 수치는 정밀도 75% 이상이라는 결과이며 행위별 재현율을 뜻하지 않는다: [JCP 원 논문](https://doi.org/10.3390/jcp6020069)

**권고**

근거마다 `표준`, `공식 도구 문서`, `동료평가 연구`, `프리프린트`, `내부 가설` 라벨을 붙인다. 수치는 데이터셋, 위협 모델, 평가 지표를 같은 문장에 적고 운영 임계값으로 바로 승격하지 않는다.

## 파일별 검토 결과

상태 표기:

- **수정 완료**: 확정 가능한 오류를 바로잡았고 추가 설계 결정 없이 참고문서로 사용할 수 있음
- **조건부 적합**: 문서 오류는 교정했지만 상위 실행·범위·버전 정책이 결정되어야 함

| 완료 | 파일 | 판정 | 주요 확인·수정 |
|---|---|---|---|
| [x] | `api-security/methodology.md` | 조건부 적합 | 인트로스펙션 용어·쿼리, JWT/OAuth 조건부 취약점, GET mutation, DoS 승인 경계, Entropy 발견 기능과 api.sh 8단계 역할 수정. WebSocket·SOAP은 제품 미지원으로 결정 |
| [x] | `api-security/references/jwt-oauth-testing.md` | 수정 완료 | 실행 불가능한 Python 예제 교체, jwt_tool의 `-rh`/`-M pb`와 공식 설치 경로, URI fragment와 Referer 구분, RFC 9700의 PKCE/nonce/state 조건 반영 |
| [x] | `api-security/references/rest-graphql-testing.md` | 조건부 적합 | Vespasian·Entropy·api.sh CLI 교정, 안전한 SSRF sink, GraphQL GET/배치 설명 수정. live 테스트는 제품 범위 밖 |
| [x] | `llm-security/methodology.md` | 조건부 적합 | 외부 유출·셸 실행 예시를 모의 도구로 변경, PoisonedRAG 조건 명시, AgentThreatBench 범위 수정 |
| [x] | `llm-security/references/agent-security-testing.md` | 조건부 적합 | 합성 sink와 부작용 없는 도구로 변경, 벤치마크가 ASI01·ASI06만 다루고 utility/security를 독립 이진 지표로 채점함을 명시 |
| [x] | `llm-security/references/owasp-llm-top10.md` | 수정 완료 | 출처 없는 비율과 잘못된 LLM 번호 제거, 방어 원칙 번역 수정 |
| [x] | `llm-security/references/prompt-injection-methodology.md` | 조건부 적합 | garak 최신 `--target_type`/`--target_name`, PyRIT 최신 API, Promptfoo plugin/strategy 구조와 원격 전용 경로의 반출 경계, 키릴 문자 동형어 수정. 실제 대상 실행은 제품 범위 밖 |
| [x] | `supply-chain-security/methodology.md` | 조건부 적합 | OSV v2와 기본 Go 호출 분석 비활성화, 규제 표현, 도달성 판단, Cosign 용어, digest 고정 예시, cdxgen dry-run 경계 수정. DEPTEX를 프리프린트로 한정 |
| [x] | `supply-chain-security/references/cicd-pipeline-security.md` | 조건부 적합 | STRIDE 부인, 포크 PR 비밀 경계, SLSA 범용 CLI 오류, Cosign v3 bundle, OSV SBOM `-L`, shell 비밀 주입 수정. 같은 job의 dry-run은 승인 게이트가 아님을 명시. 조직 runner 정책 필요 |
| [x] | `supply-chain-security/references/sbom-sca-methodology.md` | 조건부 적합 | SPDX/CycloneDX 형식, cdxgen review-first·secure 생성 경계, Syft·OSV 명령, OSV Go/Rust 호출 분석 위험, 도달성 비교, 승인된 SBOM만 읽는 cron workflow 수정 |
| [x] | `malware-analysis/methodology.md` | 조건부 적합 | 정적 기본값과 detonation 경계, CAPE/Cuckoo 계보, API 기반 과잉 추론, Azul 역할, IOC 구조와 역할 분담, 도구 설치 표현 수정 |
| [x] | `malware-analysis/references/anti-analysis-techniques.md` | 조건부 적합 | API명·시간 임계값, 유효하지 않은 반환 주소/SEH 추론, 근거 없는 YARA 신뢰도 수정. 정확도와 정밀도 구분, 논문 데이터셋 해석 한계 추가 |
| [x] | `malware-analysis/references/sandbox-orchestration.md` | 조건부 적합 | 주관적 속도·회피 강도 순위 제거, CAPE 설치·API·인증·timeout, 제출 옵션과 안티샌드박스 API 수정. 가짜 Azul CLI와 가짜 CAPE 구성 제거 |
| [x] | `malware-analysis/references/yara-sigma-rules.md` | 수정 완료 | 원 논문의 9개 범주가 합계 94가 되도록 정확한 수치 반영, YARA 범위 조건과 재귀 CLI, Sigma logsource·UUID·상태 수정 |
| [x] | `docs-generator/methodology.md` | 조건부 적합 | 자동 쓰기를 명시적 요청으로 변경, 존재하지 않는 참조 제거, 보안 재현 범위와 민감 정보 원칙 및 다수 번역 오류 수정, BOM 제거 |
| [x] | `docs-generator/references/security-report-templates.md` | 수정 완료 | 4중 outer fence로 미종료 fence 수정, 승인/범위/CVSS/마스킹/재검증·증거 식별자 항목과 번역 오류 수정 |
| [x] | `docs-generator/references/templates.md` | 수정 완료 | 잘못된 JSON `[...]`를 `[]`로 수정하고 파일 트리 fence 언어와 TOC 앵커 지정 |

## 직접 수정한 오류 유형

1. **현재 CLI 불일치**
   - Vespasian `crawl/import/generate`
   - Entropy `run --spec --target`와 dry-run/`--live`
   - api.sh의 존재하지 않는 프로토콜별 하위 명령
   - jwt_tool의 playbook 요청 헤더 옵션과 garak target 옵션
   - OSV-Scanner v2의 SBOM `-L`·호출 분석 경계, cdxgen review-first/secure mode, Syft, Cosign v3
   - YARA `yarac`/`-C`, Sigma `sigma convert`
   - PyRIT `PromptSendingAttack`, Promptfoo plugin/strategy
2. **사양·보안 사실 오류**
   - OAuth URI fragment와 HTTP Referer 구분
   - OAuth CSRF에서 PKCE/nonce/state의 조건
   - GraphQL GET mutation 405
   - AgentThreatBench 범위와 독립 이진 지표
   - ASD Azul은 샌드박스가 아니라 지식베이스·분석 플랫폼
   - SLSA에 범용 provenance 생성 CLI가 없다는 점
   - 안티분석 원 논문의 정확한 9개 범주·94개 기법 수
3. **과장되거나 출처 없는 수치**
   - OWASP LLM 위험 분포 제거
   - SCA 도달성 15% 일반화 제거
   - 안티분석 범주별 임의 수치·샌드박스 강도 순위 제거
   - PoisonedRAG·DEPTEX·YARA 연구 결과에 실험 조건과 성숙도 추가
4. **안전하지 않은 예시**
   - 실제 외부 유출·내부 URL·메타데이터 접근 예시를 합성 sink/모의 도구로 변경
   - API DoS, live DAST, 악성코드 실행에 승인·격리·중단 조건 추가
   - 공개 샘플/해시 업로드와 Promptfoo 원격 전용 생성·채점 경로의 기밀성 위험 추가
   - cdxgen의 plain 생성 명령을 dry-run 검토와 승인된 격리 생성으로 분리하고, 미신뢰 PR이 비밀을 가진
     self-hosted runner로 들어가던 CI 예시를 trusted push로 제한
5. **문서 구조**
   - `security-report-templates.md`의 중첩 fence 오류 수정
   - 3개 파일의 UTF-8 BOM 제거
   - 잘못된 JSON, 코드 fence 언어와 다수 번역 오류 수정

## 검증 기준

- 17개 파일이 파일별 체크리스트에 모두 포함되어야 한다.
- Markdown fence가 모두 닫혀야 하며, 중첩 템플릿은 outer 4중 fence를 사용해야 한다.
- 변경 파일에서 UTF-8 BOM이 없어야 한다.
- `git diff --check`가 통과해야 한다.
- `bash` fence는 실행하지 않고 `bash -n` 구문 검사를 통과해야 한다.
- 제거 대상으로 확인한 오래된/가짜 명령 패턴이 남지 않아야 한다.

## 검증 실행 결과

- **통과** — 범위의 Markdown 17개와 파일별 체크리스트 17개가 일치함
- **통과** — fence 길이를 고려한 Markdown 검사에서 미종료 fence 0개
- **통과** — 범위 파일과 이 리뷰 문서에서 UTF-8 BOM 0개
- **통과** — `git diff --check`
- **통과** — `bash` fence 15개 전체 `bash -n` 구문 검사(명령은 실행하지 않음)
- **통과** — `yaml` fence 7개 전체 Ruby Psych 구문 파싱
- **통과** — `python` fence 4개 전체 컴파일 검사(top-level await 허용)
- **해당 없음** — `json` fence 0개
- **통과** — fence 외부의 상대 Markdown 링크 대상 존재 여부
- **통과** — 교체 대상이었던 오래된/가짜 명령 패턴 재검색
- **미실행** — YARA/Sigma/CAPE/DAST의 실제 실행과 외부 시스템 통합 테스트. 프로젝트의 기본 비실행 정책과 설치 금지 범위를 지키기 위해 새 도구를 설치하거나 샘플·대상에 요청을 보내지 않았다. 상위 실행 게이트를 설계한 뒤 승인된 격리 fixture에서 별도 검증해야 한다.

## 주요 공식·1차 출처

### API

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/info/rfc8725/)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/info/rfc9700/)
- [GraphQL over HTTP draft](https://graphql.github.io/graphql-over-http/draft/)
- [Praetorian Vespasian](https://github.com/praetorian-inc/vespasian)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)

### LLM·에이전트

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [UK AISI AgentThreatBench](https://ukgovernmentbeis.github.io/inspect_evals/evals/agent_threat_bench/index.html)
- [Microsoft PyRIT](https://microsoft.github.io/PyRIT/latest/)
- [NVIDIA garak CLI](https://reference.garak.ai/en/stable/cliref.html)
- [Promptfoo red-team configuration](https://www.promptfoo.dev/docs/red-team/configuration/)
- [Promptfoo data handling](https://www.promptfoo.dev/docs/red-team/troubleshooting/data-handling/)

### 공급망

- [NTIA SBOM Minimum Elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
- [EU Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [중국 SBOM 데이터 형식 국가표준 프로젝트](https://std.samr.gov.cn/gb/search/gbDetailed?id=11DC846DDBE169A8E06397BE0A0A53ED)
- [SPDX specifications](https://spdx.dev/use/specifications/)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [cdxgen permissions and dry-run](https://github.com/cdxgen/cdxgen/blob/master/docs/PERMISSIONS.md)
- [OSV-Scanner source and SBOM scanning](https://google.github.io/osv-scanner/usage/scan-source)
- [SLSA v1.2](https://slsa.dev/spec/v1.2/)
- [Sigstore Cosign](https://docs.sigstore.dev/cosign/)

### 악성코드·탐지

- [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2)
- [Cuckoo3 documentation](https://cuckoo-hatch.cert.ee/static/docs/)
- [ASD Azul](https://github.com/AustralianCyberSecurityCentre/azul)
- [YARA documentation](https://yara.readthedocs.io/en/stable/)
- [Sigma documentation](https://sigmahq.io/docs/)
- [안티분석 YARA 평가 원 논문](https://doi.org/10.3390/jcp6020069)
