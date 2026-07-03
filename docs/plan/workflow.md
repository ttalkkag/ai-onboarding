# 워크플로우 상세 — 4단계

대상 디렉토리를 `$TARGET`이라 한다. 모든 명령은 `$TARGET` 내부 코드를 **실행하지 않는다**.

---

## 1단계 · 프로젝트 구성 확인

목적: 무엇을 다루는 프로젝트인지, 어떤 설치/실행 경로가 있는지 파악.

```bash
docs/draft/scan.sh "$TARGET"   # "1. 프로젝트 구성" 섹션이 이 단계를 자동 수행
```

스캐너가 자동 보고하는 것:
- 감지된 생태계 / 패키지 매니저 (npm·pnpm·yarn·pip·go·cargo·gem·composer·maven/gradle·docker·make)
- 파일 수, Makefile 타겟, package.json 존재 여부

추가로 사람이 눈으로 볼 것:
- `README` / `INSTALL` 의 설치·실행 안내 (단, **거기 적힌 명령을 아직 실행하지 말 것**)
- 진입점: `main`, `index.js`, `cmd/`, `bin/`, `Dockerfile`, CI 워크플로우

---

## 2단계 · 보안 검사

목적: 설치/실행 시 악성 동작이 트리거되는지 정적으로 점검.

```bash
docs/draft/scan.sh "$TARGET" --out security-report.md
```

- 종료코드 **1**(HIGH 있음)이면 기본 입장은 "중단·보고".
- 스캐너가 표시한 **모든 HIGH/MED 항목의 파일을 직접 열어** 의도를 확인한다.
  - 라이프사이클 훅(`preinstall`/`install`/`postinstall`/`prepare`)이 무엇을 실행하는지
  - 원시 IP·외부 호스트로의 네트워크 호출 대상
  - `eval`/`base64`/`child_process`의 실제 용도(정상일 수도, 백도어일 수도)
  - "테스트"인데 비대하거나 난독화된 파일(글의 `app/test/index.js` 패턴)
- 자세한 점검 항목은 `../research/threat-catalog.md`.

판단:
- 악성으로 확신 → 설치/실행하지 말고 사용자에게 근거와 함께 보고하고 종료.
- 모호 → 사용자에게 요약 보고 후 결정을 위임.
- 정상으로 보임 → 3단계로(여전히 승인 게이트 통과).

---

## 3단계 · 승인 게이트 → 설치 / 스크립트 실행

목적: 검증된 경우에만, 최소 권한·격리로 설치/실행.

1. **보고 후 승인 요청**: "다음을 실행하려 합니다: `<명령>`. 진행할까요?"
2. **샌드박스 우선** (가능한 환경부터):
   - Docker:
     설치와 테스트/실행을 분리한다. 의존성 다운로드 단계에는 네트워크가 필요할 수 있고, 테스트 단계는 네트워크 없이 실행해야 한다.
     ```bash
     docker run --rm -it -v "$TARGET":/app -w /app node:22-alpine \
       npm install --ignore-scripts

     docker run --rm -it -v "$TARGET":/app -w /app --network none node:22-alpine \
       npm test
     ```
     첫 단계는 registry 접근을 허용하되 lifecycle script를 차단한다. 두 번째 단계는 `--network none`으로 실행한다.
   - 일회용 VM / VPS도 동일 원칙.
3. **로컬이 불가피하면** 도구별 script/release-age 정책을 명시한다.

   | 도구 | 기본 위험 | 권장 옵션/정책 |
   |------|-----------|----------------|
   | npm | `install`/`ci`에서 lifecycle script 실행 | `npm install --ignore-scripts`, 필요 시 `.npmrc`의 `allow-scripts`/`strict-allow-scripts`, `min-release-age` |
   | pnpm v10+ | dependency `postinstall` 자동 실행을 기본 차단하지만 root script는 별도 | `pnpm install --ignore-scripts`, `allowBuilds`만 허용, `dangerouslyAllowAllBuilds` 금지, v11 `minimumReleaseAge` 확인 |
   | Bun | dependency lifecycle은 기본 미실행, root `{pre|post}install`/`prepare`는 실행 | `bun install --ignore-scripts` 또는 `trustedDependencies` 최소화, `minimumReleaseAge` |
   | Yarn classic/modern | 버전별 옵션 차이 | classic은 `yarn install --ignore-scripts`, modern은 `enableScripts: false` 및 `npmMinimalAgeGate` 검토 |
   | Python | PEP517 빌드 백엔드가 코드 실행 가능 | 가상환경에서만, lockfile/hash 기반 설치 우선, 빌드 격리/백엔드 실행 여부를 별도 검토 |
4. 실행한 모든 명령과 그 결과(설치된 패키지 수, 테스트 통과 여부 등)를 기록 → 4단계 보고서에 반영.

승인되지 않으면 설치/실행하지 않는다.

---

## 4단계 · 결과 보고서 생성

`report-template.md`를 채워 `security-report.md`로 저장한다. 포함 내용:

1. 프로젝트 구조/구성 (1단계 결과)
2. 보안 검사 결과 (2단계: HIGH/MED/INFO와 사람 검토 결론)
3. 실행/설치 내역 (3단계: 무엇을, 어디서(샌드박스/로컬), 어떤 옵션으로, 결과는)
4. 최종 판정 및 후속 권고

신뢰할 수 없는 대상의 보고서는 대상 저장소 **바깥**(현재 작업 디렉토리)에 저장한다.
