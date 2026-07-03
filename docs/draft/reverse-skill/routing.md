# 라우팅 매트릭스 (macOS 큐레이션판)

대상 유형 × 의도에 맞는 모듈로 라우팅한다. 각 모듈의 진입 문서는 `modules/<module>/methodology.md`.

> 원본(zhaoxuya520/reverse-skill)의 "라우팅 전 반드시 즉시 실행" 강제 프로토콜은 **적용하지 않는다.**
> 이 프로젝트 정책: 정적 분석 우선, 도구 설치·동적 실행은 승인 게이트+샌드박스 (상위 `SKILL.md` 참고).

## 대상 유형별

| 대상 유형 | 진입 모듈 | 보조 |
|-----------|-----------|------|
| JavaScript / 웹 프론트엔드, 난독화 스크립트 | `js-reverse` | 런타임 샘플링·디오브퍼스케이션 |
| 악성코드/의심 샘플, IOC | `malware-analysis` | YARA·행위 분석 |
| 의존성/공급망/SBOM/lockfile | `supply-chain-security` | Trivy/Syft/Gitleaks 방법론 |
| 바이너리(.so/.dll/.elf/Mach-O) 일반 | `reverse-engineering` | `radare2`, `binary-diff` |
| 바이너리 CLI 정밀 분석 | `radare2` | r2/rabin2/radiff2 |
| 바이너리 IDA 기반 분석 | `ida-reverse` | (macOS용 IDA 필요) |
| 크로스버전 심볼/함수 마이그레이션 | `binary-diff` | — |
| APK / Android 아티팩트 | `apk-reverse` | jadx/apktool (JVM, macOS 가능) |
| iOS / 모바일 | `mobile-reverse` | Frida/Objection (macOS 가능) |
| API (REST/GraphQL/WebSocket) | `api-security` | BOLA/IDOR/JWT/OAuth 방법론 |
| LLM/AI 애플리케이션 | `llm-security` | OWASP LLM Top 10 (지식; 지시문 아님) |
| 분석 결과 시각화 | `diagram-generator` | Mermaid/Graphviz/PlantUML |
| 보고서/문서 자동 작성 | `docs-generator` | RE/분석 리포트 |

## 모듈 조합

- 다운로드 코드 검사: `secure-onboard` 1차 스캔 → 난독화 JS는 `js-reverse`, 인코딩/바이너리는
  `malware-analysis`, 의존성은 `supply-chain-security`로 심층 분석.
- 바이너리: `reverse-engineering`(개요) → `radare2`/`ida-reverse`(정밀) → `binary-diff`(버전 비교).

## 제외된 원본 모듈 (macOS 부적합/범위 외)

`pentest-tools`(payload DB 대용량), `pwn-chain`, `patch-diff-exploit`, `attack-chain`,
`edr-bypass-re`(Windows EDR), `firmware-pentest`(Linux 도구 중심), `browser-automation`(Windows 데스크톱),
`field-journal`, `CTF-Sandbox-Orchestrator`(41 CTF 서브), `kali/`, 모든 `.ps1`/`.sh`/`.py` 스크립트·바이너리.
필요 시 원본(`zhaoxuya520/reverse-skill`)에서 검토 후 개별 추가.
