# 실행 게이트 기능·도구 후보

> 상태: **리서치 카탈로그**. 도구 이름은 제품 포함이나 지원을 뜻하지 않는다. M1 계약은 `../plan/`을 따른다.

## 채택 기준

제품에 수용할 기능은 다음 조건을 만족해야 한다.

1. Claude Code·Codex의 실행 직전 작업과 명확히 연결된다.
2. 대상 코드를 검사 과정에서 임의로 설치·빌드·실행하지 않는다.
3. 대상 프로젝트가 제공한 ignore·config·실행 파일·도구 경로·환경 주입을 신뢰하지 않는다.
4. 도구 출처·버전·무결성·설정·권한을 고정할 수 있다.
5. 시간·메모리·파일 수·출력 크기 제한과, 보호 action 실패→HIGH deny/read-only scan 실패→HIGH finding 변환을 검증할 수 있다.
6. 로그·캐시에 비밀값·소스 원문·절대 경로를 저장하지 않는다.
7. Windows와 macOS, Claude Code와 Codex에서 결과를 같은 `Finding`으로 정규화할 수 있다.

외부 프로젝트를 AI가 읽는 것은 허용되지만, 각 CLI의 공급자 데이터 정책을 따른다. 별도 검사 도구가 대상 원문을 제3자 서비스에 자동 업로드하는 기능은 기본 범위 밖이다.

## M0 — 먼저 검증할 hook 경계

| 기능 | 역할 |
|------|------|
| native client adapters | Claude/Codex payload를 `HookEnvelope`로 정규화하고 documented deny·continue 반환 |
| sentinel policy | 실제 분석 없이 HIGH/LOW/INFO 고정 판정 |
| process/result observer | target tool handler·command process 실행 0, native approval 유지, result correlation 증거 수집 |
| status probe | client별 plugin/hooks OFF와 self-test의 확인 가능 범위 기록 |

## Core — M1 확정 기능

| 기능 | 역할 |
|------|------|
| activation registry | 전역·프로젝트 활성화와 프로젝트 비활성화 우선순위 계산 |
| client adapters | Claude/Codex hook input을 `HookEnvelope`로, HIGH를 client deny로 변환 |
| command normalizer | shell, argv, cwd, action kind와 command origin 분리 |
| safe renderer | 사용자 명령·AI 예상·실행 예정·차단 명령을 안전하게 표시 |
| target fingerprint | 내용·권한·symlink와 실행 문맥 지문 생성 |
| deterministic rules | npm install과 파일 열기 최소 HIGH/LOW/INFO 규칙 |
| policy engine | 최대 severity와 `deny|continue` 결정 |
| evidence/action cache | 같은 대상·작업·버전의 중복 분석 방지 |
| local activity history | redacted 판정·차단·경고·명령 제공 event 기록 |
| status diagnostics | client별 plugin/hooks 설치·활성과 self-test, 현재 scope 상태 표시 |

Core는 LOW·INFO에서 Claude Code·Codex의 기존 sandbox·approval을 우회하지 않는다.

## M1 내장 검사 후보

| 기능 | M1 역할 | 경계 |
|------|---------|------|
| npm artifact/metadata parsing | exact local `.tgz` identity와 기본 metadata 확인 | lockfile/cache만으로 remote install bytes를 검증했다고 주장하지 않음; lifecycle→sink 도달성은 M2 |
| small pinned reputation fixture | HIGH/LOW oracle | 실제 registry의 임의 패키지를 악성으로 단정하지 않음 |
| file type/signature scan | EICAR·고정 위험 script signature·기본 형식 확인 | container·default-app 실행 경로는 M2, 기본 앱으로 파일을 열지 않음 |
| secret pattern scan | 값 없는 종류·위치 finding | source→sink 흐름은 M2, 원문 비밀 저장·로그 금지 |

AI assessment bridge, lifecycle/source→sink 분석과 container 내부 분석은 M2 후보다.

## Optional local analyzers — M1 이후

다음은 로컬·정적·비실행 모드만 검토한다. 정확한 버전과 지원 플랫폼은 채택 시 다시 확인한다.

| 후보 | 기대 역할 | 채택 전 강제 조건 |
|------|-----------|-------------------|
| Semgrep | AST·taint 기반 소스 패턴 | 로컬 규칙, 대상 ignore 무시, 네트워크·자원 제한 |
| GuardDog | PyPI/npm 악성 설치 패턴 | 로컬 파일만 스캔, 다운로드·설치 금지 |
| OSV-Scanner 또는 내장 matcher | lockfile과 악성·취약 패키지 대조 | trusted config와 전용 local DB 경로, 대상 `osv-scanner.toml` 자동 적용 금지, 수정 기능 금지, 데이터 버전 cache key 포함 |
| YARA-X | 파일·바이너리 정적 시그니처 | 검증된 규칙팩, timeout·크기 제한 |
| gitleaks | 비밀 패턴 탐지 | verification·외부 전송 없음, 값 마스킹 |
| LIEF·rabin2 | PE·ELF·Mach-O 정적 구조 | 디버그 금지, read-only 입력·자원 제한 |
| jadx·apktool | APK manifest·코드 정적 추출 | rebuild·서명·설치 금지, 대상 밖 임시 출력 |
| Syft 등 SBOM 도구 | 패키지 인벤토리 보강 | 설치·빌드·외부 호출 없는 검증 모드 |

“정적 도구”라는 이름만으로 안전하다고 가정하지 않는다. 파서 취약점, 자동 다운로드, child process, 대상 설정 주입, 네트워크 verification과 출력 경로 쓰기를 fixture로 검증한다.

## Docker 후보

Docker는 M1 필수가 아니다. 후속 정적 분석기를 격리할 때만 검토한다.

- 대상은 read-only, 출력은 대상 밖 일회용 저장소
- 네트워크, Docker socket, host 비밀, 불필요한 capability와 공유 경로 차단
- 고정 digest 이미지와 검증된 도구만 실행
- 대상 Dockerfile, package manager, build, test, entrypoint 실행 금지

Docker는 host kernel을 공유하므로 악성 대상을 안전하게 실행하는 보증 수단이 아니다.

## 보안 데이터 후보

OSV·MAL 평판 데이터는 M1 이후다. 도입할 때 다음 계약을 먼저 고정한다.

- 지원 생태계와 데이터 출처·라이선스·서명/체크섬
- max-age, 업데이트·롤백·철회 disposition
- 데이터 version을 evidence/action cache key에 포함
- 대상에서 얻은 패키지 값을 외부 서비스에 전송할지 여부와 사용자 고지
- 데이터 없음·손상·갱신 실패의 `guardrail.scan_failure` 처리

매 작업마다 무조건 전체 데이터를 다시 내려받지 않는다. 유효한 로컬 데이터와 매니페스트를 재사용하고 필요할 때만 별도 갱신한다.

## 제품 범위 밖 — 탐지 지식만 참고

- debugger, Frida·Objection, strace·ltrace, r2 debug
- Qiling·Unicorn·angr 등 에뮬레이션·심볼릭 실행
- APK/IPA 재서명·설치, 모바일 후킹
- CAPE·ANY.RUN 등 detonation
- live DAST·DoS·API/LLM probing
- cloud binary·sample upload
- 검사 과정의 package manager install, CodeQL build, 대상 Dockerfile build
- 자동 수정 명령과 lockfile·manifest write

관련 문서에서 정적 IOC·파일 형식·위험 sink를 추출할 수는 있지만 실행 절차는 제품 플로우로 가져오지 않는다.

## 도구 채택 완료 기준

- 지원 client·OS·최소 버전과 고정 도구 버전
- 공식 배포 출처, 해시·서명 또는 provenance
- 대상 설정·환경변수·cwd를 신뢰하지 않는 wrapper
- network·child process·write·resource-limit 테스트
- HIGH·LOW·INFO·오류 fixture와 exact `rule_id` oracle
- live adapter가 scanner 오류를 보호 action의 명시적 HIGH deny 또는 read-only scan의 HIGH failure report로 바꾸는 test
- 로그·hook output redaction test
- 라이선스와 업데이트·롤백 절차

## 주요 자료

- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [OSV 소개](https://google.github.io/osv.dev/)
- [OSV 데이터 덤프](https://google.github.io/osv.dev/data/)
- [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)
- [Semgrep 문서](https://semgrep.dev/docs/)
- [YARA-X](https://virustotal.github.io/yara-x/)
