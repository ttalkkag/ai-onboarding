# 능력 계층 분류 (Tier-0 / Tier-1 / Escalation)

"엔진은 아무것도 설치/조회 안 함"이라는 **install-phobia 오류**를 교정해, 정적·읽기전용 능력을 되찾은 결과.
근거: reverse-skill 재발굴 + 정적 SAST/SCA 도구 지형 + 의존성 인텔리전스 웹 리서치(4 에이전트).

## 교정 원칙 (이 문서의 토대)

**유일한 안전 불변식 = 대상 불간섭**: 검사 중 대상 프로젝트를 **설치·실행·빌드·계측**하지 않는다.

여기서 파생되는 분류 기준 — *대상을 실행하는가?* 단 하나:
- **도구 설치 필요 ≠ escalation.** 운영자가 깐 정적 도구는 대상을 실행하지 않으면 정당한 엔진 능력.
- **메타데이터 네트워크 조회 ≠ escalation.** 대상의 *선언된* 이름·버전을 공개 DB에 묻는 건 대상 실행이 아니다(프라이버시만 고려).
- **escalation = 대상을 실행/계측/설치하거나 동적(런타임).** 디버거·후킹·에뮬·샌드박스·재서명설치만 해당.

> reverse-skill 원문이 이미 `tools.md`(정적) ↔ `tools-dynamic.md`(동적)로 도구를 나눠둔 것이 이 분류의 1차 근거.

---

## Tier-0 — 제로 의존 (macOS 기본 + 번들 데이터, 무네트워크)

어디서든 즉시 실행, 데이터 유출 0. **기본 활성.**

| 능력 | 구현 |
|------|------|
| 휴리스틱 규칙 + 매니페스트 구조 파싱 | 기존 5개 레버 (proposal §4) |
| macOS 기본 정적 도구 | `file`·`strings`·`nm`·`otool -L`·`shasum -a 256`(대상 해시) |
| **OSV 오프라인 매칭** | 생태계별 `all.zip` 로컬 DB(`npm/all.zip`, `PyPI/all.zip` 등)로 이름·버전 대조 → 알려진 CVE/GHSA + **`MAL-` 악성 패키지**. 유출 0 |
| 타이포스쿼팅(사전+거리) | 상위 N 인기 패키지 + `ecosyste.ms/typosquatting-dataset` 번들 + Levenshtein≤2 / 키보드거리 / 2글자 swap / 재배열 / homophone |
| 악성 install-script 정적 휴리스틱 | GuardDog식 규칙을 *직접 구현*: setup.py cmd-overwrite·pre/postinstall·exec-base64·download-executable·env exfil·shady-links·obfuscation |
| 메타데이터 정적 플래그 | release_zero(0.0.0)·empty_information·single_file·bundled_binary·일회용/미등록 메인테이너 이메일 |
| dependency confusion 구조 신호 | npm scope 부재·`.npmrc` registry 미매핑·lockfile 핀 부재·direct URL dependency |
| 디코드-후-재스캔 | base64/hex/XOR 오프라인 디코드 → 재검사 (CyberChef 오프라인/xortool) |

## Tier-1 — 엔진-의존 정적 도구 (운영자 설치, 대상 미실행)

`brew`/`pipx`로 설치. **대상을 실행하지 않음.** 있으면 사용, 없으면 Tier-0로 동작.

### SAST / 패턴
| 도구 | 설치 | 잡는 것 | 안전 조건 |
|------|------|---------|-----------|
| **Semgrep** ⭐ | `pipx install semgrep` | AST/taint SAST + ToB 공급망/멀웨어 룰(`p/trailofbits`) | 로컬 룰만 쓰면 오프라인(소스 미업로드) |
| bandit | `pipx install bandit` | Python: eval/exec·pickle·subprocess(shell=True)·약한암호 | 완전 정적(O) |
| gosec | `brew install gosec` | Go: 크리덴셜·SQLi·InsecureSkipVerify | ⚠️ 모듈 의존성 자동 fetch → 네트워크 격리 정책 |

### SCA / 의존성 취약점
| 도구 | 설치 | 안전 조건 |
|------|------|-----------|
| **OSV-Scanner** ⭐ | `brew install osv-scanner` | lockfile/SBOM 정적 매칭. ⚠️ **`fix` 서브커맨드 금지**(대상 manifest/lockfile write + 패키지매니저 script/외부 registry 호출 가능성) |
| Trivy | `brew install trivy` | `fs`/`repo` 모드(파싱만). 취약점+시크릿+IaC 다용도 |
| Syft + Grype | `brew install syft grype` | SBOM 생성 → 취약점 매칭, 둘 다 정적 |
| npm audit | Node 내장 | `--package-lock-only`만. ⚠️ **`audit fix` 금지**(full install) |
| pip-audit | `pipx install pip-audit` | ⚠️ `--no-deps`/`--require-hashes`/`--locked` *강제*. 환경/동적-메타 모드는 대상 설치/빌드 유발 |

### 시크릿
| 도구 | 설치 | 안전 조건 |
|------|------|-----------|
| **gitleaks** ⭐ | `brew install gitleaks` | 완전 정적·무네트워크 |
| trufflehog | `brew install trufflehog` | ⚠️ **`--no-verification` 강제**(verification이 secret 유효성 확인을 위해 외부 서비스/사용자 지정 verifier와 통신할 수 있음) |

### 멀웨어 / 공급망 특화 (미션 직결)
| 도구 | 설치 | 잡는 것 |
|------|------|---------|
| **GuardDog** ⭐⭐ | `pipx install guarddog` | **install-time 백도어/난독/exfil** 특화. 로컬 tarball/디렉터리 직접 스캔(`guarddog pypi scan /path`). 미션 1순위 |
| **YARA-X** ⭐ | `brew install yara-x` | 파일/바이너리 멀웨어 시그니처·휴리스틱 룰 스캔 |
| capa | `pipx install flare-capa` | 번들 PE/ELF/.NET 바이너리의 capability(C2/지속성/anti-analysis). ⚠️ Mach-O 미지원 |

### 바이너리 정적 (대상에 바이너리/네이티브 동봉 시)
| 도구 | 설치 | 용도 |
|------|------|------|
| LIEF | `pipx install lief` | ELF/PE/**Mach-O** 파싱 — import/섹션/엔트리/서명/변조 |
| rabin2 (radare2) | `brew install radare2` | `rabin2 -I/-i/-E/-z/-S` 정적 추출. ⚠️ **`r2 -d` 디버그 금지** |
| Ghidra 헤드리스 / RetDec | brew/릴리스 | `analyzeHeadless`·`retdec-decompiler` 정적 디컴파일 (※ Ghidra `EmulatorHelper.run()`만 동적) |
| jadx / apktool | `brew install jadx apktool` | `jadx -d`·`apktool d`(Manifest/smali). ⚠️ `apktool b`+재서명+`adb install`은 escalation |
| FLOSS / Detect It Easy | pipx/brew | 난독 문자열 추출·패커 식별 |
| upx -d / xz·zstd -d | brew | 정적 언팩(매직바이트 식별 후). ⚠️ OEP dump만 escalation |

### 의존성 인텔리전스 (네트워크 조회 — 기본 ON + `--offline` 옵트아웃)
| 능력 | 소스 |
|------|------|
| deps.dev 보강 | 배포일(나이)·OpenSSF Scorecard·라이선스·repo stars·SLSA provenance |
| 배포일/나이 → cooldown | npm full packument `time`, deps.dev publishedAt: "최근 N일 배포/메인테이너 변경" |
| 다운로드 수(인기도) | npm downloads API; PyPI는 pypistats — 타이포스쿼팅 오탐 제거 |
| dependency confusion 존재성 | 선언 내부 이름을 public registry 질의 → 404=내부전용 후보, 공개버전>기대버전=shadowing |
| starjacking 검증 | 선언 repo URL의 실제 패키지명 교차조회 |
| OSV/deps.dev 실시간 | 번들 DB가 stale일 때 최신 MAL-/CVE 보강 |

## Escalation — 대상 실행/계측/동적 (엔진 밖 — 승인 + 샌드박스)

- 디버거: `gdb`·`lldb`·`r2 -d`·x64dbg (대상 실행·중단)
- 동적 계측: Frida/Objection/r2frida 후킹, `strace`/`ltrace`/Intel Pin, `LD_PRELOAD` 주입
- 심볼릭/에뮬: angr·Triton·Qiling·Unicorn·Manticore, Ghidra `EmulatorHelper.run()`
- 패커 OEP dump(런타임), 자가복호 .text dump
- APK 동적: `adb install`+실행, SSL pinning/root/탈옥 우회, 온디바이스 언패킹, IPA 복호화, 재서명 설치
- 샌드박스: **OSSF `package-analysis`(gVisor detonate)**·CAPE·Joe·ANY.RUN — *대상 실제 실행*
- 위험 모드(정적 도구의 동적 함정): `osv-scanner fix`·`npm audit fix`·pip-audit 환경/동적-메타 모드·CodeQL 컴파일 언어 빌드
- LLM 라이브 프로빙(garak/PyRIT), 웹 DAST(BOLA/IDOR/GraphQL)

---

## 네트워크 축 정책 (P2 교정)

현 P2 "대상 관련 네트워크 접근 금지"는 install-phobia와 동형의 과잉제약. 두 가지를 분리:

1. **대상-주도 네트워크 (금지)** — C2 콜백·postinstall fetch·런타임 비콘. **대상을 실행해야만 발생** → 불변식이 이미 자동으로 막음. 별도 규칙 불필요.
2. **엔진-주도 메타데이터 조회 (허용)** — 대상의 선언 이름·버전을 공개 DB에 질의. 대상 미실행. 유일 리스크 = 프라이버시.
   - **정책**: 기본 ON + `--offline`/`--no-network` 옵트아웃. 취약/악성은 **번들 OSV DB(Tier-0)로 1차** → 기본 동작 유출 0. deps.dev/registry 보강만 Tier-1 네트워크.
   - 프라이버시 고지: "대상 의존성 이름·버전을 OSV/deps.dev/레지스트리에 전송" 명시 + 옵트아웃.

> 한 줄: 금지할 것은 "대상이 네트워크에 나가는 것"(실행해야 가능 → 이미 막힘)이지 "엔진이 대상 메타데이터를 공개 DB에 묻는 것"이 아니다.

---

## 안전 주의 — "정적"인데 숨은 실행/빌드/네트워크 함정 (반드시 차단)

| 도구 | 함정 | 강제 조건 |
|------|------|-----------|
| osv-scanner | `fix`가 대상 manifest/lockfile을 수정하고 패키지매니저 script 또는 외부 registry 호출을 유발할 수 있음 | `fix` 금지, `scan`만 |
| npm audit | `audit fix`가 full `npm install`(postinstall) | `--package-lock-only`만 |
| pip-audit | 환경/동적-메타 모드가 대상 설치/PEP517 빌드 | `--no-deps`/`--require-hashes`/`--locked` |
| CodeQL | 컴파일 언어(특히 Go)는 대상 빌드 강제 + 상용 라이선스 | 비채택(JS/Py 보조만) |
| trufflehog | verification이 secret 유효성 확인을 위해 외부 서비스/사용자 지정 verifier와 통신할 수 있음 | `--no-verification` |
| radare2 | `-d` 디버그가 대상 실행 | `rabin2`/정적 모드만 |
| gosec | 타입분석용 Go 모듈 자동 fetch | 네트워크 격리 정책 |
| Socket CLI | 의존성 메타데이터를 클라우드로 egress | 오프라인 환경 부적합(보조만) |
| OSSF package-analysis | gVisor에서 대상 detonate | 채택 불가(escalation) |

---

## 미션 직결 Top 5 (install-phobia로 누락됐던 핵심)

1. **GuardDog** — install-script 악성 휴리스틱 특화, 로컬 무실행 스캔. 미션 1순위.
2. **Semgrep** + ToB 룰 — 무실행 SAST + 공급망/멀웨어 패턴.
3. **OSV-Scanner** + **OSV `MAL-` 피드** — 알려진 취약+악성 패키지 매칭(오프라인 가능).
4. **YARA-X** — 멀웨어 시그니처/휴리스틱 룰 엔진.
5. **gitleaks** — 완전 정적·무네트워크 시크릿.
보조: `ossf/malicious-packages` 데이터셋·LIEF/rabin2·capa·Trivy/Grype.

## 출처
- OSV: osv.dev/api, 생태계별 offline DB(`{local_db}/osv-scanner/{ecosystem}/all.zip`), ossf/malicious-packages
- 도구: google.github.io/osv-scanner, trivy.dev, github.com/{anchore/syft,anchore/grype,DataDog/guarddog,VirusTotal/yara-x,mandiant/capa,gitleaks/gitleaks,trufflesecurity/trufflehog,lief-project/LIEF,securego/gosec,PyCQA/bandit}, semgrep.dev, github.com/trailofbits/semgrep-rules
- 의존성 인텔: docs.deps.dev/api/v3, npm REGISTRY-API, docs.pypi.org/api, pypistats.org
- 공급망 공격: snyk.io(dependency confusion/Birsan), checkmarx.com(starjacking), nesbitt.io(typosquatting), ecosyste.ms/typosquatting-dataset
