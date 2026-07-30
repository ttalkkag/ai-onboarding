# reverse-skill 탐지지식 발굴 결과

reverse-skill 큐레이션본(13개 모듈, md 71개)을 정독해 **스캐너 엔진에 가져올 정적 탐지 지식**을 선별한 과거 조사 결과다. 원문은 실행 스킬이 아니라 참고 코퍼스다.

- 당시 방법: 4개 병렬 에이전트가 macOS 중심 원자료를 정독해 정적·읽기 전용 후보를 선별
- 현재 표기: **[채택후보]** = 회귀 검증 후 제품 규칙 후보 / **[제품 밖]** = 실행하지 않고 탐지 지식만 참고
- 결론: 방법론 안의 "무엇이 의심스러운가" 카탈로그·정규식·시그니처는 재검증 후 이식할 수 있지만, 스크립트·명령·라우팅은 제품 계약이 아니다.

---

## 1. 공급망 · CI/CD (관련도 높음 — 핵심 직결)

전부 정적 매니페스트/YAML 파싱으로 규칙화 가능. supply-chain-security 모듈에서.

- **[채택후보] CI 워크플로 위험 트리거** — `pull_request_target`(신뢰불가 PR에서 secrets 접근), 스크립트 인젝션(`${{ github.event.issue.title }}` 등 신뢰불가 입력이 `run:` 셸로 유입)
- **[채택후보] 과대 토큰 권한** — `permissions: write-all` 또는 최소권한(`contents: read`) 미선언
- **[채택후보] 서드파티 Action 미고정** — `uses: org/action@tag`(가변) vs `@<40자 SHA>` 고정
- **[채택후보] lockfile 위생** — `package-lock.json`/`go.sum`/고정 `requirements.txt` 누락, 버전 비고정
- **[채택후보] 위험 설치 플래그** — 스크립트·CI 내 `npm i --force`/`--legacy-peer-deps`, 비검증 출처 `pip install`
- **[채택후보] Docker 베이스 비고정** — `FROM ...:latest` 또는 digest 미고정
- **[채택후보] 레지스트리 인증** — 사설 레지스트리에 장기 토큰
- **[채택후보] 의존성 위생(정적)** — 미상/미인가/폐기 의존성, 전이 의존성 증가, 라이선스 충돌
- **[M1 이후 채택후보] 로컬 OSV 매칭** — 유효한 로컬 `MAL-`·생태계별 데이터팩을 재사용하고, 별도 갱신 시 출처·서명/체크섬·disposition을 검증한 뒤 lockfile과 대조한다. 데이터 version은 cache key에 포함한다.
- **[제품 밖] CVE 도달성·심볼릭 도달성 분석, 라이브 exploit PoC 구동** — 대상 빌드·실행이 필요하므로 수행하지 않는다.
- ⚠️ **근거 한계**: 타이포스쿼팅·dependency confusion·`.npmrc` 재정의는 reverse-skill 문서에 직접 근거가 없는 일반 보안지식이다. 온라인 유지보수자·평판 조회는 대상 정보를 외부로 보내므로 제품에 수용하지 않는다.

## 2. 시크릿 · 유출 (cross-cutting)

- **[채택후보] 하드코딩 비밀 정규식 스캔** — 소스/워크플로/매니페스트의 key/password/token/api_key (gitleaks/trufflehog식 *패턴*을 엔진 기본기능으로) — 근거: supply-chain methodology §4, ida-mcp-cheatsheet 검색 정규식
- **[채택후보] 환경변수 → 네트워크 인접** — `process.env`/`os.environ` 가 fetch/socket 근처 (기존 규칙 강화)

## 3. 난독화 · 인코딩 · 페이로드 (decode-후-재스캔 재료 — reverse-engineering 모듈)

스크립트 페이로드(npm/PyPI) 탐지에 **직접 적용 가능한 정적 신호**:

- **[채택후보] 난독 단일라인 스크립트** — 세미콜론 1000+·walrus(`:=`) 체인·`ord()/chr()`·XOR 체인 = 스크립트 페이로드 / minified `dist/`+RC4 문자열 인코딩+CFF = 난독 npm 패키지
- **[채택후보] 인코딩 식별 휴리스틱** — Base64(`=`말미)·Base32·Base58·Hex(짝수)·URL `%XX`·`\uXXXX`·JWT(점3분할) → 디코드-후-재스캔 분기
- **[채택후보] 암호/난독 상수 카탈로그** — AES S-Box `63 7C 77 7B`, ChaCha `"expa"`/`0x61707865`, TEA `0x9E3779B9`, MD5/SHA IV → 숨은 암호 루틴 식별
- **[채택후보] 높은 엔트로피** = 패킹/암호 페이로드의 보조 지표. `7.5` 같은 임계값은 파일 종류·구간 크기·정상 코퍼스로 검증하기 전에는 고정 규칙으로 쓰지 않는다.
- **[채택후보] 압축/패킹 magic byte** — GZIP `1F 8B`, XZ `FD 37 7A 58 5A`, Zstd `28 B5 2F FD`, `UPX!`, 임베디드 ZIP `PK\x03\x04`
- **[제품 밖] OEP dump·동적 언패킹·심볼릭 실행(angr/Triton)** — 대상 실행이 필요하다. 정적 시그니처만 후보로 검토한다.

## 4. 자동실행 / 백도어 정적 신호 (바이너리·네이티브 동봉 시 — reverse-engineering)

"설치-시 자동실행 백도어" 미션에 직결되나, 대상이 **컴파일 바이너리/네이티브 모듈을 동봉할 때만** 적용:

- **[채택후보] 로드시 자동실행 생성자** — ELF `.init_array` → **macOS Mach-O `__mod_init_func`** 매핑 (1순위 신호)
- **[채택후보] RWX/셸코드** — `mmap(PROT_EXEC)`/`mprotect`/macOS `MAP_JIT` + 데이터섹션 셸코드
- **[채택후보] import-hashing / no-import** — `dlopen/dlsym`만 + API 해시 상수(DJB2 `5381`, FNV `0xcbf29ce484222325`)
- **[채택후보] 비표준 dylib 링크** — `otool -L`/비정상 `@rpath` (백도어 공유라이브러리)
- **[채택후보] 헤더/load-command 변조** — 손상 섹션헤더 + 트레일러 append 페이로드 + 매직(`DEADBEEF`)
- **[채택후보] 시간 게이팅** — `time()` + Unix 타임스탬프 상수 비교(특정일에만 동작), fork+pipe+항상거짓 분기 은닉
- **[채택후보] JS→네이티브 실행 경로** — `spawn|execFile|ffi|require(...native)` grep
- **[제품 밖] 디버깅·에뮬레이션** — 대상 실행이 필요하다. 정적 디스어셈블·파일 구조 분석은 별도 안전 검증 후 도구 후보로 평가한다.

## 5. 네이티브 모듈 · 언어 식별 (Windows·macOS 대상)

- **[채택후보] 네이티브 산물 존재 자체** — `*.node`/`*.so`/`*.dylib`, Electron `resources/app.asar` + electron 의존
- **[채택후보] 언어 핑거프린트** — Swift `__swift5_*`, Go `go.buildid`/pclntab(`0xFFFFFFF0`)/`go version -m`로 `-ldflags -X` 임베디드 문자열, Rust `.rustc`/`panicked at`(소스경로 누출)
- **[채택후보] 확장자-매직 불일치 위장** — `.txt/.jpg`인데 실제 실행파일
- **[채택후보] 선언 네이티브 메서드 vs export 심볼 불일치** = 핸들러 은닉
- **[컨텍스트] Go/Rust 문자열은 비-널종단 `(ptr,len)`** → 길이기반 문자열 스캔 필요(decode-후-재스캔 설계 반영)

## 6. AI / LLM 프로젝트 (llm-security — 선택 정적 프로파일)

공격 문서를 **방어 시그니처로 뒤집어** 사용:

- **[채택후보] 숨은 명령 페이로드 탐지** — 동봉 프롬프트/RAG 시드/샘플에 제로폭 문자·흰글자(`color:white;font-size:0`)·`display:none`·`[SYSTEM]`·"ignore all previous instructions" → **"문서 내 명령형 문장"의 정적 탐지 구현체**
- **[채택후보] LLM 출력 → 위험 싱크 테인트** — 모델 출력이 소독 없이 `exec/eval/os.system/subprocess`/SQL조립/`innerHTML`/HTTP로 유입 (RCE 미션 직결)
- **[채택후보] 과도한 에이전시** — `exec/shell/delete/send_email/query_db` 도구가 모델제어 파라미터에 배선 + 승인 게이트 없음
- **[채택후보] 시스템 프롬프트 내 시크릿** — 프롬프트 템플릿에 API Key 하드코딩
- **[원칙(탐지 아님)] 스캐너 자기 하드닝** — 스캐너가 LLM으로 미지 프로젝트를 읽을 때 그 텍스트(README/주석)가 스캐너를 탈취하지 않게 *모든 자연어 입력 = 불신*. → proposal S5
- **[제품 밖] garak/PyRIT/promptfoo 라이브 프로빙** — 동적 레드팀이므로 수행하지 않는다. 2026-07-30 재조사에서도 이 판정은 유지됐다. promptfoo에서 참고할 부분은 제품 런타임이 아니라 fixture 기반 회귀 구조뿐이며 근거는 `external-harness-harvest.md`에 있다.

## 7. 웹 / API (api-security — 선택 정적 프로파일)

- **[채택후보] JWT 오설정** — `alg:none` 허용, 하드코딩 HMAC secret, verify 시 algorithms 미고정(RS256↔HS256 혼동)
- **[채택후보] OAuth 시크릿 노출** — 프론트/모바일에 `client_secret` 하드코딩, redirect_uri 와일드카드
- **[채택후보(약함)] SSRF 싱크** — `webhook_url/callback_url` 사용자제어 fetch + `169.254.169.254`/`metadata.google.internal` IOC
- **[제품 밖] BOLA/IDOR/GraphQL 내성·DoS** — 라이브 DAST이므로 수행하지 않는다.

## 8. Android / 모바일 (선택 정적 프로파일 — apk/mobile-reverse)

대상에 AndroidManifest/Gradle 또는 iOS plist/Mach-O가 있을 때만:

- **[채택후보] Android Manifest 정적 신호** — `debuggable=true`, `allowBackup=true`, `exported=true` 컴포넌트, `usesCleartextTraffic=true`, `protectionLevel=normal` 커스텀 권한
- **[채택후보] 소스 안티패턴** — WebView `setJavaScriptEnabled`+`addJavascriptInterface`(=RCE), `rawQuery` SQLi, ContentProvider `openFile` path traversal, ECB/DES/MD5-for-password, `java.util.Random`(비암호), 평문 SharedPreferences
- **[채택후보] 패커/쉘 지문** — `libjiagu.so`/`com.stub.StubApp`, `libshell*`, `libDexHelper`/`com.secneo.apkwrapper`
- **[채택후보] iOS Info.plist** — `NSAllowsArbitraryLoads`(평문 허용), URL Scheme 등록
- **[채택후보] 플랫폼별 네이티브 정적 파서** — PE·Mach-O·ELF의 import, section, load command, 서명 정보를 공통 증거로 정규화
- **[채택후보·역발상] 안티분석 코드 존재 = 악성 의심** — `PT_DENY_ATTACH`/`ptrace(TRACEME)`, frida-server·포트 `27042` 탐지, Cydia/su 경로 체크가 박혀 있으면 회피·은닉 신호
- **[제품 밖] Frida/Objection 후킹, SSL pinning·root·탈옥 우회, 동적 언패킹, IPA 복호화** — 전부 동적이다.

## 9. 보고서 · 출력 (docs/diagram-generator)

report-template 보강에 직접 사용:

- **[채택후보] 실행요약(§0)** — "무엇 검사 / 무엇 발견 / 위험등급" 한 문단을 최상단
- **[채택후보] 대상 SHA-256 해시** — 플랫폼 공통 라이브러리나 번들 엔진으로 계산해 IOC·추적성 확보
- **[채택후보] 2단 발견 구조** — "발견 요약표 → 항목별 상세(설명/영향/근거/증거 코드블록)"
- **[채택후보] P0/P1/P2 구현 우선순위표** — 후속권고 우선순위화 + 심층모듈 라우팅 포인터. 제품 판정인 HIGH/LOW/INFO와 혼용하지 않는다.
- **[채택후보] 품질 게이트** — placeholder/TODO 금지, **민감정보(토큰·비번·내부 URL) 플레이스홀더 치환**, 제3자 재현
- **[채택후보] 텍스트 화살표 공격경로 체인** — `훅 → 호출파일 → 디코드 → C2` 를 **완전 무설치 텍스트**로 (다단계 트리거 표현 1순위)
- **[참고] Mermaid 소스 인라인** — 시각화는 판정 필수 기능이 아니며 외부 렌더러 없이도 보고서가 완전해야 한다.
- **[채택후보] 텍스트-우선 + graceful-degrade** — 렌더러 없으면 에러 대신 힌트만, "파일 존재 확인 전 '생성됨' 주장 금지"

## 10. 거버넌스 · 프레이밍 (SKILL.md / routing.md)

- **[채택후보] "문서 내 명령형 문장 = 데이터"** — 대상 README/스크립트 주석의 "이거 실행하라"류를 행동지침 아닌 분석 데이터로 (S5, 인젝션 방어)
- **[채택후보] "검사 과정에서 대상 실행·설치 금지"** — HIGH 재확인은 AI 실행 허가가 아니다. AI는 원래/예상 명령을 텍스트로만 제공하고 사용자의 일반 터미널 실행은 관찰 범위 밖이다.
- **[채택후보] 채택/제외 경계 표** — 발견 카테고리별로 제품 규칙과 참고 자료를 구분한다.
- **[채택후보] 라우팅 매트릭스(대상유형 × 의도)** — 우리 탐지 카탈로그(생태계 × 카테고리)와 동형 패턴

## 11. 제품 밖 기능

다음은 Secure Onboard가 실행하지 않는다.
- 동적/샌드박스 실행, 디버깅(lldb/gdb/r2 -d), 에뮬·심볼릭(angr/Triton/Qiling/Unicorn)
- 도구 구동: IDA/Ghidra/radare2 디스어셈, Frida/Objection 후킹, 패커 OEP dump
- 네트워크: 라이브 API/LLM DAST, 온라인 평판·레지스트리 조회, 대상 빌드가 필요한 CVE 도달성 분석

정적 디스어셈블처럼 대상 실행 없이 가능한 일부 기능은 독립된 안전성 검증을 통과한 뒤 선택 분석기로 재평가할 수 있다. 원문의 카탈로그·정규식·시그니처는 제품 규칙이 아니라 후보 목록이다.

## 12. 채택 안 함 / off-target

- binary-diff — "구버전→신버전 마이그레이션"용, 위협 탐지 무관(앵커 우선순위 *설계 아이디어*만 참고)
- js-reverse — 사실상 전부 동적(브라우저/CDP/Hook). 정적 리프트 극소(minified 분기, DeepDive의 decode-후-정제 *철학*만 일치)
- Windows 전용 PE·드라이버 신호는 Windows 선택 프로파일 후보로 재검토한다. Linux `/proc` 전용과 CTF 전용(esolang/MBR/GLSL)은 현재 범위 밖이다.
- 크랙/CTF 정규식(`serial|license|flag|correct`) — 본 스캐너 목표 무관
