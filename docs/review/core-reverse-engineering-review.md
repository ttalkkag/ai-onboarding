# Core Reverse Engineering 모듈 최종 리뷰

> **역사적 참고 코퍼스 리뷰:** 2026-07-22 이후 제품 정책은 `README.md`와 `../plan/`을 따른다. 아래 도구/API 사실과 안전 주의는 해당 자료를 후속 분석기로 채택할 때만 재검증해 사용한다.

- 검토일: 2026-07-15, 결정 반영 재검증 2026-07-18 (Asia/Seoul)
- 범위: `docs/draft/reverse-skill/modules/reverse-engineering/**` 아래 Markdown 21개, 총 9,910줄
- 방법: 전 파일 정독, 명령/API/ABI/알고리즘 대조, 내부 링크 정적 검사, 외부 URL HTTP 검사, 공식 문서·원 논문 우선 웹 검증, 변경 전후 Python fenced-code 문법 비교
- 최종 판정: **참고 코퍼스로 보존 가능 — 내용상의 명백한 오류와 내비게이션은 교정했으나, 제품 규칙·실행 계약으로의 채택은 출처·재현성·안전 경계가 부족해 보류**

## 요약

직접 실행 결과를 틀리게 만드는 단순 오류는 문서 안에서 최소 수정했다. 대표적으로 ELF32/ELF64 고정 오프셋 혼용, Go `pclntab` 매직, Redress/GoReSym/Qiling/Frida 명령, SGX sample-RA KDF, xorshift64* 상태 갱신, `psadbw` 의미, Morse 패치 슬라이스, HD44780 E/DDRAM 명칭, AES-CBC IV 길이, Rust 기본 레이아웃 단정, FRACTRAN의 잘못된 일반 역변환을 교정했다.

최종 패스에서 실제 제목으로 수동 TOC 14개를 재생성하고 교차 링크를 함께 갱신했다. 추가 정확성 패스의 제목 정리까지 반영한 뒤 상대 링크 531개에서 파일·앵커 누락을 다시 0개로 만들었다. 문장 몇 개로 해결할 수 없는 구조적 문제는 다음 두 가지가 남는다.

1. CTF 사례 다수가 대회명·연도만 있고 원문, 바이너리 해시, 아키텍처, 도구 버전, 재현 조건이 없다. 사례 고유 동작이 일반 원리처럼 서술된 곳도 많다.
2. 실행·후킹·원격 상호작용 예제가 광범위하다. 후속 결정에서 이 기능들은 Secure Onboard 제품 범위 밖으로 제외됐으므로 현재는 참고 자료로만 보존한다. 향후 별도 절차로 채택하려면 승인 범위와 격리 기준을 포함한 safe-by-default 재설계가 필요하다.

## 구조적 발견 사항

### S1. 수동 TOC와 번역 제목이 분리된 내비게이션 문제 — 해결됨

영향:

- 사용자가 목차를 눌러도 해당 절로 이동하지 않는다.
- 에이전트가 링크를 따라 필요한 문맥을 불러오는 작업도 실패한다.
- 같은 문서가 추가 번역/편집될 때 오류가 계속 증가한다.

증거:

- 최초 검사에서는 파일 누락 2개·앵커 불일치 381개였다.
- 최다 파일: `field-notes.md` 136, `patterns.md` 37, `anti-analysis.md` 30, `tools-dynamic.md` 26, `tools-advanced.md` 21.
- 예: `anti-analysis.md`의 `#linux-anti-debug-advanced`, `field-notes.md`의 다수 영어 앵커가 실제 한국어 제목 slug와 일치하지 않는다.
- 최종 패스에서 14개 수동 TOC와 교차 링크를 실제 heading에서 계산한 GitHub식 slug로 갱신했다.
- 추가 제목 교정까지 반영한 수정 후 21개 문서의 상대 파일·앵커 링크 531개를 재검사한 결과 누락은 0개다.

권고:

1. 수동 TOC를 제거하고 렌더러가 생성하는 TOC를 사용하거나, 실제 heading에서 TOC를 생성하는 단일 스크립트를 둔다.
2. CI에서 내부 파일과 앵커를 모두 검사하고 `missing=0`을 병합 조건으로 둔다.
3. 제목 언어를 바꾸면 TOC도 같은 커밋에서 재생성한다.

참고:

- GitHub heading 링크 동작: <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes>

### S2. 위험한 샘플 실행의 보안 경계가 불충분 — 제품 범위 밖·채택 시 높음

영향:

- 악성 또는 미확인 바이너리를 호스트에서 `strace`, `ltrace`, Frida, `ldd`, qemu-user로 실행할 수 있다.
- 쓰기 가능한 호스트 디렉터리를 Docker에 마운트하거나 네트워크를 연 상태로 실행하면 분석 호스트와 외부 시스템에 영향을 줄 수 있다.
- CTF용 원격 업로드·인증 우회 예제가 승인받지 않은 대상에 재사용될 수 있다.

증거:

- 초기본의 `methodology.md`, `patterns-ctf.md`, `tools-dynamic.md`, `field-notes.md`는 실행을 빠른 첫 단계로 제시했다. methodology는 정적-first로 교정했지만 사례 파일의 직접 실행 예제는 여전히 많다.
- `patterns-ctf.md`의 ransomware 예시는 호스트 작업 디렉터리를 쓰기 가능하게 마운트했으며, 이번 수정에서 read-only·network-none·cap-drop·no-new-privileges로 바꿨다.
- `ldd` 실행은 신뢰하지 않는 실행 파일에 안전하지 않을 수 있어 `readelf -d`/`objdump -p` 우선으로 바꿨다.
- Docker와 qemu-user는 완전한 악성코드 샌드박스가 아니다.
- Node `require()`의 top-level 코드 실행, 호스트 시계 변경, 실제 CAN 송신, 하드웨어 VCC/logic-level 위험을 각 예제의 직접 진입점에 경고했다.
- 동적 실행 중심이던 methodology를 정적 분류·제어 흐름·가정 검증 후 필요한 질문만 격리 실행하는 순서로 바꿨다.

권고:

1. 모든 실행 절 앞에 “소유/명시적 허가”, “폐기 가능한 VM”, “비밀·공유 폴더 없음”, “기본 네트워크 차단”을 공통 전제 조건으로 넣는다.
2. 정적 분석을 기본 경로로, 실행은 별도의 `unsafe-dynamic-lab.md`로 분리한다.
3. 클라우드 분석 서비스에는 업로드/보존/기밀성 경고를 붙인다.
4. 실제 차량 CAN, 커널 드라이버, SGX/펌웨어, 원격 서비스는 전용 테스트 벤치와 승인 범위를 필수화한다.

공식/1차 참고:

- Docker Engine 보안: <https://docs.docker.com/engine/security/>
- QEMU user-mode 설명: <https://www.qemu.org/docs/master/user/main.html>
- `ldd` 보안 주의: <https://man7.org/linux/man-pages/man1/ldd.1.html>
- Binary Ninja Cloud 업로드 조건: <https://binary.ninja/free/>

### S3. 사례 고유 사실과 일반 규칙의 경계가 불명확 — 높음

영향:

- 특정 CTF의 오프셋, 키 길이, 루프 횟수, 레지스터 배치가 일반 ABI/알고리즘 규칙으로 오인된다.
- 원본 샘플이 없으므로 코드가 실제 사례를 재현하는지 검증할 수 없다.
- 향후 에이전트가 근거 없는 수치와 “항상/모두” 표현을 사실로 재사용한다.

증거:

- `patterns-ctf*.md`, `languages*.md`, `field-notes.md`에 하드코딩된 파일 오프셋·주소·성능 수치·프로토콜 동작이 많다.
- “참고자료: 대회명 연도”만 있고 직접 URL이나 challenge artifact 식별자가 없는 절이 다수다.
- `field-notes.md`의 웹 피싱 인프라 절은 core RE 범위를 벗어나고, 존재하지 않던 `phishing-case-study.md`를 가리켰다. 깨진 파일 링크는 제거했지만 내용 분리는 남았다.

권고:

- 각 사례에 `source URL`, `artifact SHA-256`, `arch/OS`, `tool version`, `verified on`, `case-specific assumptions`를 의무 필드로 둔다.
- 출처를 확보하지 못한 사례는 “미검증 메모”로 격리하고 일반 가이드에서 제외한다.
- 숫자·성능·지원 버전에는 측정 조건과 확인일을 붙인다.

### S4. 같은 주제가 여러 파일에 복제되어 이미 상충하기 시작함 — 중간

중복 축:

| 정본 후보 | 중복 소비자 | 현재 위험 |
|---|---|---|
| `anti-analysis.md` | `patterns.md`, `field-notes.md`, `methodology.md` | `ptrace` 반환 패치가 한 곳은 `ret`, 다른 곳은 `xor eax,eax; ret`였음 |
| `go-reverse.md` | `languages-compiled.md`, `field-notes.md` | Redress 구형 플래그와 Go 매직이 서로 다르게 오래됨 |
| `tools-dynamic.md` | `tools-advanced.md`, `field-notes.md` | Frida/Qiling API와 “모든 anti-debug 우회” 표현이 반복됨 |
| `elf-analysis.md` | `platforms-hardware.md`, `platforms.md` | AArch64 x8, LR, PC-relative 설명이 서로 다른 수준으로 단정됨 |
| `patterns-ctf*.md` | `field-notes.md`, `methodology.md` | 사례 요약이 복사되어 링크/사실 수정이 전파되지 않음 |

권고:

- 상세 설명은 한 파일만 정본으로 두고, field notes와 methodology는 2~3문장 요약과 링크만 유지한다.
- API 코드 예시는 버전 핀과 최소 smoke test가 있는 별도 snippets 디렉터리에서 가져오게 한다.

### S5. 도구 API와 버전 범위를 고정하지 않아 예제가 빠르게 부패함 — 높음

직접 확인·교정한 사례:

- Frida: `Module.findExportByName`/`Module.findBaseAddress`와 `--no-pause` 예제를 현재 API 형태로 교정하고, Stalker가 대상 함수의 진입·반환 구간에만 연결되도록 수정.
- Qiling: `hook_address`, `os.set_syscall`, `os.set_api` 호출을 현재 형태로 교정하고 Linux syscall과 Windows API 예제를 대상별 인스턴스로 분리. Qiling 공식 FAQ가 API/syscall 구현의 불완전성을 명시하므로 “모든 anti-debug 자동 우회”를 삭제.
- Redress: `-src/-pkg/-type/-interface/-filepath` 형태를 현재 `source`, `packages`, `types` subcommand와 옵션 형태로 교정.
- GoReSym: 존재하지 않는 `-o ida_script.py`를 제거하고 JSON + 공식 IDAPython import 경로로 교정.
- Binary Ninja: Free는 로컬 앱과 Cloud 두 옵션이며 둘 다 API/plugin 제한이 있고 Cloud는 바이너리 업로드가 필요함을 반영.
- Windows `GetThreadContext`: 현재 스레드의 context가 유효하다는 예제를 제거하고, 정지된 다른 스레드나 exception `CONTEXT`를 사용하도록 교정.
- Miasm `LocationDB`, Qiling `QL_INTERCEPT.CALL`과 pipe stream, RetDec 공식 설치/CLI, LIEF 1.x enum을 현재 공식 예제와 맞췄다.
- 미완성 코드를 실행 예제로 오인하지 않도록 BF 비교, one-line Python/Z3, GDB brute-force를 정적 locator 또는 명시적 골격으로 구분했다.

공식 근거:

- Frida JavaScript API: <https://frida.re/docs/javascript-api/>
- Qiling hooks: <https://docs.qiling.io/en/latest/hook/>
- Qiling syscall/API hijack: <https://docs.qiling.io/en/latest/hijack/>
- Qiling FAQ: <https://docs.qiling.io/en/latest/faq/>
- Redress: <https://github.com/goretk/redress>
- GoReSym: <https://github.com/mandiant/GoReSym>
- GoStringUngarbler 지원 범위: <https://github.com/mandiant/GoStringUngarbler>
- Binary Ninja Free/Cloud: <https://binary.ninja/free/>
- Windows `GetThreadContext`: <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext>
- Miasm 공식 예제: <https://github.com/cea-sec/miasm/blob/master/example/disasm/full.py>
- RetDec 설치/CLI: <https://github.com/avast/retdec>
- LIEF ELF Python API: <https://lief.re/doc/latest/formats/elf/python.html>
- Qiling 표준 스트림 hijack: <https://docs.qiling.io/en/latest/hijack/>

권고:

- 각 도구 절에 `verified version/date`를 추가하고, 분기별 smoke test를 실행한다.
- 설치 명령은 venv/container와 버전 핀을 사용한다.
- “최신”, star 수, 지원 버전 범위는 자동 갱신하지 못하면 제거한다.

### S6. ABI·파일 형식·언어 레이아웃을 고정 구조처럼 서술 — 높음

직접 교정한 핵심:

- ELF 헤더 고정 오프셋이 ELF64 기준임을 명시하고 ELF32 오프셋을 추가.
- AArch64 x8의 ABI 간접 결과 역할과 Linux syscall 역할을 분리.
- Rust `Option`/`Result`, `Vec`, `String`의 기본 representation이 안정 ABI가 아님을 명시.
- C++ Itanium vtable address point와 MSVC vftable을 분리.
- Kotlin/Native의 현대 메모리 관리가 tracing GC임을 반영.
- MIPS delay slot, eBPF LDDW, Classic CAN/CAN FD의 예외를 반영.
- Windows/MSVC와 Itanium C++ RTTI 전위 구조, Swift 표준 라이브러리 layout, Thumb-2 32-bit 명령, Volatility 3 ISF, AS/400의 IBM i/CCSID 범위를 추가로 분리했다.
- compact JWT를 JWS 3-segment/JWE 5-segment로 구분하고, Python pyc header 범위를 3.2/3.3/3.7 경계로 교정했다.

공식/1차 근거:

- ELF gABI header: <https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch4.eheader.html>
- AAPCS64: <https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst>
- Rust type layout: <https://doc.rust-lang.org/stable/reference/type-layout.html>
- Itanium C++ ABI: <https://itanium-cxx-abi.github.io/cxx-abi/abi.html>
- Kotlin/Native memory manager: <https://kotlinlang.org/docs/native-memory-manager.html>
- Python `dis`의 버전 의존성: <https://docs.python.org/3/library/dis.html>
- JWS/JWT: <https://datatracker.ietf.org/doc/rfc7519/>
- JWE: <https://datatracker.ietf.org/doc/html/rfc7516>

권고:

- 모든 구조체 표에 `ABI`, `arch`, `compiler/version`, `observed—not guaranteed` 열을 둔다.
- raw file offset와 VA/RVA를 예제 변수명부터 분리한다.
- 파일 헤더를 직접 덮어쓰는 예시는 class/endianness/backup 검증 없이는 제공하지 않는다.

### S7. 암호·수학 설명에서 관용구와 정의를 혼동 — 높음

교정 내용:

- TEA/XTEA를 “고정 64라운드 루프”로 식별하던 표를 32사이클·양쪽 절반 갱신으로 정리.
- `x² mod 2`가 항상 0이라는 거짓 opaque predicate를 `x(x+1)` 짝수 성질로 교체.
- xorshift64*의 각 상태 갱신에 uint64 마스크를 적용하고 곱셈 출력은 내부 state에 다시 넣지 않도록 수정.
- `psadbw`가 8바이트씩 두 개의 64-bit lane 합을 만든다는 의미로 수정.
- FRACTRAN은 분수 swap만으로 일반적으로 역산할 수 없음을 수정.
- SGX sample-RA의 KDK/SK CMAC 단계와 byte order를 복원하고, enclave measurement가 세션 키를 결정한다는 거짓 설명을 삭제.
- AES-CBC IV는 16바이트라는 제약과 `RijndaelManaged` 비-AES block size 가능성을 반영.
- 역전 수열 복구 인덱스, 커널 미로의 반대 방향 표, PKCS#7 unpadding을 교정했다.
- 가짜 CVP 코드와 유리수 `Matrix.solve()` 기반 mod-`2^32` 풀이를 exact bounded SMT/32-bit bit-vector 모델로 바꾸고 원식 검증을 추가했다.
- xorshift+홀수 곱셈의 전단사성, DNN의 full-rank/정의역/수치 조건, ZF가 단독으로 key byte를 뜻하지 않는다는 한계를 반영했다.

공식/1차 근거:

- Intel SGX attestation 개요: <https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/attestation-services.html>
- Intel SGX SDK reference: <https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_Developer_Reference_for_Linux_OS.pdf>
- .NET Rijndael block size: <https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rijndaelmanaged.blocksize>
- Linux BPF JIT 문서: <https://docs.kernel.org/6.10/networking/filter.html>
- HD44780 데이터시트 사본: <https://www.sparkfun.com/datasheets/LCD/HD44780.pdf>

권고:

- 암호 식별 표는 “필요조건/힌트일 뿐 확정 아님”으로 명시한다.
- 수학 코드에는 최소 known-answer test를 붙인다.
- 사례 고유 KDF/round count는 표준 이름만으로 일반화하지 않는다.

### S8. AI 보조 RE 절은 최신 연구 수치는 대체로 맞지만 사용 범위가 과장됨 — 중간

확인 결과:

- Decaf의 ExeBench Real-O2 26.0%→83.9%, constraint-guided multi-agent의 84~97%와 평균 비용, MOTIF의 15%→86%는 각 원 논문 초록과 부합했다.
- REMEND는 Crossref DOI metadata 기준 2026-03-20 온라인 발행, 2026-06-30 print(17권 3호)이며 metadata 생성일만 2025-07-22이다. ACM 페이지는 자동 요청에 403을 반환했지만, 저자 공식 프로젝트와 공개 논문 artifact의 동일한 초록이 89.8~92.4%, 최대 12M parameters, 평균 0.132초/function을 뒷받침한다. 문서에는 독립 재현값이 아닌 논문 보고 benchmark로 명시했다.
- LLM4Decompile은 현재 공식 README 기준 Linux x86-64 중심이며, 문서의 ARM/MIPS 지원 주장과 `llm4decompile.py --binary --arch` CLI는 근거가 없어 교정했다.
- Glaurung은 실제 프로젝트지만 active development이며 decompiler quality와 일부 아키텍처가 진행 중이므로 “모든 플랫폼 RE” 표현을 낮췄다.

원 논문/공식 저장소:

- LLM4Decompile: <https://github.com/albertan017/LLM4Decompile>
- Decaf: <https://arxiv.org/abs/2605.11501>
- Constraint-Guided Multi-Agent Decompilation: <https://arxiv.org/abs/2604.23940>
- REMEND: <https://doi.org/10.1145/3749988>
- REMEND Crossref metadata: <https://api.crossref.org/works/10.1145%2F3749988>
- REMEND 저자 공개 artifact: <https://huggingface.co/udiboy1209/REMEND>
- REMEND 저자 프로젝트: <https://mudeshi.in/projects/remaqe>
- MOTIF: <https://arxiv.org/abs/2601.01673>
- Glaurung: <https://github.com/mjbommar/glaurung>

권고:

- benchmark 이름, split, metric, model, 확인일을 수치 옆에 유지한다.
- “컴파일 성공”과 “행동 동등성”을 분리하고, 원본/후보의 I/O·부작용 비교를 필수로 한다.
- 모델 가격은 고정 표가 아니라 현재 provider 가격과 토큰 사용량으로 계산한다.

## 외부 링크 감사

- 고유 외부 URL 116개를 1차 검사했다.
- 확인된 404 세 개를 수정/제거했다: `AmateursCTF/ghidra-rust`, `getCUJO/ThreatFox/.../ghidra-golang`, `malwaretech/UnpackerFramework`.
- 수정 후 검사에서는 실제 문서 URL 기준 확인된 404가 남지 않았다.
- ARM 문서(403), Dogbolt API(401), ACM DOI(403), 일부 timeout은 HEAD/자동 요청 제한이라 “접근 불가”가 곧 “깨진 링크”를 뜻하지 않는다. 브라우저 수동 재확인이 필요하다.
- star 수, 서비스 기능, 가격처럼 변동 가능한 값은 링크 생존과 별도로 주기 검증해야 한다.

## 파일별 전체 체크리스트와 판정

| 검토 | 파일 | 판정 | 직접 수정 | 남은 핵심 이슈 |
|---|---|---|---|---|
| [x] | `anti-analysis.md` | 수정 후 재검토 필요 | syscall/GDB, GetThreadContext, exception debugger 의미, x(x+1) predicate, Frida API, MBA, Yama | OS private offset·우회 범위·SiMBA 설치 경로 검증 필요 |
| [x] | `awesome-re-resources.md` | 조건부 승인 | 404 도구 제거, MalwareBazaar 격리 경고 | star 수와 서비스 기능이 시점 의존; 업로드 기밀성 표준화 필요 |
| [x] | `crypto-decode-tools.md` | 조건부 승인 | TEA/XTEA 사이클, hash-length 단정 수정 | Ciphey 유지보수/지원 범위, 온라인 도구 비밀 유출, 식별 휴리스틱의 오탐 설명 필요 |
| [x] | `elf-analysis.md` | 조건부 승인 | ELF32/64, PT_INTERP, RW→RX, ptrace payload write, `/proc/self/mem`, qemu sysroot, 위험한 PHDR 복구 수정 | injection은 여전히 arch/kernel-policy별 실습 검증 필요 |
| [x] | `field-notes.md` | 병합 보류 | 파일 링크 2개, `ret`, Rust layout, Frida/Qiling/FRACTRAN, TOC·교차 링크 수정 | 웹 피싱 절 범위 이탈; 과도한 중복과 미검증 사례를 분리해야 함 |
| [x] | `go-reverse.md` | 조건부 승인 | pclntab magic, Redress 현재 subcommand·옵션, GoReSym, stringtable, 제작사 수정 | 기능 수·버전·복구율 수치 근거, Ghidra plugin URL, Garble 버전 핀 필요 |
| [x] | `kernel-driver-reverse.md` | 수정 후 재검토 필요 | Linux 구조체/함수명, `.modinfo`, Volatility 3 ISF, METHOD_NEITHER, MSVC/Itanium RTTI, -O3/-Os 수정 | 커널 실습 안전 경계와 버전별 구조 검증 필요 |
| [x] | `languages-compiled.md` | 병합 보류 | Redress, Rust layout/mangling, Swift `$`, Kotlin GC/CFR, Haskell 끝 구간, C++ vtable, D cipher의 mutable buffer·fence 수정 | 오래된 Haskell 도구, Swift layout 단정, C2 사례 출처/권한 문제 |
| [x] | `languages-platforms.md` | 병합 보류 | RegisterNatives, inversion 복구, Firebase 서버 경계, Node 실행, AS/400 CCSID, rotate·SGX 수정 | 여러 사례가 target-specific·미출처이며 artifact 검증 필요 |
| [x] | `languages.md` | 병합 보류 | pycdc build 문법, BF oracle 최대값, FRACTRAN 일반 역변환, CLI synopsis fence 수정 | opcode/UEFI/PyArmor 버전 단정과 임의 런타임 실행 위험 |
| [x] | `methodology.md` | 조건부 승인 | 공통 권한·격리 경고, 정적-first workflow, PIE GDB 세션 수정 | 설치 버전·venv 고정과 각 하위 사례의 직접 안전 경계 전파 필요 |
| [x] | `patterns-ctf-2.md` | 수정 후 재검토 필요 | `PROT_*`, 성능 산술, SHA-NI, GF pivot, bounded SMT와 mod-2^32 bit-vector 풀이 수정 | MAP_FIXED/RWX 안전성과 사례별 CVP embedding은 artifact 검증 필요 |
| [x] | `patterns-ctf-3.md` | 병합 보류 | Z3 골격 표시, OpenMP race, xorshift 전단사성, font/GLSL, ESP32, 가상 시간, DNN, BPF 대상 경계 수정 | VM brute-force 수치와 다수 사례의 원 artifact 근거 필요 |
| [x] | `patterns-ctf.md` | 병합 보류 | `ldd`, ransomware container, ELF64 복사본의 `e_shoff/e_shnum/e_shstrndx` 초기화, GDB fence 수정 | 원격 배포·C2 단계와 하드코딩 offset, EVP key length 가정 재검토 필요 |
| [x] | `patterns.md` | 병합 보류 | ptrace, Windows nanomite, xorshift64*, Rtl unwind API, maps/dump 의미, signal interposer, sign-extension 수정 | 운영 우회 사례와 destructive patch 실습 분리 필요 |
| [x] | `platforms-hardware.md` | 수정 후 재검토 필요 | HD44780 E/DDRAM, QEMU port, AArch64 PC-relative/LR, GDB 세션 fence 수정 | EFM32 register map은 MCU family별 1차 매뉴얼 필요; hardware safety 강화 |
| [x] | `platforms.md` | 병합 보류 | objc_msgSend ABI, Frida API, MIPS/eBPF/CAN 예외, CAN 안전 경고, 디버거 fence와 eBPF ID 자리표시자 수정 | Swift/ObjC runtime version, binwalk CLI, cloud upload·real-bus 위험 표준화 |
| [x] | `references/ai-assisted-re.md` | 조건부 승인 | 원 논문 링크, LLM4 범위/CLI, Glaurung 상태, 가격/컨텍스트 단정 수정 | 2026 연구라 변동성 높음; benchmark 세부와 모델 버전 정기 확인 필요 |
| [x] | `tools-advanced.md` | 병합 보류 | Miasm, RetDec, LIEF, Qiling, Triton/Ghidra, ZF·X-only dump 의미 수정 | BinDiff/Manticore 버전, invalid LLVM IR, GDB brute-force의 target adapter 필요 |
| [x] | `tools-dynamic.md` | 병합 보류 | Frida timespec, Qiling syscall/stream, Triton 입력 순서, angr soundness, memcmp 의미 보존 수정 | memo hook은 ABI별 smoke test, Pin 출력 격리와 실행 안전 경계 필요 |
| [x] | `tools.md` | 병합 보류 | AES/Rijndael, pyc 신뢰 경계, RISC-V segment VA, Binary Ninja/Cloud, Dogbolt 업로드 수정 | r2pipe loop, Unicorn mixed-mode state, MCP plugin 전제 필요 |

## 직접 변경 검증

- `git diff --check -- docs/draft/reverse-skill/modules/reverse-engineering`: 통과.
- CommonMark의 fence 들여쓰기를 정규화한 뒤 Python fenced code 113개를 `ast.parse`로 검사해 모두 통과했다.
- JavaScript fenced code 13개를 `node --check`로 검사해 모두 통과했다.
- Haskell 구간 탐색, 8-bit rotate, Morse 파일 슬라이스 길이, xorshift64* state/output 분리, SGX KDF label에 대한 표적 assertion 5개 통과. 로컬에 `cryptography` 패키지가 없어 SGX CMAC 실행 자체는 하지 않았고 공식 Intel 절차와 대조했다.
- 내부 링크 검사: 누락 파일 2→0, 누락 앵커 381→0. 추가 제목 교정 후 상대 파일·앵커 링크 531개를 재검사했다.
- 외부 링크 검사: 고유 URL 116개에서 확인된 404 세 개 수정; 제한 응답/timeout은 수동 확인 대상으로 기록.
- 공식 문서 대조: Frida, Qiling, GoReSym, Redress, RetDec, Miasm, LIEF, Windows thread context, JWT/JWE, Rust layout, ELF gABI, AAPCS64, BPF JIT, SGX, Binary Ninja, AI 원 논문/저자 artifact.

실제 악성 샘플, 커널 모듈, 펌웨어, 원격 CTF 대상을 실행하지는 않았다. 이는 안전상 의도된 제한이며, 사례 재현성은 artifact와 격리 랩이 제공될 때 별도 검증해야 한다.

## 제품 규칙·공식 실행 절차로 채택하기 전 완료 조건

완료된 선행 조건: 실제 heading 기준 TOC 재생성과 교차 링크 수정으로 내부 앵커 불일치 381개를 0으로 만들었다.

1. `field-notes.md`의 피싱/웹 운영 절을 범위에 맞는 모듈로 이동하거나 삭제한다.
2. 모든 CTF 사례에 source URL·artifact hash·arch·tool version·case-specific 표시를 추가한다.
3. 실행 예제를 정적-first/isolated-dynamic 두 경로로 분리하고, 공통 안전 전제를 각 직접 진입 문서에 노출한다.
4. 중복 주제의 정본을 지정하고 field notes/methodology는 링크 중심으로 축소한다.
5. Python/JS/C/C++ snippet smoke test와 Markdown link checker를 CI에 추가한다.
6. 제한 응답 외부 링크를 브라우저로 수동 확인하고, star·가격·지원 버전 같은 시점 의존 정보를 제거하거나 자동 갱신한다.
