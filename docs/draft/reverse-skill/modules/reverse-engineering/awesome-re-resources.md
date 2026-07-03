# 리버스 엔지니어링 참조 리소스 요약

> 유용성에 따라 정렬된 여러 멋진 목록에서 선별되었습니다. AI는 역분석 중에 방법론적 및 도구 지침을 위해 이러한 리소스를 참조할 수 있습니다.

---

## 포괄적인 리소스 라이브러리

| 프로젝트| Stars | 표지| 링크|
|------|-------|------|------|
| **awesome-reversing** (tylerha97)| 3k+ | 리버싱 도구/책/강좌/연습| https://github.com/tylerha97/awesome-reversing |
| **awesome-reverse-engineering**(alphaSeclab)| 4k+ | 3500개 이상의 도구 + 2300개 기사, 모든 플랫폼| https://github.com/alphaSeclab/awesome-reverse-engineering |
| **Reverse-Engineering**(mytechnotalent)| 10k+ | 무료 튜토리얼:x86/x64/ARM/AVR/RISC-V| https://github.com/mytechnotalent/Reverse-Engineering |
| **awesome-malware-analysis**(rshipp)| 12k+ | 악성 코드 분석 도구/리소스| https://github.com/rshipp/awesome-malware-analysis |
| **reversingBits** | — | 역분석/이진분석 치트시트 모음| https://github.com/mohitmishra786/reversingBits |
| **awesome-arm-exploitation** | — | ARM 활용자료(동영상/기사/도서)| https://github.com/HenryHoggard/awesome-arm-exploitation |
| **Awesome-Binary-Analysis-Automation**| — |자동화된 바이너리 분석(ML/스크립트/정적/동적)| https://github.com/user1342/Awesome-Binary-Analysis-Automation |

---

## ELF / 리눅스 리버스 엔지니어링 프로젝트

| 자원| 설명| 링크|
|------|------|------|
| **libelfmaster** | 보안 ELF 구문 분석 라이브러리(포렌식/맬웨어 재구성)| https://github.com/elfmaster/libelfmaster |
| **ELF 사양**| 공식 ELF 형식 문서| https://refspecs.linuxfoundation.org/elf/elf.pdf |
| **Linux Internals** | /proc 파일 시스템, 메모리 레이아웃, syscall| https://0xax.gitbooks.io/linux-insides/ |
| **Compiler Explorer** | C/C++/Rust/Go가 어떤 어셈블리로 컴파일되는지 온라인 확인| https://godbolt.org/ |

---

## ARM/AArch64 전문화

| 자원| 설명| 링크|
|------|------|------|
| **ARM 공식 아키텍처 매뉴얼**| 완전한 명령어 세트 참조| https://developer.arm.com/documentation |
| **Azeria Labs** | ARM 어셈블리/익스플로잇 튜토리얼(최고의 소개)| https://azeria-labs.com/writing-arm-assembly-part-1/ |
| **ARM64 시스템콜 테이블**| Linux AArch64 시스템 호출 번호| https://arm64.syscall.sh/ |
| **QEMU 사용자 모드 시뮬레이션**| ARM 바이너리를 분석하는 데 실제 장치가 필요하지 않습니다.| `qemu-aarch64 -strace ./binary` |

---

## 악성 코드 분석

| 자원| 설명| 링크|
|------|------|------|
| **YARA** | 악성 코드 서명 일치 규칙| https://github.com/VirusTotal/yara |
| **Volatility 3** | 메모리 포렌식 프레임워크| https://github.com/volatilityfoundation/volatility3 |
| **FLOSS** | 난독화된 문자열을 자동으로 추출합니다.| https://github.com/mandiant/flare-floss |
|**Detect It Easy (DiE)**| 파일 유형/패커/컴파일러 식별| https://github.com/horsicq/Detect-It-Easy |
| **PE-bear** | PE 파일 분석기| https://github.com/hasherezade/pe-bear |
| **Capa** | 바이너리 기능(네트워크/파일/암호화 등)을 자동으로 식별합니다.| https://github.com/mandiant/capa |
| **Unpacker** | 범용 언패킹 프레임워크| https://github.com/malwaretech/UnpackerFramework |

---

## 동적 분석/샌드박스

| 자원| 설명| 링크|
|------|------|------|
| **Frida** | 크로스 플랫폼 동적 계측| https://frida.re/ |
| **strace** | Linux 시스템 호출 추적| 시스템 기본 제공|
| **ltrace** | 라이브러리 함수 호출 추적| 시스템 기본 제공|
| **QEMU** | 사용자 모드/시스템 모드 시뮬레이션| https://www.qemu.org/ |
| **Unicorn** | CPU 시뮬레이션 프레임워크(프로그래밍 가능)| https://www.unicorn-engine.org/ |
| **Qiling** | 고급 바이너리 시뮬레이션 프레임워크| https://qiling.io/ |
| **angr** | 기호 실행 + 바이너리 분석| https://angr.io/ |
| **Triton** | 동적 바이너리 분석 프레임워크| https://triton-library.github.io/ |

---

## 난독화 방지/패킹 풀기

| 자원| 설명| 링크|
|------|------|------|
| **UPX** | 가장 흔한 패커, `upx -d`로 언패킹| https://upx.github.io/ |
| **unipacker** | 범용 PE 언패커| https://github.com/unipacker/unipacker |
| **de4dot** |.NET 난독화 방지| https://github.com/de4dot/de4dot |
| **JADX** | Android DEX 난독화 방지| https://github.com/skylot/jadx |
| **JEB** | 상업용 Android/ARM 디컴파일러| https://www.pnfsoftware.com/ |
| **Miasm** | 리버스 엔지니어링 프레임워크(IR/기호 실행/난독화 해제)| https://github.com/cea-sec/miasm |
| **OLLVM 난독화 방지**| 제어 흐름 평탄화/가짜 제어 흐름 대응| angr/Triton 기호 실행으로 복구 수행|

---

## 온라인 분석 플랫폼

| 플랫폼| 설명| 링크|
|------|------|------|
| **VirusTotal** | 다중 엔진 스캐닝 + 행동 분석| https://www.virustotal.com/ |
| **Joe Sandbox** | 자동화된 악성 코드 분석| https://www.joesandbox.com/ |
| **ANY.RUN** | 대화형 온라인 샌드박스| https://any.run/ |
| **Hybrid Analysis** | 무료 악성 코드 분석| https://www.hybrid-analysis.com/ |
| **Compiler Explorer** | 컴파일러 출력을 살펴보세요| https://godbolt.org/ |
| **Dogbolt** | 여러 디컴파일러(IDA/Ghidra/Binary Ninja) 비교| https://dogbolt.org/ |

---

## 학습 경로

### 시작하기(0~3개월)

1. [Reverse Engineering for Beginners](https://beginners.re/) — 무료 전자책
2. [Azeria Labs ARM Tutorial](https://azeria-labs.com/) — ARM 어셈블리 기초
3. [악몽](https://guyinatuxedo.github.io/) — CTF 리버스/폰 튜토리얼
4. [crackmes.one](https://crackmes.one/) — 리버싱 연습

### 고급(3~12개월)

1. [실용적인 이진 분석](https://practicalbinaryanalysis.com/) — 실용적인 이진 분석
2. [IDA 프로북](https://nostarch.com/idapro2.htm) — IDA 심층 활용
3. [Malware Unicorn RE101](https://malwareunicorn.org/workshops/re101.html) — 악성 코드 리버스 엔지니어링
4. [pwnable.kr](http://pwnable.kr/) / [pwnable.tw](https://pwnable.tw/) — pwn 연습

### 고급

1. [현대 바이너리 활용](https://github.com/RPISEC/MBE) — RPI 과정
2. [유령처럼 해킹하는 방법](https://nostarch.com/how-hack-ghost) — 고급 침투
3. [Windows 내부](https://docs.microsoft.com/en-us/sysinternals/) — Windows 커널
4. 실제 전투: 실제 악성코드 샘플 분석(MalwareBazaar)

---

## 치트 시트

| 치트 시트| 링크|
|--------|------|
| x86/x64 명령 빠른 확인| https://www.felixcloutier.com/x86/ |
| ARM64 명령어 간략한 검토| https://developer.arm.com/documentation/ddi0602/latest |
| Linux syscall 테이블(x64)| https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ |
| Linux 시스템콜 테이블(ARM64)| https://arm64.syscall.sh/ |
| GDB 빠른 참조| https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf |
| radare2 빠른 참조| 이 패키지의 `radare2/references/cheatsheet.md`|
| IDA 단축키| https://hex-rays.com/products/ida/support/freefiles/IDA_Pro_Shortcuts.pdf |
| Ghidra 단축키| Ghidra 내장 도움말 → 키보드 단축키|
