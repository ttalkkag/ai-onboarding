# 암호화/복호화/인코딩/디코딩 도구 빠른 점검

> 리버스 엔지니어링과 CTF에서는 암호화/인코딩/해시 데이터가 자주 등장합니다. 이 문서에는 시나리오별로 가장 유용한 도구가 나열되어 있습니다.

---

## 자동 식별 + 복호화(사용된 암호화를 모를 때)

| 도구| Stars | 목적| 링크|
|------|-------|------|------|
| **Ciphey** | 18k+ | AI가 자동으로 식별하고 복호화(50개 이상의 인코딩/암호화/해시 지원)| https://github.com/Ciphey/Ciphey |
| **CyberChef** | 29k+ | 온라인/오프라인 인코딩 및 디코딩 Swiss Army Knife(드래그 앤 드롭 작업)| https://github.com/gchq/CyberChef |
| **dcode.fr** | — | 900개 이상의 온라인 암호화/코딩/수학 도구| https://www.dcode.fr/ |

### Ciphey 사용법

```bash
pip install ciphey
# 자동으로 감지 및 복호화
ciphey -t "암호문"
# 파일에서 읽기
ciphey -f encrypted.txt
```

Ciphey는 Base64/32/16, Caesar, Vigenere, XOR, AES(약한 키), Morse, Binary, Hex, URL 인코딩, HTML 엔터티, 해시 식별 등을 지원합니다.

### CyberChef 사용법

```text
온라인 버전:https://gchq.github.io/CyberChef/
오프라인 버전: GitHub 릴리스의 HTML 파일을 다운로드하여 직접 엽니다.

일반적으로 사용되는 레시피:
- Base64에서 → Base64 디코딩
- XOR → XOR 복호화(키를 브루트포스로 시도할 수 있음)
- AES 복호화 → AES 복호화
- 매직 → 인코딩 유형 자동 감지
```

---

## 해시 식별 및 크래킹

| 도구| 목적| 링크|
|------|------|------|
| **hashID** | 해시 유형 식별(MD5/SHA/bcrypt 등)| https://github.com/psypanda/hashID |
| **hash-identifier** | 위와 동일, Python 버전| https://github.com/blackploit/hash-identifier |
| **haiti** | 최신 해시 식별 도구(더 정확함)| `gem install haiti` |
| **Hashcat** |GPU 해시 크래킹| https://hashcat.net/ |
| **John the Ripper**| CPU 해시 크래킹| https://www.openwall.com/john/ |
| **hashes.com** | 온라인 해시 조회(레인보우 테이블)| https://hashes.com/ |

```bash
# 해시 유형 식별
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
# 출력: [+] MD5

# haiti(더 정확함)
haiti '5f4dcc3b5aa765d61d8327deb882cf99'

# Hashcat 크래킹
hashcat -m 0 hash.txt rockyou.txt  # MD5
hashcat -m 1000 hash.txt rockyou.txt  # NTLM
```

---

## RSA 공격

| 도구| 목적| 링크|
|------|------|------|
| **RsaCtfTool** | RSA 자동 공격(20개 이상의 공격 방법)| https://github.com/Ganapati/RsaCtfTool |
| **SageMath** | 수학적 계산(큰 수/타원 곡선의 분해)| https://www.sagemath.org/ |
| **factordb.com** | 온라인 대수 분해 쿼리| http://factordb.com/ |
| **yafu** | 국소 대수 분해| https://github.com/bbuhrow/yafu |

```bash
# RsaCtfTool 자동 공격
python RsaCtfTool.py --publickey pub.pem --private
python RsaCtfTool.py --publickey pub.pem --uncipherfile cipher.txt

# 지원되는 공격:
# Wiener、Boneh-Durfee、Fermat、Pollard p-1、Williams p+1
# 공통 계수, Small q, Hastads, Noveltyprimes 등
```

---

## XOR 분석

| 도구| 목적| 링크|
|------|------|------|
| **xortool** | XOR 키 길이 추측 + 알려진 일반 텍스트 공격| https://github.com/hellman/xortool |
| **CyberChef XOR** | 시각적 XOR 연산| CyberChef 내장|

```bash
# XOR 키 길이 추측
xortool encrypted_file
# 추측된 키 길이를 사용하여 복호화
xortool -l 4 -c 00 encrypted_file

# 알려진 일반 텍스트 공격(일반 텍스트의 일부를 알고 있음)
xortool-xor -f encrypted -s "known_plaintext"
```

---

## 고전 암호

| 비밀번호 유형| 도구| 설명|
|---------|------|------|
| Caesar | CyberChef/dcode.fr| 25개 오프셋 브루트포스|
| Vigenere | dcode.fr/Ciphey|키 길이를 추측해야 함|
| Substitution | quipqiup.com | 주파수 분석 자동 솔루션|
| Enigma | dcode.fr | 온라인 시뮬레이터|
| Rail Fence | dcode.fr/CyberChef| 레일 펜스 암호|
| Playfair | dcode.fr | 열쇠 필요|
| Morse | CyberChef | 점과 대시를 텍스트로|
| Bacon | dcode.fr | 바이너리 스테가노그래피|
| ROT13/47 | CyberChef / `tr` | 간단한 교체|

---

## 코드 인식 및 변환

| 인코딩| 특징 식별| 디코딩 방법|
|------|---------|---------|
| Base64 | 문자 집합 A-Za-z0-9+/; `=` 패딩은 생략될 수 있음| `base64 -d` / 사이버셰프|
| Base32 | 대문자 + 2-7; `=` 패딩은 생략될 수 있음| CyberChef |
| Base58 | 없음 0/O/I/l, 비트코인에서 흔히 사용됨| CyberChef |
| Hex | 0-9a-f만, 균일한 길이| `xxd -r -p` / 사이버셰프|
| URL encoding | `%XX` 형식| `urldecode` / CyberChef |
| HTML entities | `&#XX;` 또는 `&amp;` 형식| CyberChef |
| Unicode escape | `\uXXXX` 형식|파이썬`decode('unicode_escape')`|
| JWT | 점으로 구분된 Base64URL 세그먼트: JWS는 보통 3개, JWE는 5개| jwt.io/CyberChef|
| Brainfuck | 명령은 `><+-.,[]` 8자이며, 구현에 따라 그 밖의 문자는 주석처럼 무시됨| 온라인 인터프리터|
| Ook! | `Ook.` `Ook!` `Ook?`만| 온라인 인터프리터|

---

## 리버스 엔지니어링의 암호화된 식별

### 상수를 통한 식별 알고리즘

| 상수/특성| 알고리즘|
|-----------|------|
| `0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476` | MD5 |
| `0x6A09E667, 0xBB67AE85, 0x3C6EF372` | SHA-256 |
| `0x63, 0x7C, 0x77, 0x7B` (S-Box로 시작)| AES |
| `0x243F6A88`(16진수 π)| Blowfish |
| `0xB7E15163, 0x9E3779B9` | RC5/RC6의 P/Q 상수 (`0x9E3779B9`는 TEA/XTEA 델타로도 사용) |
| `0x61707865` (리틀엔디언 ASCII `expa`)| ChaCha/Salsa 상수의 시작 |
| `0xC6EF3720` | TEA/XTEA에서 32사이클 뒤의 델타 합 |

### 행동으로 식별됨

| 행동 특성| 가능한 알고리즘|
|---------|-----------|
| 256바이트 조회 테이블 + 스왑 작업| RC4 |
|16바이트 블록 + 여러 순열 라운드| AES |
| Feistel 계열 구조(두 절반을 번갈아 갱신)| DES/Blowfish/TEA/XTEA 후보 |
| 큰 수 곱셈/모듈러 지수화| RSA |
| 타원 곡선 점 작업| ECDSA/ECDH |
| 델타 상수 + 32사이클 루프(사이클마다 양쪽 절반 갱신)| TEA/XTEA |

---

## 자동화된 암호 분석

| 도구| 목적| 링크|
|------|------|------|
| **FeatherDuster** | 자동화된 암호 분석 프레임워크| https://github.com/nccgroup/featherduster |
| **PkCrack** | ZIP 알려진 일반 텍스트 공격| https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html |
| **bkcrack** | ZIP 알려진 일반 텍스트 공격(최신 버전)| https://github.com/kimci86/bkcrack |
| **z3** | SMT 솔버(제약조건 솔버)| https://github.com/Z3Prover/z3 |
| **angr** | 기호 실행(입력 자동 해결)| https://angr.io/ |

---

## 신속한 의사결정 트리

```text
알 수 없는 데이터를 받았을 때:

1. 길이와 문자 집합을 확인
   - hex 문자만 있음 → hex 인코딩 또는 해시일 가능성
   - Base64 문자 집합과 길이/패딩이 맞음 → Base64 후보
   - 점으로 구분된 세 구간 또는 다섯 구간 → compact JWT(JWS/JWE) 후보
   - 32/40/64자 hex → 각각 MD5/SHA-1/SHA-256일 가능성이 있지만, 길이만으로 해시 종류를 확정할 수 없음

2. Ciphey로 자동 시도
ciphey -t "데이터"

3. Ciphey가 실패하면 → CyberChef Magic 모드 사용

4. 해시라면 → hashID로 유형 식별 → Hashcat/John으로 크래킹

5. RSA라면 → RsaCtfTool 자동 공격

6. XOR라면 → xortool로 키 분석

7. 커스텀 암호화라면 → IDA/Ghidra로 알고리즘 리버싱 → 복호화 스크립트 직접 작성
```

---

## 온라인 리소스

| 자원| 링크| 목적|
|------|------|------|
| CyberChef | https://gchq.github.io/CyberChef/ | 범용 코덱|
| dcode.fr | https://www.dcode.fr/ | 900개 이상의 비밀번호 도구|
| quipqiup | https://quipqiup.com/ | 비밀번호 자동 교체|
| factordb | http://factordb.com/ | RSA 큰 수 분해|
| jwt.io | https://jwt.io/ |JWT 디코딩/확인|
| hashes.com | https://hashes.com/ | 해시 역방향 조회|
| crackstation | https://crackstation.net/ | 온라인 해시 크래킹|
