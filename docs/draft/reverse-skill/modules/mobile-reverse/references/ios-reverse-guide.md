# iOS 리버스 엔지니어링 프로젝트

## IPA 획득 및 암호 해독

```bash
# 앱 스토어에서 다운로드
ipatool search "Target App"
ipatool purchase -b com.target.app
ipatool download -b com.target.app -o app.ipa

# 기기에 설치된 앱 추출
# 탈옥된 기기
scp root@device:/private/var/containers/Bundle/Application/*/Target.app .

# 암호 해독(App Store 배포 바이너리의 FairPlay 암호화 여부 확인; FAT/thin 형식과는 별개)
# frida-ios-dump (권장)
python3 dump.py com.target.app -o decrypted.ipa

# Clutch
Clutch -i  # 설치된 목록
Clutch -d 1  # 해독 1

# dumpdecrypted
DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /path/to/App
```

## Mach-O 분석

```bash
# 기본정보
otool -l TargetBinary | grep crypt    # 암호화 상태
otool -L TargetBinary                 # 동적 라이브러리 종속성
otool -hv TargetBinary                # 헤더 정보
jtool2 --pages TargetBinary           # 메모리 페이지 정보

# 지방 바이너리 슬리밍
lipo -info TargetBinary
lipo TargetBinary -thin arm64 -output TargetBinary_arm64

# 상징적 분석
nm -g TargetBinary                    # 기호 내보내기
nm -a TargetBinary                    # 모든 기호
MANGLED_NAME='REPLACE_WITH_MANGLED_NAME'
swift-demangle "$MANGLED_NAME"        # Swift 기호 복원

# class-dump
class-dump -H TargetBinary -o headers/
# ObjC 클래스 및 메서드 선언을 headers/ 디렉터리로 내보내기
```

## Objective-C 런타임 분석

```text
메시지 전달 메커니즘:
objc_msgSend(id self, SEL op,...) → 동적 메소드 디스패치
  ↓
런타임 시 찾기:
1. 클래스 메소드 목록 캐시
2. 수업방법 목록
3. 레벨별 상위 클래스 검색
4. +resolveInstanceMethod / +resolveClassMethod
5. forwardingTargetForSelector
6. methodSignatureForSelector + forwardInvocation
```

### Frida ObjC 후크

```javascript
// Hook 인스턴스 메소드
var hook = ObjC.classes.ClassName["- instanceMethod:"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        // args[0] = self, args[1] = selector, args[2+] = method args
        console.log("self: " + new ObjC.Object(args[0]));
        console.log("arg: " + args[2].toInt32());
    }
});

// Hook 수업 방법
var hook = ObjC.classes.ClassName["+ classMethod:"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        console.log("classMethod: called");
    }
});

// ObjC 메서드 호출
var NSString = ObjC.classes.NSString;
var str = NSString.stringWithString_("test");
console.log(str.UTF8String());
```

## 신속한 리버스 엔지니어링

```text
신속한 이름 맹글링:
$s10ModuleName5ClassC6method3argSi_tF
  │ │ │ │ │ │ │ └─ 매개변수 유형
  │ │ │ │ │ │ └───── 반환 유형
  │ │ │ │ │ └──────── 매개변수 이름
  │ │ │ │ └──────────────── 메소드 이름
│ │ │ └──────────────── 클래스 이름(길이 + 이름)
  │ │ └────────────────────── 모듈 이름
  │ └──────────────────────────────── 식별자
  └────────────────────────────────── 글로벌 로고

도구: Swift-demangle, Hopper(자동 복원)
```

## 탈옥 탐지 우회

```text
탐지 방법 분류:

1. 파일 시스템 확인:
   □ /Applications/Cydia.app
   □ /var/lib/apt/
   □ /bin/bash
   □ /usr/sbin/sshd
   → Hook NSFileManager.fileExistsAtPath:

2. 샌드박스 탈출 감지:
   □ fork() 성공 여부(샌드박스에서는 금지됨)
   □ system() 호출
   → Hook 포크 → return -1

3. Dyld 주입 감지:
   □ _dyld_get_image_count > 한계값
   → 반환값을 합리적인 범위로 제한

4. 계획 탐지:
   □ cydia:// URL Scheme
   → Hook UIApplication.canOpenURL:

5. sysctl 감지:
   □ CTL_KERN/KERN_PROC/KERN_PROC_PID → kinfo_proc
   → Hook sysctl → p_flag P_TRACED 비트 지우기
```

### Frida 통합 우회 스크립트

```javascript
// 파일 탐지 우회
var NSFileManager = ObjC.classes.NSFileManager;
Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
    onEnter: function(args) {
        this.path = new ObjC.Object(args[2]).toString();
    },
    onLeave: function(retval) {
        if (this.path.includes("Cydia") || this.path.includes("apt") ||
            this.path.includes("sshd") || this.path.includes("bash")) {
            retval.replace(0); // false
        }
    }
});

// 포크 바이패스
Interceptor.replace(Module.findGlobalExportByName("fork"),
    new NativeCallback(function() { return -1; }, 'int', []));

// 딜드 바이패스
var _dyld_get_image_count = Module.findGlobalExportByName("_dyld_get_image_count");
Interceptor.attach(_dyld_get_image_count, {
    onLeave: function(retval) {
        if (retval.toInt32() > 200) retval.replace(200);
    }
});
```

## 중요 보호 우회 목록

| 보호| iOS 우회 방법|
|------|-------------|
| 앱스토어 암호화| frida-ios-dump / Clutch |
| SSL Pinning | Objection `ios sslpinning disable` / SSL 킬 스위치 2|
| 탈옥 감지| Objection `ios jailbreak disable` / 사용자 정의 Frida 후크|
| 디버깅 방지(PT_DENY_ATTACH)| Frida 시작 후 /debugserver 삽입|
| 무결성 검사| 후크 MAC 확인/코드 서명 확인|
| 등 주사| __RESTRICT 섹션을 제거하려면 Mach-O를 수정하세요.|
| 신속한 난독화| Swift-demangle + LLM 보조 의미 복구|
| 스크린샷/화면 캡처 대응| `userDidTakeScreenshotNotification`은 촬영 후 알림이고, 진행 중 캡처는 `UIScreen.isCaptured`/`capturedDidChangeNotification`을 관찰합니다. `snapshotView(afterScreenUpdates:)`는 보호 우회 API가 아닙니다.|

Source: OWASP MASTG, frida-ios-dump, Apple UIKit 문서
