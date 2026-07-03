#!/bin/bash
#
# docs/draft/scan.sh
#
# 낯선 프로젝트를 설치·실행하기 전에 수행하는 "읽기 전용" 보안 스캔.
#
# 원칙 (절대 위반 금지):
#   - 대상 코드를 설치하거나 실행하지 않는다. (npm install / pip install / make 등 금지)
#   - 파일을 읽고 패턴만 검사한다. 네트워크 접근도 하지 않는다.
#   - 출력은 사람이 검토할 수 있는 보고서다. 자동 조치는 하지 않는다.
#
# 사용법:
#   scan.sh [TARGET_DIR] [--out REPORT.md]
#     TARGET_DIR  검사할 디렉토리 (기본값: 현재 디렉토리)
#     --out FILE  보고서를 FILE 에도 저장 (기본: 표준출력만)
#
# 종료 코드:
#   0  HIGH 위험 신호 없음
#   1  HIGH 위험 신호 1개 이상 (설치/실행 전 사람 검토 필수)
#   2  사용법/입력 오류

set -u
PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"
export PATH

# ---------------------------------------------------------------------------
# 인자 파싱
# ---------------------------------------------------------------------------
TARGET="."
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out)
      if [ $# -lt 2 ] || [ -z "${2:-}" ]; then
        echo "error: --out requires a file path" >&2
        exit 2
      fi
      OUT="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | grep -v '^#!' | sed 's/^# \{0,1\}//' | sed -n '1,28p'
      exit 0 ;;
    --*) echo "error: unknown option: $1" >&2; exit 2 ;;
    *) TARGET="$1"; shift ;;
  esac
done

if [ ! -d "$TARGET" ]; then
  echo "error: target dir not found: $TARGET" >&2
  exit 2
fi
TARGET="$(cd "$TARGET" && pwd)"

# 상위 디렉토리를 스캔할 때는 스캐너 폴더를 제외하고, 직접 스캐너를 검사할 때는 엔진 파일만 오탐에서 제외한다.
SELF="$(cd "$(dirname "$0")/.." && pwd)"
SCAN_SCRIPT="$SELF/scripts/scan.sh"
EXCLUDE_SELF=0
if [ "$TARGET" != "$SELF" ]; then
  case "$SELF" in
    "$TARGET"/*) EXCLUDE_SELF=1 ;;
  esac
fi

# ---------------------------------------------------------------------------
# 카운터 / 출력 버퍼
# ---------------------------------------------------------------------------
HIGH=0; MED=0; INFO=0
BODY=""        # 위험 신호 목록
COMPOSITION="" # 프로젝트 구성 목록

emit()  { BODY="${BODY}$1"$'\n'; }
comp()  { COMPOSITION="${COMPOSITION}$1"$'\n'; }

finding() { # <LEVEL> <message>
  case "$1" in
    HIGH) HIGH=$((HIGH+1)); emit "- 🔴 **HIGH** · $2" ;;
    MED)  MED=$((MED+1));   emit "- 🟠 **MED**  · $2" ;;
    INFO) INFO=$((INFO+1)); emit "- 🔵 INFO · $2" ;;
  esac
}

rel() { # 절대경로 -> 대상 기준 상대경로
  printf '%s' "${1#"$TARGET"/}"
}

# ---------------------------------------------------------------------------
# JSON 파서 선택 (시스템 도구만 사용 — 대상 코드 실행 아님)
# ---------------------------------------------------------------------------
JSONTOOL=""
if command -v python3 >/dev/null 2>&1; then JSONTOOL="python3"
elif command -v node >/dev/null 2>&1; then JSONTOOL="node"
elif command -v jq   >/dev/null 2>&1; then JSONTOOL="jq"
fi

# package.json 의 라이프사이클 훅만 추출 -> "hook<TAB>command" 줄들
pkg_lifecycle() { # <package.json 경로>
  local f="$1"
  case "$JSONTOOL" in
    python3)
      python3 - "$f" <<'PY' 2>/dev/null
import json,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
s=d.get("scripts") or {}
for k in ("preinstall","install","postinstall","prepare",
          "prepublish","prepublishOnly","prepack","postpack"):
    if k in s:
        print(k+"\t"+str(s[k]))
PY
      ;;
    node)
      node -e '
        try {
          const d=require(process.argv[1]); const s=d.scripts||{};
          for (const k of ["preinstall","install","postinstall","prepare",
                            "prepublish","prepublishOnly","prepack","postpack"])
            if (k in s) console.log(k+"\t"+s[k]);
        } catch(e){}
      ' "$f" 2>/dev/null
      ;;
    jq)
      jq -r '(.scripts // {}) | to_entries[]
             | select(.key|test("^(preinstall|install|postinstall|prepare|prepublish|prepublishOnly|prepack|postpack)$"))
             | "\(.key)\t\(.value)"' "$f" 2>/dev/null
      ;;
    *)
      # 파서가 없을 때의 근사 fallback (정밀도 낮음)
      grep -Eo '"(preinstall|install|postinstall|prepare|prepublish|prepublishOnly|prepack|postpack)"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" 2>/dev/null \
        | sed -E 's/"([a-zA-Z]+)"[[:space:]]*:[[:space:]]*"(.*)"/\1\t\2/'
      ;;
  esac
}

# 알려진 git-hook 도구인지 (라이프사이클 훅 오탐 완화)
is_known_hook_tool() { # <command 문자열>
  local cmd="$1"
  # allowlist는 단일 명령만 허용한다. 체이닝/서브셸이 있으면 정상 hook 도구 뒤에
  # 악성 명령을 붙일 수 있으므로 감점하지 않는다.
  printf '%s' "$cmd" | grep -Eq '(&&|\|\||[;|`]|[$][(])' 2>/dev/null && return 1
  printf '%s' "$cmd" | grep -Eq '^[[:space:]]*(husky|lefthook|simple-git-hooks|is-ci)[[:space:]]*$' 2>/dev/null \
    || printf '%s' "$cmd" | grep -Eq '^[[:space:]]*node[[:space:]]+\.husky(/[A-Za-z0-9_.-]+)?[[:space:]]*$' 2>/dev/null
}

# 전체 파일 목록 (.git 제외, 필요 시 스캐너 자신 제외)
find_project_files() {
  if [ "$EXCLUDE_SELF" -eq 1 ]; then
    find "$TARGET" \( -type d \( -name .git -o -path "$SELF" \) -prune \) -o -type f -print 2>/dev/null
  else
    find "$TARGET" \( -type d -name .git -prune \) -o -type f -print 2>/dev/null
  fi
}

# 정적 패턴 검사 대상 소스 파일 (.git / 의존성 / 빌드산출물 제외)
find_source_files() {
  if [ "$EXCLUDE_SELF" -eq 1 ]; then
    find "$TARGET" \
      \( -type d \( -name .git -o -name node_modules -o -name dist -o -name build -o -name .next -o -name vendor -o -name .venv -o -name venv -o -path "$SELF" \) -prune \) -o \
      \( -type f \( \
        -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' -o \
        -name '*.ts' -o -name '*.tsx' -o \
        -name '*.py' -o -name '*.rb' -o -name '*.go' -o \
        -name '*.rs' -o -name '*.php' -o \
        -name '*.sh' -o -name '*.bash' -o \
        -name '*.json' -o -name '*.xml' -o -name '*.toml' -o \
        -name 'Dockerfile' -o -name 'Makefile' -o -name '*.gradle' -o -name '*.gradle.kts' -o \
        -name '*.yml' -o -name '*.yaml' \
      \) -print0 \) 2>/dev/null
  else
    find "$TARGET" \
      \( -type d \( -name .git -o -name node_modules -o -name dist -o -name build -o -name .next -o -name vendor -o -name .venv -o -name venv \) -prune \) -o \
      \( -type f \( \
        -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' -o \
        -name '*.ts' -o -name '*.tsx' -o \
        -name '*.py' -o -name '*.rb' -o -name '*.go' -o \
        -name '*.rs' -o -name '*.php' -o \
        -name '*.sh' -o -name '*.bash' -o \
        -name '*.json' -o -name '*.xml' -o -name '*.toml' -o \
        -name 'Dockerfile' -o -name 'Makefile' -o -name '*.gradle' -o -name '*.gradle.kts' -o \
        -name '*.yml' -o -name '*.yaml' \
      \) -print0 \) 2>/dev/null
  fi
}

# 프로젝트 내부 package.json 전체. node_modules는 별도 제한 스캔으로 다룬다.
find_package_jsons() {
  if [ "$EXCLUDE_SELF" -eq 1 ]; then
    find "$TARGET" \
      \( -type d \( -name .git -o -name node_modules -o -name .next -o -name vendor -o -name .venv -o -name venv -o -path "$SELF" \) -prune \) -o \
      \( -type f -name package.json -print \) 2>/dev/null
  else
    find "$TARGET" \
      \( -type d \( -name .git -o -name node_modules -o -name .next -o -name vendor -o -name .venv -o -name venv \) -prune \) -o \
      \( -type f -name package.json -print \) 2>/dev/null
  fi
}

# 소스 파일 대상 정규식 검색 (BSD/GNU grep 모두 지원)
grep_src() { # <확장정규식>
  local re="$1" f
  while IFS= read -r -d '' f; do
    [ "$f" = "$SCAN_SCRIPT" ] && continue
    grep -IHnE "$re" "$f" 2>/dev/null || true
  done < <(find_source_files)
}

# 패턴 1건 검사 -> 적중 시 finding 등록 (최대 4개 표본 첨부)
scan_pattern() { # <LEVEL> <regex> <설명>
  local level="$1" re="$2" desc="$3" hits count sample
  hits="$(grep_src "$re" || true)"
  [ -z "$hits" ] && return 0
  count="$(printf '%s\n' "$hits" | grep -c . || true)"
  sample="$(printf '%s\n' "$hits" | head -4 \
            | sed -E "s#^${TARGET}/##" \
            | sed -E 's/:([0-9]+):/:\1 → /' \
            | cut -c1-160 \
            | sed 's/^/      • /')"
  finding "$level" "$desc  (적중 ${count}건)"$'\n'"$sample"
}

# ===========================================================================
# 1) 프로젝트 구성 파악
# ===========================================================================
declare -a ECO=()
add_eco() { ECO+=("$1"); }

[ -f "$TARGET/package.json" ]       && add_eco "Node/npm (package.json)"
[ -f "$TARGET/pnpm-lock.yaml" ]     && add_eco "pnpm (pnpm-lock.yaml)"
[ -f "$TARGET/yarn.lock" ]          && add_eco "Yarn (yarn.lock)"
[ -f "$TARGET/package-lock.json" ]  && add_eco "npm lockfile (package-lock.json)"
[ -f "$TARGET/bun.lockb" ]          && add_eco "Bun (bun.lockb)"
{ [ -f "$TARGET/requirements.txt" ] || [ -f "$TARGET/pyproject.toml" ] || \
  [ -f "$TARGET/setup.py" ] || [ -f "$TARGET/Pipfile" ]; } && add_eco "Python (pip/poetry/pipenv)"
[ -f "$TARGET/go.mod" ]             && add_eco "Go (go.mod)"
[ -f "$TARGET/Cargo.toml" ]         && add_eco "Rust (Cargo.toml)"
[ -f "$TARGET/Gemfile" ]            && add_eco "Ruby (Gemfile)"
[ -f "$TARGET/composer.json" ]      && add_eco "PHP (composer.json)"
{ [ -f "$TARGET/pom.xml" ] || [ -f "$TARGET/build.gradle" ] || \
  [ -f "$TARGET/build.gradle.kts" ]; } && add_eco "Java/JVM (maven/gradle)"
{ [ -f "$TARGET/Dockerfile" ] || [ -f "$TARGET/docker-compose.yml" ] || \
  [ -f "$TARGET/docker-compose.yaml" ] || [ -f "$TARGET/compose.yaml" ]; } && add_eco "Docker"
[ -f "$TARGET/Makefile" ]           && add_eco "Make (Makefile)"
[ -d "$TARGET/.github/workflows" ]  && add_eco "GitHub Actions (.github/workflows)"

if [ "${#ECO[@]}" -eq 0 ]; then
  comp "- 감지된 패키지 매니저/빌드 시스템 없음 (스크립트·실행파일 위주일 수 있음)"
else
  for e in "${ECO[@]}"; do comp "- $e"; done
fi

# 파일/디렉토리 규모
FILE_COUNT="$(find_project_files | grep -c . || true)"
comp "- 파일 수(.git 제외): ${FILE_COUNT}"

# 진입점/실행 지점 후보
[ -f "$TARGET/Makefile" ] && {
  TARGETS="$(grep -E '^[a-zA-Z0-9_-]+:' "$TARGET/Makefile" 2>/dev/null | cut -d: -f1 | paste -sd' ' - || true)"
  [ -n "$TARGETS" ] && comp "- Makefile 타겟: ${TARGETS}"
}
[ -f "$TARGET/package.json" ] && {
  comp "- package.json 존재 (scripts 및 라이프사이클 훅은 아래 위험 신호에서 검사)"
}

# ===========================================================================
# 2) 위험 신호 검사
# ===========================================================================

# --- 2a) 저장소에 의존성 디렉토리가 포함됨 (비정상) ---
if [ -d "$TARGET/node_modules" ]; then
  finding HIGH "저장소에 \`node_modules/\`가 포함되어 있음 — 정상 배포에서는 드묾. 변조된 의존성이 섞였을 수 있어 설치 없이 그대로 실행하면 위험."
fi
if [ -d "$TARGET/vendor" ] && [ -f "$TARGET/go.mod" ]; then
  finding INFO "Go \`vendor/\` 디렉토리 포함 — 벤더링된 의존성 직접 검토 권장."
fi

# --- 2b) npm 라이프사이클 훅 (글의 핵심 공격 벡터) ---
# 루트 + (있다면) node_modules 1단계 package.json 검사
while IFS= read -r pj; do
  [ -z "$pj" ] && continue
  scope="$(rel "$pj")"
  while IFS=$'\t' read -r hook cmd; do
    [ -z "$hook" ] && continue
    if is_known_hook_tool "$cmd"; then
      finding INFO "라이프사이클 훅 \`$hook\` (${scope}) → \`$cmd\` — 알려진 git-hook 도구로 보임(저위험)."
    else
      case "$hook" in
        preinstall|install|postinstall|prepare)
          finding HIGH "설치 시 자동 실행되는 훅 \`$hook\` 발견 (${scope}) → \`$(printf '%s' "$cmd" | cut -c1-120)\` — \`npm install\` 만으로 임의 코드가 실행됨. 글의 백도어와 동일 벡터." ;;
        *)
          finding MED "배포/패키징 훅 \`$hook\` 발견 (${scope}) → \`$(printf '%s' "$cmd" | cut -c1-120)\`" ;;
      esac
    fi
  done < <(pkg_lifecycle "$pj")
done < <(
  find_package_jsons
  find "$TARGET/node_modules" -mindepth 2 -maxdepth 3 -name package.json 2>/dev/null | head -200
)

# --- 2b-2) npm 외 설치/빌드 트리거 후보 ---
if [ "$EXCLUDE_SELF" -eq 1 ]; then
  BUILD_RS_FILES="$(find "$TARGET" \( -type d \( -name .git -o -name target -o -path "$SELF" \) -prune \) -o -type f -name build.rs -print 2>/dev/null | head -100)"
  COMPOSER_FILES="$(find "$TARGET" \( -type d \( -name .git -o -name vendor -o -path "$SELF" \) -prune \) -o -type f -name composer.json -print 2>/dev/null | head -100)"
  SETUP_PY_FILES="$(find "$TARGET" \( -type d \( -name .git -o -name .venv -o -name venv -o -path "$SELF" \) -prune \) -o -type f -name setup.py -print 2>/dev/null | head -100)"
  PYPROJECT_FILES="$(find "$TARGET" \( -type d \( -name .git -o -name .venv -o -name venv -o -path "$SELF" \) -prune \) -o -type f -name pyproject.toml -print 2>/dev/null | head -100)"
else
  BUILD_RS_FILES="$(find "$TARGET" \( -type d \( -name .git -o -name target \) -prune \) -o -type f -name build.rs -print 2>/dev/null | head -100)"
  COMPOSER_FILES="$(find "$TARGET" \( -type d \( -name .git -o -name vendor \) -prune \) -o -type f -name composer.json -print 2>/dev/null | head -100)"
  SETUP_PY_FILES="$(find "$TARGET" \( -type d \( -name .git -o -name .venv -o -name venv \) -prune \) -o -type f -name setup.py -print 2>/dev/null | head -100)"
  PYPROJECT_FILES="$(find "$TARGET" \( -type d \( -name .git -o -name .venv -o -name venv \) -prune \) -o -type f -name pyproject.toml -print 2>/dev/null | head -100)"
fi

while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -Eq '(std::process::Command|Command::new|curl|wget|reqwest|TcpStream|UdpSocket)' "$f" 2>/dev/null; then
    finding HIGH "Cargo \`build.rs\`에서 네트워크/프로세스 실행 의심 패턴 발견 ($(rel "$f")) — \`cargo build\` 전 자동 실행되는 빌드 스크립트."
  else
    finding INFO "Cargo \`build.rs\` 존재 ($(rel "$f")) — 빌드 전에 실행되므로 내용 검토 권장."
  fi
done < <(printf '%s\n' "$BUILD_RS_FILES")

while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -Eq '"(pre|post)-(install|update)-cmd"[[:space:]]*:' "$f" 2>/dev/null; then
    finding HIGH "Composer 설치/업데이트 script 발견 ($(rel "$f")) — \`composer install/update\` 중 자동 실행될 수 있음."
  fi
done < <(printf '%s\n' "$COMPOSER_FILES")

while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -Eq '(os\.system|subprocess\.|Popen\(|curl|wget|urllib|requests\.)' "$f" 2>/dev/null; then
    finding HIGH "Python \`setup.py\`에서 네트워크/프로세스 실행 의심 패턴 발견 ($(rel "$f")) — 설치/빌드 중 실행될 수 있음."
  else
    finding INFO "Python \`setup.py\` 존재 ($(rel "$f")) — 설치/빌드 중 실행될 수 있어 내용 검토 권장."
  fi
done < <(printf '%s\n' "$SETUP_PY_FILES")

while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -Eq '^[[:space:]]*build-backend[[:space:]]*=' "$f" 2>/dev/null; then
    finding INFO "Python PEP517 \`build-backend\` 선언 ($(rel "$f")) — 패키지 빌드 시 백엔드 코드가 실행될 수 있어 설치 전 검토 권장."
  fi
done < <(printf '%s\n' "$PYPROJECT_FILES")

# --- 2c) 원격 코드 실행 / 다운로드-후-실행 ---
scan_pattern HIGH '(curl|wget|fetch)[^|;`]*(\||`|\$\()[^|]*(sh|bash|python|node|eval)' \
  '원격 콘텐츠를 받아 셸/인터프리터로 즉시 실행(curl … | sh 류)'
scan_pattern HIGH '(curl|wget)[^;&|`]*(--output|-o|>)[^;&|`]+(&&|;)[[:space:]]*(sh|bash|python|node)[[:space:]]+[^;&|`]*' \
  '원격 콘텐츠를 파일로 저장한 뒤 같은 명령 체인에서 인터프리터로 실행(curl -o …; sh … 류)'
scan_pattern HIGH 'https?://([0-9]{1,3}\.){3}[0-9]{1,3}' \
  '도메인 대신 원시 IP 주소로의 네트워크 연결(C2 의심)'

# --- 2d) 동적 코드 실행 / 난독화 ---
scan_pattern MED '\beval[[:space:]]*\(' \
  'eval() 사용 — 동적 코드 실행'
scan_pattern MED '\bnew[[:space:]]+Function[[:space:]]*\(' \
  'new Function() — 문자열을 코드로 실행'
scan_pattern MED '(Buffer\.from\([^)]*base64|atob\(|base64[[:space:]]+(-d|--decode))' \
  'base64 디코딩 — 페이로드 은닉에 흔히 사용'
scan_pattern MED '(child_process|require\(["'"'"']child_process|exec(Sync)?\(|spawn(Sync)?\(|os\.system\(|subprocess\.)' \
  '외부 프로세스/셸 실행 호출'

# --- 2e) 환경변수/크리덴셜 유출 가능성 ---
scan_pattern MED '(process\.env|os\.environ).{0,80}(https?://|fetch\(|axios|request\(|net\.|socket)' \
  '환경변수를 네트워크 전송 코드 근처에서 사용 — 비밀정보 유출 의심'
scan_pattern INFO '(AWS_SECRET|PRIVATE_KEY|MNEMONIC|SEED_PHRASE|WALLET|process\.env\.[A-Z_]*KEY)' \
  '지갑/키/시드 관련 식별자 — 암호화폐 타깃 공격에서 흔함'

# --- 2f) 커스텀 npm 레지스트리 / .npmrc ---
if [ -f "$TARGET/.npmrc" ]; then
  if grep -Eq 'registry=|_authToken|//' "$TARGET/.npmrc" 2>/dev/null; then
    finding MED "프로젝트 \`.npmrc\` 가 레지스트리/토큰을 재정의함 — 신뢰할 수 없는 레지스트리로 설치를 유도할 수 있음."
  else
    finding INFO "프로젝트 \`.npmrc\` 존재 — 내용 확인 권장."
  fi
fi

# --- 2g) 테스트로 위장한 비대/난독 파일 (글의 app/test/index.js 패턴) ---
if [ "$EXCLUDE_SELF" -eq 1 ]; then
  TEST_FILES="$(find "$TARGET" -type f \( -path '*/test/*' -o -path '*/tests/*' -o -path '*/spec/*' -o -name '*.test.*' -o -name '*.spec.*' \) \
                 \( -name '*.js' -o -name '*.ts' -o -name '*.py' \) \
                 ! -path '*/.git/*' ! -path '*/node_modules/*' ! -path "$SELF/*" 2>/dev/null | head -100)"
else
  TEST_FILES="$(find "$TARGET" -type f \( -path '*/test/*' -o -path '*/tests/*' -o -path '*/spec/*' -o -name '*.test.*' -o -name '*.spec.*' \) \
                 \( -name '*.js' -o -name '*.ts' -o -name '*.py' \) \
                 ! -path '*/.git/*' ! -path '*/node_modules/*' 2>/dev/null | head -100)"
fi
while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ "$f" = "$SCAN_SCRIPT" ] && continue
  size=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
  [ -z "$size" ] && continue
  if [ "$size" -gt 15000 ]; then
    finding MED "테스트 경로의 비정상적으로 큰 파일: $(rel "$f") (${size} bytes) — 테스트로 위장한 코드일 수 있음(글의 백도어 패턴)."
  fi
done < <(printf '%s\n' "$TEST_FILES")

# --- 2h) 난독화로 의심되는 초장문 라인 ---
if [ "$EXCLUDE_SELF" -eq 1 ]; then
  LONG_LINE_FILES="$(find "$TARGET" -type f \( -name '*.js' -o -name '*.ts' -o -name '*.py' \) \
                      ! -name '*.min.js' \
                      ! -path '*/.git/*' ! -path '*/node_modules/*' \
                      ! -path "$SELF/*" 2>/dev/null | head -200)"
else
  LONG_LINE_FILES="$(find "$TARGET" -type f \( -name '*.js' -o -name '*.ts' -o -name '*.py' \) \
                      ! -name '*.min.js' \
                      ! -path '*/.git/*' ! -path '*/node_modules/*' 2>/dev/null | head -200)"
fi
while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ "$f" = "$SCAN_SCRIPT" ] && continue
  maxlen=$(awk '{ if (length>m) m=length } END{ print m+0 }' "$f" 2>/dev/null)
  [ -z "$maxlen" ] && continue
  if [ "$maxlen" -gt 5000 ]; then
    finding MED "초장문 라인(${maxlen}자) 포함: $(rel "$f") — 난독화/패킹된 코드 의심."
  fi
done < <(printf '%s\n' "$LONG_LINE_FILES")

# ===========================================================================
# 3) 보고서 출력
# ===========================================================================
TOTAL=$((HIGH+MED+INFO))
if   [ "$HIGH" -gt 0 ]; then VERDICT="🔴 위험 — 설치/실행 전 사람 검토 필수"
elif [ "$MED"  -gt 0 ]; then VERDICT="🟠 주의 — 표시 항목 검토 후 진행"
else                         VERDICT="🟢 뚜렷한 위험 신호 없음 (그래도 샌드박스 권장)"
fi

REPORT="$(cat <<EOF
# secure-onboard 스캔 결과

- 대상: \`${TARGET}\`
- 판정: **${VERDICT}**
- 위험 신호: HIGH ${HIGH} · MED ${MED} · INFO ${INFO} (총 ${TOTAL})

> ⚠️ 이 스캔은 휴리스틱 기반의 **읽기 전용** 1차 점검입니다. 어떤 코드도 설치·실행하지
> 않았습니다. HIGH/MED 항목은 사람이 직접 해당 파일을 열어 확인해야 합니다.

## 1. 프로젝트 구성
${COMPOSITION}
## 2. 위험 신호
$( [ "$TOTAL" -eq 0 ] && echo "- (없음)" || printf '%s' "$BODY" )

## 3. 권장 조치
- HIGH 항목이 있으면 **로컬에서 설치/실행하지 말 것.** 일회용 VPS·컨테이너 등 샌드박스에서만 검토.
- 부득이 설치해야 하면 라이프사이클 훅을 차단: \`npm install --ignore-scripts\` (pnpm/yarn 동일 옵션).
- 표시된 파일을 직접 열어 의도를 확인하기 전에는 진행하지 말 것.
EOF
)"

printf '%s\n' "$REPORT"
if [ -n "$OUT" ]; then
  printf '%s\n' "$REPORT" > "$OUT" && echo "" && echo "(보고서 저장됨: $OUT)"
fi

[ "$HIGH" -gt 0 ] && exit 1
exit 0
