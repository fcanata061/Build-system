#!/usr/bin/env bash
#
# 03-depsolve.sh - Resolver dependências, gerar DAG e ordem topológica (Bash)
# Saídas:
#  - ${ROOT}/build-order.txt
#  - ${ROOT}/deps/deps-map.json
#  - ${ROOT}/deps/blocked.list
#
# Integração: source logger.sh (mesmo diretório)
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then
  set -o pipefail
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# load logger
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/logger.sh"
else
  echo "logger.sh not found in ${SCRIPT_DIR}. Please place logger.sh alongside this script." >&2
  exit 1
fi

# --------------------------
# Defaults - override via config.txt
# --------------------------
: "${ROOT:=./auto-builder}"
: "${PACKAGE_DIR:=${ROOT}/package}"   # where .desc files live (package/*/*.desc)
: "${REPO_DIR:=/usr/src/repo}"        # git repo location (also contains package/)
: "${DEPS_DIR:=${ROOT}/deps}"         # output deps info
: "${BUILD_ORDER_FILE:=${ROOT}/build-order.txt}"
: "${DEPS_MAP_JSON:=${DEPS_DIR}/deps-map.json}"
: "${BLOCKED_LIST:=${DEPS_DIR}/blocked.list}"
: "${DEPS_CACHE:=${DEPS_DIR}/deps-cache.json}"
: "${DEPSOLVE_VERBOSE:=no}"
: "${IGNORE_INVALID_DESC:=no}"
: "${ALLOW_BOOTSTRAP:=yes}"           # allow special bootstrap resolution for toolchain cycles
: "${PREFERRED_PROVIDERS:=}"          # space separated preferred provider names
: "${OPTIONS_ENABLED:=}"              # e.g. "wayland pulseaudio" (space separated)
: "${DEPSOLVE_MAX_DEPTH:=1000}"
: "${TMPROOT:=${ROOT}/.tmpdepsolve}"

# canonical paths
PACKAGE_DIR="$(realpath -m "$PACKAGE_DIR")"
REPO_DIR="$(realpath -m "$REPO_DIR")"
DEPS_DIR="$(realpath -m "$DEPS_DIR")"
mkdir -p "$DEPS_DIR" "$TMPROOT"

log_init

# globals
declare -A DESC_PATH      # DESC_PATH["pkgname"]=path
declare -A NODE_VERSION   # NODE_VERSION["pkgname"]=version (string)
declare -A NODE_STAGE     # stage if present
declare -A NODE_PRIORITY  # priority
declare -A NODE_PROVIDES  # NODE_PROVIDES["pkgname"]="feat1 feat2"
declare -A NODE_BUILD_DEPS # NODE_BUILD_DEPS["pkgname"]="dep1 dep2"
declare -A NODE_RUN_DEPS  # NODE_RUN_DEPS["pkgname"]="dep1 dep2"
declare -A NODE_OPTIONS   # NODE_OPTIONS["pkgname"]="opt1 opt2"
declare -A NODE_RAW       # raw desc lines fallback
declare -A IN_DEGREE      # for Kahn
declare -A ADJ            # adjacency list: ADJ["pkg"]="space sep list of providers this pkg depends on"
declare -A REVERSE_ADJ    # reverse adjacency: provider -> dependents
declare -A BLOCK_REASON   # BLOCK_REASON["pkg"]="reason"
declare -A SELECTED_PROVIDER # SELECTED_PROVIDER["dep_expr"]="provider_pkg"

# util: debug
_dbg() {
  [ "$DEPSOLVE_VERBOSE" = "yes" ] && echo "[depsolve dbg] $*" >> "${DEPS_DIR}/debug.log"
  return 0
}

# safe write atomic
atomic_write() {
  local tmp="$(mktemp "${TMPROOT}/tmp.XXXXXX")"
  cat > "$tmp" || return 1
  mv -f "$tmp" "$1" || return 1
}

# parse dependency token (simple grammar)
# supports:
#  - pkgname
#  - pkgname>=1.2.3
#  - pkgname<=2.0
#  - pkgname=1.0
#  - pkgname>1.0
#  - pkgname<2.0
#  - pkg1|pkg2 (alternatives) - handled at higher level split by '|'
# Returns:
#  - prints normalized token to stdout
normalize_dep_token() {
  local token="$1"
  echo "$token" | tr -d '[:space:]'
}

# compare versions simple: supports numeric segments separated by dot
# return codes: 0 if comparison true, 1 false
# usage: version_cmp "1.2.3" ">=" "1.2"
version_cmp() {
  local a="$1"; local op="$2"; local b="$3"
  # split into arrays
  IFS='.' read -r -a A <<< "$a"
  IFS='.' read -r -a B <<< "$b"
  local i=0
  local max=${#A[@]}
  if [ ${#B[@]} -gt $max ]; then max=${#B[@]}; fi
  while [ "$i" -lt "$max" ]; do
    local va=${A[i]:-0}
    local vb=${B[i]:-0}
    # ensure numeric compare; strip non-digits
    va="${va//[^0-9]/}"
    vb="${vb//[^0-9]/}"
    va=${va:-0}
    vb=${vb:-0}
    if [ "$va" -lt "$vb" ]; then
      case "$op" in
        "<" | "<=" | "!=" ) return 0 ;; # a < b true for <, <=, != (partial)
        ">" | ">=" | "=" ) return 1 ;;
      esac
    elif [ "$va" -gt "$vb" ]; then
      case "$op" in
        ">" | ">=" | "!=" ) return 0 ;;
        "<" | "<=" | "=" ) return 1 ;;
      esac
    fi
    i=$((i+1))
  done
  # equal so far
  case "$op" in
    "=") return 0 ;;
    "==") return 0 ;;
    "!=") return 1 ;;
    ">=") return 0 ;;
    "<=") return 0 ;;
    ">" ) return 1 ;;
    "<" ) return 1 ;;
    *) return 1 ;;
  esac
}

# parse .desc file into arrays above
# expects fields like NAME, VERSION, BUILD_DEPS (comma or space separated), RUN_DEPS, PROVIDES, OPTIONS, STAGE, PRIORITY
parse_desc_file() {
  local file="$1"
  [ -f "$file" ] || { _dbg "parse_desc_file: missing $file"; return 1; }
  local name version build_deps run_deps provides options stage priority
  # read lines tolerant
  name=$(grep -E '^NAME' "$file" | head -n1 | cut -d'=' -f2- | xargs || echo "")
  version=$(grep -E '^VERSION' "$file" | head -n1 | cut -d'=' -f2- | xargs || echo "")
  build_deps=$(grep -E '^BUILD_DEPS' "$file" | head -n1 | cut -d'=' -f2- | xargs || echo "")
  run_deps=$(grep -E '^RUN_DEPS' "$file" | head -n1 | cut -d'=' -f2- | xargs || echo "")
  provides=$(grep -E '^PROVIDES' "$file" | head -n1 | cut -d'=' -f2- | xargs || echo "")
  options=$(grep -E '^OPTIONS' "$file" | head -n1 | cut -d'=' -f2- | xargs || echo "")
  stage=$(grep -E '^STAGE' "$file" | head -n1 | cut -d'=' -f2- | xargs || echo "")
  priority=$(grep -E '^PRIORITY' "$file" | head -n1 | cut -d'=' -f2- | xargs || echo "")
  # fallback name from filename
  if [ -z "$name" ]; then
    # try derive from path like package/<cat>/pkg/pkg.desc
    name="$(basename "$file" .desc)"
  fi
  if [ -z "$version" ]; then
    version="0"
  fi
  # normalize separators (commas to spaces)
  build_deps="${build_deps//,/ }"
  run_deps="${run_deps//,/ }"
  provides="${provides//,/ }"
  options="${options//,/ }"
  priority="${priority:-normal}"

  if [ -z "$name" ]; then
    if [ "$IGNORE_INVALID_DESC" = "yes" ]; then
      log_warn "Skipping invalid .desc with no NAME: $file"
      return 2
    else
      log_error "Invalid .desc (no NAME): $file"
      return 3
    fi
  fi

  DESC_PATH["$name"]="$file"
  NODE_VERSION["$name"]="$version"
  NODE_BUILD_DEPS["$name"]="$build_deps"
  NODE_RUN_DEPS["$name"]="$run_deps"
  NODE_PROVIDES["$name"]="$provides"
  NODE_OPTIONS["$name"]="$options"
  NODE_STAGE["$name"]="$stage"
  NODE_PRIORITY["$name"]="$priority"
  NODE_RAW["$name"]="$(cat "$file")"
  return 0
}

# scan package directories for .desc
index_all_descs() {
  log_info "Indexing .desc files from ${PACKAGE_DIR} and ${REPO_DIR}/package (if exists)"
  # find in PACKAGE_DIR
  local files
  IFS=$'\n' read -r -d '' -a files < <(find "$PACKAGE_DIR" -type f -name '*.desc' -print0 2>/dev/null || printf '\0')
  # include repo package dir
  if [ -d "${REPO_DIR}/package" ]; then
    IFS=$'\n' read -r -d '' -a repofiles < <(find "${REPO_DIR}/package" -type f -name '*.desc' -print0 2>/dev/null || printf '\0')
    files+=("${repofiles[@]}")
  fi
  local f
  for f in "${files[@]}"; do
    # handle nulls
    [ -z "$f" ] && continue
    parse_desc_file "$f" || true
  done
  log_info "Indexed ${#DESC_PATH[@]} packages"
  _dbg "Indexed packages: ${!DESC_PATH[*]}"
}

# build provides index: map feature -> providers
declare -A PROVIDES_INDEX   # PROVIDES_INDEX["feature"]="pkg1 pkg2"
build_provides_index() {
  PROVIDES_INDEX=()
  for pkg in "${!DESC_PATH[@]}"; do
    # pkg implicitly provides its own name
    PROVIDES_INDEX["$pkg"]="${PROVIDES_INDEX[$pkg]:-} $pkg"
    local p="${NODE_PROVIDES[$pkg]}"
    for feat in $p; do
      PROVIDES_INDEX["$feat"]="${PROVIDES_INDEX[$feat]:-} $pkg"
    done
  done
  # apply preferred providers ordering if set
  if [ -n "$PREFERRED_PROVIDERS" ]; then
    _dbg "Preferred providers: $PREFERRED_PROVIDERS"
  fi
  return 0
}

# helper choose provider for dependency token (pkg or virtual)
# input: dep_expr (may be "a", "a>=1.2", "a|b|c") ; returns provider name or empty
choose_provider_for_dep() {
  local dep_expr="$1"
  # handle alternatives
  IFS='|' read -r -a alt <<< "$dep_expr"
  for token in "${alt[@]}"; do
    token="$(normalize_dep_token "$token")"
    # parse operator if present
    if echo "$token" | grep -E '[<>!=]' >/dev/null 2>&1; then
      # split name and constraint
      # e.g. rust>=1.77
      local name="$(echo "$token" | sed -E 's/([a-zA-Z0-9._+-]+).*$/\1/')"
      local op_ver="$(echo "$token" | sed -E 's/^([a-zA-Z0-9._+-]+)//')"
      # op_ver like >=1.77 or =1.2 etc
      if [ -z "${PROVIDES_INDEX[$name]:-}" ]; then
        # maybe name is virtual feature, also check provides index
        # try direct provider names
        for prov in ${PROVIDES_INDEX[$name]}; do
          # compare versions
          local prov_ver="${NODE_VERSION[$prov]:-0}"
          # extract op and ver
          local op="$(echo "$op_ver" | sed -E 's/^([<>=!]+).*/\1/')" || op=""
          local ver="$(echo "$op_ver" | sed -E 's/^[<>=!]+(.*)/\1/')" || ver=""
          if [ -z "$op" ]; then
            # accept provider
            echo "$prov"
            return 0
          fi
          if version_cmp "$prov_ver" "$op" "$ver"; then
            echo "$prov"
            return 0
          fi
        done
      else
        # PROVIDES_INDEX has entries for this name
        for prov in ${PROVIDES_INDEX[$name]}; do
          local prov_ver="${NODE_VERSION[$prov]:-0}"
          local op="$(echo "$op_ver" | sed -E 's/^([<>=!]+).*/\1/')" || op=""
          local ver="$(echo "$op_ver" | sed -E 's/^[<>=!]+(.*)/\1/')" || ver=""
          if [ -z "$op" ]; then
            echo "$prov"
            return 0
          fi
          if version_cmp "$prov_ver" "$op" "$ver"; then
            echo "$prov"
            return 0
          fi
        done
      fi
      # if not found try fallback to exact name match
      if [ -n "${DESC_PATH[$name]:-}" ]; then
        echo "$name"
        return 0
      fi
    else
      # no operator: token is simple name or virtual
      if [ -n "${PROVIDES_INDEX[$token]:-}" ]; then
        # choose among providers by preference heuristics
        local candidates=(${PROVIDES_INDEX[$token]})
        # if only one
        if [ "${#candidates[@]}" -eq 1 ]; then
          echo "${candidates[0]}"
          return 0
        fi
        # prefer ones in PREFERRED_PROVIDERS order
        for pref in $PREFERRED_PROVIDERS; do
          for c in "${candidates[@]}"; do
            if [ "$c" = "$pref" ]; then
              echo "$c"; return 0
            fi
          done
        done
        # prefer lower stage (base before apps) if stage numeric
        local best=""
        for c in "${candidates[@]}"; do
          local s="${NODE_STAGE[$c]:-0}"
          s=${s:-0}
          if [ -z "$best" ] || [ "$s" -lt "${NODE_STAGE[$best]:-0}" ]; then
            best="$c"
          fi
        done
        if [ -n "$best" ]; then
          echo "$best"
          return 0
        fi
        # fallback first in list
        echo "${candidates[0]}"
        return 0
      else
        # no providers_index: maybe direct package present
        if [ -n "${DESC_PATH[$token]:-}" ]; then
          echo "$token"
          return 0
        fi
      fi
    fi
  done
  # nothing found
  echo ""
  return 1
}
