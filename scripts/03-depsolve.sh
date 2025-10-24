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
# build dependency graph for given target set (or all)
declare -A NEEDS_RESOLVED  # mark nodes to resolve

# mark all initial targets (if none, all packages)
init_targets() {
  local targets=("$@")
  if [ "${#targets[@]}" -eq 0 ]; then
    for p in "${!DESC_PATH[@]}"; do
      NEEDS_RESOLVED["$p"]=1
    done
  else
    for t in "${targets[@]}"; do
      # if t includes version express like name@ver, strip for now
      NEEDS_RESOLVED["$t"]=1
    done
  fi
}

# expand dependencies transitively, building ADJ and reverse index
expand_all_deps() {
  _dbg "Starting transitive dependency expansion"
  ADJ=()
  REVERSE_ADJ=()
  IN_DEGREE=()

  local queue=()
  for n in "${!NEEDS_RESOLVED[@]}"; do queue+=("$n"); done

  local processed=()
  local depth=0
  while [ "${#queue[@]}" -gt 0 ]; do
    local cur="${queue[0]}"
    queue=("${queue[@]:1}")
    # guard
    depth=$((depth+1))
    if [ "$depth" -gt "$DEPSOLVE_MAX_DEPTH" ]; then
      log_error "Depsolve runaway depth > $DEPSOLVE_MAX_DEPTH"
      return 1
    fi
    # if no desc skip
    if [ -z "${DESC_PATH[$cur]:-}" ]; then
      # try find by prefix or virtual? mark blocked
      BLOCK_REASON["$cur"]="no .desc found for $cur"
      _dbg "No desc for $cur"
      continue
    fi
    # gather deps string
    local bdeps="${NODE_BUILD_DEPS[$cur]:-}"
    local rdeps="${NODE_RUN_DEPS[$cur]:-}"
    # include optional deps if enabled
    local opts="${NODE_OPTIONS[$cur]:-}"
    local included_bdeps=""
    for dep in $bdeps; do
      # skip if optional notation like foo:option (we support this)
      if echo "$dep" | grep -q ':' ; then
        local name="$(echo "$dep" | cut -d: -f1)"
        local opt="$(echo "$dep" | cut -d: -f2)"
        if echo " $OPTIONS_ENABLED " | grep -q " $opt "; then
          included_bdeps="$included_bdeps $name"
        else
          _dbg "Skipping optional build dep $name for $cur (opt $opt not enabled)"
        fi
      else
        included_bdeps="$included_bdeps $dep"
      fi
    done
    # combine build + run deps for graph (build must come before run dependents; we'll treat build_deps primarily)
    local all_deps="$included_bdeps $rdeps"
    # iterate deps (support alternatives a|b)
    for dep in $all_deps; do
      # normalize token
      dep="$(normalize_dep_token "$dep")"
      if [ -z "$dep" ]; then continue; fi
      # choose provider
      local provider
      provider="$(choose_provider_for_dep "$dep")" || provider=""
      if [ -z "$provider" ]; then
        BLOCK_REASON["$cur"]="missing provider for dependency '$dep'"
        log_warn "Missing provider for $cur -> $dep"
        continue
      fi
      # add edge cur -> provider
      ADJ["$cur"]="${ADJ[$cur]:-} $provider"
      REVERSE_ADJ["$provider"]="${REVERSE_ADJ[$provider]:-} $cur"
      # mark indegree
      IN_DEGREE["$provider"]=$(( ${IN_DEGREE["$provider"]:-0} + 1 ))
      # ensure provider present in sets
      if [ -z "${DESC_PATH[$provider]:-}" ]; then
        # not present as desc; try installed db as satisfied
        _dbg "Provider $provider for $cur has no .desc; check installed db"
      fi
      # enqueue provider if not processed
      if [ -z "${processed[$provider]:-}" ]; then
        queue+=("$provider")
      fi
    done
    processed["$cur"]=1
  done

  # ensure IN_DEGREE entries exist for all nodes
  for n in "${!DESC_PATH[@]}"; do
    IN_DEGREE["$n"]=${IN_DEGREE["$n"]:-0}
  done
  _dbg "Adjacency built"
  return 0
}

# detect cycles using Kahn leftover approach
detect_cycles() {
  # perform Kahn partial run, nodes with indegree 0 are roots; remove and reduce
  local -a q=()
  local -A indeg_copy
  local node
  for node in "${!IN_DEGREE[@]}"; do indeg_copy["$node"]=${IN_DEGREE["$node"]}; done
  for node in "${!indeg_copy[@]}"; do
    if [ "${indeg_copy[$node]}" -eq 0 ]; then
      q+=("$node")
    fi
  done
  local processed_count=0
  while [ "${#q[@]}" -gt 0 ]; do
    local n="${q[0]}"; q=("${q[@]:1}")
    processed_count=$((processed_count+1))
    # for each neighbor (provider) reduce indeg
    for nb in ${ADJ[$n]:-}; do
      indeg_copy["$nb"]=$(( ${indeg_copy[$nb]:-0} - 1 ))
      if [ "${indeg_copy[$nb]}" -eq 0 ]; then
        q+=("$nb")
      fi
    done
  done
  local total_nodes=0
  for _n in "${!indeg_copy[@]}"; do total_nodes=$((total_nodes+1)); done
  if [ "$processed_count" -lt "$total_nodes" ]; then
    # cycle exists: compute nodes with indeg>0 in indeg_copy as cycle participants
    local cycle_nodes=()
    for n in "${!indeg_copy[@]}"; do
      if [ "${indeg_copy[$n]}" -gt 0 ]; then cycle_nodes+=("$n"); fi
    done
    # build cycle report text
    local report="${DEPS_DIR}/cycle_report.txt"
    {
      echo "Dependency cycle detected at $(_now)"
      echo "Cycle nodes:"
      for cn in "${cycle_nodes[@]}"; do
        echo " - $cn (desc: ${DESC_PATH[$cn]:-none})"
      done
      echo
      echo "Adjacency:"
      for cn in "${cycle_nodes[@]}"; do
        echo "$cn -> ${ADJ[$cn]:- }"
      done
    } > "$report"
    log_error "Dependency cycle detected; report: $report"
    # mark blocked
    for cn in "${cycle_nodes[@]}"; do
      BLOCK_REASON["$cn"]="dependency cycle (see $report)"
    done
    return 1
  fi
  return 0
}

# topological sort using Kahn's algorithm and respecting STAGE and PRIORITY
topological_sort() {
  log_info "Computing topological build order"
  # compute current indegree map (copy)
  declare -A indeg
  for n in "${!IN_DEGREE[@]}"; do indeg["$n"]=${IN_DEGREE["$n"]}; done
  # initial queue: nodes with indeg 0
  local -a queue=()
  for n in "${!indeg[@]}"; do
    if [ "${indeg[$n]}" -eq 0 ]; then
      queue+=("$n")
    fi
  done

  # comparator: choose nodes by stage (lower first), then priority (high first), then name
  choose_best() {
    # expects array of candidates in "$@" prints chosen as echo
    local best=""
    for c in "$@"; do
      if [ -z "$best" ]; then best="$c"; continue; fi
      local s_c=${NODE_STAGE[$c]:-0}; s_c=${s_c:-0}
      local s_b=${NODE_STAGE[$best]:-0}; s_b=${s_b:-0}
      if [ "$s_c" -lt "$s_b" ]; then best="$c"; continue; fi
      if [ "$s_c" -gt "$s_b" ]; then continue; fi
      # priority mapping: high < normal < low
      local pmap() {
        case "$1" in high) echo 1 ;; normal) echo 2 ;; low) echo 3 ;; *) echo 2 ;; esac
      }
      local pc=$(pmap "${NODE_PRIORITY[$c]:-normal}")
      local pb=$(pmap "${NODE_PRIORITY[$best]:-normal}")
      if [ "$pc" -lt "$pb" ]; then best="$c"; continue; fi
      if [ "$pc" -gt "$pb" ]; then continue; fi
      # tie: lexicographic
      if [[ "$c" < "$best" ]]; then best="$c"; fi
    done
    echo "$best"
  }

  local -a order=()
  while [ "${#queue[@]}" -gt 0 ]; do
    # pick best among queue
    local pick
    pick="$(choose_best "${queue[@]}")"
    # remove pick from queue
    local newq=()
    for el in "${queue[@]}"; do [ "$el" != "$pick" ] && newq+=("$el"); done
    queue=("${newq[@]}")
    order+=("$pick")
    # for each neighbor (provider) decrement indeg
    for nb in ${ADJ[$pick]:-}; do
      indeg["$nb"]=$(( ${indeg[$nb]:-0} - 1 ))
      if [ "${indeg[$nb]}" -eq 0 ]; then
        queue+=("$nb")
      fi
    done
  done

  # verify all nodes included (those with desc)
  local total=0
  for n in "${!DESC_PATH[@]}"; do total=$((total+1)); done
  if [ "${#order[@]}" -lt "$total" ]; then
    log_warn "Topological ordering incomplete (some nodes blocked or cycles)"
  fi

  # write build-order atomically
  mkdir -p "$(dirname "$BUILD_ORDER_FILE")"
  local tmpbo="$(mktemp "${TMPROOT}/buildorder.XXXXXX")"
  for p in "${order[@]}"; do
    echo "$p" >> "$tmpbo"
  done
  mv -f "$tmpbo" "$BUILD_ORDER_FILE"
  log_info "Build order written to $BUILD_ORDER_FILE (packages: ${#order[@]})"
  return 0
}

# write deps-map.json (simple JSON serialization without jq)
write_deps_map() {
  mkdir -p "$DEPS_DIR"
  local tmp="$(mktemp "${TMPROOT}/depsmap.XXXXXX")"
  {
    echo "{"
    echo "  \"nodes\": {"
    local first=1
    for n in "${!DESC_PATH[@]}"; do
      if [ "$first" -ne 1 ]; then echo "    ,"; fi
      first=0
      echo -n "    \"${n}\": {"
      echo -n "\"version\":\"${NODE_VERSION[$n]}\","
      echo -n "\"desc\":\"${DESC_PATH[$n]}\""
      echo -n "}"
    done
    echo
    echo "  },"
    echo "  \"edges\": ["
    local efirst=1
    for from in "${!ADJ[@]}"; do
      for to in ${ADJ[$from]}; do
        if [ "$efirst" -ne 1 ]; then echo ","; fi
        efirst=0
        echo -n "    { \"from\": \"${from}\", \"to\":\"${to}\" }"
      done
    done
    echo
    echo "  ],"
    echo "  \"blocked\": {"
    local bfirst=1
    for k in "${!BLOCK_REASON[@]}"; do
      if [ "$bfirst" -ne 1 ]; then echo ","; fi
      bfirst=0
      echo -n "    \"${k}\": \"${BLOCK_REASON[$k]}\""
    done
    echo
    echo "  }"
    echo "}"
  } > "$tmp"
  mv -f "$tmp" "$DEPS_MAP_JSON"
  log_info "Deps map written to $DEPS_MAP_JSON"
}

# produce blocked.list
write_blocked_list() {
  mkdir -p "$(dirname "$BLOCKED_LIST")"
  local tmp="$(mktemp "${TMPROOT}/blocked.XXXXXX")"
  for k in "${!BLOCK_REASON[@]}"; do
    echo "${k}  # ${BLOCK_REASON[$k]}" >> "$tmp"
  done
  mv -f "$tmp" "$BLOCKED_LIST"
  log_info "Blocked list written to $BLOCKED_LIST"
}

# explain function: print dependency tree & reason
explain_pkg() {
  local pkg="$1"
  if [ -z "$pkg" ]; then
    echo "explain: missing pkg name"
    return 1
  fi
  log_start "depsolve" "explain-${pkg}"
  echo "Explanation for package: $pkg" | tee -a "$LOGGER_CURRENT_OUT"
  if [ -n "${BLOCK_REASON[$pkg]:-}" ]; then
    echo "Blocked: ${BLOCK_REASON[$pkg]}" | tee -a "$LOGGER_CURRENT_OUT"
  fi
  echo "Version: ${NODE_VERSION[$pkg]:-unknown}" | tee -a "$LOGGER_CURRENT_OUT"
  echo "Build deps: ${NODE_BUILD_DEPS[$pkg]:-}" | tee -a "$LOGGER_CURRENT_OUT"
  echo "Run deps: ${NODE_RUN_DEPS[$pkg]:-}" | tee -a "$LOGGER_CURRENT_OUT"
  echo "Provides: ${NODE_PROVIDES[$pkg]:-}" | tee -a "$LOGGER_CURRENT_OUT"
  echo "Resolved providers (adj): ${ADJ[$pkg]:-}" | tee -a "$LOGGER_CURRENT_OUT"
  # print reverse graph paths to root (BFS up to some depth)
  echo "Dependents (reverse adj): ${REVERSE_ADJ[$pkg]:-}" | tee -a "$LOGGER_CURRENT_OUT"
  log_end 0
}

# rebuild_system: calls update.sh for each package in build-order, in order
rebuild_system() {
  log_info "Starting full system rebuild via update.sh following build-order"
  if [ ! -x "${SCRIPT_DIR}/update.sh" ]; then
    log_error "update.sh not found or not executable in ${SCRIPT_DIR}"
    return 1
  fi
  if [ ! -f "$BUILD_ORDER_FILE" ]; then
    log_error "No build-order file found at $BUILD_ORDER_FILE. Run depsolve first."
    return 1
  fi
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    log_info "Rebuilding/updating package: $pkg"
    # call update.sh (it should accept package name as arg)
    "${SCRIPT_DIR}/update.sh" "$pkg" >> "$LOGGER_CURRENT_OUT" 2>> "$LOGGER_CURRENT_ERR" || {
      log_error "update.sh failed for $pkg; aborting rebuild_system"
      return 1
    }
  done < "$BUILD_ORDER_FILE"
  log_info "System rebuild via update.sh finished"
  return 0
}

# detect silent errors in depsolve logs
detect_silent_errors_depsolve() {
  local patterns="error|fail|missing|incompat|cycle|conflict|cannot"
  if grep -Ei "$patterns" "$LOGGER_CURRENT_ERR" >/dev/null 2>&1; then
    log_warn "Silent error patterns detected in depsolve stderr"
    return 1
  fi
  return 0
}

# main flow for depsolve
depsolve_main() {
  local targets=("$@")
  log_start "depsolve" "global"
  index_all_descs
  build_provides_index
  init_targets "${targets[@]}"
  expand_all_deps || true
  # detect cycles
  if ! detect_cycles; then
    log_warn "Cycle detection flagged issues (see cycle_report.txt)"
  fi
  # generate topological order (does not include blocked nodes ideally)
  topological_sort || true
  # write outputs
  write_deps_map
  write_blocked_list
  detect_silent_errors_depsolve || true
  log_end 0
}

# --------------------------
# CLI parsing
# --------------------------
usage() {
  cat <<EOF
Usage: $0 [options]
Options:
  --all                Resolve all packages (default if no target)
  --target <pkg>       Resolve starting from <pkg> (can be repeated)
  --explain <pkg>      Explain dependency tree & block reason for <pkg>
  --rebuild-system     After computing build order, call update.sh for each package
  --rebuild-order-file <file>  Use custom build-order file
  --verbose            Enable verbose debug logging
  --help
EOF
}

# parse args
MODE="run"
TARGETS=()
REBUILD_SYS="no"
while [ $# -gt 0 ]; do
  case "$1" in
    --all) shift ;;
    --target) shift; TARGETS+=("$1"); shift ;;
    --explain) shift; EXPLAIN_PKG="$1"; shift ;;
    --rebuild-system) REBUILD_SYS="yes"; shift ;;
    --rebuild-order-file) shift; BUILD_ORDER_FILE="$1"; shift ;;
    --verbose) DEPSOLVE_VERBOSE=yes; shift ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown arg $1"; usage; exit 1 ;;
  esac
done

if [ -n "${EXPLAIN_PKG:-}" ]; then
  index_all_descs
  build_provides_index
  expand_all_deps || true
  explain_pkg "$EXPLAIN_PKG"
  exit 0
fi

# run depsolve
depsolve_main "${TARGETS[@]}"

# optionally rebuild system
if [ "$REBUILD_SYS" = "yes" ]; then
  rebuild_system || {
    log_error "rebuild_system failed"
    exit 1
  }
fi

# cleanup tmp
rm -rf "$TMPROOT" 2>/dev/null || true

exit 0
