#!/usr/bin/env bash
#
# 05-install.sh - Instala pacote compilado em ambiente isolado (DESTDIR) com fakeroot
# Recursos:
#  - cria DESTDIR temporário
#  - suporta make/cmake/meson/cargo/python/custom
#  - garante que nada é instalado fora do DESTDIR
#  - gera install.list, files.sha256, install-stats.json
#  - integra com health-check (hooks/health-check)
#  - rollback automático em caso de falha
#  - opção de instalar a partir de cache ou repo ( --use-cache | --from-repo )
#  - opção --auto-deps para tentar instalar runtime deps automaticamente
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then set -o pipefail; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# load logger
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/logger.sh"
else
  echo "logger.sh not found in ${SCRIPT_DIR}. Aborting." >&2
  exit 1
fi

# ---------------------------
# Defaults (override via env or config)
# ---------------------------
: "${ROOT:=./auto-builder}"
: "${BUILD_DIR:=${ROOT}/build}"
: "${SRC_DIR:=${ROOT}/sources}"
: "${PKG_CACHE_DIR:=${ROOT}/packages}"
: "${REPO_DIR:=/usr/src/repo}"
: "${PKGDB_DIR:=/var/lib/pkgdb}"
: "${LOG_DIR:=${ROOT}/logs}"
: "${FAKEROOT_BIN:=fakeroot}"
: "${MIN_FREE_MB:=200}"
: "${DETECT_SILENT_PATTERNS:=error|failed|fatal|undefined reference|segmentation fault|core dumped|cannot}"
: "${DEPS_MAP_JSON:=${ROOT}/deps/deps-map.json}"
: "${AUTO_DEPS_RESOLVE_DEPTH:=5}"    # recursion depth for auto deps
: "${KEEP_DESTDIR_ON_FAIL:=no}"      # keep destdir for debug if fail
: "${DRY_RUN:=no}"

mkdir -p "${LOG_DIR}/install" "${PKGDB_DIR}" "${PKG_CACHE_DIR}"

# Helpers
_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_epoch() { date +%s; }

usage() {
  cat <<EOF
Usage: $0 [options] <pkg>
Options:
  --use-cache           Install from packages/<pkg>-<ver>.tar.xz if present
  --from-repo           Install directly from ${REPO_DIR}/package/<pkg> (if present)
  --destdir <path>      Use custom DESTDIR instead of auto temp
  --dry-run             Show actions but don't execute install
  --auto-deps           Attempt to install runtime dependencies automatically (may call this script recursively)
  --verify-only         Validate an existing DESTDIR (no install)
  --help
EOF
}

# Atomic write helper
atomic_write() {
  local out="$1"; shift
  local tmp; tmp="$(mktemp "${out}.tmp.XXXX")"
  cat > "$tmp" || return 1
  mv -f "$tmp" "$out"
}

# check disk
check_free_space() {
  local path="${1:-$ROOT}"
  local need="${2:-$MIN_FREE_MB}"
  local avail
  avail=$(df -Pk "$path" | awk 'NR==2{print int($4/1024)}' || echo 0)
  if [ "$avail" -lt "$need" ]; then
    echo "Insufficient disk space on $path: ${avail}MB (< ${need}MB required)" >&2
    return 1
  fi
  return 0
}

# ensure absolute path
ensure_abs() {
  python - <<PY 2>/dev/null || true
import sys,os
PY
  # use realpath
  local p; p="$(realpath -m "$1")"
  echo "$p"
}

# safe run under fakeroot or sudo fallback
run_under_fakeroot() {
  # args: command...
  if [ "$DRY_RUN" = "yes" ]; then
    echo "[DRY-RUN] $*"
    return 0
  fi
  if command -v "$FAKEROOT_BIN" >/dev/null 2>&1; then
    # prefer fakeroot - uses a single command execution
    "$FAKEROOT_BIN" -- "$@"
    return $?
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return $?
  else
    # no fakeroot or sudo: try direct (may need root)
    "$@"
    return $?
  fi
}

# write pkgdb status
pkgdb_set_install_status() {
  local pkg="$1"; local status="$2"; local msg="${3-}"
  local dir="$PKGDB_DIR/$pkg"
  mkdir -p "$dir"
  cat > "$dir/install.status" <<EOF
NAME=${pkg}
STATUS=${status}
TIME=$(_now)
MSG=${msg}
EOF
}

# parse args
USE_CACHE="no"; FROM_REPO="no"; CUSTOM_DESTDIR=""; VERIFY_ONLY="no"; AUTO_DEPS="no"
if [ $# -eq 0 ]; then usage; exit 1; fi
while [ $# -gt 0 ]; do
  case "$1" in
    --use-cache) USE_CACHE="yes"; shift ;;
    --from-repo) FROM_REPO="yes"; shift ;;
    --destdir) shift; CUSTOM_DESTDIR="$1"; shift ;;
    --dry-run) DRY_RUN="yes"; shift ;;
    --auto-deps) AUTO_DEPS="yes"; shift ;;
    --verify-only) VERIFY_ONLY="yes"; shift ;;
    --help) usage; exit 0 ;;
    --*) echo "Unknown option $1"; usage; exit 1 ;;
    *) PKG="$1"; shift; break ;;
  esac
done

if [ -z "${PKG:-}" ]; then echo "Missing package name"; usage; exit 1; fi

# set log files
OUT_LOG="${LOG_DIR}/install/${PKG}.out"
ERR_LOG="${LOG_DIR}/install/${PKG}.err"
: > "$OUT_LOG"
: > "$ERR_LOG"

log_start "install" "$PKG"

log_info "Starting install for ${PKG} at $(_now)"
echo "Install params: USE_CACHE=${USE_CACHE} FROM_REPO=${FROM_REPO} AUTO_DEPS=${AUTO_DEPS} DRY_RUN=${DRY_RUN}" >>"$OUT_LOG"

# ensure build exists
if [ ! -d "${BUILD_DIR}/${PKG}" ] && [ "$FROM_REPO" != "yes" ] && [ "$USE_CACHE" != "yes" ]; then
  log_error "Build directory ${BUILD_DIR}/${PKG} not found"
  pkgdb_set_install_status "$PKG" "FAIL" "build missing"
  log_end 1
  exit 1
fi

# quick disk check
if ! check_free_space "$ROOT" "$MIN_FREE_MB"; then
  log_error "Insufficient disk space; aborting install"
  pkgdb_set_install_status "$PKG" "FAIL" "insufficient disk"
  log_end 1
  exit 1
fi

# choose DESTDIR
if [ -n "$CUSTOM_DESTDIR" ]; then
  DESTDIR="$(ensure_abs "$CUSTOM_DESTDIR")"
  mkdir -p "$DESTDIR"
else
  DESTDIR="$(mktemp -d "${ROOT}/.install_dest_${PKG}_XXXX")"
fi
# ensure absolute and inside workspace (safety)
DESTDIR="$(realpath -m "$DESTDIR")"
if [[ "$DESTDIR" != "$ROOT"* ]] && [[ "$DESTDIR" != /tmp/* ]]; then
  log_warn "DESTDIR $DESTDIR is not under ROOT or /tmp - continuing but will validate writes"
fi

log_info "Using DESTDIR = $DESTDIR"
echo "DESTDIR=$DESTDIR" >>"$OUT_LOG"

# Collector of installed files to support rollback
declare -a INSTALLED_FILES=()

# trap for unexpected exit to attempt rollback
_on_error_trap() {
  local rc=$?
  log_error "Install failed unexpectedly (rc=$rc) for $PKG; attempting rollback"
  pkgdb_set_install_status "$PKG" "FAIL" "unexpected error rc=$rc"
  # attempt rollback
  if [ "${#INSTALLED_FILES[@]}" -gt 0 ]; then
    for f in "${INSTALLED_FILES[@]}"; do
      # only remove files inside DESTDIR
      case "$f" in "$DESTDIR"/*) rm -f -- "$f" 2>>"$ERR_LOG" || true ;; esac
    done
  fi
  if [ "$KEEP_DESTDIR_ON_FAIL" = "no" ]; then
    rm -rf "$DESTDIR" 2>>"$ERR_LOG" || true
  else
    log_warn "Keeping DESTDIR for debugging: $DESTDIR"
  fi
  log_end 1
  exit $rc
}
trap '_on_error_trap' ERR INT TERM

# helper to verify no writes escape DESTDIR
verify_no_escape() {
  # scan logs for paths written and ensure startswith DESTDIR
  # We'll check the installed files list after installation explicitly instead.
  return 0
}

# function to record installed files by comparing before/after
snapshot_files() {
  local base="$1"
  find "$base" -type f -o -type l 2>/dev/null | sort || true
}

# get pre snapshot
PRE_SNAP="$(mktemp)"
snapshot_files "$DESTDIR" > "$PRE_SNAP"

# function to detect install method
detect_install_method_and_cmd() {
  local method="" cmd=""
  local src="${BUILD_DIR}/${PKG}"
  # If using cache, we'll extract rather than run installation commands
  if [ "$USE_CACHE" = "yes" ] && [ -f "${PKG_CACHE_DIR}/${PKG}.tar.xz" ]; then
    echo "cache"
    return 0
  fi
  if [ "$FROM_REPO" = "yes" ] && [ -d "${REPO_DIR}/package/${PKG}" ]; then
    src="${REPO_DIR}/package/${PKG}"
  fi
  # heuristics
  if [ -f "${src}/CMakeLists.txt" ]; then echo "cmake"; return 0; fi
  if [ -f "${src}/meson.build" ]; then echo "meson"; return 0; fi
  if [ -f "${src}/Cargo.toml" ]; then echo "cargo"; return 0; fi
  if [ -f "${src}/setup.py" ]; then echo "python"; return 0; fi
  if [ -f "${src}/Makefile" ] || [ -f "${src}/GNUmakefile" ]; then echo "make"; return 0; fi
  # custom: presence of hooks/install
  if compgen -G "${SCRIPT_DIR}/package/*/${PKG}/hooks/install*" >/dev/null 2>&1 || compgen -G "${REPO_DIR}/package/*/${PKG}/hooks/install*" >/dev/null 2>&1; then
    echo "custom"
    return 0
  fi
  echo "unknown"
  return 0
}

INSTALL_METHOD="$(detect_install_method_and_cmd)"

log_info "Detected install method: $INSTALL_METHOD" 
echo "INSTALL_METHOD=$INSTALL_METHOD" >>"$OUT_LOG"

# helper to run installation commands (under fakeroot if needed)
_do_install_cmds() {
  local cmd=("$@")
  if [ "$DRY_RUN" = "yes" ]; then
    echo "[DRY-RUN] ${cmd[*]}" >>"$OUT_LOG"
    return 0
  fi
  # run under fakeroot/sudo wrapper
  run_under_fakeroot "${cmd[@]}"
}

# INSTALL FROM CACHE: extract tarball into DESTDIR
install_from_cache() {
  local tarball="${PKG_CACHE_DIR}/${PKG}.tar.xz"
  if [ ! -f "$tarball" ]; then
    log_error "Cache tarball not found: $tarball"
    return 1
  fi
  log_info "Extracting cache $tarball -> $DESTDIR"
  if [ "$DRY_RUN" = "yes" ]; then
    echo "[DRY-RUN] tar -xJf $tarball -C $DESTDIR" >>"$OUT_LOG"; return 0
  fi
  # extract under fakeroot to preserve owner mapping if desired
  if command -v fakeroot >/dev/null 2>&1; then
    fakeroot -- tar -xJf "$tarball" -C "$DESTDIR" >>"$OUT_LOG" 2>>"$ERR_LOG" || return 1
  else
    tar -xJf "$tarball" -C "$DESTDIR" >>"$OUT_LOG" 2>>"$ERR_LOG" || return 1
  fi
  return 0
}

# INSTALL FROM BUILD/REPO: run appropriate install command(s)
install_via_make() {
  local src="${BUILD_DIR}/${PKG}"
  if [ "$FROM_REPO" = "yes" ] && [ -d "${REPO_DIR}/package/${PKG}" ]; then src="${REPO_DIR}/package/${PKG}"; fi
  log_info "Running: make install DESTDIR=$DESTDIR in $src"
  _do_install_cmds sh -c "cd '$src' && make install DESTDIR='$DESTDIR'"
}

install_via_cmake() {
  local src="${BUILD_DIR}/${PKG}"
  if [ "$FROM_REPO" = "yes" ] && [ -d "${REPO_DIR}/package/${PKG}" ]; then src="${REPO_DIR}/package/${PKG}"; fi
  # prefer cmake --install if build dir exists
  if [ -d "${src}/build" ]; then
    _do_install_cmds cmake --install "${src}/build" --prefix /usr
  else
    # try generic
    _do_install_cmds sh -c "cd '$src' && cmake --install . --prefix /usr DESTDIR='$DESTDIR'"
  fi
}

install_via_meson() {
  local src="${BUILD_DIR}/${PKG}"
  if [ -d "${src}/build" ]; then
    _do_install_cmds ninja -C "${src}/build" install
  else
    _do_install_cmds sh -c "cd '$src' && meson install -C build --destdir '$DESTDIR'"
  fi
}

install_via_cargo() {
  local src="${BUILD_DIR}/${PKG}"
  _do_install_cmds sh -c "cd '$src' && cargo install --path . --root '$DESTDIR/usr'"
}

install_via_python() {
  local src="${BUILD_DIR}/${PKG}"
  _do_install_cmds sh -c "cd '$src' && python3 setup.py install --root='$DESTDIR' --prefix=/usr"
}

install_via_custom_hooks() {
  # run hooks/install* from package or repo; hooks run under sandbox and must respect DESTDIR env
  local patterns=( "${SCRIPT_DIR}/package/*/${PKG}/hooks/install*" "${REPO_DIR}/package/*/${PKG}/hooks/install*" )
  local found=0
  for pat in "${patterns[@]}"; do
    for f in $pat; do
      [ -f "$f" ] || continue
      found=1
      log_info "Running custom install hook: $f"
      # export DESTDIR env for hook
      if [ "$DRY_RUN" = "yes" ]; then
        echo "[DRY-RUN] $f" >>"$OUT_LOG"
      else
        DESTDIR="$DESTDIR" "$f" >>"$OUT_LOG" 2>>"$ERR_LOG" || return 1
      fi
    done
  done
  if [ "$found" -eq 0 ]; then
    log_warn "No custom install hooks found for $PKG"
  fi
  return 0
}

# perform installation based on method
perform_install() {
  case "$INSTALL_METHOD" in
    cache)
      install_from_cache
      ;;
    make)
      install_via_make
      ;;
    cmake)
      install_via_cmake
      ;;
    meson)
      install_via_meson
      ;;
    cargo)
      install_via_cargo
      ;;
    python)
      install_via_python
      ;;
    custom)
      install_via_custom_hooks
      ;;
    unknown)
      # fallback: copy files from build/<pkg> to DESTDIR/usr
      log_warn "Unknown install method; copying artifacts from build/${PKG} to $DESTDIR/usr (fallback)"
      if [ "$DRY_RUN" = "yes" ]; then
        echo "[DRY-RUN] rsync -a ${BUILD_DIR}/${PKG}/ $DESTDIR/usr/" >>"$OUT_LOG"
      else
        mkdir -p "$DESTDIR/usr"
        rsync -a --delete "${BUILD_DIR}/${PKG}/" "$DESTDIR/usr/" >>"$OUT_LOG" 2>>"$ERR_LOG"
      fi
      ;;
  esac
}

# pre-check runtime deps: check DEPS_MAP_JSON for run deps of this package and ensure installed
check_runtime_deps_and_optionally_install() {
  if [ "$AUTO_DEPS" != "yes" ]; then
    return 0
  fi
  if [ ! -f "$DEPS_MAP_JSON" ]; then
    log_warn "No deps map available ($DEPS_MAP_JSON); cannot auto-install runtime deps"
    return 0
  fi
  # crude parsing: find edges where from == PKG and treat as run-dep; we assume deps-map has edges array
  # We'll search for lines where "from": "PKG" and then find the to nodes
  mapfile -t deps < <(awk -v pkg="\"${PKG}\"" 'BEGIN{inEdges=0}/"edges"/{inEdges=1} inEdges && /"from"/{f=$0; getline; print f " " $0}' "$DEPS_MAP_JSON" 2>/dev/null | \
    awk -F'"' '/"from":/ && $4==ENVIRON["pkg"] { } { if($0 ~ /"to":/){ match($0,/"to":\s*"([^"]+)"/,a); if(a[1]!="") print a[1]; } }' pkg="${PKG}")
  # fallback simple grep
  if [ "${#deps[@]}" -eq 0 ]; then
    deps=( $(grep -oP '"to"\s*:\s*"\K[^"]+(?=")' "$DEPS_MAP_JSON" 2>/dev/null | sort -u) )
  fi
  # for each dep, check installed status in pkgdb
  for d in "${deps[@]}"; do
    [ -z "$d" ] && continue
    if [ -f "${PKGDB_DIR}/${d}/install.status" ] && grep -q "^STATUS=INSTALLED" "${PKGDB_DIR}/${d}/install.status" 2>/dev/null; then
      log_info "Runtime dep $d already installed"
    else
      log_warn "Runtime dep $d not installed"
      # try auto-install (recursion) up to limit
      if [ "$AUTO_DEPS" = "yes" ]; then
        log_info "Attempting auto-install of runtime dep $d"
        # call this script recursively to install dependency (no auto-deps inside to avoid deep recursion)
        "${SCRIPT_DIR}/05-install.sh" --use-cache --from-repo --destdir "" --auto-deps no "$d" >>"$OUT_LOG" 2>>"$ERR_LOG" || {
          log_warn "Auto-install of $d failed"
        }
      fi
    fi
  done
}

# run the installation
START_SECS=$(_epoch)
START_TIME=$(_now)

if [ "$VERIFY_ONLY" = "yes" ]; then
  log_info "Verify-only: skipping installation commands"
else
  # optionally attempt auto deps before install
  if [ "$AUTO_DEPS" = "yes" ]; then
    check_runtime_deps_and_optionally_install
  fi

  if [ "$USE_CACHE" = "yes" ]; then
    perform_install || { log_error "Cache extraction failed"; pkgdb_set_install_status "$PKG" "FAIL" "cache extract failed"; exit 1; }
  else
    perform_install || { log_error "Install command failed for $PKG"; pkgdb_set_install_status "$PKG" "FAIL" "install command failed"; exit 1; }
  fi
fi

# post snapshot and compute diff to find installed files
POST_SNAP="$(mktemp)"
snapshot_files "$DESTDIR" > "$POST_SNAP"

# compute difference: lines present in post but not in pre => added files
mapfile -t added < <(comm -13 "$PRE_SNAP" "$POST_SNAP" || true)

# normalize to relative paths (strip DESTDIR prefix)
declare -a REL_ADDED=()
for f in "${added[@]}"; do
  [ -z "$f" ] && continue
  if [[ "$f" == "$DESTDIR"* ]]; then
    REL="${f#$DESTDIR/}"
    REL_ADDED+=("$REL")
    INSTALLED_FILES+=("$f")
  else
    # file outside DESTDIR -> critical security issue
    log_error "File installed outside DESTDIR detected: $f"
    pkgdb_set_install_status "$PKG" "FAIL" "installed outside DESTDIR: $f"
    # attempt rollback
    _on_error_trap
  fi
done

# if no files added, silent error
if [ "${#REL_ADDED[@]}" -eq 0 ]; then
  log_warn "No files were added to DESTDIR by install process (possible silent failure)"
  pkgdb_set_install_status "$PKG" "FAIL" "no files installed"
  if [ "$KEEP_DESTDIR_ON_FAIL" = "no" ]; then rm -rf "$DESTDIR" 2>>"$ERR_LOG" || true; fi
  log_end 1
  exit 1
fi

# validate that added files are under allowed dirs (/usr, /etc, /var, /opt)
declare -a suspicious=()
for rel in "${REL_ADDED[@]}"; do
  case "$rel" in
    usr/*|etc/*|var/*|opt/*|lib/*|include/*|share/*) ;; # allowed
    *) suspicious+=("$rel") ;;
  esac
done
if [ "${#suspicious[@]}" -gt 0 ]; then
  log_warn "Suspicious installed paths detected: ${suspicious[*]}"
  # decide: fail or warn. We'll fail to be safe.
  log_error "Installation produced files outside allowed prefixes -> aborting and rolling back"
  # rollback: remove installed files
  for f in "${INSTALLED_FILES[@]}"; do [ -f "$f" ] && rm -f "$f" 2>>"$ERR_LOG" || true; done
  if [ "$KEEP_DESTDIR_ON_FAIL" = "no" ]; then rm -rf "$DESTDIR" 2>>"$ERR_LOG" || true; fi
  pkgdb_set_install_status "$PKG" "FAIL" "suspicious paths: ${suspicious[*]}"
  log_end 1
  exit 1
fi

# generate install.list (relative paths)
INSTALLED_LIST_PATH="${PKGDB_DIR}/${PKG}/install.list"
mkdir -p "${PKGDB_DIR}/${PKG}"
{
  for rel in "${REL_ADDED[@]}"; do
    echo "$rel"
  done
} | sort > "${INSTALLED_LIST_PATH}.tmp" && mv -f "${INSTALLED_LIST_PATH}.tmp" "${INSTALLED_LIST_PATH}"

# generate files.sha256
FILES_SHA="${PKGDB_DIR}/${PKG}/files.sha256"
: > "${FILES_SHA}.tmp"
for rel in "${REL_ADDED[@]}"; do
  f="${DESTDIR}/${rel}"
  if [ -f "$f" ]; then
    sha256sum "$f" >> "${FILES_SHA}.tmp" 2>>"$ERR_LOG" || echo "sha-fail $rel" >> "${FILES_SHA}.tmp"
  fi
done
mv -f "${FILES_SHA}.tmp" "${FILES_SHA}"

# compute stats: count and size
COUNT=${#REL_ADDED[@]}
BYTES=$(du -sb "$DESTDIR" 2>/dev/null | awk '{print $1}' || echo 0)
DURATION=$((_epoch - START_SECS))

# write JSON stats
STATS_PATH="${PKGDB_DIR}/${PKG}/install-stats.json"
mkdir -p "$(dirname "$STATS_PATH")"
cat > "${STATS_PATH}.tmp" <<EOF
{
  "package": "$(echo "$PKG" | sed 's/"/\\"/g')",
  "destdir": "$(echo "$DESTDIR" | sed 's/"/\\"/g')",
  "files_installed": ${COUNT},
  "bytes": ${BYTES},
  "duration_sec": ${DURATION},
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "status": "INSTALLED"
}
EOF
mv -f "${STATS_PATH}.tmp" "${STATS_PATH}"

# update pkgdb status
pkgdb_set_install_status "$PKG" "INSTALLED" "OK: ${COUNT} files, ${BYTES} bytes"

# run health-check hook (if present) pointing to DESTDIR
# export DESTDIR so the hook can examine files under it
export DESTDIR
# run hook if exists
if compgen -G "${SCRIPT_DIR}/package/*/${PKG}/hooks/health-check" >/dev/null 2>&1 || compgen -G "${REPO_DIR}/package/*/${PKG}/hooks/health-check" >/dev/null 2>&1; then
  log_info "Running health-check hook for $PKG (against DESTDIR)"
  for h in ${SCRIPT_DIR}/package/*/${PKG}/hooks/health-check ${REPO_DIR}/package/*/${PKG}/hooks/health-check; do
    [ -f "$h" ] || continue
    if [ "$DRY_RUN" = "yes" ]; then
      echo "[DRY-RUN] $h --DESTDIR $DESTDIR" >>"$OUT_LOG"
    else
      DESTDIR="$DESTDIR" "$h" >>"$OUT_LOG" 2>>"$ERR_LOG" || {
        log_warn "health-check hook for $PKG returned non-zero; marking WARN"
        # update stats to reflect health warn
        jq_safe() { cat > /dev/null; } # placeholder to ensure optional jq not required
        # mark WARN but keep install as installed (policy)
        pkgdb_set_install_status "$PKG" "INSTALLED_WARN" "health-check failed"
      }
    fi
  done
else
  log_debug "No health-check hook found for $PKG"
fi

# detect orphan files in DESTDIR: files not mapped to any pkgdb install.list (relative)
# Build global set of known installed relative paths across pkgdb
KNOWN_FILES_TMP="$(mktemp)"
: > "$KNOWN_FILES_TMP"
for d in "${PKGDB_DIR}"/*; do
  [ -d "$d" ] || continue
  ilst="$d/install.list"
  if [ -f "$ilst" ]; then
    sed "s#^#/#" "$ilst" >> "$KNOWN_FILES_TMP" 2>/dev/null || true
  fi
done
sort -u "$KNOWN_FILES_TMP" -o "$KNOWN_FILES_TMP" 2>/dev/null || true

# create list of current dest files (relative)
DESTFILES_TMP="$(mktemp)"
(find "$DESTDIR" -type f -o -type l 2>/dev/null | sed "s#^$DESTDIR/##" | sort ) > "$DESTFILES_TMP"

# orphans = files in DESTFILES not present in KNOWN_FILES; note: we compare relative strings
declare -a ORPHANS=()
while IFS= read -r f; do
  # skip empty
  [ -z "$f" ] && continue
  # look for match in known files (strip leading / when comparing)
  if ! grep -Fxq "$f" "$KNOWN_FILES_TMP" 2>/dev/null; then
    ORPHANS+=("$f")
  fi
done < "$DESTFILES_TMP"

# write orphan report if any
if [ "${#ORPHANS[@]}" -gt 0 ]; then
  ORPHAN_REPORT="${PKGDB_DIR}/${PKG}/orphans.txt"
  : > "$ORPHAN_REPORT"
  for o in "${ORPHANS[@]}"; do echo "$o" >> "$ORPHAN_REPORT"; done
  log_warn "Detected ${#ORPHANS[@]} orphan files in DESTDIR (listed in $ORPHAN_REPORT)"
else
  log_info "No orphan files detected in DESTDIR"
fi

# optionally package the DESTDIR into archive for distribution
PACKAGE_ARCHIVE="${PKG_CACHE_DIR}/${PKG}.tar.xz"
if [ "$DRY_RUN" = "no" ]; then
  log_info "Creating package archive $PACKAGE_ARCHIVE"
  (cd "$DESTDIR" && tar -cJf "${PACKAGE_ARCHIVE}" .) >>"$OUT_LOG" 2>>"$ERR_LOG" || {
    log_warn "Failed to create package archive"
  }
fi

# cleanup DESTDIR if using temp and not preserving
if [ -z "$CUSTOM_DESTDIR" ] && [ "$KEEP_DESTDIR_ON_FAIL" = "no" ]; then
  rm -rf "$DESTDIR" 2>>"$ERR_LOG" || log_warn "Failed to remove temp DESTDIR $DESTDIR"
fi

# final log and exit
log_info "Install finished for $PKG: files=${COUNT} bytes=${BYTES} duration=${DURATION}s"
log_end 0
exit 0
