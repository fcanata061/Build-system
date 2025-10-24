#!/usr/bin/env bash
#
# 04-build.sh - Compilação de pacotes (prepara/configura/compila). NÃO instala.
# Integração: source logger.sh (mesmo diretório)
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then
  set -o pipefail
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# source logger
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/logger.sh"
else
  echo "logger.sh not found in ${SCRIPT_DIR}. Please place logger.sh alongside this script." >&2
  exit 1
fi

##### Defaults (override via config.txt or env)
: "${ROOT:=./auto-builder}"
: "${BUILD_ORDER_FILE:=${ROOT}/build-order.txt}"
: "${SRC_DIR:=${ROOT}/sources}"
: "${BUILD_DIR:=${ROOT}/build}"
: "${PKGDB_DIR:=/var/lib/pkgdb}"
: "${REPO_DIR:=/usr/src/repo}"
: "${LOG_DIR:=${ROOT}/logs}"
: "${BUILD_JOBS:=1}"                     # parallel jobs default
: "${MAKEFLAGS:=-j$(nproc 2>/dev/null || echo 1)}"
: "${CFLAGS:=-O2 -g}"
: "${CXXFLAGS:=-O2 -g}"
: "${LDFLAGS:=}"
: "${ROLLBACK_ON_FAIL:=yes}"             # keep backups and attempt restore on fail
: "${BACKUP_BEFORE_BUILD:=yes}"          # create backup of build dir before build
: "${RESUME_ENABLED:=yes}"               # resume incomplete builds
: "${HOOKS_DIRS:=${REPO_DIR}/hooks}"     # global hooks dir
: "${BUILD_TIMEOUT_SEC:=0}"              # 0 = unlimited
: "${DEPS_MAP_JSON:=${ROOT}/deps/deps-map.json}"
: "${DETECT_SILENT_PATTERNS:=error|failed|undefined reference|fatal|segmentation fault|core dumped|No such file or directory|cannot find|ld: }"
: "${KEEP_BUILD_ARTIFACTS:=yes}"         # keep build/dir on success

# canonicalize
BUILD_ORDER_FILE="$(realpath -m "$BUILD_ORDER_FILE")"
BUILD_DIR="$(realpath -m "$BUILD_DIR")"
SRC_DIR="$(realpath -m "$SRC_DIR")"
PKGDB_DIR="$(realpath -m "$PKGDB_DIR")"
LOG_DIR="$(realpath -m "$LOG_DIR")"
TMPDIR="${ROOT}/.tmpbuild"
mkdir -p "$TMPDIR" "$BUILD_DIR" "$LOG_DIR/build" "$PKGDB_DIR"

log_init

# Helpers
_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_epoch() { date +%s; }

# safe command runner: redirect stdout/stderr to package logs
# run_cmd <pkg> <cmd...>
run_cmd() {
  local pkg="$1"; shift
  local cmd=( "$@" )
  # Ensure LOG files exist
  local out="${LOG_DIR}/build/${pkg}.out"
  local err="${LOG_DIR}/build/${pkg}.err"
  mkdir -p "$(dirname "$out")"
  : > "$out"
  : > "$err"
  # run with optional timeout
  if [ "${BUILD_TIMEOUT_SEC:-0}" -gt 0 ] && command -v timeout >/dev/null 2>&1; then
    timeout "${BUILD_TIMEOUT_SEC}"s "${cmd[@]}" >>"$out" 2>>"$err"
    return $?
  else
    "${cmd[@]}" >>"$out" 2>>"$err"
    return $?
  fi
}

# append a message to both logs via logger macros (convenience)
log_pkg_info() {
  local pkg="$1"; shift
  echo "[$(_now)] INFO: $*" >> "${LOG_DIR}/build/${pkg}.out"
}
log_pkg_err() {
  local pkg="$1"; shift
  echo "[$(_now)] ERROR: $*" >> "${LOG_DIR}/build/${pkg}.err"
}

# mark status in pkgdb
pkgdb_set_status() {
  local pkg="$1"; local stage="$2"; local status="$3"; local msg="${4-}"
  local pkgdb="$PKGDB_DIR/$pkg"
  mkdir -p "$pkgdb"
  cat > "$pkgdb/status" <<EOF
NAME=${pkg}
STAGE=${stage}
STATUS=${status}
TIME=$(_now)
MSG=${msg}
EOF
}

# lock / unlock per-package to avoid races
pkg_lock() {
  local pkg="$1"
  local lockfile="${BUILD_DIR}/${pkg}/.lock"
  mkdir -p "${BUILD_DIR}/${pkg}"
  exec 9>"$lockfile"
  if ! flock -n 9; then
    return 1
  fi
  export PKG_LOCK_FD=9
  return 0
}
pkg_unlock() {
  if [ -n "${PKG_LOCK_FD-}" ]; then
    flock -u "$PKG_LOCK_FD" 2>/dev/null || true
    eval "exec ${PKG_LOCK_FD}>&-"
    unset PKG_LOCK_FD || true
  fi
}

# snapshot backup before build (tar.xz into pkgdb backup)
backup_build_dir() {
  local pkg="$1"
  local target="${BUILD_DIR}/${pkg}"
  local pkgdb="$PKGDB_DIR/$pkg"
  mkdir -p "$pkgdb/backup"
  if [ ! -d "$target" ]; then return 0; fi
  local stamp
  stamp="$(date -u +"%Y%m%dT%H%M%SZ")"
  local bak="$pkgdb/backup/${pkg}_prebuild_${stamp}.tar.xz"
  if tar -cJf "$bak" -C "$target" . >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"; then
    log_info "Backup of existing build ${pkg} created: $bak"
  else
    log_warn "Backup failed for ${pkg}; continuing without backup"
  fi
}

# rollback: restore most recent backup if exists, else remove broken build dir
rollback_build() {
  local pkg="$1"
  local pkgdb="$PKGDB_DIR/$pkg"
  local backup_dir="$pkgdb/backup"
  if [ -d "$backup_dir" ] && [ -n "$(ls -A "$backup_dir" 2>/dev/null)" ]; then
    local latest
    latest=$(ls -1t "$backup_dir"/* 2>/dev/null | head -n1 || true)
    if [ -n "$latest" ]; then
      rm -rf "${BUILD_DIR}/${pkg}" 2>>"${LOG_DIR}/build/${pkg}.err" || true
      mkdir -p "${BUILD_DIR}/${pkg}"
      if tar -xJf "$latest" -C "${BUILD_DIR}/${pkg}" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"; then
        log_info "Rollback: restored $pkg from $latest"
        pkgdb_set_status "$pkg" "build" "ROLLED_BACK" "Restored from $latest"
        return 0
      else
        log_warn "Rollback failed when extracting $latest"
      fi
    fi
  fi
  # fallback: remove build dir to leave clean state
  rm -rf "${BUILD_DIR}/${pkg}" 2>>"${LOG_DIR}/build/${pkg}.err" || true
  log_info "Rollback: removed broken build dir for $pkg"
  return 1
}

# detect build system in source dir (or in build/<pkg>)
detect_build_system() {
  local pkg="$1"
  local src_dir="${BUILD_DIR}/${pkg}"
  # check custom hook first
  if [ -f "${SCRIPT_DIR}/hooks/custom_${pkg}.sh" ] || [ -f "${SRC_DIR}/${pkg}.custom" ]; then
    echo "custom"
    return 0
  fi
  # prefer looking at the extracted build dir
  if [ -f "${src_dir}/configure" ]; then echo "autotools"; return 0; fi
  if [ -f "${src_dir}/CMakeLists.txt" ]; then echo "cmake"; return 0; fi
  if [ -f "${src_dir}/meson.build" ]; then echo "meson"; return 0; fi
  if ls "${src_dir}"/*.pro >/dev/null 2>&1; then echo "qmake"; return 0; fi
  if [ -f "${src_dir}/Cargo.toml" ]; then echo "cargo"; return 0; fi
  if [ -f "${src_dir}/setup.py" ]; then echo "python"; return 0; fi
  if [ -f "${src_dir}/Makefile" ] || [ -f "${src_dir}/GNUmakefile" ]; then echo "make"; return 0; fi
  # fallback: unknown
  echo "unknown"
  return 0
}

# run hooks present in package hooks dir or repo hooks dir
# run_hooks <pkg> <phase>
run_hooks() {
  local pkg="$1"; local phase="$2"
  local hooks_local="${SCRIPT_DIR}/package_hooks/${pkg}/${phase}"
  # user-provided hooks may be under package/<cat>/<pkg>/hooks/phase-*
  # look for both repo and package locations
  local patterns=()
  patterns+=("${REPO_DIR}/package/*/${pkg}/hooks/${phase}*")
  patterns+=("${SCRIPT_DIR}/package/*/${pkg}/hooks/${phase}*")
  patterns+=("${SCRIPT_DIR}/hooks/${pkg}/${phase}*")
  patterns+=("${REPO_DIR}/hooks/${pkg}/${phase}*")
  for pat in "${patterns[@]}"; do
    for f in $pat; do
      [ -f "$f" ] || continue
      if [ -x "$f" ]; then
        log_info "Running hook $phase for $pkg: $f"
        "$f" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || {
          log_warn "Hook $f returned non-zero for $pkg"
          # do not fail whole build because of hook unless configured otherwise (could add HOOK_FAIL_OK)
        }
      else
        log_debug "Hook file $f exists but not executable; skipping or consider chmod +x"
      fi
    done
  done
}

# copy sources into BUILD_DIR/<pkg> if not present (prepare)
prepare_pkg() {
  local pkg="$1"
  local src_archive
  # expected src in SRC_DIR/<pkg>.tar.* or extracted dir in SRC_DIR/<pkg> or repo dir
  local candidates=()
  candidates+=( "${SRC_DIR}/${pkg}.tar.xz" )
  candidates+=( "${SRC_DIR}/${pkg}.tar.gz" )
  candidates+=( "${SRC_DIR}/${pkg}.tar.bz2" )
  candidates+=( "${SRC_DIR}/${pkg}.zip" )
  candidates+=( "${SRC_DIR}/${pkg}" )
  candidates+=( "${REPO_DIR}/package/${pkg}" )
  # choose first existing
  for c in "${candidates[@]}"; do
    if [ -e "$c" ]; then
      src_archive="$c"
      break
    fi
  done

  # ensure build dir exists and is writable
  mkdir -p "${BUILD_DIR}/${pkg}"
  # if already a completed build and RESUME_ENABLED, skip extraction
  if [ -f "${BUILD_DIR}/${pkg}/.status" ] && grep -q "SUCCESS" "${BUILD_DIR}/${pkg}/.status" && [ "$RESUME_ENABLED" = "yes" ]; then
    log_info "Build already completed for $pkg and resume enabled — skipping prepare"
    return 0
  fi

  # create fresh tmp dir
  local tmpd
  tmpd="$(mktemp -d "${TMPDIR}/${pkg}.XXXX")" || { log_error "Cannot create temp dir"; return 1; }

  if [ -z "${src_archive:-}" ]; then
    log_warn "No source archive or repo entry found for $pkg in ${SRC_DIR} or ${REPO_DIR}"
    # still continue: maybe build system uses repo fetch or generated code
    rm -rf "$tmpd"
    return 0
  fi

  # if it's a directory, copy contents
  if [ -d "$src_archive" ]; then
    log_info "Copying source dir for $pkg from $src_archive"
    rsync -a --delete "$src_archive"/ "$tmpd"/ >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || {
      log_error "Failed to copy sources for $pkg"
      rm -rf "$tmpd"
      return 1
    }
  else
    # archive: extract to tmpd (safe extraction)
    log_info "Extracting $src_archive -> $tmpd"
    case "$src_archive" in
      *.tar.xz|*.txz) tar -xJf "$src_archive" -C "$tmpd" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || { log_error "tar.xz extract failed"; rm -rf "$tmpd"; return 1; } ;;
      *.tar.gz|*.tgz) tar -xzf "$src_archive" -C "$tmpd" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || { log_error "tar.gz extract failed"; rm -rf "$tmpd"; return 1; } ;;
      *.tar.bz2) tar -xjf "$src_archive" -C "$tmpd" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || { log_error "tar.bz2 extract failed"; rm -rf "$tmpd"; return 1; } ;;
      *.zip) unzip -q "$src_archive" -d "$tmpd" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || { log_error "zip extract failed"; rm -rf "$tmpd"; return 1; } ;;
      *) log_warn "Unknown archive format for $src_archive; attempting tar -xf"; tar -xf "$src_archive" -C "$tmpd" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || { log_error "generic tar extract failed"; rm -rf "$tmpd"; return 1; } ;;
    esac
  fi

  # If extraction produced a single top-level dir, move its contents up
  local entries=( "$tmpd"/* )
  if [ "${#entries[@]}" -eq 1 ] && [ -d "${entries[0]}" ]; then
    rsync -a --delete "${entries[0]}/" "${BUILD_DIR}/${pkg}/" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || true
  else
    rsync -a --delete "$tmpd"/ "${BUILD_DIR}/${pkg}/" >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || true
  fi

  rm -rf "$tmpd"
  log_info "Prepare completed for $pkg"
  return 0
}
# configure step for different build systems
configure_pkg() {
  local pkg="$1"
  local bs="$2"
  local src="${BUILD_DIR}/${pkg}"
  log_info "Configuring $pkg (system: $bs)"
  case "$bs" in
    autotools)
      # run autoreconf if configure missing
      if [ ! -x "$src/configure" ] && command -v autoreconf >/dev/null 2>&1; then
        (cd "$src" && autoreconf -fi) >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err" || log_warn "autoreconf failed for $pkg"
      fi
      (cd "$src" && ./configure --prefix=/usr CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" LDFLAGS="$LDFLAGS") >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    cmake)
      (cd "$src" && mkdir -p build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS") >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    meson)
      (cd "$src" && meson setup build) >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    qmake)
      (cd "$src" && qmake) >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    cargo)
      # cargo doesn't have configure
      return 0
      ;;
    python)
      # no configure for setuptools
      return 0
      ;;
    make)
      # nothing to configure
      return 0
      ;;
    custom)
      # custom configure may be in hooks
      run_hooks "$pkg" "pre-configure"
      run_hooks "$pkg" "configure"
      return 0
      ;;
    *)
      log_warn "Unknown build system for $pkg; skipping configure"
      return 0
      ;;
  esac
}

# compile step
compile_pkg() {
  local pkg="$1"
  local bs="$2"
  local src="${BUILD_DIR}/${pkg}"
  log_info "Compiling $pkg (system: $bs)"
  case "$bs" in
    autotools)
      (cd "$src" && make $MAKEFLAGS) >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    cmake)
      (cd "$src" && cmake --build build -- -j${BUILD_JOBS}) >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    meson)
      ninja -C "${src}/build" -j${BUILD_JOBS} >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    qmake|make)
      (cd "$src" && make $MAKEFLAGS) >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    cargo)
      (cd "$src" && cargo build --release -j ${BUILD_JOBS}) >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    python)
      (cd "$src" && python3 setup.py build) >>"${LOG_DIR}/build/${pkg}.out" 2>>"${LOG_DIR}/build/${pkg}.err"
      return $?
      ;;
    custom)
      # run custom build hook(s)
      run_hooks "$pkg" "build"
      return 0
      ;;
    *)
      log_error "Unsupported/unknown build system for $pkg"
      return 2
      ;;
  esac
}

# detect silent errors in logs for this package and step
detect_silent_errors_build() {
  local pkg="$1"
  local errfile="${LOG_DIR}/build/${pkg}.err"
  local outfile="${LOG_DIR}/build/${pkg}.out"
  local patterns="${DETECT_SILENT_PATTERNS}"
  local found=0
  if [ -f "$errfile" ] && grep -Ei "$patterns" "$errfile" >/dev/null 2>&1; then
    found=1
    log_warn "Silent error patterns found in stderr for $pkg"
  fi
  if [ -f "$outfile" ] && grep -Ei "$patterns" "$outfile" >/dev/null 2>&1; then
    found=1
    log_warn "Silent error patterns found in stdout for $pkg"
  fi
  # check empty out as suspicious
  if [ -f "$outfile" ] && [ ! -s "$outfile" ]; then
    found=1
    log_warn "Empty build stdout for $pkg — possible silent failure"
  fi
  return $found
}

# write .status file for build dir (INCOMPLETE, CONFIGURED, BUILT, FAILED)
write_build_status() {
  local pkg="$1"; local status="$2"; local msg="${3-}"
  local sfile="${BUILD_DIR}/${pkg}/.status"
  cat > "$sfile" <<EOF
STATUS=${status}
TIME=$(_now)
MSG=${msg}
EOF
}

# mark dependents blocked (uses deps-map.json if present)
mark_dependents_blocked() {
  local pkg="$1"; local reason="$2"
  if [ -f "$DEPS_MAP_JSON" ]; then
    # find "from" nodes that depend on this pkg by scanning JSON edges "to":"$pkg"
    # crude jq-less parsing: find lines containing "to": "<pkg>"
    local dependents
    dependents=$(grep -oP '"from"\s*:\s*"\K[^"]+(?=")' "$DEPS_MAP_JSON" | while read -r f; do
      # check if that edge had to "$pkg"
      if grep -F "\"from\": \"$f\"" -n "$DEPS_MAP_JSON" >/dev/null 2>&1 && grep -F "\"to\": \"$pkg\"" -n "$DEPS_MAP_JSON" >/dev/null 2>&1; then
        echo "$f"
      fi
    done | sort -u || true)
    for d in $dependents; do
      log_warn "Marking dependent $d blocked because $pkg failed"
      pkgdb_set_status "$d" "build" "BLOCKED" "Depends on failed package $pkg: $reason"
    done
  fi
}

# single package build pipeline
build_pkg() {
  local pkg="$1"
  log_start "build" "$pkg"
  # initialize per-package logs
  : > "${LOG_DIR}/build/${pkg}.out"
  : > "${LOG_DIR}/build/${pkg}.err"

  # attempt lock
  if ! pkg_lock "$pkg"; then
    log_warn "Could not acquire lock for $pkg — skipping (another process building?)"
    log_end 1
    return 1
  fi

  # backup existing build dir
  if [ "$BACKUP_BEFORE_BUILD" = "yes" ]; then
    backup_build_dir "$pkg"
  fi

  # prepare stage
  run_hooks "$pkg" "pre-prepare"
  if ! prepare_pkg "$pkg"; then
    log_error "Prepare failed for $pkg"
    pkgdb_set_status "$pkg" "build" "FAIL" "prepare failed"
    write_build_status "$pkg" "FAILED" "prepare failed"
    pkg_unlock || true
    rollback_build "$pkg" || true
    mark_dependents_blocked "$pkg" "prepare failed"
    log_end 1
    return 1
  fi
  run_hooks "$pkg" "post-prepare"

  # detect build system
  local bsys
  bsys="$(detect_build_system "$pkg")"
  log_info "Detected build system for $pkg: $bsys"
  write_build_status "$pkg" "CONFIGURING" "detected $bsys"

  # configure stage
  run_hooks "$pkg" "pre-configure"
  if ! configure_pkg "$pkg" "$bsys"; then
    log_error "Configure failed for $pkg"
    pkgdb_set_status "$pkg" "build" "FAIL" "configure failed"
    write_build_status "$pkg" "FAILED" "configure failed"
    run_hooks "$pkg" "post-configure" || true
    pkg_unlock || true
    rollback_build "$pkg" || true
    mark_dependents_blocked "$pkg" "configure failed"
    log_end 1
    return 1
  fi
  run_hooks "$pkg" "post-configure"
  write_build_status "$pkg" "CONFIGURED"

  # build stage
  run_hooks "$pkg" "pre-build"
  if ! compile_pkg "$pkg" "$bsys"; then
    log_error "Build failed for $pkg"
    pkgdb_set_status "$pkg" "build" "FAIL" "build failed"
    write_build_status "$pkg" "FAILED" "build failed"
    run_hooks "$pkg" "post-build" || true
    pkg_unlock || true
    rollback_build "$pkg" || true
    mark_dependents_blocked "$pkg" "build failed"
    log_end 1
    return 1
  fi
  run_hooks "$pkg" "post-build"
  write_build_status "$pkg" "BUILT"
  pkgdb_set_status "$pkg" "build" "BUILT" "Build completed"

  # detect silent errors after build
  if detect_silent_errors_build "$pkg"; then
    log_warn "Silent errors detected for $pkg; marking as WARN"
    pkgdb_set_status "$pkg" "build" "WARN" "Silent errors detected (check logs)"
    # optionally treat as fail; here we keep as WARN but you can change policy
  fi

  # optionally cleanup or leave artifacts
  if [ "$KEEP_BUILD_ARTIFACTS" != "yes" ]; then
    rm -rf "${BUILD_DIR}/${pkg}" 2>>"${LOG_DIR}/build/${pkg}.err" || true
  fi

  pkg_unlock || true
  log_info "Build completed for $pkg"
  log_end 0
  return 0
}

# orchestrate builds in parallel with job control
build_all() {
  log_info "Starting builds using build order ${BUILD_ORDER_FILE} with jobs=${BUILD_JOBS}"
  if [ ! -f "$BUILD_ORDER_FILE" ]; then
    log_error "Build order file not found: $BUILD_ORDER_FILE"
    return 1
  fi
  local -a pids=()
  while IFS= read -r pkg || [ -n "$pkg" ]; do
    [ -z "$pkg" ] && continue
    # skip if pkg already built and resume enabled
    if [ -f "${BUILD_DIR}/${pkg}/.status" ] && grep -q "BUILT" "${BUILD_DIR}/${pkg}/.status" && [ "$RESUME_ENABLED" = "yes" ]; then
      log_info "Skipping $pkg: already built"
      continue
    fi
    # start build in background if jobs>1
    build_pkg "$pkg" &
    pids+=($!)
    # control concurrency
    while [ "${#pids[@]}" -ge "$BUILD_JOBS" ]; do
      wait -n
      # rebuild pids array
      pids=($(jobs -p))
    done
  done < "$BUILD_ORDER_FILE"

  # wait for remaining jobs
  for pid in "${pids[@]}"; do
    wait "$pid" || log_warn "A build process (PID=$pid) exited with error"
  done

  log_info "All builds from build-order processed"
  return 0
}

# CLI and main
usage() {
  cat <<EOF
Usage: $0 [options]
Options:
  --jobs N             Run up to N builds in parallel (overrides BUILD_JOBS)
  --order <file>       Use custom build order file
  --clean-first        Remove build/<pkg> before building (fresh)
  --help
EOF
}

# parse args
CLEAN_FIRST="no"
while [ $# -gt 0 ]; do
  case "$1" in
    --jobs) shift; BUILD_JOBS="$1"; shift ;;
    --order) shift; BUILD_ORDER_FILE="$1"; shift ;;
    --clean-first) CLEAN_FIRST="yes"; shift ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown arg $1"; usage; exit 1 ;;
  esac
done

# entrypoint
main() {
  log_start "build" "global"
  log_info "Build driver starting at $(_now); jobs=${BUILD_JOBS}"

  if [ "$CLEAN_FIRST" = "yes" ]; then
    log_info "Clean-first requested: removing all build dirs before starting"
    rm -rf "${BUILD_DIR}"/* 2>>"${LOG_DIR}/build/clean.err" || true
    mkdir -p "${BUILD_DIR}"
  fi

  if ! build_all; then
    log_error "Some builds failed (check logs)"
    log_end 1
    return 1
  fi

  log_info "Build driver finished"
  log_end 0
  return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main
fi
