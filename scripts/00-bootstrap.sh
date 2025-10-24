#!/usr/bin/env bash
#
# 00-bootstrap.sh
# Prepara ambiente inicial e constrói toolchain mínima (binutils, gcc, glibc).
# - cria diretórios
# - verifica ferramentas do host
# - baixa fontes (se necessário) e valida checksums
# - compila binutils, gcc (fase bootstrap), glibc
# - configura env (PATH, LD_LIBRARY_PATH) em env/bootstrap.env
# - registra logs e status JSON
# - rollback automático em caso de falha
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then set -o pipefail; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try to source logger (for colored logs). If not present, provide minimal logger.
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/logger.sh"
else
  # Minimal colored logger fallback
  RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"; BLUE="\033[0;34m"; NC="\033[0m"
  log_info()  { printf "%b[INFO] %s%b\n"  "$BLUE" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
  log_warn()  { printf "%b[WARN] %s%b\n"  "$YELLOW" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
  log_error() { printf "%b[ERROR] %s%b\n" "$RED" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
  log_debug(){ printf "%b[DEBUG] %s%b\n" "$BLUE" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
  log_start(){ :; }
  log_end(){ :; }
fi

# ---------------------------
# Defaults and configuration
# ---------------------------
: "${ROOT:=/usr/src/repo}"
: "${SOURCES_DIR:=${ROOT}/sources}"
: "${BUILD_DIR:=${ROOT}/build}"
: "${LOG_DIR:=${ROOT}/logs/bootstrap}"
: "${TOOLCHAIN_PREFIX:=${ROOT}/toolchain}"
: "${ENV_FILE:=${ROOT}/env/bootstrap.env}"
: "${STATUS_JSON:=${LOG_DIR}/status.json}"
: "${BACKUP_DIR:=${ROOT}/.bootstrap_backups}"
: "${WORKDIR_TMP:=/tmp/bootbuild.$$}"
: "${DOWNLOAD_RETRIES:=3}"
: "${SILENT_PATTERNS:=error:|undefined reference|segmentation fault|core dumped|internal compiler error|fatal error|ld: }"
: "${MIN_FREE_MB:=2000}"   # recommend at least 2GB free
: "${MAKEFLAGS:=-j$(nproc 2>/dev/null || echo 1)}"

mkdir -p "${SOURCES_DIR}" "${BUILD_DIR}" "${LOG_DIR}" "${BACKUP_DIR}" "${TOOLCHAIN_PREFIX}" "${WORKDIR_TMP}"

# Sources and expected sha256 (defaults — you can override by providing files in SOURCES_DIR or env vars)
: "${BINUTILS_TARBALL:=binutils-2.40.tar.xz}"
: "${BINUTILS_URL:=https://ftp.gnu.org/gnu/binutils/${BINUTILS_TARBALL}}"
: "${BINUTILS_SHA256:=}"  # optional, set if known

: "${GCC_TARBALL:=gcc-12.2.0.tar.xz}"
: "${GCC_URL:=https://ftp.gnu.org/gnu/gcc/gcc-12.2.0/${GCC_TARBALL}}"
: "${GCC_SHA256:=}"

: "${GLIBC_TARBALL:=glibc-2.36.tar.xz}"
: "${GLIBC_URL:=https://ftp.gnu.org/gnu/libc/${GLIBC_TARBALL}}"
: "${GLIBC_SHA256:=}"

# Log files
BINUTILS_LOG="${LOG_DIR}/binutils.log"
GCC_LOG="${LOG_DIR}/gcc.log"
GLIBC_LOG="${LOG_DIR}/glibc.log"
MAIN_LOG="${LOG_DIR}/bootstrap.log"

# Trap and rollback variables
ROLLBACK_REQUIRED=no
ROLLBACK_REASON=""
BACKUP_ARCHIVE=""

# Utility: write status JSON (merge partial)
_status_write() {
  local tmp="$(mktemp)"
  # $1 is a key, $2 is a JSON fragment or value
  # We'll assemble a simple status file; keep it small and human-readable
  # For simplicity, just append lines and create JSON at the end.
  echo "$1=$2" >> "${LOG_DIR}/.status_kv"
}

# Detect essential host commands
req_cmds=(bash gcc g++ make tar xz wget curl ld as sha256sum file awk sed patch gzip bzip2)
_missing=()
for c in "${req_cmds[@]}"; do
  if ! command -v "$c" >/dev/null 2>&1; then
    _missing+=("$c")
  fi
done

if [ "${#_missing[@]}" -ne 0 ]; then
  log_warn "Host is missing required commands: ${_missing[*]}"
  log_warn "Bootstrapping may attempt to continue, but recommend installing the missing tools first."
fi

# Check free disk space on ROOT
_free_mb=$(df -Pm "${ROOT}" | awk 'NR==2{print $4}' 2>/dev/null || echo 0)
if [ "$_free_mb" -lt "$MIN_FREE_MB" ]; then
  log_warn "Low free space on ${ROOT}: ${_free_mb}MB (< ${MIN_FREE_MB}MB recommended)."
fi

# helper: retry wrapper
_retry() {
  local tries=${1:-3}; shift
  local wait=2
  local i=0
  until "$@"; do
    rc=$?
    i=$((i+1))
    if [ "$i" -ge "$tries" ]; then
      return $rc
    fi
    log_warn "Command failed (rc=$rc), retrying in ${wait}s... ($i/$tries)"
    sleep "$wait"
    wait=$((wait*2))
  done
  return 0
}

# helper: detect silent errors in a logfile
_detect_silent_errors_in_log() {
  local logf="$1"
  if [ -f "$logf" ] && grep -Ei "${SILENT_PATTERNS}" "$logf" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# trap for unexpected exit to perform rollback
_on_exit() {
  rc=$?
  if [ $rc -ne 0 ]; then
    log_error "Bootstrap failed (rc=$rc). Triggering rollback."
    ROLLBACK_REQUIRED=yes
    ROLLBACK_REASON="bootstrap-failed (rc=$rc)"
    _perform_rollback
    log_end 1
  else
    log_info "Bootstrap completed successfully."
    log_end 0
  fi
}
trap _on_exit EXIT

# create a safe backup of current toolchain prefix before destructive operations
_create_toolchain_backup() {
  if [ -d "${TOOLCHAIN_PREFIX}" ]; then
    local stamp
    stamp="$(date -u +"%Y%m%dT%H%M%SZ")"
    BACKUP_ARCHIVE="${BACKUP_DIR}/toolchain_backup_${stamp}.tar.xz"
    log_info "Creating backup of existing toolchain at ${BACKUP_ARCHIVE}"
    tar -cJf "${BACKUP_ARCHIVE}" -C "$(dirname "${TOOLCHAIN_PREFIX}")" "$(basename "${TOOLCHAIN_PREFIX}")" >>"${MAIN_LOG}" 2>&1 || {
      log_warn "Backup creation failed (non-fatal)."
      BACKUP_ARCHIVE=""
    }
  fi
}
# perform rollback using backup archive if present
_perform_rollback() {
  if [ "${ROLLBACK_REQUIRED}" != "yes" ]; then
    log_warn "Rollback not required."
    return 0
  fi
  if [ -n "${BACKUP_ARCHIVE}" ] && [ -f "${BACKUP_ARCHIVE}" ]; then
    log_info "Restoring toolchain from backup: ${BACKUP_ARCHIVE}"
    tar -xJf "${BACKUP_ARCHIVE}" -C / || log_error "Failed to restore backup archive ${BACKUP_ARCHIVE}"
    log_info "Restoration attempted."
  else
    log_warn "No backup archive available; attempting cleanup of partial toolchain."
    rm -rf "${TOOLCHAIN_PREFIX}" || true
  fi
  return 0
}

# download a URL to SOURCES_DIR if not present; verify optional sha256
_download_and_verify() {
  local url="$1"; local tarball="$2"; local sha256_expected="${3-}"
  local dest="${SOURCES_DIR}/${tarball}"
  if [ -f "$dest" ]; then
    log_info "Source already present: $dest"
  else
    log_info "Downloading ${url} -> ${dest}"
    _retry "${DOWNLOAD_RETRIES}" curl -L --retry 5 -o "$dest" "$url" >>"${MAIN_LOG}" 2>&1 || {
      log_error "Download failed: $url"
      return 1
    }
  fi
  if [ -n "$sha256_expected" ]; then
    log_info "Verifying SHA256 for $dest"
    if ! sha256sum -c <(printf "%s  %s\n" "$sha256_expected" "$dest") >/dev/null 2>&1; then
      log_error "SHA256 mismatch for $dest"
      return 2
    fi
  fi
  return 0
}

# prepare build dir helper (clean, then mkdir)
_prepare_build_dir() {
  local pkg="$1"
  local d="${BUILD_DIR}/${pkg}"
  rm -rf "$d"
  mkdir -p "$d"
  echo "$d"
}

# Build binutils
_build_binutils() {
  log_info "=== Building binutils ==="
  _status_write "binutils" "building"
  local src="${SOURCES_DIR}/${BINUTILS_TARBALL}"
  if [ ! -f "$src" ]; then
    _download_and_verify "${BINUTILS_URL}" "${BINUTILS_TARBALL}" "${BINUTILS_SHA256}" || return 1
  fi
  local srcdir
  srcdir="$(_prepare_build_dir binutils_src)"
  tar -xJf "${src}" -C "$srcdir" --strip-components=1 >>"${BINUTILS_LOG}" 2>&1 || { log_error "Failed to extract binutils"; return 1; }
  local buildd="$(_prepare_build_dir binutils_build)"
  mkdir -p "${buildd}"
  (cd "$buildd" && "$srcdir/configure" --prefix="${TOOLCHAIN_PREFIX}" --disable-multilib >>"${BINUTILS_LOG}" 2>&1) || { log_error "binutils configure failed"; return 1; }
  (cd "$buildd" && make ${MAKEFLAGS} >>"${BINUTILS_LOG}" 2>&1) || { log_error "binutils make failed"; return 1; }
  (cd "$buildd" && make install >>"${BINUTILS_LOG}" 2>&1) || { log_error "binutils install failed"; return 1; }
  _status_write "binutils" "ok"
  if _detect_silent_errors_in_log "${BINUTILS_LOG}"; then
    log_warn "Silent error patterns found while building binutils (check ${BINUTILS_LOG})"
  fi
  return 0
}

# Build gcc (bootstrap minimal)
_build_gcc() {
  log_info "=== Building GCC (bootstrap) ==="
  _status_write "gcc" "building"
  local src="${SOURCES_DIR}/${GCC_TARBALL}"
  if [ ! -f "$src" ]; then
    _download_and_verify "${GCC_URL}" "${GCC_TARBALL}" "${GCC_SHA256}" || return 1
  fi
  local srcdir
  srcdir="$(_prepare_build_dir gcc_src)"
  tar -xJf "${src}" -C "$srcdir" --strip-components=1 >>"${GCC_LOG}" 2>&1 || { log_error "Failed to extract gcc"; return 1; }

  # gcc needs prerequisites (gmp/mpfr/mpc) — try to use contrib script if available, else rely on host libs
  if [ -f "${srcdir}/contrib/download_prerequisites" ]; then
    (cd "$srcdir" && ./contrib/download_prerequisites >>"${GCC_LOG}" 2>&1) || log_warn "download_prerequisites failed (may have system libs)"
  fi

  local buildd="$(_prepare_build_dir gcc_build)"
  mkdir -p "${buildd}"
  # configure minimal language C only
  PATH="${TOOLCHAIN_PREFIX}/bin:${PATH}" \
  LD_LIBRARY_PATH="${TOOLCHAIN_PREFIX}/lib:${LD_LIBRARY_PATH:-}" \
  (cd "$buildd" && "$srcdir/configure" --prefix="${TOOLCHAIN_PREFIX}" --enable-languages=c --disable-multilib --disable-bootstrap >>"${GCC_LOG}" 2>&1) || { log_error "gcc configure failed"; return 1; }
  (cd "$buildd" && make ${MAKEFLAGS} all-gcc >>"${GCC_LOG}" 2>&1) || { log_error "gcc build (all-gcc) failed"; return 1; }
  (cd "$buildd" && make install-gcc >>"${GCC_LOG}" 2>&1) || { log_error "gcc install-gcc failed"; return 1; }

  _status_write "gcc" "ok"
  if _detect_silent_errors_in_log "${GCC_LOG}"; then
    log_warn "Silent error patterns found while building gcc (check ${GCC_LOG})"
  fi
  return 0
}

# Build glibc
_build_glibc() {
  log_info "=== Building glibc ==="
  _status_write "glibc" "building"
  local src="${SOURCES_DIR}/${GLIBC_TARBALL}"
  if [ ! -f "$src" ]; then
    _download_and_verify "${GLIBC_URL}" "${GLIBC_TARBALL}" "${GLIBC_SHA256}" || return 1
  fi
  local srcdir
  srcdir="$(_prepare_build_dir glibc_src)"
  tar -xJf "${src}" -C "$srcdir" --strip-components=1 >>"${GLIBC_LOG}" 2>&1 || { log_error "Failed to extract glibc"; return 1; }
  local buildd="$(_prepare_build_dir glibc_build)"
  mkdir -p "${buildd}"
  # glibc configure requires proper CC and path to headers; use the just-installed gcc
  PATH="${TOOLCHAIN_PREFIX}/bin:${PATH}" \
  LD_LIBRARY_PATH="${TOOLCHAIN_PREFIX}/lib:${LD_LIBRARY_PATH:-}" \
  (cd "$buildd" && "$srcdir/configure" --prefix="${TOOLCHAIN_PREFIX}" --disable-multilib >>"${GLIBC_LOG}" 2>&1) || { log_error "glibc configure failed"; return 1; }
  (cd "$buildd" && make ${MAKEFLAGS} >>"${GLIBC_LOG}" 2>&1) || { log_error "glibc make failed"; return 1; }
  (cd "$buildd" && make install >>"${GLIBC_LOG}" 2>&1) || { log_error "glibc install failed"; return 1; }
  _status_write "glibc" "ok"
  if _detect_silent_errors_in_log "${GLIBC_LOG}"; then
    log_warn "Silent error patterns found while building glibc (check ${GLIBC_LOG})"
  fi
  return 0
}

# write the environment file that other scripts can source
_write_env_file() {
  log_info "Writing environment file to ${ENV_FILE}"
  mkdir -p "$(dirname "${ENV_FILE}")"
  cat > "${ENV_FILE}.tmp" <<EOF
# bootstrap env generated on $(_now)
export PATH="${TOOLCHAIN_PREFIX}/bin:\$PATH"
export LD_LIBRARY_PATH="${TOOLCHAIN_PREFIX}/lib:\${LD_LIBRARY_PATH:-}"
export CC="${TOOLCHAIN_PREFIX}/bin/gcc"
export CXX="${TOOLCHAIN_PREFIX}/bin/g++"
export CFLAGS="-O2 -pipe"
export LDFLAGS="-Wl,-rpath,${TOOLCHAIN_PREFIX}/lib"
EOF
  mv -f "${ENV_FILE}.tmp" "${ENV_FILE}"
  log_info "Environment file written."
}

# test the toolchain by compiling a hello.c and executing via new gcc
_test_toolchain() {
  log_info "Testing toolchain: compiling simple program with ${TOOLCHAIN_PREFIX}/bin/gcc"
  local testc="${WORKDIR_TMP}/hello.c"
  local testbin="${WORKDIR_TMP}/hello"
  cat > "${testc}" <<'CBOILER'
#include <stdio.h>
int main(void){ puts("hello-toolchain"); return 0; }
CBOILER
  PATH="${TOOLCHAIN_PREFIX}/bin:${PATH}" \
  LD_LIBRARY_PATH="${TOOLCHAIN_PREFIX}/lib:${LD_LIBRARY_PATH:-}" \
  "${TOOLCHAIN_PREFIX}/bin/gcc" -O2 -o "${testbin}" "${testc}" >>"${MAIN_LOG}" 2>&1 || { log_error "Test compile failed"; return 1; }
  if [ ! -x "${testbin}" ]; then log_error "Test binary not generated"; return 1; fi
  # run using the new loader by setting LD_LIBRARY_PATH
  LD_LIBRARY_PATH="${TOOLCHAIN_PREFIX}/lib" "${testbin}" > "${WORKDIR_TMP}/hello.out" 2>&1 || { log_error "Test binary execution failed"; return 1; }
  if ! grep -q "hello-toolchain" "${WORKDIR_TMP}/hello.out"; then
    log_error "Test program did not produce expected output"
    return 1
  fi
  log_info "Toolchain test succeeded."
  return 0
}

# assemble status JSON
_write_status_json() {
  local ts
  ts="$(_now)"
  cat > "${STATUS_JSON}.tmp" <<EOF
{
  "timestamp": "${ts}",
  "root": "${ROOT}",
  "toolchain_prefix": "${TOOLCHAIN_PREFIX}"
}
EOF
  mv -f "${STATUS_JSON}.tmp" "${STATUS_JSON}"
}

# main orchestration
_main() {
  log_start "bootstrap" "global"
  log_info "Bootstrap start at $(_now)"
  _create_toolchain_backup

  # 1) build binutils
  if ! _build_binutils; then
    log_error "Binutils build failed"
    ROLLBACK_REQUIRED=yes; ROLLBACK_REASON="binutils-failed"; return 1
  fi

  # ensure the just-built tools are used
  export PATH="${TOOLCHAIN_PREFIX}/bin:${PATH}"
  export LD_LIBRARY_PATH="${TOOLCHAIN_PREFIX}/lib:${LD_LIBRARY_PATH:-}"

  # 2) build gcc (bootstrap)
  if ! _build_gcc; then
    log_error "GCC bootstrap build failed"
    ROLLBACK_REQUIRED=yes; ROLLBACK_REASON="gcc-failed"; return 1
  fi

  # 3) build glibc
  if ! _build_glibc; then
    log_error "glibc build failed"
    ROLLBACK_REQUIRED=yes; ROLLBACK_REASON="glibc-failed"; return 1
  fi

  # write env and test
  _write_env_file
  if ! _test_toolchain; then
    log_error "Toolchain verification failed"
    ROLLBACK_REQUIRED=yes; ROLLBACK_REASON="test-failed"; return 1
  fi

  # summary status JSON
  _write_status_json

  # success: cleanup temporary workdir
  if [ -d "${WORKDIR_TMP}" ]; then rm -rf "${WORKDIR_TMP}"; fi

  log_info "Bootstrap finished successfully at $(_now)"
  log_end 0
  return 0
}

# Run main and capture failures for rollback handling
if ! _main; then
  log_error "Bootstrap encountered errors: ${ROLLBACK_REASON:-unknown}"
  # _on_exit trap will run rollback
  exit 1
fi

# if everything ok, make env file readable and show instructions
chmod 644 "${ENV_FILE}" || true
log_info "Bootstrap environment created. Source it with:"
log_info "  source ${ENV_FILE}"
exit 0
