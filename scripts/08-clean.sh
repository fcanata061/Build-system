#!/usr/bin/env bash
# 08-clean.sh - Limpeza e manutenção do ambiente do auto-builder
# Requisitos: bash, tar, gzip, find, df, realpath, rsync (opcional), fuser or lsof (optional)
# Integração: source logger.sh -> usa log_start/log_end/log_info/log_warn/log_error/log_set_status
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then
  set -o pipefail
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# load logger; assume it's in same dir
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/logger.sh"
else
  echo "logger.sh not found in ${SCRIPT_DIR}. Please place logger.sh alongside this script." >&2
  exit 1
fi

### Defaults (override via ROOT/config.txt if desired)
: "${ROOT:=./auto-builder}"
: "${SRC_DIR:=${ROOT}/sources}"
: "${PKG_DIR:=${ROOT}/packages}"
: "${BUILD_DIR:=${ROOT}/build}"
: "${LOG_DIR:=${ROOT}/logs}"
: "${TMP_DIR:=${ROOT}/tmp}"
: "${DB_DIR:=/var/lib/pkgdb}"
: "${KEEP_LOGS:=yes}"
: "${COMPRESS_LOGS:=yes}"
: "${MIN_FREE_MB:=500}"            # mínimo MB livre exigido para operação segura
: "${LOG_BACKUP_DAYS:=30}"         # comprimir logs mais antigos que N dias
: "${SAFE_DELETE_LIST:=build tmp .tmp_extract .partial}"  # diretórios seguros dentro do ROOT para remoção
: "${BACKUP_BEFORE_CLEAN:=yes}"    # se 'yes' faz backup (tar.xz) de build dirs antes de remover
: "${MAX_DELETE_AGE_DAYS:=365}"    # só remove builds inativos com idade > esse valor (evita remover recentes)
: "${ALLOW_SUDO:=yes}"             # se necessário, tentará sudo para remoção
: "${CLEAN_FORCE:=no}"             # se 'yes' ignora alguns avisos (use com cautela)
: "${REPORT_JSON:=${LOG_DIR}/summary/clean-summary.json}"

# safety: create absolute canonical root
ROOT="$(realpath -m "$ROOT")"
LOG_DIR="$(realpath -m "$LOG_DIR")"
SRC_DIR="$(realpath -m "$SRC_DIR")"
PKG_DIR="$(realpath -m "$PKG_DIR")"
BUILD_DIR="$(realpath -m "$BUILD_DIR")"
TMP_DIR="$(realpath -m "$TMP_DIR")"
DB_DIR="$(realpath -m "$DB_DIR")"

# Ensure logger initialized
log_init

# Globals to collect stats
REMOVED_BUILD_DIRS=0
ARCHIVED_LOGS=0
REMOVED_PARTIALS=0
ORPHANS_REMOVED=0
START_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ERRCOUNT=0
WARNCOUNT=0

# trap unexpected errors
_trap_err() {
  local rc=$?
  log_error "Internal clean script error (rc=${rc})"
  # write summary with FAIL marker
  _report_summary "FAIL"
  exit $rc
}
trap '_trap_err' ERR INT TERM

### Helpers ###
_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_epoch() { date +%s; }

# safe realpath + prefix check
_is_under_root() {
  local p=$(realpath -m "$1" 2>/dev/null || echo "")
  case "$p" in
    "$ROOT"/*) return 0 ;;
    "$ROOT") return 0 ;;
    *) return 1 ;;
  esac
}

# safe remove with retries, permissions fallback and EBUSY mitigation
safe_rm() {
  local target="$1"
  local tries=0
  local maxtries=3
  if [ -z "$target" ]; then return 0; fi
  if ! _is_under_root "$target"; then
    log_warn "safe_rm: refusing to remove outside ROOT: $target"
    WARNCOUNT=$((WARNCOUNT+1))
    return 1
  fi
  while [ "$tries" -lt "$maxtries" ]; do
    if rm -rf -- "$target" 2>>"$LOGGER_CURRENT_ERR"; then
      return 0
    else
      local rc=$?
      # analyze stderr for common issues
      if grep -Eqi "busy|device or resource busy|resource busy|text file busy" "$LOGGER_CURRENT_ERR" 2>/dev/null; then
        log_warn "safe_rm: target busy, attempting to kill holders and retry: $target"
        if command -v fuser >/dev/null 2>&1; then
          fuser -kv "$target" 2>/dev/null || true
        elif command -v lsof >/dev/null 2>&1; then
          lsof +D "$target" 2>/dev/null | awk 'NR>1{print $2}' | xargs -r kill -9 2>/dev/null || true
        fi
        sleep 1
        tries=$((tries+1))
        continue
      fi
      if grep -Ei "permission denied|operation not permitted" "$LOGGER_CURRENT_ERR" >/dev/null 2>&1; then
        log_warn "safe_rm: permission denied when removing $target"
        if [ "$ALLOW_SUDO" = "yes" ] && command -v sudo >/dev/null 2>&1; then
          log_info "Attempting sudo rm -rf $target"
          sudo rm -rf -- "$target" 2>>"$LOGGER_CURRENT_ERR" && return 0 || true
        fi
        tries=$((tries+1))
        sleep 1
        continue
      fi
      # fallback: try moving to tmp and delete there
      local moved="${TMP_DIR}/to_delete_$(date +%s)_$RANDOM"
      mkdir -p "$(dirname "$moved")"
      if mv "$target" "$moved" 2>>"$LOGGER_CURRENT_ERR"; then
        # remove moved
        rm -rf "$moved" 2>>"$LOGGER_CURRENT_ERR" || true
        return 0
      fi
      tries=$((tries+1))
      sleep 1
    fi
  done
  log_error "safe_rm: failed to remove $target after $maxtries attempts"
  ERRCOUNT=$((ERRCOUNT+1))
  return 1
}

# ensure essential directories exist (and are under ROOT)
ensure_structure() {
  for d in "$SRC_DIR" "$PKG_DIR" "$BUILD_DIR" "$LOG_DIR" "$TMP_DIR" "$DB_DIR"; do
    if [ ! -d "$d" ]; then
      if _is_under_root "$d"; then
        mkdir -p "$d" 2>>"$LOGGER_CURRENT_ERR" || {
          log_error "Failed to create directory $d"
          ERRCOUNT=$((ERRCOUNT+1))
        }
      else
        log_warn "Skipping create of non-root path $d"
        WARNCOUNT=$((WARNCOUNT+1))
      fi
    fi
  done
}

# verify disk space on ROOT or a specific path
verify_disk_space() {
  local path="${1:-$ROOT}"
  local need_mb="${2:-$MIN_FREE_MB}"
  local avail
  avail=$(df -Pk "$path" | awk 'NR==2{print int($4/1024)}' 2>/dev/null || echo 0)
  if [ "$avail" -lt "$need_mb" ]; then
    log_error "Insufficient disk space on $(realpath "$path"): ${avail}MB available (< ${need_mb}MB required)"
    ERRCOUNT=$((ERRCOUNT+1))
    return 1
  fi
  log_info "Disk space OK on $(realpath "$path"): ${avail}MB available"
  return 0
}

# archive/compress logs older than LOG_BACKUP_DAYS
archive_logs() {
  if [ "$COMPRESS_LOGS" != "yes" ]; then
    log_info "Compress logs disabled by config"
    return 0
  fi
  mkdir -p "$LOG_DIR/archive"
  # find log files older than LOG_BACKUP_DAYS and compress
  while IFS= read -r -d '' f; do
    # skip already compressed
    case "$f" in *.gz|*.xz) continue ;; esac
    # safety: ensure file is under LOG_DIR
    if ! _is_under_root "$f"; then
      log_warn "Skipping compress outside ROOT: $f"
      continue
    fi
    if gzip -9 -c "$f" > "${f}.gz" 2>>"$LOGGER_CURRENT_ERR"; then
      mv -f "${f}.gz" "$LOG_DIR/archive/" 2>>"$LOGGER_CURRENT_ERR" || true
      rm -f "$f" 2>>"$LOGGER_CURRENT_ERR" || true
      ARCHIVED_LOGS=$((ARCHIVED_LOGS+1))
    else
      log_warn "Failed to compress $f (see ${LOGGER_CURRENT_ERR})"
      WARNCOUNT=$((WARNCOUNT+1))
    fi
  done < <(find "$LOG_DIR" -type f -mtime +"$LOG_BACKUP_DAYS" -name "*.log" -print0 2>/dev/null)
  log_info "Archived $ARCHIVED_LOGS log files older than $LOG_BACKUP_DAYS days"
}

# remove partial downloads and temp files under SRC_DIR and TMP_DIR
remove_partial_pkgs() {
  local patterns=( "*.part" "*.partial" "*.tmp" ".partial_*" ".tmp_*" )
  for p in "${patterns[@]}"; do
    while IFS= read -r -d '' f; do
      if _is_under_root "$f"; then
        safe_rm "$f" && REMOVED_PARTIALS=$((REMOVED_PARTIALS+1)) || true
      else
        log_warn "Skipping partial file outside ROOT: $f"
        WARNCOUNT=$((WARNCOUNT+1))
      fi
    done < <(find "$SRC_DIR" "$TMP_DIR" -type f -name "$p" -print0 2>/dev/null || true)
  done
  # also remove ".part" directories
  while IFS= read -r -d '' d; do
    if _is_under_root "$d"; then
      safe_rm "$d" && REMOVED_PARTIALS=$((REMOVED_PARTIALS+1)) || true
    fi
  done < <(find "$SRC_DIR" "$TMP_DIR" -type d -name ".part*" -print0 2>/dev/null || true)
  log_info "Removed $REMOVED_PARTIALS partial files/directories"
}

# remove old build directories safely (older than MAX_DELETE_AGE_DAYS)
remove_old_builds() {
  # only target subdirs inside BUILD_DIR
  if [ ! -d "$BUILD_DIR" ]; then
    log_info "No build dir to clean: $BUILD_DIR"
    return 0
  fi
  local deleted=0
  while IFS= read -r -d '' d; do
    # skip if matches protected names (e.g. important artifacts). we only remove dirs older than threshold
    local age_days
    age_days=$(expr \( "$(date +%s)" - "$(stat -c %Y "$d")" \) / 86400)
    if [ "$age_days" -lt "$MAX_DELETE_AGE_DAYS" ] && [ "$CLEAN_FORCE" != "yes" ]; then
      log_debug "Skipping $d (age ${age_days}d < ${MAX_DELETE_AGE_DAYS}d)"
      continue
    fi
    if _is_under_root "$d"; then
      # backup before removal if enabled
      if [ "$BACKUP_BEFORE_CLEAN" = "yes" ]; then
        local pkgname
        pkgname="$(basename "$d")"
        local pkgdb="$DB_DIR/$pkgname"
        mkdir -p "$pkgdb/backup"
        local bak="${pkgdb}/backup/${pkgname}_clean_backup_$(date -u +"%Y%m%dT%H%M%SZ").tar.xz"
        if tar -cJf "$bak" -C "$d" . >>"$LOGGER_CURRENT_OUT" 2>>"$LOGGER_CURRENT_ERR"; then
          log_info "Backup of $d saved to $bak"
        else
          log_warn "Backup failed for $d; continuing with removal"
        fi
      fi
      safe_rm "$d" && deleted=$((deleted+1)) || true
    else
      log_warn "Skipping build dir outside ROOT: $d"
    fi
  done < <(find "$BUILD_DIR" -mindepth 1 -maxdepth 2 -type d -print0 2>/dev/null || true)
  REMOVED_BUILD_DIRS=$((REMOVED_BUILD_DIRS + deleted))
  log_info "Removed $deleted old build directories under $BUILD_DIR"
}

# clean orphan entries in DB_DIR (pkgdb) - remove entries with no corresponding package present
clean_orphan_db() {
  if [ ! -d "$DB_DIR" ]; then
    return 0
  fi
  local removed=0
  while IFS= read -r -d '' d; do
    local pkgname
    pkgname="$(basename "$d")"
    # if no package tarball or package dir exists, consider orphan
    if [ ! -f "$SRC_DIR/${pkgname}.tar.xz" ] && [ ! -d "$PKG_DIR/$pkgname" ] && [ ! -d "$BUILD_DIR/$pkgname" ]; then
      if _is_under_root "$d"; then
        safe_rm "$d" && removed=$((removed+1)) || true
      else
        log_warn "Skipping orphan pkgdb outside root: $d"
      fi
    fi
  done < <(find "$DB_DIR" -mindepth 1 -maxdepth 2 -type d -print0 2>/dev/null || true)
  ORPHANS_REMOVED=$((ORPHANS_REMOVED + removed))
  log_info "Removed $removed orphan pkgdb entries"
}

# detect silent errors during clean: scan recent logs & stderr for patterns
detect_silent_errors_clean() {
  local patterns="Input/output error|Permission denied|Device or resource busy|read-only file system|cannot remove|operation not permitted|No such file or directory"
  # scan global recent error logs
  if grep -Ei "$patterns" "$LOGGER_CURRENT_ERR" >/dev/null 2>&1; then
    log_warn "Silent error patterns detected in clean stderr"
    WARNCOUNT=$((WARNCOUNT+1))
    return 1
  fi
  return 0
}

# recreate basic structure if missing
recreate_structure() {
  ensure_structure
  # ensure summary dir exists
  mkdir -p "$LOG_DIR/summary" "$LOG_DIR/archive" 2>>"$LOGGER_CURRENT_ERR" || true
  # fix perms for directories under ROOT to be accessible
  chmod -R u+rwX,go+rX "$ROOT" 2>/dev/null || true
  log_info "Base structure ensured under $ROOT"
}

# report final summary JSON
_report_summary() {
  local status="${1:-SUCCESS}"
  local end_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local disk_free
  disk_free=$(df -Pk "$ROOT" | awk 'NR==2{print int($4/1024)}' 2>/dev/null || echo 0)
  mkdir -p "$(dirname "$REPORT_JSON")" 2>/dev/null || true
  cat > "$REPORT_JSON" <<EOF
{
  "clean_summary": {
    "start": "${START_TS}",
    "end": "${end_ts}",
    "removed_build_dirs": ${REMOVED_BUILD_DIRS},
    "archived_logs": ${ARCHIVED_LOGS},
    "removed_partial_files": ${REMOVED_PARTIALS},
    "orphans_removed": ${ORPHANS_REMOVED},
    "disk_free_mb": ${disk_free},
    "warnings": ${WARNCOUNT},
    "errors": ${ERRCOUNT},
    "status": "${status}"
  }
}
EOF
  log_info "Clean summary written to $REPORT_JSON"
}

# main flow
main() {
  log_start "clean" "environment"

  log_info "Starting environment clean at $START_TS"

  # validate & recreate structure
  recreate_structure

  # verify disk space
  if ! verify_disk_space "$ROOT" "$MIN_FREE_MB"; then
    log_error "Aborting clean due to insufficient disk space"
    _report_summary "FAIL"
    log_end 1
    return 1
  fi

  # archive old logs
  archive_logs

  # remove partial downloads / temp
  remove_partial_pkgs

  # remove old build directories
  remove_old_builds

  # clean orphan pkgdb entries
  clean_orphan_db

  # final safety checks and perms
  detect_silent_errors_clean || true

  # final recreation of structure and permission fixes
  recreate_structure

  # final summary
  _report_summary "SUCCESS"
  log_end 0
  return 0
}

# If script executed directly
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main
fi
