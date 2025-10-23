#!/usr/bin/env bash
# logger.sh - subsistema de logs para o auto-builder
# Requisitos: bash, mkdir, date, grep, sed, tar (opcionais: gzip)
# Integração: source logger.sh && log_init && log_start ... log_end ...
set -u
# pipefail em bash
if [ -n "${BASH_VERSION-}" ]; then
  set -o pipefail
fi

##### CONFIG DEFAULTS (podem ser sobrescritas por config.txt que o controller faz source) #####
: "${ROOT:=./auto-builder}"
: "${LOG_DIR:=${ROOT}/logs}"
: "${DB_DIR:=/var/lib/pkgdb}"
: "${PACKAGES_DIR:=${ROOT}/packages}"
: "${KEEP_LOGS:=yes}"
: "${COMPRESS_OLD_LOGS:=yes}"
: "${LOG_LEVEL:=INFO}"                # DEBUG, INFO, WARN, ERROR
: "${ROLLBACK_ON_FAIL:=yes}"          # yes/no
: "${STOP_ON_FAIL:=no}"               # yes/no
: "${MAX_LOG_BACKUP_DAYS:=30}"
: "${COLOR_ENABLE:=auto}"             # auto/yes/no

##### Color detection #####
detect_color() {
  if [ "$COLOR_ENABLE" = "no" ]; then
    COLOR_RESET=""; COLOR_RED=""; COLOR_YELLOW=""; COLOR_GREEN=""; COLOR_BLUE=""
  elif [ "$COLOR_ENABLE" = "yes" ]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[1;31m'; COLOR_YELLOW='\033[1;33m'
    COLOR_GREEN='\033[1;32m'; COLOR_BLUE='\033[1;34m'
  else
    if [ -t 1 ]; then
      COLOR_RESET='\033[0m'; COLOR_RED='\033[1;31m'; COLOR_YELLOW='\033[1;33m'
      COLOR_GREEN='\033[1;32m'; COLOR_BLUE='\033[1;34m'
    else
      COLOR_RESET=""; COLOR_RED=""; COLOR_YELLOW=""; COLOR_GREEN=""; COLOR_BLUE=""
    fi
  fi
}
detect_color

##### Internal helpers #####
_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_epoch() { date +%s; }

log_mkpath() {
  mkdir -p "$1" 2>/dev/null || {
    echo "ERROR: cannot create dir $1" >&2
    return 1
  }
}

json_escape() {
  # simples escape para strings de JSON (não robusto para todos os casos, suficiente aqui)
  echo "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'
}

# log level numeric
level_to_num() {
  case "${1:-INFO}" in
    DEBUG) echo 10 ;;
    INFO)  echo 20 ;;
    WARN)  echo 30 ;;
    ERROR) echo 40 ;;
    *) echo 20 ;;
  esac
}

_should_log() {
  local want=$(level_to_num "$1")
  local have=$(level_to_num "$LOG_LEVEL")
  [ "$want" -ge "$have" ]
}

##### Inicialização do logger (cria dirs e arquivos mestres) #####
log_init() {
  log_mkpath "$LOG_DIR"/build
  log_mkpath "$LOG_DIR"/install
  log_mkpath "$LOG_DIR"/error
  log_mkpath "$LOG_DIR"/summary
  log_mkpath "$DB_DIR"
  # summary master file
  SUMMARY_JSON="$LOG_DIR/summary/summary.json"
  if [ ! -f "$SUMMARY_JSON" ]; then
    printf '{ "runs": [] }' > "$SUMMARY_JSON"
  fi
}

##### Abrir log de uma etapa #####
# log_start <stage> <package> [extra_context_json]
log_start() {
  local stage="$1"; local pkg="$2"; local ctx="${3-}"
  : "${stage:?}" : "${pkg:?}"
  local pkgdir="$LOG_DIR/${stage}/${pkg}"
  log_mkpath "$pkgdir"
  local start_ts=$(_epoch)
  local start_iso=$(_now)
  # arquivos
  local meta="$pkgdir/meta.json"
  local out="$pkgdir/output.log"
  local err="$pkgdir/error.log"
  printf '{"package":"%s","stage":"%s","start_time":"%s","status":"RUNNING","errors":[],"warnings":[]}\n' \
    "$(json_escape "$pkg")" "$(json_escape "$stage")" "$start_iso" > "$meta"
  # touch logs
  : > "$out"
  : > "$err"
  # export context for other functions
  export LOGGER_CURRENT_STAGE="$stage"
  export LOGGER_CURRENT_PKG="$pkg"
  export LOGGER_CURRENT_META="$meta"
  export LOGGER_CURRENT_OUT="$out"
  export LOGGER_CURRENT_ERR="$err"
  export LOGGER_CURRENT_START_TS="$start_ts"
  # nice terminal message
  if _should_log DEBUG; then
    printf "%b[>]%b START %s:%s (%s)\n" "$COLOR_BLUE" "$COLOR_RESET" "$stage" "$pkg" "$start_iso"
  else
    printf "%b[>]%b %s: %s ...\n" "$COLOR_BLUE" "$COLOR_RESET" "$stage" "$pkg"
  fi
}

##### Internal: append message to both plain log and JSON meta #####
_log_append() {
  local type="$1"; local msg="$2"
  [ -z "${LOGGER_CURRENT_OUT-}" ] && return 0
  echo "[$(_now)] ${msg}" >> "${LOGGER_CURRENT_${type^^}}"
  # update meta json arrays (simple: append line to meta "warnings" or "errors")
  if [ -f "$LOGGER_CURRENT_META" ]; then
    # Insert into JSON by naive sed: add to array before closing ]
    # This is not perfect JSON manipulation but keeps small footprint.
    if echo "$type" | grep -qi '^err'; then
      # add to errors
      tmp=$(mktemp)
      awk -v s="$(json_escape "$msg")" '
        BEGIN{added=0}
        /"errors": \[/ && !added {
          print; getline
          if ($0 ~ /\]/) {
            print "    \"" s "\"," 
            print $0
          } else {
            print $0
          }
          added=1; next
        }
        {print}
      ' "$LOGGER_CURRENT_META" > "$tmp" && mv "$tmp" "$LOGGER_CURRENT_META"
    else
      # warnings
      tmp=$(mktemp)
      awk -v s="$(json_escape "$msg")" '
        BEGIN{added=0}
        /"warnings": \[/ && !added {
          print; getline
          if ($0 ~ /\]/) {
            print "    \"" s "\"," 
            print $0
          } else {
            print $0
          }
          added=1; next
        }
        {print}
      ' "$LOGGER_CURRENT_META" > "$tmp" && mv "$tmp" "$LOGGER_CURRENT_META"
    fi
  fi
}

log_info() {
  local msg="$*"
  [ "$LOG_LEVEL" = "ERROR" ] && return 0
  echo "[$(_now)] INFO: $msg" | tee -a "${LOGGER_CURRENT_OUT-}" >&2
}

log_debug() {
  [ $(_should_log DEBUG) = 1 ] 2>/dev/null || true
  if _should_log DEBUG ; then
    local msg="$*"
    echo "[$(_now)] DEBUG: $msg" >> "${LOGGER_CURRENT_OUT-}"
  fi
}

log_warn() {
  local msg="$*"
  printf "%b[!] WARN:%b %s\n" "$COLOR_YELLOW" "$COLOR_RESET" "$msg" | tee -a "${LOGGER_CURRENT_OUT-}" >&2
  _log_append out "$msg"
  _log_append err "WARN: $msg"
}

log_error() {
  local msg="$*"
  printf "%b[✖] ERROR:%b %s\n" "$COLOR_RED" "$COLOR_RESET" "$msg" | tee -a "${LOGGER_CURRENT_ERR-}" >&2
  _log_append err "ERROR: $msg"
  # write status file in DB_DIR
  if [ -n "${LOGGER_CURRENT_PKG-}" ]; then
    log_set_status "$LOGGER_CURRENT_PKG" "$LOGGER_CURRENT_STAGE" "FAIL" "$msg"
  fi
}

# Escreve status para /var/lib/pkgdb/<pkg>/status
log_set_status() {
  local pkg="$1"; local stage="$2"; local status="$3"; local msg="${4-}"
  local pkgdb="$DB_DIR/$pkg"
  log_mkpath "$pkgdb"
  cat > "$pkgdb/status" <<EOF
NAME=${pkg}
STAGE=${stage}
STATUS=${status}
TIME=$(_now)
MSG=$(json_escape "$msg")
EOF
}

##### Detecta erros silenciosos scaneando o output e o error log #####
detect_silent_errors() {
  local outfile="${LOGGER_CURRENT_OUT-}"
  local errfile="${LOGGER_CURRENT_ERR-}"
  local patterns="error|failed|no such file|undefined reference|fatal error|permission denied|segmentation fault|unresolved symbol"
  local found=0
  if [ -f "$errfile" ] && [ -s "$errfile" ]; then
    if grep -Ei "$patterns" "$errfile" >/dev/null 2>&1; then
      found=1
      log_warn "Detected suspicious patterns in stderr for ${LOGGER_CURRENT_PKG:-unknown}"
    fi
  fi
  if [ -f "$outfile" ]; then
    if grep -Ei "$patterns" "$outfile" >/dev/null 2>&1; then
      found=1
      log_warn "Detected suspicious patterns in stdout for ${LOGGER_CURRENT_PKG:-unknown}"
    fi
  fi
  # check truncation / empty logs
  if [ -f "$outfile" ] && [ ! -s "$outfile" ]; then
    found=1
    log_error "Output log is empty (possible silent failure)"
  fi
  return $found
}

##### Valida a criação de artefatos básicos (heurística) #####
check_artifacts() {
  local pkg="${LOGGER_CURRENT_PKG-}"
  local stage="${LOGGER_CURRENT_STAGE-}"
  local destdir="${DESTDIR-}"
  local ok=1
  if [ "$stage" = "install" ]; then
    # if DESTDIR not set, try /tmp/${pkg}_dest
    if [ -z "${DESTDIR-}" ]; then
      destdir="./work/${pkg}/destdir"
    fi
    if [ ! -d "$destdir" ] || [ -z "$(ls -A "$destdir" 2>/dev/null)" ]; then
      log_error "No files installed into DESTDIR (empty or missing): $destdir"
      ok=0
    fi
  elif [ "$stage" = "build" ]; then
    # check common artifacts under build dir or packages dir
    # This is heuristic — projects vary. We check for typical expected outputs.
    if [ -n "${BUILD_DIR-}" ] && [ -d "${BUILD_DIR}" ]; then
      if [ -z "$(find "$BUILD_DIR" -maxdepth 3 -type f -name "*.so" -o -name "${pkg}*" 2>/dev/null)" ]; then
        # don't treat absence of .so as fatal for small pkgs, mark warning
        log_warn "No shared libraries or obvious binaries found under $BUILD_DIR (heuristic)"
      fi
    fi
  fi
  return $ok
}

##### Finaliza log de etapa #####
# log_end <exit_code>
log_end() {
  local code="${1-0}"
  local end_ts=$(_epoch)
  local duration=$(( end_ts - (LOGGER_CURRENT_START_TS:-end_ts) ))
  local meta="$LOGGER_CURRENT_META"
  local start_iso="$(jq -r .start_time 2>/dev/null <"$meta" 2>/dev/null || sed -n 's/.*"start_time":"\([^"]*\)".*/\1/p' "$meta" 2>/dev/null || _now)"
  local end_iso=$(_now)
  local status="SUCCESS"
  if [ "$code" -ne 0 ]; then
    status="FAIL"
    log_error "Stage ${LOGGER_CURRENT_STAGE}:${LOGGER_CURRENT_PKG} exited with code $code"
  fi

  # Detect silent errors and artifacts problems
  if detect_silent_errors; then
    status="FAIL"
  fi
  if ! check_artifacts; then
    status="FAIL"
  fi

  # update meta.json final fields
  if [ -f "$meta" ]; then
    # naive JSON update: replace RUNNING with final status and add end_time/duration
    tmp=$(mktemp)
    awk -v st="$status" -v et="$end_iso" -v d="$duration" '
      { gsub(/"status":"RUNNING"/, "\"status\":\"" st "\""); print }
    ' "$meta" > "$tmp" && mv "$tmp" "$meta"
    # append end_time and duration if not present
    if ! grep -q '"end_time"' "$meta"; then
      tmp2=$(mktemp)
      awk -v et="$et" -v d="$d" '
        /}/ && !done { print "  \"end_time\": \"" et "\","; print "  \"duration_sec\": " d ","; done=1 }
        {print}
      ' "$meta" > "$tmp2" && mv "$tmp2" "$meta"
    fi
  fi

  # write summary entry into global summary.json (append)
  local summary_entry
  summary_entry=$(cat <<EOF
{
  "package": "$(json_escape "${LOGGER_CURRENT_PKG:-unknown}")",
  "stage": "$(json_escape "${LOGGER_CURRENT_STAGE:-unknown}")",
  "start_time": "$(json_escape "$start_iso")",
  "end_time": "$(json_escape "$end_iso")",
  "status": "$(json_escape "$status")",
  "duration_sec": $duration
}
EOF
)
  # insert into summary file array
  if [ -f "$SUMMARY_JSON" ]; then
    # insert before final ]
    tmp=$(mktemp)
    awk -v entry="$summary_entry" '
      BEGIN{printed=0}
      NR==1 && /{ "runs": \[/ { print; next }
      /]/{ 
        if(!printed){ print entry; printed=1 }
        print; next
      }
      {print}
    ' "$SUMMARY_JSON" > "$tmp" && mv "$tmp" "$SUMMARY_JSON"
  fi

  # DB status
  if [ -n "${LOGGER_CURRENT_PKG-}" ]; then
    log_set_status "$LOGGER_CURRENT_PKG" "$LOGGER_CURRENT_STAGE" "$status" "Exit code $code"
  fi

  # print final message
  if [ "$status" = "SUCCESS" ]; then
    printf "%b[✓] %s:%s - SUCCESS (%ss)%b\n" "$COLOR_GREEN" "$LOGGER_CURRENT_STAGE" "$LOGGER_CURRENT_PKG" "$duration" "$COLOR_RESET"
  else
    printf "%b[✖] %s:%s - %s (%ss)%b\n" "$COLOR_RED" "$LOGGER_CURRENT_STAGE" "$LOGGER_CURRENT_PKG" "$status" "$duration" "$COLOR_RESET"
    # if rollback configured -> attempt rollback
    if [ "${ROLLBACK_ON_FAIL}" = "yes" ]; then
      log_warn "Rollback enabled — attempting rollback for package ${LOGGER_CURRENT_PKG}"
      rollback_package "${LOGGER_CURRENT_PKG}"
    fi
    # if STOP_ON_FAIL=yes, exit immediately with non-zero
    if [ "${STOP_ON_FAIL}" = "yes" ]; then
      echo "STOP_ON_FAIL=yes -> aborting controller" >&2
      exit 1
    fi
  fi

  # optionally compress logs older than threshold (basic)
  if [ "${COMPRESS_OLD_LOGS}" = "yes" ]; then
    _compress_old_logs &
  fi

  return 0
}

_compress_old_logs() {
  # compress logs older than MAX_LOG_BACKUP_DAYS (background)
  find "$LOG_DIR" -type f -mtime +"$MAX_LOG_BACKUP_DAYS" -name "*.log" -print0 2>/dev/null | while IFS= read -r -d '' f; do
    gzip -9 -- "$f" 2>/dev/null || true
  done
}

##### Rollback implementation (heurística prática) #####
# Tentativa de revert: usa backups armazenados em /var/lib/pkgdb/<pkg>/backup or packages cache
rollback_package() {
  local pkg="$1"
  local pkgdb="$DB_DIR/$pkg"
  local backup_dir="$pkgdb/backup"
  if [ ! -d "$pkgdb" ]; then
    log_error "No pkgdb for $pkg, cannot rollback"
    return 1
  fi
  if [ -d "$backup_dir" ] && [ -n "$(ls -A "$backup_dir" 2>/dev/null)" ]; then
    log_info "Found backups in $backup_dir. Attempting restore..."
    # try to find a tarball artifact (artifact may be packages/<pkg>/pkgname-version.tar.xz)
    for f in "$backup_dir"/*.{tar.xz,tar.zst,tar.gz,tar} 2>/dev/null; do
      [ -f "$f" ] || continue
      log_info "Restoring package from backup $f"
      # perform uninstall of current version if files.list exists
      if [ -f "$pkgdb/files.list" ]; then
        while IFS= read -r p; do
          rm -f "$p" 2>/dev/null || true
          # cleanup empty dirs
          dir=$(dirname "$p")
          rmdir --ignore-fail-on-non-empty "$dir" 2>/dev/null || true
        done < "$pkgdb/files.list"
        log_info "Removed files from current installation based on files.list"
      fi
      # extract backup into / (requires root or simulator). Instead extract to temp and then copy
      tmpd=$(mktemp -d)
      case "$f" in
        *.tar.zst) tar -I zstd -xf "$f" -C "$tmpd" 2>/dev/null || tar -xf "$f" -C "$tmpd" ;;
        *) tar -xf "$f" -C "$tmpd" ;;
      esac
      # move files to root with fakeroot ideally; here we attempt safe copy
      if [ -d "$tmpd" ]; then
        (cd "$tmpd" && rsync -aH --numeric-ids . /) 2>/dev/null || {
          log_warn "rsync to / failed (permission?). Try manual inspection of $tmpd"
        }
        rm -rf "$tmpd"
      fi
      log_info "Rollback for $pkg from $f attempted (check logs and file system)."
      # update DB status
      log_set_status "$pkg" "rollback" "SUCCESS" "Rolled back using $f"
      return 0
    done
    # if here, no supported archive found
    log_warn "No supported backup archive found in $backup_dir"
    return 2
  else
    log_warn "No backup dir found for $pkg in $pkgdb"
    return 3
  fi
}

##### Public helper: force compress and rotate logs #####
rotate_logs() {
  if [ "${KEEP_LOGS}" != "yes" ]; then
    find "$LOG_DIR" -type f -name "*.log" -exec gzip -9 {} \; 2>/dev/null || true
  fi
}

##### Trap for unexpected errors in this script #####
_trap_err() {
  local rc=$?
  # if inside a package context, mark failure
  if [ -n "${LOGGER_CURRENT_PKG-}" ]; then
    log_error "Internal logger script error (rc=$rc). See ${LOGGER_CURRENT_ERR-}"
    log_set_status "$LOGGER_CURRENT_PKG" "$LOGGER_CURRENT_STAGE" "FAIL" "Logger internal error rc=$rc"
  else
    echo "Logger internal error rc=$rc" >&2
  fi
  exit $rc
}
trap '_trap_err' ERR

##### Usage example (documentação embutida) #####
# Exemplo de integração no script de build:
# source /path/to/logger.sh
# log_init
# log_start build firefox
# build commands >> "$LOGGER_CURRENT_OUT" 2>> "$LOGGER_CURRENT_ERR" || true
# log_end $?
#
# Observações:
# - Os outros scripts devem redirecionar stdout e stderr para
#   ${LOGGER_CURRENT_OUT} e ${LOGGER_CURRENT_ERR}, respectivamente.
# - DESTDIR, BUILD_DIR e outras variáveis de contexto podem ser exportadas
#   antes de chamar log_start para serem usadas por check_artifacts.
#
# Exemplo curto:
# log_start "build" "bc"
# ( ./configure --prefix=/usr >> "$LOGGER_CURRENT_OUT" 2>> "$LOGGER_CURRENT_ERR" &&
#   make -j$(nproc) >> "$LOGGER_CURRENT_OUT" 2>> "$LOGGER_CURRENT_ERR" ) || true
# log_end $?

# fim do arquivo
