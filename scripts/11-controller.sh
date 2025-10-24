#!/usr/bin/env bash
#
# scripts/11-controller.sh
# Controller / Orquestrador mestre do pipeline de build.
# - Mostra painel resumido em tela durante execução (sem despejar logs)
# - Grava logs completos em disco (/var/log/pkg/controller/)
# - Lê fila de pacotes em /var/lib/pkgdb/depsolve.map
# - Reexecuta falhas até MAX_RETRY, detecta erros silenciosos, gera relatório final
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then set -o pipefail; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ----------------------
# Config defaults
# ----------------------
DEFAULT_CONFIG="${SCRIPT_DIR}/config.txt"
: "${CONFIG_FILE:=${DEFAULT_CONFIG}}"
: "${ROOT:=/usr/src/repo}"
: "${PKGDB_DIR:=/var/lib/pkgdb}"
: "${LOG_DIR:=/var/log/pkg/controller}"
: "${LOCK_FILE:=/var/run/controller.lock}"
: "${DEPSOLVE_MAP:=${PKGDB_DIR}/depsolve.map}"
: "${PROGRESS_FILE:=${PKGDB_DIR}/controller.progress}"
: "${STAGE_TIMEOUT:=3600}"        # timeout per stage (seconds)
: "${MAX_RETRY:=2}"
: "${ALLOW_RETRY:=yes}"
: "${SILENT_PATTERNS:=permission denied|segmentation fault|undefined reference|core dumped|internal compiler error|I/O error|read-only file system}"
: "${PARALLEL_JOBS:=1}"
: "${REBUILD_ON_FAIL:=yes}"
: "${GENERATE_JSON_REPORT:=yes}"
: "${SKIP_CLEAN:=no}"
: "${DRY_RUN:=no}"

# Scripts (assumed in same dir)
: "${BOOTSTRAP_SCRIPT:=${SCRIPT_DIR}/00-bootstrap.sh}"
: "${FETCH_SCRIPT:=${SCRIPT_DIR}/01-fetch.sh}"
: "${EXTRACT_SCRIPT:=${SCRIPT_DIR}/02-extract.sh}"
: "${DEPSOLVE_SCRIPT:=${SCRIPT_DIR}/03-depsolve.sh}"
: "${BUILD_SCRIPT:=${SCRIPT_DIR}/04-build.sh}"
: "${INSTALL_SCRIPT:=${SCRIPT_DIR}/05-install.sh}"
: "${PACKAGE_SCRIPT:=${SCRIPT_DIR}/06-package.sh}"
: "${CLEAN_SCRIPT:=${SCRIPT_DIR}/08-clean.sh}"

# Ensure dirs
mkdir -p "${LOG_DIR}"
mkdir -p "$(dirname "${PROGRESS_FILE}")"

# Minimal logger (uses colors if terminal)
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"; BLUE="\033[0;34m"; NC="\033[0m"
log_info(){ printf "%b[INFO] %s%b\n" "$BLUE" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
log_warn(){ printf "%b[WARN] %s%b\n" "$YELLOW" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
log_error(){ printf "%b[ERROR] %s%b\n" "$RED" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }

# ----------------------
# Helpers
# ----------------------
usage() {
  cat <<EOF
Usage: $0 [options]
Options:
  --config FILE        Use config file (default: ${CONFIG_FILE})
  --resume             Resume from last progress
  --dry-run            Do a dry-run (no destructive actions)
  --help
EOF
  exit 1
}

# parse args
RESUME="no"
while [ $# -gt 0 ]; do
  case "$1" in
    --config) shift; CONFIG_FILE="$1"; shift ;;
    --resume) RESUME="yes"; shift ;;
    --dry-run) DRY_RUN="yes"; shift ;;
    --help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

# load config file if exists
if [ -f "${CONFIG_FILE}" ]; then
  # shellcheck disable=SC1090
  source "${CONFIG_FILE}" || log_warn "Failed to source ${CONFIG_FILE}"
fi

# apply env overrides (already set by defaults above)
: "${MAX_RETRY:=${MAX_RETRY}}"
: "${ALLOW_RETRY:=${ALLOW_RETRY}}"
: "${SILENT_PATTERNS:=${SILENT_PATTERNS}}"

# trap for cleanup
_on_exit() {
  local rc=$?
  flock -u 9 2>/dev/null || true
  if [ $rc -ne 0 ]; then
    log_error "Controller exited with error code $rc"
  fi
}
trap _on_exit EXIT INT TERM

# acquire lock to avoid concurrent controllers
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  log_error "Another controller is running (lock: ${LOCK_FILE}). Aborting."
  exit 1
fi

# time helpers
_now_ts(){ date -u +"%s"; }
_fmt_duration() {
  local s=$1 h m
  h=$((s/3600)); m=$(( (s%3600)/60 )); s=$((s%60))
  printf "%02dh %02dm %02ds" "$h" "$m" "$s"
}

# read depsolve map (queue)
read_queue() {
  if [ ! -f "${DEPSOLVE_MAP}" ]; then
    log_error "Depsolve map not found: ${DEPSOLVE_MAP}"
    return 1
  fi
  mapfile -t QUEUE < "${DEPSOLVE_MAP}"
  # trim blank entries
  local filtered=()
  for p in "${QUEUE[@]}"; do
    p="$(echo "$p" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -n "$p" ] && filtered+=("$p")
  done
  QUEUE=("${filtered[@]}")
  return 0
}

# find desc for package (to get deps)
find_desc() {
  local pkg="$1"
  # try common locations under ROOT/package
  local path
  path="$(find "${ROOT}/package" -maxdepth 4 -type f -name "${pkg}.desc" 2>/dev/null | head -n1 || true)"
  if [ -z "$path" ] && [ -f "${ROOT}/package/${pkg}.desc" ]; then path="${ROOT}/package/${pkg}.desc"; fi
  echo "$path"
}

# simple desc field getter
desc_get_field() {
  local desc="$1" key="$2"
  [ -f "$desc" ] || { echo ""; return 0; }
  awk -F= -v k="$key" '$1==k{ $1=""; sub(/^=/,""); sub(/^ */,""); print substr($0,2); exit }' "$desc" 2>/dev/null || true
}

# show panel for current package
show_panel() {
  local stage="$1" pkg="$2" idx="$3" total="$4" deps="$5" logpath="$6"
  local loadavg
  loadavg="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "N/A")"
  # draw
  printf "\n\033[1;34m──────────────────────────────────────────────────────────────────\033[0m\n"
  printf "\033[1;36m[%s]\033[0m (\033[1;33m%3d/%3d\033[0m) \033[1;32m%s\033[0m\n" "$stage" "$idx" "$total" "$pkg"
  printf "Deps: \033[0;33m%s\033[0m\n" "${deps:-none}"
  printf "Load Avg: \033[1;35m%s\033[0m | Log: \033[0;90m%s\033[0m\n" "$loadavg" "$logpath"
  printf "\033[1;34m──────────────────────────────────────────────────────────────────\033[0m\n"
}

# run a given stage command quietly, logging to pkg log; retries handled by caller
safe_run_stage() {
  local cmd="$1" logf="$2" timeout_sec="$3"
  if [ "${DRY_RUN}" = "yes" ]; then
    echo "[DRY-RUN] $cmd" >> "$logf"
    return 0
  fi
  # ensure log dir exists
  mkdir -p "$(dirname "$logf")"
  # Run with timeout, append stdout/stderr to log
  if command -v timeout >/dev/null 2>&1; then
    timeout --preserve-status "${timeout_sec}" bash -lc "$cmd" >>"$logf" 2>&1
    return $?
  else
    bash -lc "$cmd" >>"$logf" 2>&1
    return $?
  fi
}

# detect silent errors in a log
log_has_silent_errors() {
  local logfile="$1"
  if [ -f "$logfile" ] && grep -Ei "${SILENT_PATTERNS}" "$logfile" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# controller progress tracking
write_progress() {
  local idx="$1" pkg="$2" stage="$3" status="$4"
  # overwrite progress file with last processed package and index
  cat > "${PROGRESS_FILE}.tmp" <<EOF
INDEX=${idx}
PKG=${pkg}
STAGE=${stage}
STATUS=${status}
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF
  mv -f "${PROGRESS_FILE}.tmp" "${PROGRESS_FILE}"
}

# arrays for summary
SUCCEEDED=()
FAILED=()
WARNED=()

# stages to run for each package (sequence)
PKG_STAGES=("fetch" "extract" "build" "install" "package" "clean")
# mapping stage -> script
stage_to_script() {
  local s="$1"
  case "$s" in
    fetch) echo "${FETCH_SCRIPT}" ;;
    extract) echo "${EXTRACT_SCRIPT}" ;;
    build) echo "${BUILD_SCRIPT}" ;;
    install) echo "${INSTALL_SCRIPT}" ;;
    package) echo "${PACKAGE_SCRIPT}" ;;
    clean) echo "${CLEAN_SCRIPT}" ;;
    *) echo "" ;;
  esac
}

# default per-stage timeout may be STAGE_TIMEOUT; can be overridden in config by STAGE_TIMEOUT_<stage>
get_stage_timeout() {
  local s="$1"
  local var="STAGE_TIMEOUT_${s^^}"   # e.g., STAGE_TIMEOUT_BUILD
  if [ -n "${!var-}" ]; then
    echo "${!var}"
  else
    echo "${STAGE_TIMEOUT}"
  fi
}

# process single package with retries per stage
process_package() {
  local pkg="$1"
  local idx="$2" total="$3"
  local pkglog="${LOG_DIR}/${pkg}.log"
  : > "${pkglog}"
  local desc="$(find_desc "$pkg")"
  local deps=""
  if [ -n "$desc" ]; then
    deps="$(desc_get_field "$desc" BUILD_DEPS) $(desc_get_field "$desc" RUN_DEPS)"
    deps="$(echo "$deps" | sed 's/  */ /g' | sed 's/^ //;s/ $//')"
  fi

  show_panel "processing" "$pkg" "$idx" "$total" "$deps" "$pkglog"

  local pkg_start ts_stage_start ts_stage_end stage_elapsed
  pkg_start=$(_now_ts)

  local overall_status="OK"
  for stage in "${PKG_STAGES[@]}"; do
    # skip clean if SKIP_CLEAN=yes
    if [ "$stage" = "clean" ] && [ "${SKIP_CLEAN}" = "yes" ]; then
      continue
    fi
    local script
    script="$(stage_to_script "$stage")"
    if [ ! -x "${script}" ]; then
      # no script available for this stage -> mark as warn and continue
      log_warn "Stage ${stage} script not found for ${pkg} (expected ${script}). Marking WARN and continuing."
      echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") WARN: Stage ${stage} script missing" >> "${pkglog}"
      overall_status="WARN"
      continue
    fi

    # update screen for this specific stage
    show_panel "${stage}" "$pkg" "$idx" "$total" "$deps" "$pkglog"
    printf "Status: \033[1;33mExecuting %s...\033[0m\n" "$stage"

    local attempt=0
    local stage_rc=0
    local timeout_sec
    timeout_sec="$(get_stage_timeout "$stage")"

    while true; do
      attempt=$((attempt+1))
      ts_stage_start=$(_now_ts)
      # run the script for this package: scripts accept package arg
      # We redirect output to pkg log; script should support "pkg" as arg
      safe_run_stage "bash '${script}' '${pkg}'" "${pkglog}" "${timeout_sec}"
      stage_rc=$?
      ts_stage_end=$(_now_ts)
      stage_elapsed=$((ts_stage_end - ts_stage_start))

      # log summary line for stage
      printf "%s STAGE=%s ATTEMPT=%d RC=%d DURATION=%ds\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$stage" "$attempt" "$stage_rc" "$stage_elapsed" >> "${pkglog}"

      if [ $stage_rc -eq 0 ]; then
        # success: check for silent errors
        if log_has_silent_errors "${pkglog}"; then
          log_warn "Silent errors detected during ${pkg}:${stage}. Marking WARN."
          overall_status="WARN"
          WARNED+=("$pkg")
        fi
        printf "✔ [%s] %s (%ds)\n" "OK" "$stage" "$stage_elapsed"
        break
      else
        # failure: decide to retry or abort
        if [ "${ALLOW_RETRY}" = "yes" ] && [ "$attempt" -le "${MAX_RETRY}" ]; then
          log_warn "Stage ${stage} for ${pkg} failed (rc=${stage_rc}). Retrying (${attempt}/${MAX_RETRY})..."
          printf "Retrying %s (attempt %d/%d)...\n" "$stage" "$attempt" "${MAX_RETRY}"
          sleep 2
          continue
        else
          log_error "Stage ${stage} for ${pkg} failed after ${attempt} attempts (rc=${stage_rc})."
          overall_status="FAILED"
          FAILED+=("$pkg")
          # write progress
          write_progress "$idx" "$pkg" "$stage" "FAILED"
          # attempt rollback for this package (best-effort)
          if [ -x "${SCRIPT_DIR}/09-uninstall.sh" ]; then
            log_warn "Attempting uninstall of partially installed ${pkg}"
            safe_run_stage "bash '${SCRIPT_DIR}/09-uninstall.sh' '${pkg}'" "${pkglog}" "${timeout_sec}" || true
          fi
          # stop processing remaining stages for this package
          break 2
        fi
      fi
    done
    # write intermediate progress
    write_progress "$idx" "$pkg" "$stage" "$overall_status"
  done

  # package done or aborted
  local pkg_end=$(_now_ts)
  local pkg_total=$((pkg_end - pkg_start))
  if [ "$overall_status" = "OK" ]; then
    SUCCEEDED+=("$pkg")
    write_progress "$idx" "$pkg" "done" "OK"
    printf "✔ [\033[1;32mOK\033[0m] %s (total %s)\n" "$pkg" "$(_fmt_duration "$pkg_total")"
  elif [ "$overall_status" = "WARN" ]; then
    SUCCEEDED+=("$pkg")   # warns counted as succeeded but with warnings
    WARNED+=("$pkg")
    write_progress "$idx" "$pkg" "done" "WARN"
    printf "⚠ [\033[1;33mWARN\033[0m] %s (total %s) - check %s\n" "$pkg" "$(_fmt_duration "$pkg_total")" "${LOG_DIR}/${pkg}.log"
  else
    FAILED+=("$pkg")
    write_progress "$idx" "$pkg" "done" "FAILED"
    printf "❌ [\033[1;31mFAILED\033[0m] %s (total %s) - check %s\n" "$pkg" "$(_fmt_duration "$pkg_total")" "${LOG_DIR}/${pkg}.log"
  fi

  return 0
}

# ----------------------
# Main controller flow
# ----------------------
main_start=$(_now_ts)
log_info "Controller started at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
[ "${DRY_RUN}" = "yes" ] && log_info "Running in DRY-RUN mode"

# read queue
if ! read_queue; then
  log_error "Failed to read queue; aborting."
  exit 1
fi

total_pkgs="${#QUEUE[@]}"
if [ "$total_pkgs" -eq 0 ]; then
  log_info "Queue empty. Nothing to do."
  exit 0
fi

# If resume enabled and progress exists, find resume index
start_index=1
if [ "${RESUME}" = "yes" ] && [ -f "${PROGRESS_FILE}" ]; then
  # read index
  idx_val="$(awk -F= '/^INDEX=/{print $2; exit}' "${PROGRESS_FILE}" 2>/dev/null || echo "")"
  if [ -n "${idx_val}" ] && [[ "${idx_val}" =~ ^[0-9]+$ ]]; then
    start_index=$((idx_val + 1))
    log_info "Resuming from index $start_index (previous INDEX=${idx_val})"
  else
    log_info "No valid progress index found; starting from 1"
  fi
fi

# iterate queue
i=0
for pkg in "${QUEUE[@]}"; do
  i=$((i+1))
  if [ "$i" -lt "$start_index" ]; then
    continue
  fi
  # process package
  process_package "$pkg" "$i" "$total_pkgs"
  # optionally flush progress to disk (already done inside)
done

# final report
main_end=$(_now_ts)
main_elapsed=$((main_end - main_start))

# prepare lists
succeed_count=${#SUCCEEDED[@]}
fail_count=${#FAILED[@]}
warn_count=${#WARNED[@]}

# Build Report output
echo
echo -e "\033[1;34mBuild Report - $(date +%F)\033[0m"
echo "================================================================"
echo "Total time: $(_fmt_duration "$main_elapsed")"
echo "Packages built: $((succeed_count + fail_count))"
echo "Succeeded: ${succeed_count}"
if [ "${fail_count}" -gt 0 ]; then
  echo -n "Failed: ${fail_count} ("
  printf "%s" "${FAILED[0]}"
  for ((k=1;k<${#FAILED[@]};k++)); do printf ", %s" "${FAILED[$k]}"; done
  echo ")"
else
  echo "Failed: 0"
fi
if [ "${warn_count}" -gt 0 ]; then
  echo -n "Silent warnings: ${warn_count} ("
  printf "%s" "${WARNED[0]}"
  for ((k=1;k<${#WARNED[@]};k++)); do printf ", %s" "${WARNED[$k]}"; done
  echo ")"
else
  echo "Silent warnings: 0"
fi
echo "Logs saved: ${LOG_DIR}"
echo "================================================================"

# write final JSON status if configured
if [ "${GENERATE_JSON_REPORT}" = "yes" ]; then
  jq_available=no
  if command -v jq >/dev/null 2>&1; then jq_available=yes; fi
  status_json="${LOG_DIR}/status.json"
  if [ "${jq_available}" = "yes" ]; then
    # create arrays for json
    jq -n --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      --arg total_time "$(_fmt_duration "$main_elapsed")" \
      --argjson built $((succeed_count + fail_count)) \
      --argjson success "${succeed_count}" \
      --argjson failed "${fail_count}" \
      --argjson warnings "${warn_count}" \
      --arg logs "${LOG_DIR}" \
      --argjson fail_list "$(printf '%s\n' "${FAILED[@]}" | jq -R . | jq -s .)" \
      --argjson warn_list "$(printf '%s\n' "${WARNED[@]}" | jq -R . | jq -s .)" \
      '{
        timestamp: $ts,
        total_time: $total_time,
        packages_built: ($built),
        succeeded: ($success),
        failed: ($failed),
        warnings: ($warnings),
        failed_list: $ARGS.positional[0],
        warning_list: $ARGS.positional[1],
        logs_dir: $logs
      }' "${FAILED[@]}" "${WARNED[@]}" > "${status_json}.tmp" && mv -f "${status_json}.tmp" "${status_json}"
  else
    # fallback to simple JSON via heredoc
    cat > "${status_json}.tmp" <<EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "total_time": "$(_fmt_duration "$main_elapsed")",
  "packages_built": $((succeed_count + fail_count)),
  "succeeded": ${succeed_count},
  "failed": ${fail_count},
  "warnings": ${warn_count},
  "failed_list": ["$(printf "%s\",\"" "${FAILED[@]}" | sed 's/","$//')"],
  "warning_list": ["$(printf "%s\",\"" "${WARNED[@]}" | sed 's/","$//')"],
  "logs_dir": "${LOG_DIR}"
}
EOF
    mv -f "${status_json}.tmp" "${status_json}"
  fi
  log_info "JSON status written to ${status_json}"
fi

# cleanup lock (trap will release fd)
log_info "Controller finished"
exit 0
