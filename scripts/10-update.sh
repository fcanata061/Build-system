#!/usr/bin/env bash
#
# scripts/10-update.sh
# Update orchestrator — updates dependencies first (reads depsolve.map), then package.
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then set -o pipefail; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load logger if available
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/logger.sh"
else
  # minimal logger
  RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"; BLUE="\033[0;34m"; NC="\033[0m"
  log_info(){ printf "%b[INFO] %s%b\n" "$BLUE" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
  log_warn(){ printf "%b[WARN] %s%b\n" "$YELLOW" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
  log_error(){ printf "%b[ERROR] %s%b\n" "$RED" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
  log_debug(){ printf "%b[DEBUG] %s%b\n" "$BLUE" "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - $*" "$NC"; }
  log_start(){ :; }
  log_end(){ :; }
fi

# Config (override with env if needed)
: "${ROOT:=/usr/src/repo}"
: "${DESC_ROOT:=${ROOT}/package}"
: "${PKGDB_DIR:=/var/lib/pkgdb}"
: "${LOG_DIR:=/var/log/pkg/update}"
: "${LOCK_FILE:=/var/run/pkgupdate.lock}"
: "${DOWNLOAD_TMP:=/tmp/pkg_update.$$}"
: "${DEPSOLVE_SCRIPT:=${SCRIPT_DIR}/03-depsolve.sh}"
: "${FETCH_SCRIPT:=${SCRIPT_DIR}/01-fetch.sh}"
: "${EXTRACT_SCRIPT:=${SCRIPT_DIR}/02-extract.sh}"
: "${BUILD_SCRIPT:=${SCRIPT_DIR}/04-build.sh}"
: "${INSTALL_SCRIPT:=${SCRIPT_DIR}/05-install.sh}"
: "${PACKAGE_SCRIPT:=${SCRIPT_DIR}/06-package.sh}"
: "${UNINSTALL_SCRIPT:=${SCRIPT_DIR}/09-uninstall.sh}"
: "${REMOTE_MODE:=rsync}"    # rsync|git
: "${REMOTE_TARGET:=}"
: "${REMOTE_RETRY:=3}"
: "${SILENT_PATTERNS:=permission denied|segmentation fault|undefined reference|core dumped|internal compiler error|I/O error|read-only file system}"
: "${MAX_DEP_UPDATE_DEPTH:=12}"
: "${DRY_RUN:=no}"
: "${AUTO_CONFIRM:=no}"

mkdir -p "${LOG_DIR}" "${DOWNLOAD_TMP}" "${PKGDB_DIR}"

# Usage
usage(){ cat <<EOF
Usage: $0 [options] <pkg>
Options:
  --check              Only check for newer stable version (no changes)
  --rebuild-only       Rebuild (build/install/package) using current .desc
  --no-publish         Do not publish remote
  --remote-mode MODE   rsync|git
  --remote-target TGT  set remote target
  --dry-run            Simulate actions
  --yes                Auto-confirm prompts
  --help
EOF
exit 1; }

# parse args
CHECK_ONLY="no"; REBUILD_ONLY="no"; NO_PUBLISH="no"
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK_ONLY=yes; shift;;
    --rebuild-only) REBUILD_ONLY=yes; shift;;
    --no-publish) NO_PUBLISH=yes; shift;;
    --remote-mode) shift; REMOTE_MODE="$1"; shift;;
    --remote-target) shift; REMOTE_TARGET="$1"; shift;;
    --dry-run) DRY_RUN=yes; shift;;
    --yes) AUTO_CONFIRM=yes; shift;;
    --help) usage;;
    --*) echo "Unknown opt $1"; usage;;
    *) break;;
  esac
done
if [ $# -lt 1 ]; then usage; fi
PKG_ARG="$1"

# Helpers
_find_desc_for_pkg() {
  local pkg="$1"
  local path
  path="$(find "${DESC_ROOT}" -maxdepth 4 -type f -name "${pkg}.desc" 2>/dev/null | head -n1 || true)"
  if [ -z "$path" ] && [ -f "${DESC_ROOT}/${pkg}.desc" ]; then path="${DESC_ROOT}/${pkg}.desc"; fi
  echo "$path"
}

DESC_FILE="$(_find_desc_for_pkg "$PKG_ARG")"
if [ -z "$DESC_FILE" ]; then log_error "Cannot find .desc for ${PKG_ARG} under ${DESC_ROOT}"; exit 1; fi
PKG="$(basename "${DESC_FILE}" .desc)"
LOG_FILE="${LOG_DIR}/${PKG}.log"
: > "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

log_start "update" "$PKG"
log_info "Starting update for ${PKG} (desc=${DESC_FILE})"
[ "${DRY_RUN}" = "yes" ] && log_info "DRY-RUN enabled"

# lock (fd9)
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then log_error "Another update running (lock ${LOCK_FILE})."; exit 1; fi

# desc parsing helper
desc_get(){ awk -F= -v k="$1" '$1==k{ sub(/^[^=]+=/,""); print; exit }' "${DESC_FILE}" 2>/dev/null || true; }

NAME="$(desc_get NAME)"; VERSION="$(desc_get VERSION)"; URL="$(desc_get URL)"; SHA256="$(desc_get SHA256)"
BUILD_DEPS_RAW="$(desc_get BUILD_DEPS)"; RUN_DEPS_RAW="$(desc_get RUN_DEPS)"
log_info "Parsed: NAME=${NAME:-$PKG} VERSION=${VERSION:-unknown} URL=${URL:-none}"

# helper: write status JSON
write_status_json(){
  local status="$1" note="$2"; local jf="${LOG_DIR}/${PKG}.status.json"
  cat > "${jf}.tmp" <<EOF
{
  "package":"${PKG}",
  "old_version":"${VERSION}",
  "status":"${status}",
  "note":"${note:-}",
  "ts":"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
  mv -f "${jf}.tmp" "${jf}"
}

# find_latest_version - simple directory scrape of base URL; ignore beta/rc/nightly
find_latest_version(){
  local base="$1" pattern="$2"
  local html
  if ! html="$(curl -fsSL --retry 3 "$base")"; then
    log_warn "Could not fetch $base"
    return 2
  fi
  local vers=()
  local regex="$(echo "$pattern" | sed 's/<VER>/([0-9]\+\(\.[0-9]\+\)*)/g; s/\./\\./g')"
  while IFS= read -r line; do
    if [[ "$line" =~ $regex ]]; then
      local v="${BASH_REMATCH[1]}"
      # filter unstable tokens in same line
      if echo "$line" | grep -Ei "beta|alpha|rc|pre|nightly|b[0-9]+" >/dev/null 2>&1; then
        continue
      fi
      vers+=("$v")
    fi
  done < <(echo "$html")
  if [ "${#vers[@]}" -eq 0 ]; then
    mapfile -t vers < <(echo "$html" | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -V | uniq)
  fi
  if [ "${#vers[@]}" -eq 0 ]; then log_warn "No versions found at ${base}"; return 3; fi
  printf "%s\n" "${vers[@]}" | sort -V | tail -n1
}

# compare major
is_major_update(){
  local old="$1" new="$2"
  local om="${old%%.*}"; local nm="${new%%.*}"
  if ! [[ "$om" =~ ^[0-9]+$ ]] || ! [[ "$nm" =~ ^[0-9]+$ ]]; then
    # fallback to semantic compare: require new > old and major component different
    if [ "$(printf "%s\n%s\n" "$old" "$new" | sort -V | tail -n1)" = "$new" ] && [ "$old" != "$new" ]; then
      return 0
    else
      return 1
    fi
  fi
  (( nm > om )) && return 0 || return 1
}

# download and sha verify
download_and_verify(){
  local url="$1" expect="$2"
  local dest="${DOWNLOAD_TMP}/$(basename "$url")"
  if [ "${DRY_RUN}" = "yes" ]; then
    log_info "[DRY-RUN] would download ${url}"
    echo "${dest}"; return 0
  fi
  if ! curl -fSL --retry 3 -o "${dest}.partial" "${url}"; then
    log_error "Download failed: ${url}"; return 1
  fi
  mv -f "${dest}.partial" "${dest}"
  if [ -n "${expect}" ]; then
    if ! sha256sum -c <(printf "%s  %s\n" "${expect}" "${dest}") >/dev/null 2>&1; then
      log_error "SHA256 mismatch for ${dest}"; return 2
    fi
  fi
  echo "${dest}"
}

# backup desc and pkgdb
backup_desc_and_pkgdb(){
  local desc="$1" pkg="$2"
  local bak="${desc}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a -- "$desc" "$bak"
  log_info "Backed up desc -> $bak"
  if [ -d "${PKGDB_DIR}/${pkg}" ]; then
    mkdir -p "${PKGDB_DIR}/.backups"
    local pkgbak="${PKGDB_DIR}/.backups/${pkg}_$(date -u +%Y%m%dT%H%M%SZ).tar.xz"
    if tar -cJf "${pkgbak}" -C "${PKGDB_DIR}" "${pkg}" >>"$LOG_FILE" 2>&1; then
      log_info "Pkgdb backed up -> ${pkgbak}"
    else
      log_warn "pkgdb backup failed (non-fatal)"
    fi
  fi
  echo "$bak"
}

restore_desc(){
  local bak="$1" desc="$2"
  if [ -f "$bak" ]; then cp -a -- "$bak" "$desc"; log_info "Restored desc from $bak"; return 0; fi
  log_warn "Desc backup $bak not found"; return 1
}

detect_silent_errors_in_log(){
  local f="$1"
  if [ -f "$f" ] && grep -Ei "${SILENT_PATTERNS}" "$f" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

run_hook(){
  local typ="$1" pkg="$2"
  local hook="${SCRIPT_DIR}/hooks/${typ}/${pkg}"
  [ -x "$hook" ] || { log_debug "No hook $typ for $pkg"; return 0; }
  log_info "Running hook $hook"
  if [ "${DRY_RUN}" = "yes" ]; then log_info "[DRY-RUN] $hook"; return 0; fi
  if ! bash "$hook" >>"$LOG_FILE" 2>&1; then log_warn "Hook $hook returned non-zero"; fi
}
# ---------- Part 2 ----------
DEPSOLVE_MAP="${PKGDB_DIR}/depsolve.map"
DEPSOLVE_BLOCKED="${PKGDB_DIR}/depsolve.blocked"

# call depsolve to compute order; depsolve writes DEPSOLVE_MAP and DEPSOLVE_BLOCKED
run_depsolve_for_pkg(){
  local pkg="$1"
  log_info "Running depsolve for ${pkg} (this will write ${DEPSOLVE_MAP})"
  if [ ! -x "${DEPSOLVE_SCRIPT}" ]; then
    log_warn "Depsolve script missing: ${DEPSOLVE_SCRIPT}"
    return 2
  fi
  if [ "${DRY_RUN}" = "yes" ]; then
    log_info "[DRY-RUN] ${DEPSOLVE_SCRIPT} ${pkg}"
    return 0
  fi
  # call depsolve with package as target (depsolve_main in your script expects targets)
  if ! bash "${DEPSOLVE_SCRIPT}" "${pkg}" >>"$LOG_FILE" 2>&1; then
    log_warn "Depsolve returned non-zero (check logs)"
    # still proceed to see if map was written
  fi
  if [ ! -f "${DEPSOLVE_MAP}" ]; then
    log_warn "Depsolve did not create ${DEPSOLVE_MAP}"
    return 3
  fi
  return 0
}

# Read update queue from depsolve.map
read_update_queue(){
  if [ ! -f "${DEPSOLVE_MAP}" ]; then
    log_error "Depsolve map not found: ${DEPSOLVE_MAP}"
    return 1
  fi
  mapfile -t UPDATE_QUEUE < "${DEPSOLVE_MAP}"
  # remove any empty lines
  UPDATE_QUEUE=("${UPDATE_QUEUE[@]// /}")
  return 0
}

# avoid infinite recursion
declare -A VISITED
update_recursive(){
  local pkg="$1" depth="${2:-0}"
  if [ "${depth}" -gt "${MAX_DEP_UPDATE_DEPTH}" ]; then
    log_error "Max update recursion reached for ${pkg}"
    return 1
  fi
  if [ "${VISITED[$pkg]+_}" ]; then
    log_debug "Already updated ${pkg} in this run"
    return 0
  fi
  VISITED[$pkg]=1

  # find desc for pkg
  local desc="$(_find_desc_for_pkg "$pkg")"
  if [ -z "$desc" ]; then
    log_warn "No desc for dependency ${pkg}; skipping"
    return 0
  fi

  # run update for dependency (call this script)
  if [ "${DRY_RUN}" = "yes" ]; then
    log_info "[DRY-RUN] would update dependency ${pkg}"
    return 0
  fi

  log_info "Invoking update for dependency ${pkg}"
  # call same script non-interactively, auto-confirm
  if ! "${SCRIPT_DIR}/10-update.sh" --yes --remote-mode "${REMOTE_MODE}" --remote-target "${REMOTE_TARGET}" "${pkg}"; then
    log_error "Update call failed for dependency ${pkg}"
    return 1
  fi
  return 0
}

# perform update for main package after deps processed
perform_update(){
  local newver="$1" newurl="$2" newsha="$3"
  log_info "Starting perform_update for ${PKG} -> ${newver}"
  local bak_desc
  bak_desc="$(backup_desc_and_pkgdb "${DESC_FILE}" "${PKG}")" || bak_desc=""

  # update desc
  update_desc_inplace(){
    local desc="$1" ver="$2" url="$3" sha="$4"
    local tmp="${desc}.tmp.$$"
    awk -v ver="$ver" -v url="$url" -v sha="$sha" '
      BEGIN{v=0;u=0;s=0}
      /^VERSION=/ && v==0 { print "VERSION="ver; v=1; next }
      /^URL=/ && u==0 { print "URL="url; u=1; next }
      /^SHA256=/ && s==0 { print "SHA256="sha; s=1; next }
      { print $0 }
      END{
        if(v==0) print "VERSION="ver
        if(u==0) print "URL="url
        if(s==0) print "SHA256="sha
      }' "$desc" > "$tmp" && mv -f "$tmp" "$desc"
  }

  update_desc_inplace "${DESC_FILE}" "${newver}" "${newurl}" "${newsha}"
  log_info ".desc updated (in-place)"

  # run pre-update hook
  run_hook "pre-update" "${PKG}"

  # Uninstall old
  if [ -x "${UNINSTALL_SCRIPT}" ]; then
    log_info "Uninstalling old version of ${PKG}"
    if ! safe_run "bash \"${UNINSTALL_SCRIPT}\" \"${PKG}\""; then
      log_error "Uninstall failed; restoring .desc"
      restore_desc "${bak_desc}" "${DESC_FILE}"; return 1
    fi
  else
    log_warn "Uninstall script not found: ${UNINSTALL_SCRIPT}"
  fi

  # Fetch -> Extract -> Build -> Install -> Package
  if [ -x "${FETCH_SCRIPT}" ]; then
    log_info "Fetching via ${FETCH_SCRIPT}"
    if ! safe_run "bash \"${FETCH_SCRIPT}\" \"${PKG}\""; then restore_desc "${bak_desc}" "${DESC_FILE}"; return 1; fi
  fi
  if [ -x "${EXTRACT_SCRIPT}" ]; then
    log_info "Extracting via ${EXTRACT_SCRIPT}"
    if ! safe_run "bash \"${EXTRACT_SCRIPT}\" \"${PKG}\""; then restore_desc "${bak_desc}" "${DESC_FILE}"; return 1; fi
  fi
  if [ -x "${BUILD_SCRIPT}" ]; then
    log_info "Building via ${BUILD_SCRIPT}"
    if ! safe_run "bash \"${BUILD_SCRIPT}\" \"${PKG}\""; then restore_desc "${bak_desc}" "${DESC_FILE}"; return 1; fi
  fi
  if [ -x "${INSTALL_SCRIPT}" ]; then
    log_info "Installing via ${INSTALL_SCRIPT}"
    if ! safe_run "bash \"${INSTALL_SCRIPT}\" \"${PKG}\""; then restore_desc "${bak_desc}" "${DESC_FILE}"; return 1; fi
  fi
  if [ -x "${PACKAGE_SCRIPT}" ]; then
    log_info "Packaging via ${PACKAGE_SCRIPT}"
    safe_run "bash \"${PACKAGE_SCRIPT}\" \"${PKG}\"" || log_warn "Package step failed (non-fatal)"
  fi

  # run post-update hook
  run_hook "post-update" "${PKG}"

  # update pkgdb metadata
  mkdir -p "${PKGDB_DIR}/${PKG}"
  echo "NAME=${PKG}" > "${PKGDB_DIR}/${PKG}/metadata"
  echo "VERSION=${newver}" >> "${PKGDB_DIR}/${PKG}/metadata"
  echo "UPDATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "${PKGDB_DIR}/${PKG}/metadata"
  pkgdb_status_write "VERSION" "${newver}"
  pkgdb_status_write "STATUS" "INSTALLED_OK"

  log_info "Perform_update completed for ${PKG}"
  return 0
}

# publish helpers (rsync/git)
publish_rs(){
  local file="$1"
  local remote_dir="${REMOTE_TARGET%/}/${PKG}/"
  local tries=0
  if [ -z "${REMOTE_TARGET}" ]; then log_warn "REMOTE_TARGET empty; skipping publish"; return 0; fi
  while [ $tries -lt ${REMOTE_RETRY} ]; do
    if [ "${DRY_RUN}" = "yes" ]; then log_info "[DRY-RUN] rsync ${file} ${remote_dir}"; return 0; fi
    if rsync -av --partial --progress "${file}" "${remote_dir}" >>"$LOG_FILE" 2>&1; then log_info "rsync ok"; return 0; fi
    tries=$((tries+1)); sleep $((2**tries))
  done
  log_error "rsync publish failed"
  return 1
}

publish_git(){
  local file="$1"
  if [ -z "${REMOTE_TARGET}" ]; then log_warn "REMOTE_TARGET empty; skipping git publish"; return 0; fi
  if [ "${DRY_RUN}" = "yes" ]; then log_info "[DRY-RUN] git publish ${file}"; return 0; fi
  if ! command -v git >/dev/null 2>&1; then log_error "git not available"; return 1; fi
  local tmp="$(mktemp -d "${DOWNLOAD_TMP}/git.XXXX")"
  if ! git clone --depth 1 "${REMOTE_TARGET}" "${tmp}" >>"$LOG_FILE" 2>&1; then rm -rf "${tmp}"; log_error "git clone failed"; return 1; fi
  mkdir -p "${tmp}/${PKG}"
  cp -a "${file}" "${tmp}/${PKG}/" || log_warn "copy to git repo failed"
  cp -a "${DESC_FILE}" "${tmp}/${PKG}/" || true
  (cd "${tmp}" && git add -A && git commit -m "update ${PKG} $(date -u +"%Y-%m-%dT%H:%M:%SZ")") >>"$LOG_FILE" 2>&1 || true
  (cd "${tmp}" && git push origin HEAD:master --tags) >>"$LOG_FILE" 2>&1 || { rm -rf "${tmp}"; log_error "git push failed"; return 1; }
  rm -rf "${tmp}"; log_info "git publish succeeded"; return 0
}

publish_file(){
  local f="$1"
  case "${REMOTE_MODE}" in
    rsync) publish_rs "$f" ;;
    git) publish_git "$f" ;;
    *) log_warn "Unknown remote mode ${REMOTE_MODE}" ;;
  esac
}

# perform the full update flow
main(){
  write_status_json "START" "Beginning update flow"

  if [ "${REBUILD_ONLY}" = "yes" ]; then
    log_info "--rebuild-only: running build/install/package"
    [ -x "${BUILD_SCRIPT}" ] && safe_run "bash \"${BUILD_SCRIPT}\" \"${PKG}\""
    [ -x "${INSTALL_SCRIPT}" ] && safe_run "bash \"${INSTALL_SCRIPT}\" \"${PKG}\""
    [ -x "${PACKAGE_SCRIPT}" ] && safe_run "bash \"${PACKAGE_SCRIPT}\" \"${PKG}\""
    write_status_json "OK" "Rebuild-only done"; return 0
  fi

  # require URL in desc to auto-discover
  if [ -z "${URL}" ]; then log_error "No URL in desc; cannot auto-discover"; write_status_json "FAIL" "No URL"; return 1; fi
  base_dir="$(dirname "${URL}")/"
  fname_template="$(basename "${URL}")"

  # find latest stable
  latest="$(find_latest_version "${base_dir}" "${fname_template}" 2>>"$LOG_FILE" || true)" || true
  if [ -z "${latest}" ]; then log_warn "No candidate found"; write_status_json "NO_CANDIDATE" ""; return 2; fi
  log_info "Candidate latest: ${latest}"

  if ! is_major_update "${VERSION}" "${latest}"; then
    log_info "Not a major update (current ${VERSION}, candidate ${latest}); exiting."
    write_status_json "NO_UPDATE" "Candidate not major"
    return 0
  fi

  # assemble new url by naive substitution
  new_url="${URL//$VERSION/$latest}"
  log_info "Assumed new URL: ${new_url}"

  # download to compute sha
  dlpath=""
  if [ "${DRY_RUN}" = "yes" ]; then dlpath="${DOWNLOAD_TMP}/$(basename "${new_url}")"; newsha="DRY-RUN"; else
    dlpath="$(download_and_verify "${new_url}" "" )" || { log_error "Download/verify failed"; write_status_json "FAIL" "Download failed"; return 3; }
    newsha="$(sha256sum "${dlpath}" | awk '{print $1}')"
  fi
  log_info "New SHA256: ${newsha}"

  [ "${CHECK_ONLY}" = "yes" ] && { write_status_json "CANDIDATE" "Found ${latest}"; return 0; }

  # confirm
  if [ "${AUTO_CONFIRM}" != "yes" ] && [ "${DRY_RUN}" != "yes" ]; then
    printf "Update %s %s -> %s. Proceed? [y/N]: " "${PKG}" "${VERSION}" "${latest}"; read -r ans || true
    if [[ ! "$ans" =~ ^[Yy] ]]; then log_info "User declined"; write_status_json "ABORT"; return 0; fi
  fi

  # run depsolve to generate map
  if ! run_depsolve_for_pkg "${PKG}"; then log_error "Depsolve failed or map missing"; write_status_json "FAIL" "Depsolve"; return 4; fi

  # read update queue
  if ! read_update_queue; then log_error "Cannot read update queue"; write_status_json "FAIL" "No queue"; return 5; fi

  # ensure main pkg is present; remove it from queue to avoid updating twice
  # process each package in queue until reaching PKG, updating dependencies first
  for dep in "${UPDATE_QUEUE[@]}"; do
    [ -z "$dep" ] && continue
    if [ "$dep" = "$PKG" ]; then
      log_debug "Reached main package in queue: ${PKG}; dependencies processed"
      break
    fi
    log_info "Queue dependency: ${dep} (will update before ${PKG})"
    # call update recursively for dependency
    if ! update_recursive "${dep}" 0; then log_error "Dependency update failed: ${dep}"; do_rollback_and_exit; return 6; fi
  done

  # perform update now for PKG
  if ! perform_update "${latest}" "${new_url}" "${newsha}"; then
    log_error "Main package update failed; starting rollback"
    # restore desc and pkgdb
    latestbak="$(ls -1t "${DESC_FILE}.bak."* 2>/dev/null | head -n1 || true)"
    do_rollback_full "${latestbak}" "${PKG}"
    write_status_json "ROLLBACK" "Update failed and rollback attempted"
    return 7
  fi

  # publish if requested
  if [ "${NO_PUBLISH}" != "yes" ] && [ -n "${REMOTE_TARGET}" ]; then
    # try find package archive in default location
    PKG_CACHE_DIR="${ROOT}/packages"
    archive="$(ls -1t "${PKG_CACHE_DIR}/${PKG}-"* 2>/dev/null | head -n1 || true)"
    if [ -n "${archive}" ]; then
      publish_file "${archive}" || log_warn "Publish failed (continuing)"
    else
      # publish desc as fallback
      publish_file "${DESC_FILE}" || log_warn "Publish metadata failed"
    fi
  fi

  # detect silent errors
  if detect_silent_errors_in_log "${LOG_FILE}"; then
    log_warn "Silent errors found in logs; check ${LOG_FILE}"
    pkgdb_status_write "WARNINGS" "silent-errors-detected"
  fi

  # cleanup
  rm -rf "${DOWNLOAD_TMP}" || true
  write_status_json "SUCCESS" "Updated to ${latest}"
  log_info "Update completed for ${PKG}"
  return 0
}

# rollback helper called in some failure paths
do_rollback_full(){
  local descbak="$1" pkg="$2"
  log_warn "Rollback: restoring desc and pkgdb for ${pkg}"
  [ -n "$descbak" ] && restore_desc "$descbak" "${DESC_FILE}"
  # restore pkgdb backup if available
  latestpkgbak="$(ls -1t "${PKGDB_DIR}/.backups/${pkg}_*.tar.xz" 2>/dev/null | head -n1 || true)"
  if [ -n "$latestpkgbak" ]; then
    tar -xJf "${latestpkgbak}" -C "${PKGDB_DIR}" || log_warn "pkgdb restore failed"
  fi
  # try uninstall partial new package (best-effort)
  if [ -x "${UNINSTALL_SCRIPT}" ]; then safe_run "bash \"${UNINSTALL_SCRIPT}\" \"${pkg}\"" || true; fi
  log_warn "Rollback attempted for ${pkg}"
}

# wrapper to call rollback & exit (used in loops)
do_rollback_and_exit(){
  local descbak="$(ls -1t "${DESC_FILE}.bak."* 2>/dev/null | head -n1 || true)"
  do_rollback_full "$descbak" "${PKG}"
  write_status_json "ROLLBACK" "Dependency update aborted"
  exit 1
}

# Run main
if ! main; then
  log_error "Update flow failed for ${PKG}; check ${LOG_FILE}"
  log_end 1
  exit 1
fi

log_info "Exiting successfully for ${PKG}"
log_end 0
exit 0
