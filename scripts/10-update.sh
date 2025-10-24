#!/usr/bin/env bash
#
# scripts/10-update.sh
# Atualizador de pacotes (estável/major-only). Integra depsolve, build, uninstall, package e publish.
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then set -o pipefail; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# load logger (must exist as you confirmed); fallback minimal if missing
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/logger.sh"
else
  log_info()  { echo "[INFO] $*"; }
  log_warn()  { echo "[WARN] $*"; }
  log_error() { echo "[ERROR] $*" >&2; }
  log_start(){ :; }
  log_end(){ :; }
fi

# Defaults / config
: "${ROOT:=/usr/src/repo}"
: "${DESC_ROOT:=${ROOT}/package}"           # where package/<category>/<pkg>/<pkg>.desc live (we will accept path)
: "${PKGDB_DIR:=/var/lib/pkgdb}"
: "${LOG_DIR:=/var/log/pkg/update}"
: "${LOCK_FILE:=/var/run/pkgupdate.lock}"
: "${DOWNLOAD_TMP:=/tmp/pkg_update.$$}"
: "${REMOTE_MODE:=rsync}"                   # rsync or git
: "${REMOTE_TARGET:=}"                      # set by CLI or env (user@host:/path or git URL)
: "${REMOTE_RETRY:=3}"
: "${SILENT_PATTERNS:=permission denied|segmentation fault|undefined reference|core dumped|internal compiler error|I/O error|read-only file system}"
: "${SCRIPTS_DIR:=${SCRIPT_DIR}}"
: "${DEPSOLVE_SCRIPT:=${SCRIPTS_DIR}/03-depsolve.sh}"
: "${FETCH_SCRIPT:=${SCRIPTS_DIR}/01-fetch.sh}"
: "${EXTRACT_SCRIPT:=${SCRIPTS_DIR}/02-extract.sh}"
: "${BUILD_SCRIPT:=${SCRIPTS_DIR}/04-build.sh}"
: "${INSTALL_SCRIPT:=${SCRIPTS_DIR}/05-install.sh}"
: "${PACKAGE_SCRIPT:=${SCRIPTS_DIR}/06-package.sh}"
: "${UNINSTALL_SCRIPT:=${SCRIPTS_DIR}/09-uninstall.sh}"
: "${KEEP_DESC_BACKUPS:=yes}"
: "${DRY_RUN:=no}"
: "${AUTO_CONFIRM:=no}"  # --yes to auto confirm destructive ops
: "${MAX_DEP_UPDATE_DEPTH:=10}" # guard against recursion explosion

mkdir -p "${LOG_DIR}"
mkdir -p "${DOWNLOAD_TMP}"

# Usage
usage() {
  cat <<EOF
Usage: $0 [options] <pkg>
Options:
  --check              Only check for newer stable version (no changes)
  --rebuild-only       Rebuild (run build/install/package) using current .desc
  --no-publish         Do not publish remote even if configured
  --remote-mode MODE   rsync|git (overrides env REMOTE_MODE)
  --remote-target TGT  remote target (rsync path or git URL)
  --dry-run            Do not perform destructive actions, only simulate
  --yes                Auto-confirm prompts
  --help
EOF
  exit 1
}

# parse args
CHECK_ONLY="no"
REBUILD_ONLY="no"
NO_PUBLISH="no"
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK_ONLY="yes"; shift ;;
    --rebuild-only) REBUILD_ONLY="yes"; shift ;;
    --no-publish) NO_PUBLISH="yes"; shift ;;
    --remote-mode) shift; REMOTE_MODE="$1"; shift ;;
    --remote-target) shift; REMOTE_TARGET="$1"; shift ;;
    --dry-run) DRY_RUN="yes"; shift ;;
    --yes) AUTO_CONFIRM="yes"; shift ;;
    --help) usage ;;
    --*) echo "Unknown option $1"; usage ;;
    *) break ;;
  esac
done

if [ $# -lt 1 ]; then usage; fi
PKG_ARG="$1"

# compute desc path: try to find in package tree matching pkg
find_desc_for_pkg() {
  local pkg="$1"
  # search pattern: package/*/<pkg>/<pkg>.desc
  local path
  path="$(find "${DESC_ROOT}" -maxdepth 3 -type f -name "${pkg}.desc" 2>/dev/null | head -n1 || true)"
  if [ -z "$path" ]; then
    # accept package/<pkg>.desc fallback
    if [ -f "${DESC_ROOT}/${pkg}.desc" ]; then
      path="${DESC_ROOT}/${pkg}.desc"
    fi
  fi
  echo "$path"
}

DESC_FILE="$(find_desc_for_pkg "$PKG_ARG")"
if [ -z "${DESC_FILE}" ]; then
  log_error "Could not locate .desc for package '$PKG_ARG' under ${DESC_ROOT}"
  exit 1
fi
PKG_BASENAME="$(basename "$PKG_ARG")"
PKG="$(basename "$DESC_FILE" .desc)"  # package name from file

LOG_FILE="${LOG_DIR}/${PKG}.log"
: > "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

log_start "update" "$PKG"
log_info "Starting update for package: $PKG"
log_info "DESC_FILE=${DESC_FILE}"
if [ "$DRY_RUN" = "yes" ]; then log_info "DRY-RUN mode enabled"; fi

# lock to prevent concurrent updates
_acquire_lock() {
  exec 9>"${LOCK_FILE}"
  if ! flock -n 9; then
    log_error "Another update is running (lock ${LOCK_FILE}). Aborting."
    exit 1
  fi
  # keep fd 9 open to hold lock
}
_acquire_lock

# helper: safe run with logging and optional dry-run
safe_run() {
  local cmd="$*"
  if [ "$DRY_RUN" = "yes" ]; then
    log_info "[DRY-RUN] $cmd"
    return 0
  fi
  log_info "RUN: $cmd"
  eval "$cmd"
}

# helper: retry wrapper
retry_cmd() {
  local tries=${1:-3}; shift
  local cmd="$*"
  local i=0
  local wait=2
  until eval "$cmd"; do
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

# parse .desc small helper: gets key=value (first occurrence)
desc_get() {
  local key="$1"
  # supports KEY=VALUE lines
  awk -F= -v k="$key" '$1==k{ $1=""; sub(/^=/,""); sub(/^ */,""); print substr($0,2); exit }' "${DESC_FILE}" 2>/dev/null || true
}

# write status in pkgdb status file
pkgdb_status_write() {
  local key="$1"; local val="$2"
  local statusfile="${PKGDB_DIR}/${PKG}/status"
  mkdir -p "$(dirname "$statusfile")"
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") $key=$val" >> "$statusfile"
}

# find latest stable version by scraping base URL listing (accepts index listing)
# params: base_url (must end with /), tarball_name_template (e.g. firefox-<VER>.tar.xz)
find_latest_version() {
  local base_url="$1"
  local pattern="$2"   # must contain <VER> token
  # fetch directory listing (try index.html)
  local html
  if ! html="$(curl -fsSL --retry 3 "${base_url}")"; then
    log_warn "Could not fetch base URL ${base_url} to discover versions"
    return 2
  fi
  # find version-like tokens using regex: sequences of digits and dots, avoid beta/rc/nightly
  # We'll search for occurrences of pattern with a version in place of <VER>
  local vers=()
  # build regex from pattern by replacing <VER> with ([0-9]+(\.[0-9]+)+)
  local regex
  regex="$(echo "$pattern" | sed 's/\./\\./g; s/<VER>/([0-9]+\(\.[0-9]+\)*)/g')"
  # grep all matches
  while IFS= read -r line; do
    # extract version group
    if [[ "$line" =~ $regex ]]; then
      ver="${BASH_REMATCH[1]}"
      # ignore alpha/beta/rc/nightly if appear in same href (skip lines with 'beta' etc)
      if echo "$line" | grep -Ei "beta|alpha|rc|pre|nightly|b[0-9]+" >/dev/null 2>&1; then
        continue
      fi
      vers+=("$ver")
    fi
  done < <(echo "$html")
  if [ "${#vers[@]}" -eq 0 ]; then
    # fallback: try to extract versions by common patterns
    mapfile -t vers < <(echo "$html" | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -V | uniq)
  fi
  if [ "${#vers[@]}" -eq 0 ]; then
    log_warn "No version candidates found at ${base_url}"
    return 3
  fi
  # pick highest version by sort -V
  local latest
  latest="$(printf "%s\n" "${vers[@]}" | sort -V | tail -n1)"
  echo "$latest"
  return 0
}

# compare major versions: return 0 if new_major > old_major
is_major_update() {
  local old="$1" new="$2"
  # extract major (part before first dot)
  local o_major="${old%%.*}"; local n_major="${new%%.*}"
  # default numeric compare
  if ! [[ "$o_major" =~ ^[0-9]+$ ]] || ! [[ "$n_major" =~ ^[0-9]+$ ]]; then
    # fallback: if versions not numeric, require inequality via sort -V
    if [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n1)" = "$new" ] && [ "$old" != "$new" ]; then
      # treat as larger but we still enforce only major-type updates: check first component differs
      [ "$old" != "$new" ] && return 0 || return 1
    else
      return 1
    fi
  fi
  if (( n_major > o_major )); then
    return 0
  fi
  return 1
}

# download tarball and compute sha256; expects full tarball URL and expected sha (optional)
download_and_verify() {
  local url="$1"
  local expect_sha="$2"
  local dest="${DOWNLOAD_TMP}/$(basename "$url")"
  log_info "Downloading ${url} -> ${dest}"
  if [ "$DRY_RUN" = "yes" ]; then
    echo "[DRY-RUN] curl -fSL -o ${dest} ${url}"
    return 0
  fi
  retry_cmd 3 curl -fSL -o "${dest}.partial" "$url" || return 1
  mv -f "${dest}.partial" "${dest}"
  if [ -n "$expect_sha" ]; then
    log_info "Verifying SHA256 for ${dest}"
    if ! sha256sum -c <(printf "%s  %s\n" "$expect_sha" "$dest") >/dev/null 2>&1; then
      log_error "SHA256 mismatch for ${dest}"
      return 2
    fi
    log_info "SHA256 OK"
  else
    log_info "No expected SHA provided; computing sha256 for record"
    local sha
    sha="$(sha256sum "${dest}" | awk '{print $1}')"
    echo "$sha"
  fi
  echo "$dest"
  return 0
}

# backup .desc and pkgdb
backup_desc_and_pkgdb() {
  local desc="$1"
  local pkg="$2"
  local bak_desc="${desc}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a -- "$desc" "$bak_desc"
  log_info "Backed up .desc -> $bak_desc"
  if [ -d "${PKGDB_DIR}/${pkg}" ]; then
    mkdir -p "${PKGDB_DIR}/.backups"
    local pkgbak="${PKGDB_DIR}/.backups/${pkg}_$(date -u +%Y%m%dT%H%M%SZ).tar.xz"
    tar -cJf "${pkgbak}" -C "${PKGDB_DIR}" "${pkg}" >>"$LOG_FILE" 2>&1 || {
      log_warn "Failed to backup pkgdb for ${pkg}"
    }
    log_info "Pkgdb backed up -> ${pkgbak}"
  fi
  echo "$bak_desc"
}

# restore desc from backup
restore_desc_from_backup() {
  local bak="$1"
  local desc="$2"
  if [ -f "$bak" ]; then
    cp -a -- "$bak" "$desc"
    log_info "Restored .desc from $bak"
    return 0
  fi
  log_warn "Backup desc not found: $bak"
  return 1
}

# update .desc: replace VERSION, URL, SHA256 lines while preserving file structure
update_desc_inplace() {
  local desc="$1" newver="$2" newurl="$3" newsha="$4"
  # create tmp
  local tmp="${desc}.tmp.$$"
  awk -v ver="$newver" -v url="$newurl" -v sha="$newsha" '
    BEGIN{ doneV=0; doneU=0; doneS=0 }
    /^VERSION=/ && !doneV { print "VERSION="ver; doneV=1; next }
    /^URL=/ && !doneU { print "URL="url; doneU=1; next }
    /^SHA256=/ && !doneS { print "SHA256="sha; doneS=1; next }
    { print $0 }
    END {
      if (!doneV) print "VERSION="ver
      if (!doneU) print "URL="url
      if (!doneS) print "SHA256="sha
    }' "$desc" > "$tmp"
  mv -f "$tmp" "$desc"
  log_info "Updated .desc with VERSION=${newver}, URL=..., SHA256=..."
}

# scan a log file for silent errors/patterns and return non-zero if any found
detect_silent_errors() {
  local logfile="$1"
  if [ -f "$logfile" ] && grep -Ei "${SILENT_PATTERNS}" "$logfile" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# helper: run hooks if exist; don't fail the update if hook returns non-zero (only warn)
run_hook() {
  local hooktype="$1" pkg="$2"
  local hook="${SCRIPT_DIR}/hooks/${hooktype}/${pkg}"
  if [ -x "$hook" ]; then
    log_info "Running hook ${hooktype} for ${pkg}: $hook"
    if [ "$DRY_RUN" = "yes" ]; then
      echo "[DRY-RUN] $hook"
      return 0
    fi
    if ! bash "$hook" >>"$LOG_FILE" 2>&1; then
      log_warn "Hook ${hook} returned non-zero for ${pkg}"
    fi
  else
    log_debug "No hook ${hooktype} for ${pkg}"
  fi
}

# helper to publish archive / metadata (implemented later)
publish_package_remote() {
  true
}
# main orchestration functions
# 1) read important desc fields
NAME="$(desc_get NAME || true)"
VERSION="$(desc_get VERSION || true)"
URL="$(desc_get URL || true)"
SHA256="$(desc_get SHA256 || true)"
BUILD_DEPS="$(desc_get BUILD_DEPS || true)"
RUN_DEPS="$(desc_get RUN_DEPS || true)"

log_info "Parsed .desc: NAME=${NAME} VERSION=${VERSION} URL=${URL}"

# helper: create status JSON
write_status_json() {
  local status="$1" note="$2"
  local jfile="${LOG_DIR}/${PKG}.status.json"
  cat > "${jfile}.tmp" <<EOF
{
  "package": "${PKG}",
  "old_version": "${VERSION}",
  "status": "${status}",
  "note": "${note:-}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
  mv -f "${jfile}.tmp" "${jfile}"
}

# call depsolve to get dependency update queue for a new .desc (expect depsolve to accept a temp .desc or flags)
# We'll generate a temporary .desc with new version/url/sha and ask depsolve to compute build order.
get_update_queue_via_depsolve() {
  local tmpdesc="${DOWNLOAD_TMP}/${PKG}.desc.tmp"
  # clone current desc and patch fields
  cp -a -- "${DESC_FILE}" "${tmpdesc}"
  update_desc_inplace "${tmpdesc}" "$1" "$2" "$3"
  if [ ! -x "${DEPSOLVE_SCRIPT}" ]; then
    log_warn "depsolve script not found at ${DEPSOLVE_SCRIPT}; skipping auto depsolve"
    echo ""
    return 0
  fi
  # depsolve should output newline-separated packages in build order. We call it with --desc param (assumed supported).
  # If your depsolve script uses different flags, adjust here.
  local out
  if out="$("${DEPSOLVE_SCRIPT}" --desc "${tmpdesc}" --show-build-order 2>>"$LOG_FILE")"; then
    # trim
    printf "%s\n" "$out"
  else
    log_warn "depsolve failed to compute update queue (see ${LOG_FILE})"
    printf "%s\n" ""
  fi
}

# recursively update dependencies first; record visited to avoid loops
declare -A VISITED_UPDATES
update_package_and_deps() {
  local pkg_to_update="$1"
  local depth="${2:-0}"
  if [ "${depth}" -gt "${MAX_DEP_UPDATE_DEPTH}" ]; then
    log_error "Max dependency update recursion depth exceeded for $pkg_to_update"
    return 1
  fi
  if [ "${VISITED_UPDATES[$pkg_to_update]+_}" ]; then
    log_info "Already processed $pkg_to_update; skipping to avoid cycles"
    return 0
  fi
  VISITED_UPDATES[$pkg_to_update]=1

  # find desc for that package
  local descp
  descp="$(find_desc_for_pkg "$pkg_to_update")"
  if [ -z "$descp" ]; then
    log_warn "No desc found for dependency $pkg_to_update; skipping auto-update for it"
    return 0
  fi

  # read its current version and fetch candidate new version (reuse functions)
  local curver
  curver="$(awk -F= '/^VERSION=/{print $2; exit}' "$descp" 2>/dev/null || true)"
  local baseurl
  baseurl="$(awk -F= '/^URL=/{print $2; exit}' "$descp" 2>/dev/null || true)"
  # try to derive base listing URL if URL points to a file (strip filename)
  if [ -n "$baseurl" ]; then
    baseurl_dir="$(dirname "$baseurl")/"
  else
    baseurl_dir=""
  fi
  if [ -n "$baseurl_dir" ]; then
    candidate="$(find_latest_version "$baseurl_dir" "$(basename "$baseurl")" 2>/dev/null || true)" || true
  else
    candidate=""
  fi

  if [ -n "$candidate" ] && is_major_update "$curver" "$candidate"; then
    log_info "Dependency $pkg_to_update has major update candidate $candidate (current $curver)"
    # Prepare new tarball URL by substituting version into filename if possible
    # We attempt to replace curver with candidate in URL; if fails, use baseurl_dir + guessed filename
    # derive filename pattern from current URL
    local cururl
    cururl="$(awk -F= '/^URL=/{print $2; exit}' "$descp" 2>/dev/null || true)"
    local newurl=""
    if [ -n "$cururl" ]; then
      newurl="${cururl//$curver/$candidate}"
    fi
    # compute expected new sha? We'll download and verify
    # call update flow for dependency (recursively)
    log_info "Scheduling update of dependency $pkg_to_update -> $candidate"
    # call this script recursively (same binary) to update dependency; pass remote publish/no-publish flags forward
    if [ "$DRY_RUN" = "yes" ]; then
      log_info "[DRY-RUN] would invoke update for dependency $pkg_to_update"
    else
      # run in same interpreter to preserve environment; use --yes to avoid prompts
      "${SCRIPT_DIR}/10-update.sh" --yes --remote-mode "${REMOTE_MODE}" --remote-target "${REMOTE_TARGET}" "$pkg_to_update" || {
        log_error "Auto-update of dependency $pkg_to_update failed; aborting main update"
        return 1
      }
    fi
  else
    log_info "No major update needed for dependency $pkg_to_update (current $curver; candidate $candidate)"
  fi
  return 0
}

# perform the actual update for the main package (after deps updated)
perform_update_for_pkg() {
  local newver="$1"
  local newurl="$2"
  local newsha="$3"

  log_info "Performing update for ${PKG}: ${VERSION} -> ${newver}"

  # backup desc and pkgdb
  local bak_desc
  bak_desc="$(backup_desc_and_pkgdb "${DESC_FILE}" "${PKG}")" || {
    log_warn "Failed to backup .desc or pkgdb; continuing cautiously"
  }

  # update .desc in-place
  update_desc_inplace "${DESC_FILE}" "${newver}" "${newurl}" "${newsha}"

  # run pre-update hook
  run_hook "pre-update" "${PKG}"

  # Rebuild sequence: uninstall old, build new, install new, package new
  # 1) uninstall old version
  log_info "Uninstalling old version of ${PKG}"
  if ! safe_run "bash \"${UNINSTALL_SCRIPT}\" \"${PKG}\""; then
    log_error "Uninstall failed for ${PKG}; attempting rollback of .desc"
    restore_desc_from_backup "${bak_desc}" "${DESC_FILE}"
    return 1
  fi

  # 2) fetch new sources via fetch script (if available) or directly download
  if [ -x "${FETCH_SCRIPT}" ]; then
    log_info "Fetching new sources via ${FETCH_SCRIPT}"
    if ! safe_run "bash \"${FETCH_SCRIPT}\" \"${PKG}\""; then
      log_error "Fetch failed for ${PKG} after updating .desc; restoring .desc"
      restore_desc_from_backup "${bak_desc}" "${DESC_FILE}"
      return 1
    fi
  else
    log_info "No fetch script found; ensuring tarball downloaded to sources"
    # attempt to download via download_and_verify if newurl provided
    if [ -n "${newurl}" ]; then
      if ! download_and_verify "${newurl}" "${newsha}" >/dev/null; then
        log_error "Failed to download new tarball ${newurl}"
        restore_desc_from_backup "${bak_desc}" "${DESC_FILE}"
        return 1
      fi
    else
      log_warn "No new URL provided and no fetch script; skipping fetch step"
    fi
  fi

  # 3) extract
  if [ -x "${EXTRACT_SCRIPT}" ]; then
    log_info "Extracting via ${EXTRACT_SCRIPT}"
    if ! safe_run "bash \"${EXTRACT_SCRIPT}\" \"${PKG}\""; then
      log_error "Extract failed for ${PKG}; restoring .desc"
      restore_desc_from_backup "${bak_desc}" "${DESC_FILE}"
      return 1
    fi
  fi

  # 4) build
  if [ -x "${BUILD_SCRIPT}" ]; then
    log_info "Building ${PKG} via ${BUILD_SCRIPT}"
    if ! safe_run "bash \"${BUILD_SCRIPT}\" \"${PKG}\""; then
      log_error "Build failed for ${PKG}; restoring .desc and pkgdb"
      restore_desc_from_backup "${bak_desc}" "${DESC_FILE}"
      return 1
    fi
  else
    log_warn "Build script not found: ${BUILD_SCRIPT}"
  fi

  # 5) install
  if [ -x "${INSTALL_SCRIPT}" ]; then
    log_info "Installing ${PKG} via ${INSTALL_SCRIPT}"
    if ! safe_run "bash \"${INSTALL_SCRIPT}\" \"${PKG}\""; then
      log_error "Install failed for ${PKG}; attempting rollback"
      restore_desc_from_backup "${bak_desc}" "${DESC_FILE}"
      return 1
    fi
  else
    log_warn "Install script not found: ${INSTALL_SCRIPT}"
  fi

  # 6) package
  if [ -x "${PACKAGE_SCRIPT}" ]; then
    log_info "Packaging ${PKG} via ${PACKAGE_SCRIPT}"
    if ! safe_run "bash \"${PACKAGE_SCRIPT}\" \"${PKG}\""; then
      log_warn "Package step failed for ${PKG} (non-fatal)"
      # continue; package failure doesn't imply system broken
    fi
  else
    log_warn "Package script not found: ${PACKAGE_SCRIPT}"
  fi

  # run post-update hook
  run_hook "post-update" "${PKG}"

  # update pkgdb metadata (write new version and timestamp)
  mkdir -p "${PKGDB_DIR}/${PKG}"
  echo "NAME=${PKG}" > "${PKGDB_DIR}/${PKG}/metadata"
  echo "VERSION=${newver}" >> "${PKGDB_DIR}/${PKG}/metadata"
  echo "BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "${PKGDB_DIR}/${PKG}/metadata"
  pkgdb_status_write "VERSION" "${newver}"
  pkgdb_status_write "STATUS" "INSTALLED_OK"

  log_info "Update of ${PKG} to ${newver} completed successfully"
  write_status_json "SUCCESS" "Updated to ${newver}"
  return 0
}

# publish via rsync (archive and metadata); expects REMOTE_TARGET set and PKG archive
publish_via_rsync() {
  local archive="$1"
  local remote_dir="${REMOTE_TARGET%/}/${PKG}/"
  local tries=0
  if [ -z "${REMOTE_TARGET}" ]; then
    log_warn "REMOTE_TARGET not configured; skipping rsync publish"
    return 0
  fi
  while [ $tries -lt "${REMOTE_RETRY}" ]; do
    if [ "$DRY_RUN" = "yes" ]; then
      log_info "[DRY-RUN] rsync -av ${archive} ${remote_dir}"
      return 0
    fi
    if ! command -v rsync >/dev/null 2>&1; then
      log_error "rsync not available"
      return 1
    fi
    log_info "Publishing ${archive} -> ${remote_dir} (rsync attempt $((tries+1)))"
    if rsync -av --partial --progress --checksum "${archive}" "${remote_dir}" >>"$LOG_FILE" 2>&1; then
      log_info "rsync publish succeeded"
      return 0
    fi
    tries=$((tries+1))
    sleep $((2**tries))
  done
  log_error "rsync publish failed after ${REMOTE_RETRY} attempts"
  return 1
}

# publish via git (clone, copy, commit, push)
publish_via_git() {
  local archive="$1"
  if [ -z "${REMOTE_TARGET}" ]; then
    log_warn "REMOTE_TARGET not configured; skipping git publish"
    return 0
  fi
  if [ "$DRY_RUN" = "yes" ]; then
    log_info "[DRY-RUN] git clone ${REMOTE_TARGET} /tmp/repo && cp ${archive} /tmp/repo/${PKG}/"
    return 0
  fi
  if ! command -v git >/dev/null 2>&1; then
    log_error "git not available"
    return 1
  fi
  local tmprepo
  tmprepo="$(mktemp -d "${DOWNLOAD_TMP}/gitrepo.XXXX")"
  if ! git clone --depth 1 "${REMOTE_TARGET}" "${tmprepo}" >>"$LOG_FILE" 2>&1; then
    log_error "Failed to clone remote git repo ${REMOTE_TARGET}"
    rm -rf "${tmprepo}"
    return 1
  fi
  mkdir -p "${tmprepo}/${PKG}"
  cp -a "${archive}" "${tmprepo}/${PKG}/" || log_warn "Could not copy archive to git repo tmp"
  cp -a "${DESC_FILE}" "${tmprepo}/${PKG}/" || true
  (cd "${tmprepo}" && git add -A && git commit -m "Add/update package ${PKG} $(date -u +"%Y-%m-%dT%H:%M:%SZ")" ) >>"$LOG_FILE" 2>&1 || true
  (cd "${tmprepo}" && git push origin HEAD:master --tags) >>"$LOG_FILE" 2>&1 || {
    log_error "git push failed"
    rm -rf "${tmprepo}"
    return 1
  }
  rm -rf "${tmprepo}"
  log_info "git publish succeeded"
  return 0
}

publish_package_remote() {
  local archive="$1"
  case "${REMOTE_MODE}" in
    rsync) publish_via_rsync "$archive" ;;
    git) publish_via_git "$archive" ;;
    *) log_warn "Unknown REMOTE_MODE=${REMOTE_MODE}; skipping publish"; return 0 ;;
  esac
}

# rollback handler: restore desc backup, restore pkgdb backup if available, try to uninstall partially installed new version
do_rollback_full() {
  local desc_bak="$1"
  local pkg="$2"
  log_warn "Starting rollback for ${pkg}"
  if [ -n "$desc_bak" ] && [ -f "$desc_bak" ]; then
    restore_desc_from_backup "$desc_bak" "${DESC_FILE}" || log_warn "Could not restore .desc from $desc_bak"
  fi
  # restore pkgdb backup if found
  local latestpkgbak
  latestpkgbak="$(ls -1t "${PKGDB_DIR}/.backups/"${pkg}_*.tar.xz 2>/dev/null | head -n1 || true)"
  if [ -n "$latestpkgbak" ] && [ -f "$latestpkgbak" ]; then
    log_info "Restoring pkgdb from ${latestpkgbak}"
    tar -xJf "$latestpkgbak" -C "${PKGDB_DIR}" || log_warn "Failed to restore pkgdb archive"
  fi
  # attempt uninstall of any partially installed package (best-effort)
  if [ -x "${UNINSTALL_SCRIPT}" ]; then
    log_info "Attempting uninstall of partial ${pkg}"
    safe_run "bash \"${UNINSTALL_SCRIPT}\" \"${pkg}\"" || log_warn "Partial uninstall may have failed"
  fi
  write_status_json "ROLLBACK" "Rollback attempted for ${pkg}"
  log_warn "Rollback finished (check logs)"
}

# MAIN LOGIC
main() {
  local start_ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  write_status_json "START" "Starting update flow"

  # quick checks
  if [ "$REBUILD_ONLY" = "yes" ]; then
    log_info "--rebuild-only specified: running build/install/package using current .desc"
    # run build/install/package directly
    if [ -x "${BUILD_SCRIPT}" ]; then safe_run "bash \"${BUILD_SCRIPT}\" \"${PKG}\""; fi
    if [ -x "${INSTALL_SCRIPT}" ]; then safe_run "bash \"${INSTALL_SCRIPT}\" \"${PKG}\""; fi
    if [ -x "${PACKAGE_SCRIPT}" ]; then safe_run "bash \"${PACKAGE_SCRIPT}\" \"${PKG}\""; fi
    write_status_json "OK" "Rebuild-only completed"
    return 0
  fi

  # find candidate latest stable version
  # derive base URL and pattern from current URL in desc
  if [ -z "${URL}" ]; then
    log_error "No URL found in ${DESC_FILE}; cannot discover new versions automatically"
    write_status_json "FAIL" "No URL in desc"
    return 1
  fi
  base_dir="$(dirname "${URL}")/"
  filename_template="$(basename "${URL}")"  # example: firefox-<VER>.tar.xz or firefox-118.0.tar.xz
  log_info "Discovering latest stable version at ${base_dir}"
  latest_ver="$(find_latest_version "${base_dir}" "${filename_template}" 2>>"$LOG_FILE" || true)" || true
  if [ -z "${latest_ver}" ]; then
    log_warn "Could not discover latest version automatically for ${PKG}; aborting update-check"
    write_status_json "NO_CANDIDATE" "Could not discover latest stable version"
    return 2
  fi
  log_info "Latest candidate version discovered: ${latest_ver}"

  if ! is_major_update "${VERSION}" "${latest_ver}"; then
    log_info "No major-version update (current ${VERSION}, candidate ${latest_ver}). Exiting."
    write_status_json "NO_UPDATE" "Candidate ${latest_ver} not major > ${VERSION}"
    if [ "$CHECK_ONLY" = "yes" ]; then return 0; else return 0; fi
  fi

  # compute new tarball URL by substituting old version with new one in URL when possible
  new_url="${URL//$VERSION/$latest_ver}"
  log_info "Assumed new URL: ${new_url}"

  # Download tarball temporarily and get sha256
  dl_res=""
  if [ "$DRY_RUN" = "yes" ]; then
    log_info "[DRY-RUN] would download ${new_url}"
    dl_res="${DOWNLOAD_TMP}/$(basename "${new_url}")"
  else
    if ! dl_res="$(download_and_verify "${new_url}" "" 2>>"$LOG_FILE")"; then
      log_error "Failed to download/verify ${new_url}"
      write_status_json "FAIL" "Download failed"
      return 3
    fi
  fi

  # compute sha if not provided
  if [ "$DRY_RUN" = "yes" ]; then
    new_sha="DRY-RUN-SHA"
  else
    new_sha="$(sha256sum "${dl_res}" | awk '{print $1}')"
    log_info "Computed SHA256: ${new_sha}"
  fi

  if [ "$CHECK_ONLY" = "yes" ]; then
    log_info "--check only: candidate ${latest_ver} available at ${new_url}, sha256=${new_sha}"
    write_status_json "CANDIDATE_FOUND" "Candidate ${latest_ver} found"
    return 0
  fi

  # confirm with user unless auto-confirm
  if [ "${AUTO_CONFIRM}" != "yes" ] && [ "$DRY_RUN" != "yes" ]; then
    printf "Update %s: %s -> %s. Proceed? [y/N]: " "${PKG}" "${VERSION}" "${latest_ver}"
    read -r ans || true
    if [[ ! "$ans" =~ ^[Yy] ]]; then
      log_info "User declined update"
      write_status_json "ABORTED" "User cancelled"
      return 0
    fi
  fi

  # perform depsolve to build queue (recompute dependencies based on new desc)
  log_info "Generating update queue via depsolve for ${PKG}"
  update_queue="$(get_update_queue_via_depsolve "${latest_ver}" "${new_url}" "${new_sha}" 2>>"$LOG_FILE" || true)"
  # update_queue may be newline separated list of packages in order (deps first)
  log_info "Depsolve returned queue (may be empty):"
  printf "%s\n" "${update_queue}"

  # execute update for each dependency first (if any). We ensure we don't re-update main pkg as dependency loop.
  if [ -n "${update_queue}" ]; then
    # iterate lines
    while IFS= read -r dep_pkg; do
      [ -z "$dep_pkg" ] && continue
      if [ "$dep_pkg" = "${PKG}" ]; then
        log_debug "Skipping self ${PKG} in queue"
        continue
      fi
      log_info "Processing dependency update for ${dep_pkg} before ${PKG}"
      # call this script recursively to update dependency; this will also handle its deps
      if [ "$DRY_RUN" = "yes" ]; then
        log_info "[DRY-RUN] Would call update for dependency ${dep_pkg}"
      else
        if ! "${SCRIPT_DIR}/10-update.sh" --yes --remote-mode "${REMOTE_MODE}" --remote-target "${REMOTE_TARGET}" "${dep_pkg}"; then
          log_error "Failed to update dependency ${dep_pkg}; aborting update of ${PKG}"
          write_status_json "FAIL" "Dependency ${dep_pkg} update failed"
          return 4
        fi
      fi
    done < <(printf "%s\n" "${update_queue}")
  fi

  # now perform update for main package
  local desc_backup
  desc_backup="$(backup_desc_and_pkgdb "${DESC_FILE}" "${PKG}")" || desc_backup=""

  if ! perform_update_for_pkg "${latest_ver}" "${new_url}" "${new_sha}"; then
    log_error "Update failed for ${PKG}; initiating rollback"
    do_rollback_full "${desc_backup}" "${PKG}"
    return 5
  fi

  # publish: look for package archive (pkgcache) in PKG_CACHE_DIR (06-package creates it) or allow remote publish of desc
  if [ "${NO_PUBLISH}" != "yes" ] && [ -n "${REMOTE_TARGET}" ]; then
    # attempt to find archive under default packages dir
    PKG_CACHE_DIR="${ROOT}/packages"
    archive_candidate="$(ls -1t "${PKG_CACHE_DIR}/${PKG}-"* 2>/dev/null | head -n1 || true)"
    if [ -n "${archive_candidate}" ]; then
      log_info "Publishing archive ${archive_candidate} to remote (${REMOTE_MODE})"
      if ! publish_package_remote "${archive_candidate}"; then
        log_warn "Publish failed for ${PKG}; continuing (publish non-fatal)"
      fi
    else
      # as fallback, publish the .desc and metadata
      log_info "No local archive found; publishing .desc metadata to remote"
      tmpmeta="$(mktemp "${DOWNLOAD_TMP}/${PKG}.meta.XXXX")"
      cp -a "${DESC_FILE}" "${tmpmeta}"
      if ! publish_package_remote "${tmpmeta}"; then
        log_warn "Publish of metadata failed"
      fi
      rm -f "${tmpmeta}" || true
    fi
  else
    log_info "Publish disabled or REMOTE_TARGET not set"
  fi

  # final checks: detect silent errors in log file
  if detect_silent_errors "${LOG_FILE}"; then
    log_warn "Silent errors detected in logs; please inspect ${LOG_FILE}"
    pkgdb_status_write "WARNINGS" "silent-errors-detected"
  fi

  # cleanup temporaries
  rm -rf "${DOWNLOAD_TMP}" || true

  write_status_json "SUCCESS" "Update flow completed for ${PKG}"
  log_info "Update flow completed successfully for ${PKG}"
  return 0
}

# run main and capture errors to perform rollback when needed
if ! main; then
  log_error "Update script failed for ${PKG}; check logs ${LOG_FILE}"
  log_end 1
  exit 1
fi

log_end 0
exit 0
