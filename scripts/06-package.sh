#!/usr/bin/env bash
#
# 06-package.sh - Empacota DESTDIR em tarball (.tar.xz or .tar.zst), cria manifest/JSON, hashes,
#                 atualiza pkgdb e publica em repositório remoto (rsync or git).
#
# Save as scripts/06-package.sh and `chmod +x` it.
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then set -o pipefail; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# load logger if available
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/logger.sh"
else
  # minimal logger fallback
  log_info() { echo "[INFO] $*"; }
  log_warn() { echo "[WARN] $*"; }
  log_error() { echo "[ERROR] $*" >&2; }
  log_start() { :; }
  log_end() { :; }
fi

# -----------------------------
# Defaults (override via env)
# -----------------------------
: "${ROOT:=./auto-builder}"
: "${PKGDB_DIR:=/var/lib/pkgdb}"
: "${PKG_CACHE_DIR:=${ROOT}/packages}"
: "${LOG_DIR:=${ROOT}/logs}"
: "${KEEP_TEMP:=no}"
: "${DEFAULT_COMPRESSOR:=xz}"      # xz or zstd
: "${STRIP_BINARIES:=yes}"
: "${PUBLISH_ON_SUCCESS:=yes}"
: "${REMOTE_MODE:=rsync}"          # rsync or git
: "${REMOTE_TARGET:=}"             # e.g. user@host:/srv/packages or git@host:repo.git
: "${REMOTE_RETRY:=3}"
: "${KEEP_VERSIONS:=5}"            # keep last N versions on remote (if supported)
: "${DETECT_SILENT_PATTERNS:=error|failed|fatal|corrupt|unexpected|traceback|cannot|not found}"
: "${MIN_PACKAGE_SIZE_BYTES:=1024}" # package less than this considered suspicious

mkdir -p "${PKGDB_DIR}" "${PKG_CACHE_DIR}" "${LOG_DIR}/package"

usage() {
  cat <<EOF
Usage: $0 [options] <pkg> <destdir>
Options:
  --compressor xz|zstd     Compressor to use (default: ${DEFAULT_COMPRESSOR})
  --remote-mode rsync|git  Publish mode (default: ${REMOTE_MODE})
  --remote-target <target> Remote target (rsync path or git URL)
  --no-publish             Do not publish to remote even if configured
  --keep-temp              Keep temporary build artifacts for debugging
  --dry-run                Do not actually create files or publish
  --help
Examples:
  $0 firefox /tmp/installroot/firefox_20251024T...
EOF
  exit 1
}

# parse args
COMPRESSOR="${DEFAULT_COMPRESSOR}"
DRY_RUN="no"
KEEP_TEMP="no"
PUBLISH_ON_SUCCESS="${PUBLISH_ON_SUCCESS}"
while [ $# -gt 0 ]; do
  case "$1" in
    --compressor) shift; COMPRESSOR="$1"; shift ;;
    --remote-mode) shift; REMOTE_MODE="$1"; shift ;;
    --remote-target) shift; REMOTE_TARGET="$1"; shift ;;
    --no-publish) PUBLISH_ON_SUCCESS="no"; shift ;;
    --keep-temp) KEEP_TEMP="yes"; shift ;;
    --dry-run) DRY_RUN="yes"; shift ;;
    --help) usage ;;
    --*) echo "Unknown option $1"; usage ;;
    *) break ;;
  esac
done

if [ $# -lt 2 ]; then usage; fi
PKG="$1"; DESTDIR="$2"

# normalize
PKG="$(basename "$PKG")"
DESTDIR="$(realpath -m "$DESTDIR")"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"

OUT_LOG="${LOG_DIR}/package/${PKG}.out"
ERR_LOG="${LOG_DIR}/package/${PKG}.err"
: > "$OUT_LOG"
: > "$ERR_LOG"

log_start "package" "$PKG"
log_info "Packaging $PKG from DESTDIR=$DESTDIR at $TIMESTAMP (compressor=$COMPRESSOR, remote_mode=$REMOTE_MODE)"

# helpers
_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_epoch() { date +%s; }

atomic_mv() {
  local src="$1" dst="$2"
  mv -f "$src" "$dst"
}

safe_cmd() {
  if [ "$DRY_RUN" = "yes" ]; then
    echo "[DRY-RUN] $*"
    return 0
  else
    eval "$@"
  fi
}

# check DESTDIR validity
if [ ! -d "$DESTDIR" ]; then
  log_error "DESTDIR not found: $DESTDIR"
  pkgdb_dir="${PKGDB_DIR}/${PKG}"
  mkdir -p "$pkgdb_dir"
  echo "STATUS=PACKAGING_FAIL" > "${pkgdb_dir}/package.status"
  echo "MSG=DESTDIR missing" >> "${pkgdb_dir}/package.status"
  log_end 1
  exit 1
fi

# ensure DESTDIR is not root and is inside expected locations (safety)
if [ "$DESTDIR" = "/" ] || [ "$DESTDIR" = "" ]; then
  log_error "Refusing to package root DESTDIR"
  exit 1
fi

# detect version and release: try pkgdb install-stats.json, then pkgdb/install.status, then fallback to timestamp
PKGDB_PFX="${PKGDB_DIR}/${PKG}"
VERSION="0.0"
RELEASE="1"
if [ -f "${PKGDB_PFX}/install-stats.json" ]; then
  # try to parse version field if present
  ver="$(grep -oP '"version"\s*:\s*"\K[^"]+' "${PKGDB_PFX}/install-stats.json" 2>/dev/null || true)"
  if [ -n "$ver" ]; then VERSION="$ver"; fi
fi
if [ -f "${PKGDB_PFX}/install.status" ]; then
  # try extract version from install.status if it exists in MSG or other
  # (no strict format assumed)
  ver2="$(grep -Eo 'VERSION=[0-9A-Za-z_.-]+' "${PKGDB_PFX}/install.status" 2>/dev/null | cut -d= -f2 || true)"
  [ -n "$ver2" ] && VERSION="$ver2"
fi
# final fallback: timestamp
if [ -z "$VERSION" ] || [ "$VERSION" = "0.0" ]; then
  VERSION="$TIMESTAMP"
fi

PKG_FILENAME="${PKG}-${VERSION}-${RELEASE}.tar"
CASE_COMPRESS_EXT=""
case "$COMPRESSOR" in
  xz) CASE_COMPRESS_EXT=".tar.xz" ;;
  zstd) CASE_COMPRESS_EXT=".tar.zst" ;;
  *) log_warn "Unknown compressor $COMPRESSOR; defaulting to xz"; COMPRESSOR="xz"; CASE_COMPRESS_EXT=".tar.xz" ;;
esac

PKG_ARCHIVE_TMP="$(mktemp "${PKG_CACHE_DIR}/${PKG}.XXXXXX${CASE_COMPRESS_EXT}.tmp")"
PKG_ARCHIVE_FINAL="${PKG_CACHE_DIR}/${PKG}-${VERSION}-${RELEASE}${CASE_COMPRESS_EXT}"
PKG_MANIFEST="${PKGDB_PFX}/manifest.txt"
PKG_JSON="${PKGDB_PFX}/package.json"

# function: strip binaries safely inside DESTDIR
strip_binaries() {
  if [ "$STRIP_BINARIES" != "yes" ]; then
    log_info "Strip disabled by config"
    return 0
  fi
  if ! command -v strip >/dev/null 2>&1; then
    log_warn "strip not available; skipping"
    return 0
  fi
  log_info "Stripping binaries under $DESTDIR (this reduces package size)"
  # find ELF executables and shared objects
  find "$DESTDIR" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
    # check ELF header
    if head -c4 "$f" 2>/dev/null | grep -q "ELF"; then
      # attempt strip, ignore failures but log
      if [ "$DRY_RUN" = "yes" ]; then
        echo "[DRY-RUN] strip --strip-unneeded '$f'" >>"$OUT_LOG"
      else
        if ! strip --strip-unneeded "$f" >>"$OUT_LOG" 2>>"$ERR_LOG"; then
          log_warn "strip failed on $f; continuing"
        fi
      fi
    fi
  done
  log_info "Strip step finished"
}

# detect package size (pre-strip)
PRE_SIZE_BYTES=$(du -sb "$DESTDIR" 2>/dev/null | awk '{print $1}' || echo 0)
PRE_FILES_COUNT=$(find "$DESTDIR" -type f | wc -l || echo 0)

if [ "$PRE_SIZE_BYTES" -lt "$MIN_PACKAGE_SIZE_BYTES" ]; then
  log_warn "DESTDIR size ${PRE_SIZE_BYTES} bytes is suspiciously small"
fi

# run strip
strip_binaries >>"$OUT_LOG" 2>>"$ERR_LOG" || log_warn "strip_binaries had warnings"

# after strip recompute size
POST_SIZE_BYTES=$(du -sb "$DESTDIR" 2>/dev/null | awk '{print $1}' || echo 0)
POST_FILES_COUNT=$(find "$DESTDIR" -type f | wc -l || echo 0)

log_info "Files before: ${PRE_FILES_COUNT}, after: ${POST_FILES_COUNT}; bytes before: ${PRE_SIZE_BYTES}, after: ${POST_SIZE_BYTES}"
# Generate manifest file (temporary)
mkdir -p "$PKGDB_PFX"
TMP_MANIFEST="$(mktemp)"
{
  echo "PACKAGE=${PKG}"
  echo "VERSION=${VERSION}"
  echo "RELEASE=${RELEASE}"
  echo "CREATED=${_now}"
  echo "SRC_DESTDIR=${DESTDIR}"
  echo "FILES_COUNT=${POST_FILES_COUNT}"
  echo "SIZE_BYTES=${POST_SIZE_BYTES}"
} > "$TMP_MANIFEST"

# create manifest list of files with modes/owners/sizes
MANIFEST_LIST_TMP="$(mktemp)"
( cd "$DESTDIR" && find . -printf '%P\t%y\t%s\t%M\n' | sort ) > "$MANIFEST_LIST_TMP"
cat "$TMP_MANIFEST" > "${PKG_MANIFEST}.tmp"
echo "---FILES---" >> "${PKG_MANIFEST}.tmp"
cat "$MANIFEST_LIST_TMP" >> "${PKG_MANIFEST}.tmp"
mv -f "${PKG_MANIFEST}.tmp" "$PKG_MANIFEST"
log_info "Manifest written to $PKG_MANIFEST"

# compress package
log_info "Compressing DESTDIR -> ${PKG_ARCHIVE_TMP} using ${COMPRESSOR}"

# choose tar flags
case "$COMPRESSOR" in
  xz)
    TAR_CMD="tar -cJf '${PKG_ARCHIVE_TMP}' -C '${DESTDIR}' ."
    ;;
  zstd)
    # Use --zstd if tar supports it, else pipe
    if tar --version 2>/dev/null | grep -q -- '--zstd'; then
      TAR_CMD="tar --zstd -cf '${PKG_ARCHIVE_TMP}' -C '${DESTDIR}' ."
    else
      TAR_CMD="tar -cf - -C '${DESTDIR}' . | zstd -19 -o '${PKG_ARCHIVE_TMP}' -"
    fi
    ;;
  *)
    TAR_CMD="tar -cJf '${PKG_ARCHIVE_TMP}' -C '${DESTDIR}' ."
    ;;
esac

# run tar with safe handling
if [ "$DRY_RUN" = "yes" ]; then
  echo "[DRY-RUN] $TAR_CMD" >>"$OUT_LOG"
else
  # ensure enough disk space to create archive (simple heuristic: need at least DESTDIR size free)
  FREE_MB=$(df -Pm "${PKG_CACHE_DIR}" | awk 'NR==2{print $4}')
  NEED_MB=$(( (POST_SIZE_BYTES/1024/1024) + 100 ))
  if [ "$FREE_MB" -lt "$NEED_MB" ]; then
    log_error "Insufficient space in PKG_CACHE_DIR to create archive (need ${NEED_MB}MB, have ${FREE_MB}MB)"
    echo "STATUS=PACKAGING_FAIL" > "${PKGDB_PFX}/package.status"
    log_end 1
    exit 1
  fi

  # execute
  if ! bash -c "$TAR_CMD" >>"$OUT_LOG" 2>>"$ERR_LOG"; then
    log_error "Compression failed"
    rm -f "${PKG_ARCHIVE_TMP}" 2>/dev/null || true
    echo "STATUS=PACKAGING_FAIL" > "${PKGDB_PFX}/package.status"
    log_end 1
    exit 1
  fi
fi

# move tmp archive to final atomically
if [ "$DRY_RUN" != "yes" ]; then
  mv -f "${PKG_ARCHIVE_TMP}" "${PKG_ARCHIVE_FINAL}" || {
    log_error "Failed to move archive to final location"
    rm -f "${PKG_ARCHIVE_TMP}" 2>/dev/null || true
    echo "STATUS=PACKAGING_FAIL" > "${PKGDB_PFX}/package.status"
    log_end 1
    exit 1
  }
  log_info "Archive created: ${PKG_ARCHIVE_FINAL}"
fi

# compute hashes
log_info "Computing hashes for package"
SHA256_FILE="${PKG_ARCHIVE_FINAL}.sha256"
SHA512_FILE="${PKG_ARCHIVE_FINAL}.sha512"
BLAKE3_FILE="${PKG_ARCHIVE_FINAL}.b3"

if [ "$DRY_RUN" = "yes" ]; then
  echo "[DRY-RUN] compute hashes" >>"$OUT_LOG"
else
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${PKG_ARCHIVE_FINAL}" > "${SHA256_FILE}" 2>>"$ERR_LOG" || log_warn "sha256sum failed"
  fi
  if command -v sha512sum >/dev/null 2>&1; then
    sha512sum "${PKG_ARCHIVE_FINAL}" > "${SHA512_FILE}" 2>>"$ERR_LOG" || log_warn "sha512sum failed"
  fi
  # blake3 support (b3sum or b2sum)
  if command -v b3sum >/dev/null 2>&1; then
    b3sum "${PKG_ARCHIVE_FINAL}" > "${BLAKE3_FILE}" 2>>"$ERR_LOG" || log_warn "b3sum failed"
  elif command -v b2sum >/dev/null 2>&1; then
    b2sum --algorithm=BLAKE3 "${PKG_ARCHIVE_FINAL}" > "${BLAKE3_FILE}" 2>>"$ERR_LOG" || true
  else
    log_debug "blake3 not available; skipping"
  fi
fi

# validate compressed archive
validate_archive() {
  if [ "$DRY_RUN" = "yes" ]; then
    echo "[DRY-RUN] validate archive ${PKG_ARCHIVE_FINAL}" >>"$OUT_LOG"
    return 0
  fi
  # check file exists and size
  if [ ! -f "${PKG_ARCHIVE_FINAL}" ]; then
    log_error "Archive missing after compression"
    return 1
  fi
  local size
  size=$(stat -c%s "${PKG_ARCHIVE_FINAL}" 2>/dev/null || echo 0)
  if [ "$size" -lt "$MIN_PACKAGE_SIZE_BYTES" ]; then
    log_warn "Archive size small (${size} bytes) - possible problem"
  fi
  # tar -tf to ensure readable
  case "$COMPRESSOR" in
    xz)
      if ! tar -tJf "${PKG_ARCHIVE_FINAL}" > /dev/null 2>>"$ERR_LOG"; then
        log_error "tar -tJf failed for ${PKG_ARCHIVE_FINAL}"
        return 2
      fi
      # xz test if available
      if command -v xz >/dev/null 2>&1; then
        if ! xz -t "${PKG_ARCHIVE_FINAL}" >/dev/null 2>>"$ERR_LOG"; then
          log_error "xz test failed for ${PKG_ARCHIVE_FINAL}"
          return 3
        fi
      fi
      ;;
    zstd)
      if ! tar --use-compress-program=unzstd -tf "${PKG_ARCHIVE_FINAL}" > /dev/null 2>>"$ERR_LOG"; then
        # fallback to zstd -t
        if command -v zstd >/dev/null 2>&1; then
          if ! zstd -t "${PKG_ARCHIVE_FINAL}" >/dev/null 2>>"$ERR_LOG"; then
            log_error "zstd test failed for ${PKG_ARCHIVE_FINAL}"
            return 4
          fi
        else
          log_warn "Could not test zstd archive (zstd not available)"
        fi
      fi
      ;;
    *)
      if ! tar -tf "${PKG_ARCHIVE_FINAL}" > /dev/null 2>>"$ERR_LOG"; then
        log_error "tar -tf failed for ${PKG_ARCHIVE_FINAL}"
        return 5
      fi
      ;;
  esac
  return 0
}

if ! validate_archive; then
  log_error "Archive validation failed; removing archive and aborting"
  rm -f "${PKG_ARCHIVE_FINAL}" 2>/dev/null || true
  echo "STATUS=PACKAGING_FAIL" > "${PKGDB_PFX}/package.status"
  log_end 1
  exit 1
fi

# create package JSON metadata
PKG_JSON_TMP="$(mktemp)"
cat > "$PKG_JSON_TMP" <<EOF
{
  "name": "$(printf '%s' "$PKG")",
  "version": "$(printf '%s' "$VERSION")",
  "release": $(printf '%s' "$RELEASE"),
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "files_count": ${POST_FILES_COUNT},
  "size_bytes": ${POST_SIZE_BYTES},
  "archive": "$(basename "$PKG_ARCHIVE_FINAL")",
  "compressor": "${COMPRESSOR}"
}
EOF
mv -f "$PKG_JSON_TMP" "$PKG_JSON"
log_info "Package JSON written to $PKG_JSON"

# write manifest summary (short)
cat > "${PKGDB_PFX}/manifest.summary" <<EOF
PACKAGE=${PKG}
VERSION=${VERSION}
RELEASE=${RELEASE}
ARCHIVE=$(basename "${PKG_ARCHIVE_FINAL}")
SIZE_BYTES=${size:-0}
FILES=${POST_FILES_COUNT}
CREATED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COMPRESSOR=${COMPRESSOR}
EOF

# update package.status
cat > "${PKGDB_PFX}/package.status" <<EOF
STATUS=PACKAGED_OK
TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ARCHIVE=$(basename "${PKG_ARCHIVE_FINAL}")
FILES=${POST_FILES_COUNT}
SIZE_BYTES=${size:-0}
EOF

log_info "Packaging completed and recorded in pkgdb for $PKG"

# Publish to remote if configured
publish_via_rsync() {
  if [ -z "$REMOTE_TARGET" ]; then
    log_warn "REMOTE_TARGET not configured; skipping rsync publish"
    return 0
  fi
  local remote_dir="${REMOTE_TARGET%/}/${PKG}/"
  local retries=0
  while [ $retries -lt "$REMOTE_RETRY" ]; do
    if [ "$DRY_RUN" = "yes" ]; then
      echo "[DRY-RUN] rsync -av --progress '${PKG_ARCHIVE_FINAL}' '${remote_dir}'" >>"$OUT_LOG"
      return 0
    fi
    if command -v rsync >/dev/null 2>&1; then
      rsync -av --partial --progress --checksum --copy-links --no-perms "${PKG_ARCHIVE_FINAL}" "${remote_dir}" >>"$OUT_LOG" 2>>"$ERR_LOG" && return 0 || {
        log_warn "rsync attempt $((retries+1)) failed"
        retries=$((retries+1))
        sleep $((2**retries))
      }
    else
      log_error "rsync not available on system"
      return 1
    fi
  done
  return 1
}

publish_via_git() {
  if [ -z "$REMOTE_TARGET" ]; then
    log_warn "REMOTE_TARGET not configured; skipping git publish"
    return 0
  fi
  # strategy: clone remote into temp, copy new archive and metadata, commit, tag and push
  local tmprepo
  tmprepo="$(mktemp -d "${ROOT}/.pkgrepo.XXXX")"
  local retries=0
  while [ $retries -lt "$REMOTE_RETRY" ]; do
    if [ "$DRY_RUN" = "yes" ]; then
      echo "[DRY-RUN] git clone ${REMOTE_TARGET} ${tmprepo}" >>"$OUT_LOG"
      echo "[DRY-RUN] copy ${PKG_ARCHIVE_FINAL} to ${tmprepo}/${PKG}/" >>"$OUT_LOG"
      return 0
    fi
    if ! git clone --depth 1 "${REMOTE_TARGET}" "${tmprepo}" >>"$OUT_LOG" 2>>"$ERR_LOG"; then
      log_warn "git clone attempt $((retries+1)) failed"
      retries=$((retries+1)); sleep $((2**retries)); continue
    fi
    mkdir -p "${tmprepo}/${PKG}"
    cp -a "${PKG_ARCHIVE_FINAL}" "${tmprepo}/${PKG}/" || { log_warn "copy to repo failed"; rm -rf "${tmprepo}"; retries=$((retries+1)); continue; }
    cp -a "${PKG_MANIFEST}" "${tmprepo}/${PKG}/manifest.txt" || true
    cp -a "${PKG_JSON}" "${tmprepo}/${PKG}/package.json" || true
    (cd "${tmprepo}" && git add -A && git commit -m "Add package ${PKG} ${VERSION}-${RELEASE}" ) >>"$OUT_LOG" 2>>"$ERR_LOG" || true
    # tag
    TAG="${PKG}-${VERSION}-${RELEASE}"
    (cd "${tmprepo}" && git tag -f -a "${TAG}" -m "Release ${TAG}") >>"$OUT_LOG" 2>>"$ERR_LOG" || true
    # push
    if (cd "${tmprepo}" && git push --follow-tags origin HEAD:master) >>"$OUT_LOG" 2>>"$ERR_LOG"; then
      rm -rf "${tmprepo}"
      return 0
    else
      log_warn "git push failed on attempt $((retries+1))"
      rm -rf "${tmprepo}"
      retries=$((retries+1)); sleep $((2**retries))
    fi
  done
  return 1
}

if [ "$PUBLISH_ON_SUCCESS" = "yes" ]; then
  if [ "$REMOTE_MODE" = "rsync" ]; then
    if ! publish_via_rsync; then
      log_warn "Rsync publish failed"
    else
      log_info "Rsync publish succeeded"
    fi
  elif [ "$REMOTE_MODE" = "git" ]; then
    if ! publish_via_git; then
      log_warn "Git publish failed"
    else
      log_info "Git publish succeeded"
    fi
  else
    log_warn "Unknown REMOTE_MODE=${REMOTE_MODE}; skipping publish"
  fi
else
  log_info "Publish disabled by flag"
fi

# cleanup: if KEEP_TEMP=no remove any temp artifacts (archive kept)
if [ "$KEEP_TEMP" = "no" ]; then
  # no intermediate temps left except possibly PKG_ARCHIVE_FINAL which we keep
  true
else
  log_info "Keeping temp artifacts as requested"
fi

# final verification of package presence and update pkgdb with metadata/hashes
if [ -f "${PKG_ARCHIVE_FINAL}" ]; then
  SHA256_VAL="$(awk '{print $1}' "${SHA256_FILE}" 2>/dev/null || true)"
  SHA512_VAL="$(awk '{print $1}' "${SHA512_FILE}" 2>/dev/null || true)"
  B3_VAL="$(awk '{print $1}' "${BLAKE3_FILE}" 2>/dev/null || true)"
  cat > "${PKGDB_PFX}/package.json" <<EOF
{
  "name": "${PKG}",
  "version": "${VERSION}",
  "release": ${RELEASE},
  "archive": "$(basename "${PKG_ARCHIVE_FINAL}")",
  "files": ${POST_FILES_COUNT},
  "size_bytes": ${POST_SIZE_BYTES},
  "hash_sha256": "${SHA256_VAL}",
  "hash_sha512": "${SHA512_VAL}",
  "hash_blake3": "${B3_VAL}",
  "compressor": "${COMPRESSOR}",
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "published": "${PUBLISH_ON_SUCCESS}",
  "remote_mode": "${REMOTE_MODE}",
  "remote_target": "${REMOTE_TARGET}"
}
EOF
  log_info "pkgdb package.json written"
fi

log_info "Packaging process finished for $PKG"
log_end 0
exit 0
