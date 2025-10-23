#!/usr/bin/env bash
#
# 02-extract.sh - Extrai fontes, aplica patches, prepara build dirs
# Requisitos: bash, tar, patch, rsync (opcional), df, mktemp
# Integração: source logger.sh -> use log_start/log_end and LOGGER_CURRENT_* variables
#
set -euo pipefail
if [ -n "${BASH_VERSION-}" ]; then
  set -o pipefail
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/logger.sh"

# ----------------------------
# Defaults (override via config.txt)
# ----------------------------
: "${ROOT:=./auto-builder}"
: "${SRC_DIR:=${ROOT}/sources}"
: "${BUILD_DIR:=${ROOT}/build}"
: "${PATCH_DIR:=${ROOT}/patches}"
: "${LOG_DIR:=${ROOT}/logs}"
: "${DB_DIR:=/var/lib/pkgdb}"
: "${MIN_FREE_MB:=500}"     # mínimo de MB livre exigido antes de extrair
: "${EXTRACT_JOBS:=1}"      # por padrão sequencial; >1 possibilita paralelismo simples
: "${KEEP_PREVIOUS_BUILD:=yes}"  # se 'yes' cria backup antes de limpar
: "${STRIP_COMPONENTS:=0}"  # número padrão de --strip-components ao extrair
: "${SAFE_TAR_FLAGS:='--no-same-owner --no-overwrite-dir --warning=no-unknown-keyword'}"

# Trap para captura de erros inesperados
_trap_err() {
  local rc=$?
  echo "02-extract.sh: internal error rc=${rc}" >&2
  # se dentro de um contexto de pacote, informe ao logger
  if [ -n "${CURRENT_PKG-}" ]; then
    log_error "Internal extract script error (rc=${rc}) for ${CURRENT_PKG}"
    # tenta rollback local do pacote
    rollback_extract "${CURRENT_PKG}"
  fi
  exit $rc
}
trap '_trap_err' ERR INT TERM

# ----------------------------
# Helpers
# ----------------------------
_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_epoch() { date +%s; }

# verifica espaço livre (MB) no filesystem do path
check_disk_space() {
  local path="${1:-.}"
  local need_mb="${2:-$MIN_FREE_MB}"
  local avail
  avail=$(df -Pk "$path" | awk 'NR==2{print int($4/1024)}')
  if [ -z "$avail" ]; then
    log_warn "Não foi possível determinar espaço livre em $path"
    return 1
  fi
  if [ "$avail" -lt "$need_mb" ]; then
    log_error "Espaço insuficiente em $(realpath "$path"): ${avail}MB disponível (< ${need_mb}MB requerido)"
    return 2
  fi
  return 0
}

# test tarball integrity quickly (tar -tf)
test_tarball() {
  local tarball="$1"
  if [ ! -f "$tarball" ]; then
    log_error "Tarball não encontrado: $tarball"
    return 1
  fi
  # tar tf can still return 0 for some corruptions but it's a useful quick check
  if ! tar -tf "$tarball" > /dev/null 2>>"$LOGGER_CURRENT_ERR"; then
    log_error "tar -tf falhou (arquivo possivelmente corrompido): $tarball"
    return 2
  fi
  return 0
}

# safe extraction into target dir using temporary directory
extract_to_temp() {
  local tarball="$1"
  local target="$2"
  local strip="${3:-$STRIP_COMPONENTS}"
  local tmp
  tmp=$(mktemp -d "${BUILD_DIR}/.tmp_extract_XXXX") || { log_error "Não conseguiu criar tmpdir"; return 1; }
  # extract safely
  if ! tar --no-same-owner --no-overwrite-dir -xvf "$tarball" -C "$tmp" --strip-components="$strip" 1>>"$LOGGER_CURRENT_OUT" 2>>"$LOGGER_CURRENT_ERR"; then
    rm -rf "$tmp"
    log_error "tar falhou ao extrair $tarball"
    return 2
  fi
  # basic check: ensure extracted dir not empty
  if [ -z "$(ls -A "$tmp" 2>/dev/null)" ]; then
    rm -rf "$tmp"
    log_error "Extração resultou em diretório vazio (possível tar inválido): $tarball"
    return 3
  fi
  # move tmp to final (atomic-ish)
  mkdir -p "$(dirname "$target")"
  if [ -d "$target" ]; then
    # caller should have handled backup; but here ensure we avoid clobber
    rm -rf "${target}.old" || true
    mv "$target" "${target}.old" 2>/dev/null || true
  fi
  mv "$tmp" "$target"
  # remove possible leftover .old
  if [ -d "${target}.old" ] && [ "${KEEP_PREVIOUS_BUILD}" != "yes" ]; then
    rm -rf "${target}.old" || true
  fi
  return 0
}

# aplica todos os patches em patches/<pkg>/*.patch (ordem alfanumérica)
apply_patches() {
  local pkg="$1"
  local target_dir="$2"
  local patches_dir="$PATCH_DIR/$pkg"
  if [ ! -d "$patches_dir" ]; then
    return 0
  fi
  shopt -s nullglob 2>/dev/null || true
  local p
  for p in "$patches_dir"/*.patch; do
    [ -f "$p" ] || continue
    log_info "Aplicando patch $(basename "$p") em $pkg"
    # executar patch no diretório alvo; salvar saída para análise
    if ! (cd "$target_dir" && patch -p1 --forward < "$p" >>"$LOGGER_CURRENT_OUT" 2>>"$LOGGER_CURRENT_ERR"); then
      # detectar mensagens silenciosas: "Hunk FAILED" pode sair como exit 0 in certain patch implementations, but generally patch returns non-zero
      if grep -Eqi "Hunk FAILED|FAILED|Reversed|already applied|malformed" "$LOGGER_CURRENT_ERR" 2>/dev/null; then
        log_error "Patch $(basename "$p") falhou de forma silenciosa para $pkg (veja ${LOGGER_CURRENT_ERR})"
        return 2
      else
        log_error "Patch $(basename "$p") retornou erro para $pkg"
        return 3
      fi
    fi
  done
  return 0
}

# corrige permissões e donos básicos (não altera owner se não executado como root)
fix_permissions() {
  local target="$1"
  # garante leitura/executável para todos onde aplicável, e escrita para owner
  if [ -d "$target" ]; then
    chmod -R u+rwX,go+rX "$target" 2>/dev/null || true
  fi
  return 0
}

# executa hooks se existirem: hooks/pre-extract/<pkg>, hooks/post-extract/<pkg>
run_hook_if_exists() {
  local phase="$1" pkg="$2"
  local hook="${ROOT}/hooks/${phase}/${pkg}"
  if [ -x "$hook" ]; then
    log_info "Executando hook ${phase} para $pkg"
    if ! "$hook" >>"$LOGGER_CURRENT_OUT" 2>>"$LOGGER_CURRENT_ERR"; then
      log_warn "Hook ${phase}/${pkg} retornou não-zero (considere revisar)"
    fi
  fi
}

# cria backup do build atual (tarball) antes de sobrescrever
backup_previous_build() {
  local pkg="$1"
  local target="$2"
  local pkgdb="$DB_DIR/$pkg"
  local backup_dir="$pkgdb/backup"
  if [ ! -d "$target" ]; then
    return 0
  fi
  if [ "${KEEP_PREVIOUS_BUILD}" != "yes" ]; then
    rm -rf "$target"
    return 0
  fi
  mkdir -p "$backup_dir"
  local timestamp
  timestamp=$(_now | sed 's/[:T-]/_/g' | sed 's/Z//g')
  local archive="$backup_dir/${pkg}_pre_extract_${timestamp}.tar.xz"
  log_info "Fazendo backup do build anterior em $archive"
  (cd "$target" && tar -cJf "$archive" .) >>"$LOGGER_CURRENT_OUT" 2>>"$LOGGER_CURRENT_ERR" || {
    log_warn "Backup do build anterior falhou para $pkg (continuando sem backup)"
    rm -f "$archive" 2>/dev/null || true
  }
}

# rollback básico: restaura backup mais recente se existir
rollback_extract() {
  local pkg="$1"
  local pkgdb="$DB_DIR/$pkg"
  local backup_dir="$pkgdb/backup"
  if [ ! -d "$backup_dir" ]; then
    log_warn "Rollback: nenhum backup encontrado para $pkg"
    return 1
  fi
  # pegar arquivo mais recente
  local latest
  latest=$(ls -1t "$backup_dir"/* 2>/dev/null | head -n1 || true)
  if [ -z "$latest" ] || [ ! -f "$latest" ]; then
    log_warn "Rollback: nenhum arquivo de backup válido encontrado para $pkg"
    return 2
  fi
  local target_dir="$BUILD_DIR/$pkg"
  log_info "Rollback: restaurando $latest para $target_dir"
  rm -rf "$target_dir" 2>/dev/null || true
  mkdir -p "$target_dir"
  tar -xJf "$latest" -C "$target_dir" >>"$LOGGER_CURRENT_OUT" 2>>"$LOGGER_CURRENT_ERR" || {
    log_error "Rollback: falha ao extrair backup $latest"
    return 3
  }
  log_set_status "$pkg" "extract" "ROLLED_BACK" "Restaurado a partir de $latest"
  return 0
}

# detectar erros silenciosos após extração/aplicação de patch
detect_silent_errors_extract() {
  # procura padrões nos logs do pacote atual
  local patterns="error|failed|Hunk FAILED|Reversed|malformed|truncated|unexpected EOF|Permission denied"
  if grep -Ei "$patterns" "$LOGGER_CURRENT_ERR" 2>/dev/null >/dev/null; then
    log_warn "Detectados padrões suspeitos durante a extração/aplicação de patches para ${CURRENT_PKG}"
    return 1
  fi
  # também analisar output caso stderr vazio
  if [ -s "$LOGGER_CURRENT_OUT" ] && grep -Ei "$patterns" "$LOGGER_CURRENT_OUT" 2>/dev/null >/dev/null; then
    log_warn "Detectados padrões suspeitos no stdout durante extração para ${CURRENT_PKG}"
    return 1
  fi
  return 0
}

# ----------------------------
# Fluxo principal para extrair um pacote
# ----------------------------
# args: desc_file
extract_pkg() {
  local desc_file="$1"
  local name version url sha256
  name=$(grep -E '^NAME' "$desc_file" | cut -d'=' -f2- | xargs || true)
  version=$(grep -E '^VERSION' "$desc_file" | cut -d'=' -f2- | xargs || true)
  url=$(grep -E '^URL' "$desc_file" | cut -d'=' -f2- | xargs || true)
  sha256=$(grep -E '^SHA256' "$desc_file" | cut -d'=' -f2- | xargs || true)

  if [ -z "$name" ] || [ -z "$version" ]; then
    log_error "DESC inválido (NAME/VERSION ausente): $desc_file"
    return 1
  fi

  local pkg="${name}-${version}"
  export CURRENT_PKG="$pkg"   # usado nos handlers/traps
  local tarball="$SRC_DIR/${pkg}.tar.xz"
  local target_dir="$BUILD_DIR/$pkg"

  log_start "extract" "$pkg"

  # verifica pré-condições
  if [ ! -f "$tarball" ]; then
    log_error "Tarball ausente para $pkg: $tarball"
    log_end 1
    return 1
  fi

  if ! check_disk_space "$BUILD_DIR" "$MIN_FREE_MB"; then
    log_end 1
    return 1
  fi

  # teste rápido do tarball
  if ! test_tarball "$tarball"; then
    log_error "Tarball inválido/integro falhou: $tarball"
    log_end 1
    return 1
  fi

  # backup do build anterior
  backup_previous_build "$pkg" "$target_dir"

  # hook pre-extract
  run_hook_if_exists "pre-extract" "$pkg"

  # extrair para tmp e mover
  if ! extract_to_temp "$tarball" "$target_dir"; then
    log_error "Falha na extração de $pkg"
    rollback_extract "$pkg" || true
    log_end 1
    return 1
  fi

  # aplicar patches (se existirem)
  if ! apply_patches "$pkg" "$target_dir"; then
    log_error "Falha ao aplicar patches para $pkg"
    rollback_extract "$pkg" || true
    log_end 1
    return 1
  fi

  # detectar erros silenciosos
  if ! detect_silent_errors_extract; then
    log_error "Erros silenciosos detectados durante a extração de $pkg"
    rollback_extract "$pkg" || true
    log_end 1
    return 1
  fi

  # permissões
  fix_permissions "$target_dir"

  # hook post-extract
  run_hook_if_exists "post-extract" "$pkg"

  # marcar status OK
  log_set_status "$pkg" "extract" "SUCCESS" "Extraction OK"
  log_info "Extração e preparação concluídas: $pkg"
  log_end 0
  return 0
}

# ----------------------------
# Processa todos os .desc (sequencial / simples paralelismo)
# ----------------------------
extract_all() {
  log_init
  log_info "Iniciando extração de pacotes (jobs=${EXTRACT_JOBS})"

  local desc_files
  IFS=$'\n' read -r -d '' -a desc_files < <(find "${ROOT}/package" -type f -name '*.desc' -print0 2>/dev/null && printf '\0') || desc_files=()

  if [ "${#desc_files[@]}" -eq 0 ]; then
    # fallback: procurar em repo
    IFS=$'\n' read -r -d '' -a desc_files < <(find "${BUILD_DIR}" -type f -name '*.desc' -print0 2>/dev/null && printf '\0') || desc_files=()
  fi

  if [ "${#desc_files[@]}" -eq 0 ]; then
    log_warn "Nenhum arquivo .desc encontrado para extrair"
    return 0
  fi

  if [ "$EXTRACT_JOBS" -le 1 ]; then
    for d in "${desc_files[@]}"; do
      extract_pkg "$d"
    done
  else
    # simples paralelismo com limite de jobs (não muito sofisticado)
    local -a pids=()
    for d in "${desc_files[@]}"; do
      extract_pkg "$d" &
      pids+=($!)
      # controlar número de jobs
      while [ "${#pids[@]}" -ge "$EXTRACT_JOBS" ]; do
        wait -n
        # recompor pids array
        pids=($(jobs -p))
      done
    done
    # aguardar remanescentes
    for pid in "${pids[@]}"; do
      wait "$pid" || log_warn "Uma extração falhou (PID=$pid)"
    done
  fi

  log_info "Todas as extrações concluídas."
}

# ----------------------------
# Execução direta se chamado standalone
# ----------------------------
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  extract_init() {
    log_init
    mkdir -p "$BUILD_DIR" "$PATCH_DIR"
    log_info "Diretórios de build e patches prontos"
  }
  extract_init
  extract_all
fi
