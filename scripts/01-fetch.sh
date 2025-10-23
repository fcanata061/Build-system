#!/usr/bin/env bash
# 01-fetch.sh - Download de fontes e descrições (.desc) com segurança e paralelismo
# Requer logger.sh (no mesmo diretório)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/logger.sh"

# ==============================
# CONFIGURAÇÕES GLOBAIS
# ==============================
: "${ROOT:=./auto-builder}"
: "${SRC_DIR:=${ROOT}/sources}"
: "${REPO_DIR:=/usr/src/repo}"
: "${DESC_DIR:=${REPO_DIR}/package}"
: "${LOG_DIR:=${ROOT}/logs}"
: "${MIRRORS:=https://ftp.gnu.org/gnu}"
: "${FETCH_JOBS:=4}"
: "${RETRY_LIMIT:=3}"
: "${RETRY_BACKOFF:=5}"
: "${VERIFY_MODE:=sha256}" # sha256|gpg|none
: "${OFFLINE_MODE:=no}"

# ==============================
# INICIALIZAÇÃO
# ==============================
fetch_init() {
  log_init
  log_info "Inicializando sistema de fetch"
  mkdir -p "$SRC_DIR" "$DESC_DIR" "$REPO_DIR" "$LOG_DIR/fetch"
}

# ==============================
# BAIXAR REPOSITÓRIO GIT (.desc e binários)
# ==============================
fetch_git_repo() {
  local git_url
  git_url=$(grep -E '^GIT_REPO=' "${ROOT}/config.txt" | cut -d'=' -f2- | xargs)
  [ -z "$git_url" ] && log_warn "Nenhum repositório GIT definido em config.txt" && return 0

  log_start "fetch" "repo"
  if [ -d "$REPO_DIR/.git" ]; then
    log_info "Atualizando repositório existente em $REPO_DIR"
    git -C "$REPO_DIR" pull --ff-only >> "$LOGGER_CURRENT_OUT" 2>> "$LOGGER_CURRENT_ERR" || {
      log_warn "Falha ao atualizar o repositório git, tentando limpar e clonar novamente..."
      rm -rf "$REPO_DIR"
      git clone --depth=1 "$git_url" "$REPO_DIR" >> "$LOGGER_CURRENT_OUT" 2>> "$LOGGER_CURRENT_ERR"
    }
  else
    log_info "Clonando repositório git: $git_url"
    git clone --depth=1 "$git_url" "$REPO_DIR" >> "$LOGGER_CURRENT_OUT" 2>> "$LOGGER_CURRENT_ERR"
  fi
  log_end $?
}

# ==============================
# VERIFICAÇÃO DE INTEGRIDADE
# ==============================
verify_integrity() {
  local file="$1"
  local expected="$2"

  if [ ! -f "$file" ]; then
    log_error "Arquivo não encontrado: $file"
    return 1
  fi

  # Verificar tamanho > 0
  if [ ! -s "$file" ]; then
    log_error "Arquivo vazio: $file"
    return 1
  fi

  # Checar tipo MIME
  if file "$file" | grep -qi 'HTML'; then
    log_error "Arquivo HTML detectado em vez de tarball válido: $file"
    return 1
  fi

  # Validar hash SHA256
  if [ "$VERIFY_MODE" = "sha256" ]; then
    local got
    got=$(sha256sum "$file" | awk '{print $1}')
    if [ "$got" != "$expected" ]; then
      log_error "SHA256 incorreto: esperado=$expected obtido=$got"
      return 1
    fi
  fi
  return 0
}

# ==============================
# DOWNLOAD COM RETRY + MIRRORS
# ==============================
try_download() {
  local url="$1"
  local dest="$2"
  local pkg="$3"
  local attempt=1

  while [ "$attempt" -le "$RETRY_LIMIT" ]; do
    log_info "Baixando ($attempt/$RETRY_LIMIT): $url"
    if curl -fL --retry 0 --connect-timeout 15 --max-time 600 -o "$dest.part" "$url" >>"$LOGGER_CURRENT_OUT" 2>>"$LOGGER_CURRENT_ERR"; then
      # Checar se é HTML ou vazio
      if ! check_html_corruption "$dest.part"; then
        mv "$dest.part" "$dest"
        return 0
      fi
    fi
    log_warn "Falha no download: tentativa $attempt"
    sleep $((RETRY_BACKOFF * attempt))
    attempt=$((attempt + 1))
  done

  # Tentar mirrors
  for mirror in $MIRRORS; do
    local mirror_url="${mirror}/$(basename "$url")"
    log_info "Tentando mirror: $mirror_url"
    if curl -fL -o "$dest.part" "$mirror_url" >>"$LOGGER_CURRENT_OUT" 2>>"$LOGGER_CURRENT_ERR"; then
      if ! check_html_corruption "$dest.part"; then
        mv "$dest.part" "$dest"
        return 0
      fi
    fi
  done

  log_error "Falha definitiva ao baixar $pkg"
  return 1
}

# ==============================
# DETECTA HTML CORROMPIDO
# ==============================
check_html_corruption() {
  local file="$1"
  if file "$file" | grep -qi 'HTML'; then
    log_warn "Download inválido (HTML recebido): $file"
    rm -f "$file"
    return 1
  fi
  return 0
}

# ==============================
# TRATAMENTO DE ERROS SILENCIOSOS
# ==============================
detect_silent_errors_fetch() {
  local logf="$1"
  grep -Eqi 'error|fail|timeout|connection refused' "$logf" && {
    log_warn "Erros silenciosos detectados no fetch: $logf"
    return 1
  }
  return 0
}

# ==============================
# FETCH DE UM PACOTE INDIVIDUAL
# ==============================
fetch_pkg() {
  local desc_file="$1"
  local name version url sha256
  name=$(grep -E '^NAME' "$desc_file" | cut -d'=' -f2 | xargs)
  version=$(grep -E '^VERSION' "$desc_file" | cut -d'=' -f2 | xargs)
  url=$(grep -E '^URL' "$desc_file" | cut -d'=' -f2 | xargs)
  sha256=$(grep -E '^SHA256' "$desc_file" | cut -d'=' -f2 | xargs)

  local pkg="${name}-${version}"
  local dest="${SRC_DIR}/${pkg}.tar.xz"

  log_start "fetch" "$pkg"

  if [ "$OFFLINE_MODE" = "yes" ]; then
    if [ -f "$dest" ] && verify_integrity "$dest" "$sha256"; then
      log_info "$pkg já está presente e válido (modo offline)"
      log_end 0
      return 0
    else
      log_error "Modo offline: pacote ausente ou inválido ($pkg)"
      log_end 1
      return 1
    fi
  fi

  # Verificar cache
  if [ -f "$dest" ] && verify_integrity "$dest" "$sha256"; then
    log_info "Cache válido encontrado: $pkg"
    log_end 0
    return 0
  fi

  # Executar download
  if ! try_download "$url" "$dest" "$pkg"; then
    log_error "Falha em todas as tentativas de download para $pkg"
    log_end 1
    return 1
  fi

  # Verificar integridade final
  if ! verify_integrity "$dest" "$sha256"; then
    rm -f "$dest"
    log_error "Falha na verificação final de integridade para $pkg"
    log_end 1
    return 1
  fi

  detect_silent_errors_fetch "$LOGGER_CURRENT_ERR" || true

  log_info "Download concluído: $pkg"
  log_end 0
}

# ==============================
# MULTI-DOWNLOAD EM PARALELO
# ==============================
fetch_all() {
  log_init
  fetch_git_repo

  log_info "Iniciando fetch de pacotes em paralelo ($FETCH_JOBS jobs)"
  local desc_files=($(find "$DESC_DIR" -type f -name '*.desc'))
  local -a pids=()

  for desc in "${desc_files[@]}"; do
    fetch_pkg "$desc" &
    pids+=($!)

    # limitar jobs paralelos
    if [ "${#pids[@]}" -ge "$FETCH_JOBS" ]; then
      wait -n
      pids=($(jobs -p))
    fi
  done

  # aguardar todos terminarem
  for pid in "${pids[@]}"; do
    wait "$pid" || log_warn "Um dos downloads falhou (PID=$pid)"
  done

  log_info "Todos os downloads concluídos."
}

# ==============================
# LIMPAR ARQUIVOS PARCIAIS
# ==============================
cleanup_partials() {
  find "$SRC_DIR" -type f -name "*.part" -delete 2>/dev/null || true
}

# ==============================
# EXECUÇÃO DIRETA
# ==============================
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  fetch_init
  cleanup_partials
  fetch_all
fi
