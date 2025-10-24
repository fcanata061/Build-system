#!/usr/bin/env bash
#
# 09-uninstall.sh — Remove pacotes instalados com rollback, purge e verificação de órfãos
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/logger.sh" ]; then
  source "${SCRIPT_DIR}/logger.sh"
else
  log_info() { echo "[INFO] $*"; }
  log_warn() { echo "[WARN] $*"; }
  log_error() { echo "[ERROR] $*" >&2; }
  log_start() { :; }
  log_end() { :; }
fi

# Configurações padrão
: "${ROOT:=/}"
: "${PKGDB_DIR:=/var/lib/pkgdb}"
: "${LOG_DIR:=/var/log/pkg/uninstall}"
: "${BACKUP_DIR:=/var/backups/pkg}"
: "${HOOKS_DIR:=/hooks/post-uninstall}"
: "${ROLLBACK_ON_ERROR:=yes}"
: "${DRY_RUN:=no}"
: "${SILENT_PATTERNS:=permission denied|busy|read-only|not found|input/output error}"

mkdir -p "$LOG_DIR" "$BACKUP_DIR"

usage() {
  cat <<EOF
Uso: $0 [opções] <pacote>
Opções:
  --purge         Remove configs e dados de usuário
  --verify-only   Apenas verifica arquivos instalados
  --deps-clean    Remove pacotes órfãos após desinstalação
  --no-rollback   Desativa rollback automático
  --dry-run       Mostra o que seria removido
  --help
EOF
  exit 1
}

# Argumentos
PURGE=no
VERIFY_ONLY=no
DEPS_CLEAN=no

while [ $# -gt 0 ]; do
  case "$1" in
    --purge) PURGE=yes ;;
    --verify-only) VERIFY_ONLY=yes ;;
    --deps-clean) DEPS_CLEAN=yes ;;
    --no-rollback) ROLLBACK_ON_ERROR=no ;;
    --dry-run) DRY_RUN=yes ;;
    --help) usage ;;
    --*) echo "Opção desconhecida: $1"; usage ;;
    *) break ;;
  esac
  shift
done

if [ $# -lt 1 ]; then usage; fi
PKG="$1"
PKG_DIR="${PKGDB_DIR}/${PKG}"
LOG_FILE="${LOG_DIR}/${PKG}.log"
BACKUP_FILE="${BACKUP_DIR}/${PKG}_$(date -u +%Y%m%dT%H%M%SZ).tar.gz"

exec > >(tee -a "$LOG_FILE") 2>&1
log_start "uninstall" "$PKG"
log_info "Iniciando remoção de $PKG (purge=$PURGE, verify=$VERIFY_ONLY, deps_clean=$DEPS_CLEAN)"

if [ ! -d "$PKG_DIR" ]; then
  log_error "Pacote não encontrado em $PKGDB_DIR"
  exit 1
fi

FILES_LIST="${PKG_DIR}/files.list"
if [ ! -f "$FILES_LIST" ]; then
  log_error "Arquivo files.list não encontrado. Instalação corrompida."
  exit 1
fi

TOTAL_FILES=$(wc -l < "$FILES_LIST")
log_info "Total de arquivos registrados: $TOTAL_FILES"

# Backup antes de remover
if [ "$VERIFY_ONLY" = "no" ] && [ "$DRY_RUN" = "no" ]; then
  tar -czf "$BACKUP_FILE" -T "$FILES_LIST" --ignore-failed-read 2>/dev/null || log_warn "Backup parcial criado"
  log_info "Backup salvo em $BACKUP_FILE"
fi

# Função segura de remoção
safe_remove() {
  local file="$1"
  [ -z "$file" ] && return 0
  if [ ! -e "$file" ]; then
    log_warn "Arquivo já inexistente: $file"
    return 0
  fi
  # segurança extra
  local real="$(realpath "$file")"
  [[ "$real" == /usr/* || "$real" == /etc/* || "$real" == /var/* || "$real" == /opt/* ]] || {
    log_warn "Ignorando caminho suspeito fora do sistema: $real"
    return 0
  }
  # verificar se outro pacote usa o arquivo
  if grep -q "$real" "$PKGDB_DIR"/*/files.list 2>/dev/null | grep -v "$PKG_DIR"; then
    log_warn "Arquivo compartilhado, ignorado: $real"
    return 0
  fi
  if [ "$DRY_RUN" = "yes" ]; then
    echo "[DRY-RUN] Remover $real"
    return 0
  fi
  if ! rm -f "$real" 2>>"$LOG_FILE"; then
    log_error "Falha ao remover $real"
    return 1
  fi
}

# Verificação de integridade (modo --verify-only)
if [ "$VERIFY_ONLY" = "yes" ]; then
  MISSING=0
  while read -r f; do
    [ -e "$f" ] || { log_warn "Arquivo ausente: $f"; MISSING=$((MISSING+1)); }
  done < "$FILES_LIST"
  log_info "Verificação concluída: $MISSING arquivos ausentes"
  exit 0
fi
# Remoção principal
REMOVED=0
FAILED=0
while read -r f; do
  if safe_remove "$f"; then
    REMOVED=$((REMOVED+1))
  else
    FAILED=$((FAILED+1))
  fi
done < "$FILES_LIST"

log_info "Removidos: $REMOVED / Falhas: $FAILED"

# PURGE — limpa configs e caches adicionais
if [ "$PURGE" = "yes" ]; then
  log_info "Executando modo --purge"
  for path in "/etc/${PKG}" "/var/cache/${PKG}" "/var/lib/${PKG}" "/opt/${PKG}" "$HOME/.config/${PKG}"; do
    if [ -d "$path" ]; then
      log_info "Removendo diretório $path"
      [ "$DRY_RUN" = "yes" ] || rm -rf "$path"
    fi
  done
fi

# Limpa diretórios vazios
log_info "Removendo diretórios vazios..."
find /usr /etc /var /opt -type d -empty -delete 2>/dev/null || true

# Executa hook pós-uninstall se existir
if [ -x "${HOOKS_DIR}/${PKG}" ]; then
  log_info "Executando hook pós-desinstalação: ${HOOKS_DIR}/${PKG}"
  bash "${HOOKS_DIR}/${PKG}" || log_warn "Hook pós-uninstall retornou erro"
fi

# Integração com sistema de dependências para limpar órfãos
if [ "$DEPS_CLEAN" = "yes" ]; then
  log_info "Verificando pacotes órfãos..."
  ORPHANS_TMP="$(mktemp)"
  for pkgdb in "${PKGDB_DIR}"/*/deps.list; do
    [ -f "$pkgdb" ] || continue
    dep_pkg=$(basename "$(dirname "$pkgdb")")
    if ! grep -q "$dep_pkg" "${PKGDB_DIR}"/*/deps.list 2>/dev/null; then
      echo "$dep_pkg" >> "$ORPHANS_TMP"
    fi
  done
  if [ -s "$ORPHANS_TMP" ]; then
    log_info "Pacotes órfãos detectados:"
    cat "$ORPHANS_TMP"
    while read -r orphan; do
      log_info "Removendo órfão: $orphan"
      "$0" "$orphan" --no-rollback || log_warn "Falha ao remover órfão $orphan"
    done < "$ORPHANS_TMP"
    mv "$ORPHANS_TMP" "${PKGDB_DIR}/orphans.list"
  else
    log_info "Nenhum órfão encontrado."
  fi
fi

# Rollback se falhas detectadas
if [ "$FAILED" -gt 0 ] && [ "$ROLLBACK_ON_ERROR" = "yes" ]; then
  log_warn "Falhas detectadas, revertendo mudanças..."
  tar -xpf "$BACKUP_FILE" -C / || log_error "Falha ao restaurar backup"
  echo "ROLLBACK=TRIGGERED" > "${PKG_DIR}/uninstall.status"
  echo "STATUS=UNINSTALL_ROLLBACK" >> "${PKG_DIR}/uninstall.status"
  log_end 1
  exit 1
fi

# Atualiza pkgdb
{
  echo "PKG=$PKG"
  echo "REMOVED=$REMOVED"
  echo "FAILED=$FAILED"
  echo "PURGE=$PURGE"
  echo "ROLLBACK=NOT_TRIGGERED"
  echo "STATUS=UNINSTALLED_OK"
  echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "${PKG_DIR}/uninstall.status"

# Remove pkgdb se desinstalado com sucesso
if [ "$FAILED" -eq 0 ] && [ "$DRY_RUN" = "no" ]; then
  rm -rf "$PKG_DIR"
  log_info "Removido banco de dados de $PKG"
fi

# Detecção de erros silenciosos
if grep -Ei "$SILENT_PATTERNS" "$LOG_FILE" >/dev/null; then
  log_warn "Erros silenciosos detectados durante a remoção."
  echo "STATUS=UNINSTALL_WARN" >> "${PKG_DIR}/uninstall.status"
fi

log_info "Desinstalação concluída: $PKG"
log_end 0
exit 0
