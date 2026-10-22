#!/usr/bin/env bash
# Check all Node.js binaries for CVE-2026-111497 patch status.
# The patched decoder defines BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH = -17.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

check_node() {
  local bin="$1"
  local ver
  ver=$("$bin" -v 2>/dev/null) || return
  local val
  val=$("$bin" -p "require('zlib').constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH||'NO'" 2>/dev/null) || val="ERR"

  if [[ "$val" == "-17" ]]; then
    printf "${GREEN}PATCHED${NC}  %s (%s)\n" "$bin" "$ver"
  else
    printf "${RED}VULNERABLE${NC}  %s (%s) — upgrade to 22.23.4 / 24.22.1 / 26.12.1\n" "$bin" "$ver"
  fi
}

echo "=== CVE-2026-111497 Patch Check ==="
echo ""

# Check all node binaries on PATH
found=0
while IFS= read -r bin; do
  check_node "$bin"
  found=1
done < <(which -a node 2>/dev/null || true)

# Check common locations
for dir in /usr/local/bin /usr/bin /opt/homebrew/bin "$HOME/.nvm/versions/node"/*/bin "$HOME/.local/bin"; do
  if [[ -x "$dir/node" ]] && ! which -a node 2>/dev/null | grep -qF "$dir/node"; then
    check_node "$dir/node"
    found=1
  fi
done

if [[ $found -eq 0 ]]; then
  echo "No Node.js binaries found."
fi

# Check system libbrotlidec (Debian/Ubuntu)
if command -v dpkg &>/dev/null; then
  echo ""
  echo "=== System libbrotlidec ==="
  dpkg -l libbrotli1 2>/dev/null | grep -E '^ii' || echo "Not installed (Node.js uses bundled Brotli)"
fi
