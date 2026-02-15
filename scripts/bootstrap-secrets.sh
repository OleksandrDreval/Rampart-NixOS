#!/usr/bin/env bash

# Bootstrap script for SOPS secrets - first-time system build
# This script decrypts secrets.yaml and populates /run/secrets/
# so nixos-rebuild can read them during the first build.
#
# USAGE: Run from within nix-shell WITHOUT sudo:
#   nix-shell -p sops yq-go
#   ./scripts/bootstrap-secrets.sh

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly SECRETS_FILE="$PROJECT_ROOT/secrets/secrets.yaml"
readonly SECRETS_DIR="/run/secrets"

# Color output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Check if secrets.yaml exists
if [[ ! -f "$SECRETS_FILE" ]]; then
    log_error "Secrets file not found: $SECRETS_FILE"
    exit 1
fi

# Check if sops is available
if ! command -v sops &> /dev/null; then
    log_error "sops command not found."
    log_error "Please run this script from within nix-shell:"
    log_error "  nix-shell -p sops yq-go"
    log_error "  ./scripts/bootstrap-secrets.sh"
    exit 1
fi

# Check if yq is available
if ! command -v yq &> /dev/null; then
    log_error "yq command not found."
    log_error "Please run this script from within nix-shell:"
    log_error "  nix-shell -p sops yq-go"
    log_error "  ./scripts/bootstrap-secrets.sh"
    exit 1
fi

log_info "Creating secrets directory structure..."
sudo mkdir -p "$SECRETS_DIR"/{boot,user,security,nix,locale,usbguard}

log_info "Decrypting secrets file (once)..."

# Decrypt the entire secrets file once to avoid repeated decryption calls
readonly DECRYPTED_FILE=$(mktemp)
cleanup() {
    rm -f "$DECRYPTED_FILE"
}
trap cleanup EXIT

if ! sops -d "$SECRETS_FILE" > "$DECRYPTED_FILE"; then
    log_error "Failed to decrypt $SECRETS_FILE"
    exit 1
fi

log_info "Populating secrets..."

# Helper function to extract and write a single secret value
# Works with scalars (string/int/bool) and multiline strings (lists stored as |-blocks)
extract_secret() {
    local yaml_path="$1"
    local output_file="$2"

    local tmp_file
    tmp_file=$(mktemp)

    if ! yq -r "$yaml_path" "$DECRYPTED_FILE" > "$tmp_file"; then
        log_error "[FAILED] Failed to extract: $yaml_path"
        rm -f "$tmp_file"
        return 1
    fi

    sudo mv "$tmp_file" "$output_file"
    log_info "[OK] $(basename "$(dirname "$output_file")")/$(basename "$output_file")"
}

# Boot secrets
log_info "Boot secrets..."
extract_secret '.boot.luksRootUUID' "$SECRETS_DIR/boot/luksRootUUID"
extract_secret '.boot.luksSwapUUID' "$SECRETS_DIR/boot/luksSwapUUID"
extract_secret '.boot.bootPartitionUUID' "$SECRETS_DIR/boot/bootPartitionUUID"
extract_secret '.boot.timeout' "$SECRETS_DIR/boot/timeout"
extract_secret '.boot.configLimit' "$SECRETS_DIR/boot/configLimit"

# User secrets
log_info "User secrets..."
extract_secret '.user.mainUser' "$SECRETS_DIR/user/mainUser"
extract_secret '.user.mainUserDescription' "$SECRETS_DIR/user/mainUserDescription"
extract_secret '.user.mainUserHashedPassword' "$SECRETS_DIR/user/mainUserHashedPassword"

# Security secrets
log_info "Security secrets..."
extract_secret '.security.sudoPasswdTimeout' "$SECRETS_DIR/security/sudoPasswdTimeout"
extract_secret '.security.sudoTimestampTimeout' "$SECRETS_DIR/security/sudoTimestampTimeout"
extract_secret '.security.sudoPasswdTries' "$SECRETS_DIR/security/sudoPasswdTries"
extract_secret '.security.sudoSecurePath' "$SECRETS_DIR/security/sudoSecurePath"
extract_secret '.security.sudoLogFile' "$SECRETS_DIR/security/sudoLogFile"
extract_secret '.security.sudoMaxSeq' "$SECRETS_DIR/security/sudoMaxSeq"
extract_secret '.security.loginFailDelay' "$SECRETS_DIR/security/loginFailDelay"
extract_secret '.security.shadowHashRounds' "$SECRETS_DIR/security/shadowHashRounds"

# Nix secrets
log_info "Nix secrets..."
extract_secret '.nix.experimentalFeatures' "$SECRETS_DIR/nix/experimentalFeatures"
extract_secret '.nix.autoOptimiseStore' "$SECRETS_DIR/nix/autoOptimiseStore"
extract_secret '.nix.trustedUsers' "$SECRETS_DIR/nix/trustedUsers"
extract_secret '.nix.allowedUsers' "$SECRETS_DIR/nix/allowedUsers"
extract_secret '.nix.allowUnfree' "$SECRETS_DIR/nix/allowUnfree"
extract_secret '.nix.permittedInsecurePackages' "$SECRETS_DIR/nix/permittedInsecurePackages"
extract_secret '.nix.allowUnfreeList' "$SECRETS_DIR/nix/allowUnfreeList"
extract_secret '.nix.substituters' "$SECRETS_DIR/nix/substituters"
extract_secret '.nix.trustedPublicKeys' "$SECRETS_DIR/nix/trustedPublicKeys"
extract_secret '.nix.gcAutomatic' "$SECRETS_DIR/nix/gcAutomatic"
extract_secret '.nix.gcDates' "$SECRETS_DIR/nix/gcDates"
extract_secret '.nix.gcOptions' "$SECRETS_DIR/nix/gcOptions"

# Localization secrets
log_info "Localization secrets..."
extract_secret '.locale.timeZone' "$SECRETS_DIR/locale/timeZone"
extract_secret '.locale.defaultLocale' "$SECRETS_DIR/locale/defaultLocale"
extract_secret '.locale.consoleKeyMap' "$SECRETS_DIR/locale/consoleKeyMap"
extract_secret '.locale.keyboardLayout' "$SECRETS_DIR/locale/keyboardLayout"

# USBGuard secrets
log_info "USBGuard secrets..."
extract_secret '.usbguard.allowedDevices' "$SECRETS_DIR/usbguard/allowedDevices"

# Set proper permissions
log_info "Setting permissions..."
# Restrict directory access to root only (security hardening)
sudo chmod 700 "$SECRETS_DIR"
sudo chmod 700 "$SECRETS_DIR"/{boot,user,security,nix,locale,usbguard}
# Set strict permissions for sensitive files
sudo find "$SECRETS_DIR" -type f -name "mainUserHashedPassword" -exec chmod 400 {} \;
sudo find "$SECRETS_DIR" -type f -name "luks*" -exec chmod 400 {} \;
# Set read-only for root on all other files
sudo find "$SECRETS_DIR" -type f ! -name "mainUserHashedPassword" ! -name "luks*" -exec chmod 400 {} \;

log_info ""
log_info "[SUCCESS] Bootstrap complete! Secrets populated in $SECRETS_DIR"
log_info ""
log_info "You can now run:"
log_info "  sudo nixos-rebuild build --impure --flake .#RampartNix"
log_info ""
log_warn "NOTE: After successful 'nixos-rebuild switch', SOPS will manage these files automatically."
log_warn "      This bootstrap is only needed for the FIRST build."
