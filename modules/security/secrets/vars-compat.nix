{ config, lib, ... }:

# Variables Migration Helper from SOPS Secrets
# Reconstructs the vars structure from:
# - Public values: modules/includes/flake-public-vars.nix (system, hostName, stateVersion)
# - Encrypted values: secrets/secrets.yaml via SOPS (all other configuration)

let
  # Import public variables (used by flake.nix outputs)
  publicVars = import ../../includes/flake-public-vars.nix;

  # Helper to get secret placeholder (for string values)
  # SOPS replaces placeholders with actual values during system activation
  # This allows using secrets in configuration without reading files during evaluation
  readSecret = secretPath:
    builtins.getAttr secretPath config.sops.placeholder;

  # Helper to read secret file content directly (for runtime-parsed values)
  # Note: This requires --impure and only works after secrets are decrypted
  readSecretFile = secretPath:
    config.sops.secrets.${secretPath}.path;

  # Helper to read secret and parse as integer
  # For typed values, we must read from file path (not placeholder)
  readSecretInt = secretPath:
    lib.strings.toInt (lib.strings.trim (builtins.readFile (readSecretFile secretPath)));

  # Helper to read secret and parse as boolean
  readSecretBool = secretPath:
    let value = lib.strings.trim (builtins.readFile (readSecretFile secretPath));
    in value == "true" || value == "1";

  # Helper to read secret and parse as list (YAML array stored as newline-separated)
  readSecretList = secretPath:
    let
      content = lib.strings.trim (builtins.readFile (readSecretFile secretPath));
    in
      if content == "" || content == "[]" || content == "[ ]"
      then []
      else
        # Try to parse as JSON array first
        if lib.strings.hasPrefix "[" content
        then builtins.fromJSON content
        # Otherwise split by newlines
        else lib.filter (x: x != "") (lib.strings.splitString "\n" content);

  # Reconstruct the vars structure
  vars = {
    # ############################################################################
    # PUBLIC CONFIGURATION (from flake-public-vars.nix)
    # ############################################################################
    system = publicVars.system;
    hostName = publicVars.hostName;
    stateVersion = publicVars.stateVersion;

    # ############################################################################
    # DISK ENCRYPTION (from SOPS secrets)
    # ############################################################################
    luksSwapUUID = readSecret "boot/luksSwapUUID";
    luksRootUUID = readSecret "boot/luksRootUUID";
    bootPartitionUUID = readSecret "boot/bootPartitionUUID";

    # ############################################################################
    # USER CONFIGURATION
    # ############################################################################
    mainUser = readSecret "user/mainUser";
    mainUserDescription = readSecret "user/mainUserDescription";
    mainUserHashedPassword = readSecret "user/mainUserHashedPassword";

    # ############################################################################
    # BOOT CONFIGURATION
    # ############################################################################
    bootTimeout = readSecretInt "boot/timeout";
    bootConfigLimit = readSecretInt "boot/configLimit";

    # ############################################################################
    # SECURITY CONFIGURATION
    # ############################################################################
    sudoPasswdTimeout = readSecretInt "security/sudoPasswdTimeout";
    sudoTimestampTimeout = readSecretInt "security/sudoTimestampTimeout";
    sudoPasswdTries = readSecretInt "security/sudoPasswdTries";
    sudoSecurePath = readSecret "security/sudoSecurePath";
    sudoLogFile = readSecret "security/sudoLogFile";
    sudoMaxSeq = readSecretInt "security/sudoMaxSeq";
    loginFailDelay = readSecretInt "security/loginFailDelay";
    shadowHashRounds = readSecretInt "security/shadowHashRounds";

    # ############################################################################
    # NIX CONFIGURATION
    # ############################################################################
    nixExperimentalFeatures = readSecretList "nix/experimentalFeatures";
    nixAutoOptimiseStore = readSecretBool "nix/autoOptimiseStore";
    nixTrustedUsers = readSecretList "nix/trustedUsers";
    nixAllowedUsers = readSecretList "nix/allowedUsers";
    allowUnfree = readSecretBool "nix/allowUnfree";
    permittedInsecurePackages = readSecretList "nix/permittedInsecurePackages";
    allowUnfreeList = readSecretList "nix/allowUnfreeList";
    substituters = readSecretList "nix/substituters";
    trustedPublicKeys = readSecretList "nix/trustedPublicKeys";
    gcAutomatic = readSecretBool "nix/gcAutomatic";
    gcDates = readSecret "nix/gcDates";
    gcOptions = readSecret "nix/gcOptions";

    # ############################################################################
    # LOCALIZATION
    # ############################################################################
    timeZone = readSecret "locale/timeZone";
    defaultLocale = readSecret "locale/defaultLocale";
    consoleKeyMap = readSecret "locale/consoleKeyMap";
    keyboardLayout = readSecret "locale/keyboardLayout";

    # ############################################################################
    # USBGUARD CONFIGURATION
    # ############################################################################
    usbguardAllowedDevices = readSecretList "usbguard/allowedDevices";
  };
in

# This module returns vars directly (not wrapped in attrset)
# Import it in other modules with appropriate relative path:
#
# Example from modules/core/boot.nix:
#   vars = import ../security/secrets/vars-compat.nix { inherit config lib; };
#
# Example from modules/networking/networking.nix:
#   vars = import ../security/secrets/vars-compat.nix { inherit config lib; };
#
# Then use: vars.hostName, vars.mainUser, etc.

vars
