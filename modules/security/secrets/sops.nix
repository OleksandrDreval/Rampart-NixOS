{ config, lib, ... }:

# SOPS (Secrets OPerationS) Configuration
# Manages encrypted secrets for NixOS using age encryption
# Secrets are stored encrypted in Git and decrypted during system activation

{
  sops = {
    # Default secrets file - contains all system secrets
    # This file should be encrypted with SOPS before committing to Git
    defaultSopsFile = ../../../secrets/secrets.yaml;

    # Default format for secrets files
    defaultSopsFormat = "yaml";

    # Validate secrets on rebuild (recommended)
    validateSopsFiles = true;

    # Age encryption configuration
    age = {
      # Automatically convert SSH host keys to age keys for decryption
      # This allows the system to decrypt secrets using its SSH host key
      sshKeyPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];

      # Alternative: Use a dedicated age key file
      # Uncomment if you prefer a separate key:
      # keyFile = "/var/lib/sops-nix/key.txt";
      # generateKey = true;  # Auto-generate if doesn't exist
    };

    # Secrets configuration
    # Each secret will be decrypted to /run/secrets/<name>
    # Note: system, hostName, stateVersion are PUBLIC (in flake-public-vars.nix)
    secrets = {
      # ############################################################################
      # BOOT CONFIGURATION
      # Note: Using 'key' attribute with dot notation for nested YAML structures
      # ############################################################################
      "boot/luksSwapUUID" = {
        key = "boot.luksSwapUUID";
        mode = "0400";
        owner = "root";
      };

      "boot/luksRootUUID" = {
        key = "boot.luksRootUUID";
        mode = "0400";
        owner = "root";
      };

      "boot/bootPartitionUUID" = {
        key = "boot.bootPartitionUUID";
        mode = "0400";
        owner = "root";
      };

      "boot/timeout" = {
        key = "boot.timeout";
        mode = "0444";
        owner = "root";
      };

      "boot/configLimit" = {
        key = "boot.configLimit";
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # USER CONFIGURATION
      # Note: Using 'key' attribute with dot notation for nested YAML structures
      # ############################################################################
      "user/mainUser" = {
        key = "user.mainUser";
        mode = "0444";
        owner = "root";
      };

      "user/mainUserHashedPassword" = {
        key = "user.mainUserHashedPassword";
        mode = "0400";
        owner = "root";
      };

      "user/mainUserDescription" = {
        key = "user.mainUserDescription";
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # SECURITY CONFIGURATION
      # Note: Using 'key' attribute with dot notation for nested YAML structures
      # ############################################################################
      "security/sudoPasswdTimeout" = {
        key = "security.sudoPasswdTimeout";
        mode = "0444";
        owner = "root";
      };

      "security/sudoTimestampTimeout" = {
        key = "security.sudoTimestampTimeout";
        mode = "0444";
        owner = "root";
      };

      "security/sudoPasswdTries" = {
        key = "security.sudoPasswdTries";
        mode = "0444";
        owner = "root";
      };

      "security/sudoSecurePath" = {
        key = "security.sudoSecurePath";
        mode = "0444";
        owner = "root";
      };

      "security/sudoLogFile" = {
        key = "security.sudoLogFile";
        mode = "0444";
        owner = "root";
      };

      "security/sudoMaxSeq" = {
        key = "security.sudoMaxSeq";
        mode = "0444";
        owner = "root";
      };

      "security/loginFailDelay" = {
        key = "security.loginFailDelay";
        mode = "0444";
        owner = "root";
      };

      "security/shadowHashRounds" = {
        key = "security.shadowHashRounds";
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # NIX CONFIGURATION
      # Fix: Use 'key' attribute with dot notation for nested YAML structures
      # SOPS interprets slash as level separator but expects intermediate levels
      # to be strings, not objects. Using 'key' with dots resolves this.
      # ############################################################################
      "nix/experimentalFeatures" = {
        key = "nix.experimentalFeatures";
        mode = "0444";
        owner = "root";
      };

      "nix/autoOptimiseStore" = {
        key = "nix.autoOptimiseStore";
        mode = "0444";
        owner = "root";
      };

      "nix/trustedUsers" = {
        key = "nix.trustedUsers";
        mode = "0444";
        owner = "root";
      };

      "nix/allowedUsers" = {
        key = "nix.allowedUsers";
        mode = "0444";
        owner = "root";
      };

      "nix/allowUnfree" = {
        key = "nix.allowUnfree";
        mode = "0444";
        owner = "root";
      };

      "nix/permittedInsecurePackages" = {
        key = "nix.permittedInsecurePackages";
        mode = "0444";
        owner = "root";
      };

      "nix/allowUnfreeList" = {
        key = "nix.allowUnfreeList";
        mode = "0444";
        owner = "root";
      };

      "nix/substituters" = {
        key = "nix.substituters";
        mode = "0444";
        owner = "root";
      };

      "nix/trustedPublicKeys" = {
        key = "nix.trustedPublicKeys";
        mode = "0444";
        owner = "root";
      };

      "nix/gcAutomatic" = {
        key = "nix.gcAutomatic";
        mode = "0444";
        owner = "root";
      };

      "nix/gcDates" = {
        key = "nix.gcDates";
        mode = "0444";
        owner = "root";
      };

      "nix/gcOptions" = {
        key = "nix.gcOptions";
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # LOCALIZATION
      # Note: Using 'key' attribute with dot notation for nested YAML structures
      # ############################################################################
      "locale/timeZone" = {
        key = "locale.timeZone";
        mode = "0444";
        owner = "root";
      };

      "locale/defaultLocale" = {
        key = "locale.defaultLocale";
        mode = "0444";
        owner = "root";
      };

      "locale/consoleKeyMap" = {
        key = "locale.consoleKeyMap";
        mode = "0444";
        owner = "root";
      };

      "locale/keyboardLayout" = {
        key = "locale.keyboardLayout";
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # USBGUARD CONFIGURATION
      # Note: Using 'key' attribute with dot notation for nested YAML structures
      # ############################################################################
      "usbguard/allowedDevices" = {
        key = "usbguard.allowedDevices";
        mode = "0444";
        owner = "root";
      };
    };
  };

  # Helper functions to read secrets
  # Usage in other modules:
  #   vars.hostName = lib.strings.fileContents config.sops.secrets."system/hostName".path;

  # Note: Secrets are available at runtime in /run/secrets/
  # Example paths:
  #   /run/secrets/system/hostName
  #   /run/secrets/user/mainUserHashedPassword
  #   /run/secrets/boot/luksRootUUID
}
