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
      # Note: SOPS-nix automatically interprets slash as separator for nested YAML
      # ############################################################################
      "boot/luksSwapUUID" = {
        mode = "0400";
        owner = "root";
      };

      "boot/luksRootUUID" = {
        mode = "0400";
        owner = "root";
      };

      "boot/bootPartitionUUID" = {
        mode = "0400";
        owner = "root";
      };

      "boot/timeout" = {
        mode = "0444";
        owner = "root";
      };

      "boot/configLimit" = {
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # USER CONFIGURATION
      # ############################################################################
      "user/mainUser" = {
        mode = "0444";
        owner = "root";
      };

      "user/mainUserHashedPassword" = {
        mode = "0400";
        owner = "root";
      };

      "user/mainUserDescription" = {
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # SECURITY CONFIGURATION
      # ############################################################################
      "security/sudoPasswdTimeout" = {
        mode = "0444";
        owner = "root";
      };

      "security/sudoTimestampTimeout" = {
        mode = "0444";
        owner = "root";
      };

      "security/sudoPasswdTries" = {
        mode = "0444";
        owner = "root";
      };

      "security/sudoSecurePath" = {
        mode = "0444";
        owner = "root";
      };

      "security/sudoLogFile" = {
        mode = "0444";
        owner = "root";
      };

      "security/sudoMaxSeq" = {
        mode = "0444";
        owner = "root";
      };

      "security/loginFailDelay" = {
        mode = "0444";
        owner = "root";
      };

      "security/shadowHashRounds" = {
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # NIX CONFIGURATION
      # Note: SOPS-nix automatically interprets slash as separator for nested YAML
      # ############################################################################
      "nix/experimentalFeatures" = {
        mode = "0444";
        owner = "root";
      };

      "nix/autoOptimiseStore" = {
        mode = "0444";
        owner = "root";
      };

      "nix/trustedUsers" = {
        mode = "0444";
        owner = "root";
      };

      "nix/allowedUsers" = {
        mode = "0444";
        owner = "root";
      };

      "nix/allowUnfree" = {
        mode = "0444";
        owner = "root";
      };

      "nix/permittedInsecurePackages" = {
        mode = "0444";
        owner = "root";
      };

      "nix/allowUnfreeList" = {
        mode = "0444";
        owner = "root";
      };

      "nix/substituters" = {
        mode = "0444";
        owner = "root";
      };

      "nix/trustedPublicKeys" = {
        mode = "0444";
        owner = "root";
      };

      "nix/gcAutomatic" = {
        mode = "0444";
        owner = "root";
      };

      "nix/gcDates" = {
        mode = "0444";
        owner = "root";
      };

      "nix/gcOptions" = {
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # LOCALIZATION
      # ############################################################################
      "locale/timeZone" = {
        mode = "0444";
        owner = "root";
      };

      "locale/defaultLocale" = {
        mode = "0444";
        owner = "root";
      };

      "locale/consoleKeyMap" = {
        mode = "0444";
        owner = "root";
      };

      "locale/keyboardLayout" = {
        mode = "0444";
        owner = "root";
      };

      # ############################################################################
      # USBGUARD CONFIGURATION
      # ############################################################################
      "usbguard/allowedDevices" = {
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
