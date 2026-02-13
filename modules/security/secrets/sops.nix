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
    secrets = {
      # System configuration
      "system/hostName" = {
        mode = "0444";  # Read-only by all (non-sensitive metadata)
        owner = "root";
        group = "root";
      };

      # Boot configuration
      "boot/luksSwapUUID" = {
        mode = "0400";  # Read-only by root only
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

      # User credentials
      "user/mainUser" = {
        mode = "0444";
        owner = "root";
      };
      
      "user/mainUserHashedPassword" = {
        mode = "0400";  # Sensitive - root only
        owner = "root";
      };
      
      "user/mainUserDescription" = {
        mode = "0444";
        owner = "root";
      };

      # Security settings (can be shared)
      "security/sudoTimeout" = { mode = "0444"; };
      "security/loginFailDelay" = { mode = "0444"; };
      "security/shadowHashRounds" = { mode = "0444"; };

      # Locale settings (non-sensitive)
      "locale/timeZone" = { mode = "0444"; };
      "locale/defaultLocale" = { mode = "0444"; };
      "locale/consoleKeyMap" = { mode = "0444"; };
      "locale/keyboardLayout" = { mode = "0444"; };

      # Example: Service-specific secrets
      # Uncomment and customize as needed:
      
      # "services/postgresql/password" = {
      #   mode = "0400";
      #   owner = "postgres";
      #   group = "postgres";
      # };
      
      # "services/api/token" = {
      #   mode = "0400";
      #   owner = "myapp";
      #   group = "myapp";
      # };
      
      # "ssh/privateKey" = {
      #   mode = "0600";
      #   owner = config.users.users.mainUser.name;
      # };
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
