# Core System Modules Coordinator
# Automatically imports all core system modules with smart defaults

{ config, lib, ... }:

{
  imports = [
    ./hardware-configuration.nix
    ./boot.nix
    ./entropy.nix
    ./filesystems.nix
    ./memory.nix
    # ./kernel.nix is optional, depending on security requirements
    # ./boot-secure.nix conflicts with boot.nix
  ];

  options.rampart.core = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable core system modules";
    };

    bootMode = lib.mkOption {
      type = lib.types.enum [ "standard" "secure" ];
      default = "standard";
      description = ''
        Boot configuration mode:
        - standard: systemd-boot
        - secure: Lanzaboote with Secure Boot
      '';
    };

    enableKernelHardening = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable advanced kernel hardening (may break compatibility)";
    };
  };

  # Configuration based on options would go here if needed
  # Currently core modules are always imported
}
