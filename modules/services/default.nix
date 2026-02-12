# Services Modules Coordinator
# Manages system services (SSH, virtualization, etc.)

{ config, lib, ... }:

{
  options.rampart.services = {
    ssh = lib.mkEnableOption "Enable SSH server/client configuration";
    virtualization = lib.mkEnableOption "Enable virtualization support (QEMU/KVM)";
  };

  config = {
    imports = lib.mkMerge [
      (lib.mkIf config.rampart.services.ssh [
        ./ssh.nix
      ])
      (lib.mkIf config.rampart.services.virtualization [
        ./virtualisation.nix
      ])
    ];
  };
}
