# Security Modules Coordinator
# Combines all security-related modules with conditional imports

{ config, lib, ... }:

{
  options.rampart.security = {
    enable = lib.mkEnableOption "Enable security hardening modules";

    level = lib.mkOption {
      type = lib.types.enum [ "minimal" "standard" "paranoid" ];
      default = "standard";
      description = ''
        Security hardening level:
        - minimal: Basic security features
        - standard: Recommended security setup
        - paranoid: Maximum security (may break some apps)
      '';
    };

    apparmor = lib.mkEnableOption "Enable AppArmor Mandatory Access Control";
    usbguard = lib.mkEnableOption "Enable USBGuard device authorization";

    privilegeEscalation = lib.mkOption {
      type = lib.types.enum [ "sudo" "doas" "run0" ];
      default = "sudo";
      description = ''
        Privilege escalation method:
        - sudo: Traditional sudo (feature-rich)
        - doas: OpenBSD doas (simpler, smaller attack surface)
        - run0: systemd-run based (no SUID, modern architecture)
      '';
    };
  };

  config = lib.mkIf config.rampart.security.enable {
    imports = lib.mkMerge [
      # Always import permissions and hardened services
      [
        ./nixos-permissions.nix
        ./hardened-services
      ]

      # Conditional security modules
      (lib.mkIf config.rampart.security.apparmor [
        ./mandatory-access-control/apparmor.nix
      ])
      (lib.mkIf config.rampart.security.usbguard [
        ./device-control/usbguard.nix
      ])

      # Privilege escalation (mutually exclusive)
      (lib.mkIf (config.rampart.security.privilegeEscalation == "sudo") [
        ./privilege-escalation/sudo.nix
      ])
      (lib.mkIf (config.rampart.security.privilegeEscalation == "doas") [
        ./privilege-escalation/doas.nix
      ])
      (lib.mkIf (config.rampart.security.privilegeEscalation == "run0") [
        ./privilege-escalation/run0.nix
      ])
    ];

    # Base security settings
    security = {
      polkit.enable = true;
      rtkit.enable = true;
    };

    # System hardening based on level
    boot.kernel.sysctl = lib.mkMerge [
      {
        # Standard level
        "kernel.dmesg_restrict" = lib.mkIf (config.rampart.security.level == "standard") 1;
        "kernel.kptr_restrict" = lib.mkIf (config.rampart.security.level == "standard") 2;
      }
      {
        # Paranoid level
        "kernel.yama.ptrace_scope" = lib.mkIf (config.rampart.security.level == "paranoid") 3;
        "net.core.bpf_jit_harden" = lib.mkIf (config.rampart.security.level == "paranoid") 2;
      }
    ];
  };
}
