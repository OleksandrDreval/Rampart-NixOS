{ config, lib, ... }:

{
  /*
    Rampart Rescue Service Hardening Module

    This module applies MINIMAL hardening to the rescue shell service.
    rescue.service is a RECOVERY mechanism — its purpose is to give the
    administrator a single-user root shell for system repair. Upstream
    systemd intentionally applies ZERO hardening to this service.

    We apply only the lightest restrictions that do not impair recovery:
    - LockPersonality: prevents changing execution domain (never needed)
    - SystemCallArchitectures: blocks non-native syscall ABIs

    IMPORTANT — do NOT set any of these:
    - ProtectSystem: administrator needs to edit /etc/fstab, /etc/nixos/*, etc.
    - ProtectKernelTunables: may need to adjust sysctl for diagnosis
    - ProtectControlGroups: may need to manipulate cgroups for service repair
    - PrivateNetwork: may need network for downloading packages or SSH help
    - PrivateTmp: unnecessary complexity in rescue environment
  */

  systemd.services.rescue.serviceConfig = {
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls
  };
}
