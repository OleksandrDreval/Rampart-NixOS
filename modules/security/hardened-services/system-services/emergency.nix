{ config, lib, ... }:

{
  /*
    Rampart Emergency Service Hardening Module

    This module applies MINIMAL hardening to the emergency shell service.
    emergency.service is a RECOVERY mechanism — its sole purpose is to give
    the administrator a root shell to fix a broken system. Upstream systemd
    intentionally applies ZERO hardening to this service.

    We apply only the lightest restrictions that do not impair recovery:
    - LockPersonality: prevents changing execution domain (never needed)
    - SystemCallArchitectures: blocks non-native syscall ABIs

    IMPORTANT — do NOT set any of these:
    - ProtectSystem: administrator needs to edit /etc/fstab, /etc/nixos/*, etc.
    - ProtectKernelTunables: may need to adjust sysctl for diagnosis
    - ProtectControlGroups: may need to manipulate cgroups for service repair
    - PrivateNetwork: may need network for downloading packages or SSH help
    - PrivateTmp: unnecessary complexity in emergency environment
  */

  systemd.services.emergency.serviceConfig = {
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls
  };
}
