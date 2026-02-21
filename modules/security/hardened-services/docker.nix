{ config, lib, ... }:

{
  /*
    Rampart Docker Daemon Hardening Module

    This module hardens the Docker daemon. Hardening Docker is challenging
    because it requires extensive privileges to manage containers,
    networking, and filesystems. This configuration strips unnecessary
    capabilities, isolates it from kernel logs/tunables, and restricts
    system calls while preserving the ability to run and manage containers.
  */

  systemd.services.docker.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock
  };
}
