{ config, lib, ... }:

{
  /*
    Rampart fwupd (Firmware Update Daemon) Hardening Module

    Based on upstream fwupd.service.in and NixOS configurations.
    fwupd requires access to low-level hardware (USB, UEFI variables, PCI)
    to flash firmware, but its filesystem access can be strictly sandboxed.
  */

  systemd.services.fwupd.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = false; # Upstream explicitly sets to false
    RestrictSUIDSGID = true;
    RestrictRealtime = true;

    # Filesystem Isolation
    ProtectSystem = "full"; # Upstream uses full, not strict (needs /etc access)
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = false;

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    LockPersonality = true;
    KeyringMode = "private";
    # DeviceAllow is omitted: fwupd needs broad device access for flashing

    # Process Isolation
    RestrictNamespaces = true;
    ProtectProc = "invisible";
    RestrictAddressFamilies = [
       "AF_UNIX"
       "AF_NETLINK"
       "AF_INET"
       "AF_INET6"
    ];

    Environment = "GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK";

    # System Call Filtering
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
  };

  # fwupd-refresh updates metadata
  systemd.services.fwupd-refresh.serviceConfig = {
    NoNewPrivileges = false;
    RestrictSUIDSGID = true;
    RestrictRealtime = true;
    ProtectSystem = "full";
    ProtectHome = true;
    PrivateTmp = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    RestrictAddressFamilies = [
       "AF_UNIX"
       "AF_INET"
       "AF_INET6"
    ];
  };
}
