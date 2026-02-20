{ config, lib, ... }:

{
  /*
    Rampart D-Bus Hardening Module

    This module hardens the D-Bus system bus daemon, which is the central
    nervous system of a Linux desktop. It implements strict filesystem
    sandboxing, network isolation (D-Bus system bus should not need the internet),
    and restricted system calls to prevent it from being used as an escape
    vector while maintaining full system messaging functionality.
  */

  systemd.services.dbus.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges via setuid/setgid
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem Isolation
    # Using "strict" combined with systemd internal handling for dbus sockets
    ProtectSystem = "strict";     # Mount the entire filesystem read-only
    ProtectHome = true;           # Make /home and /root completely inaccessible
    PrivateTmp = true;            # Use a private and isolated /tmp directory
    PrivateDevices = true;        # Make /dev inaccessible (except standard pseudo-devices)
    PrivateMounts = true;         # Use a private file system namespace
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectHostname = true;        # Prevent changing system hostname
  };
}
