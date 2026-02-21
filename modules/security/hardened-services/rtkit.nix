{ config, lib, ... }:

{
  /*
    Rampart Realtime Kit (rtkit) Hardening Module

    This module hardens rtkit-daemon, which hands out realtime priority to
    user processes (like audio servers). Since it deals with process
    priorities and scheduling, it is isolated from the network, kernel
    internals, and most of the filesystem to prevent it from being abused
    to cause system-wide denial of service.
  */

  systemd.services.rtkit-daemon.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service

    # Filesystem Isolation
    ProtectSystem = "strict";  # Mount the entire filesystem read-only
    ProtectHome = true;        # Make /home and /root completely inaccessible
    PrivateTmp = true;         # Use a private and isolated /tmp directory
    PrivateMounts = true;      # Use a private file system namespace
    PrivateDevices = true;     # Make /dev inaccessible (except standard ones)

    # Kernel & Hardware Protection
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    # rtkit does not need network access at all
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "~AF_INET6"   # Disable IPv6
      "~AF_INET"    # Disable IPv4
      "~AF_PACKET"  # Disable raw packet access
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;  # Prevent W^X memory regions
    DevicePolicy = "closed";        # Allow access only to /dev/null, /dev/zero, etc.
  };
}
