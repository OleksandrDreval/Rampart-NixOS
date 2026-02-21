{ config, lib, ... }:

{
  /*
    Rampart Colord Service Hardening Module

    This module hardens the colord service, which manages color profiles for
    devices like monitors and printers. It implements strict filesystem
    sandboxing, hides processes, and restricts network access. Persistent
    storage for color profiles is maintained via a dedicated StateDirectory.
  */

  systemd.services.colord.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Block specific capabilities that are not needed for color management
    CapabilityBoundingSet = [
      "~CAP_CHOWN"
      "~CAP_FSETID"
      "~CAP_SETFCAP"
    ];

    # Filesystem Isolation
    ProtectSystem = "strict";   # Mount the entire filesystem read-only
    ProtectHome = true;         # Make /home and /root completely inaccessible
    StateDirectory = "colord";  # Allow write access to /var/lib/colord
    PrivateTmp = true;          # Use a private and isolated /tmp directory

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    # Disable network access (color management is local)
    RestrictAddressFamilies = [
      "~AF_INET6"
      "~AF_INET"
      "~AF_PACKET"
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallFilter = [
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@mount"          # Block filesystem mounting
    ];
  };
}
