{ config, lib, ... }:

{
  /*
    Rampart ACPI Daemon (acpid) Hardening Module

    This module hardens acpid, which handles hardware events like power
    buttons and laptop lids. It isolates the service from the network,
    hides other processes, and applies strict system call filtering to
    ensure that power management events are processed securely without
    exposing a large attack surface.
  */

  systemd.services.acpid.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Block specific capabilities that are not needed for ACPI events
    CapabilityBoundingSet = [
      "~CAP_CHOWN"
      "~CAP_FSETID"
      "~CAP_SETFCAP"
    ];

    # Filesystem & Process Isolation
    ProtectSystem = "full";     # Protect /usr, /boot, and /etc from writes
    ProtectHome = true;         # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace

    # Kernel & Hardware Protection
    # acpid needs to interact with /proc/acpi and /sys, so we are careful
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network Isolation
    PrivateNetwork = true;      # Completely isolate the service from the network
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    # Limit allowed network address families
    RestrictAddressFamilies = [
      "~AF_INET6"
      "~AF_INET"
      "~AF_PACKET"
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
    ];
  };
}
