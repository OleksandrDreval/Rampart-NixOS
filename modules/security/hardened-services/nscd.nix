{ config, lib, ... }:

{
  /*
    Rampart Name Service Cache Daemon (nscd) Hardening Module

    This module hardens nscd, which caches lookups for hosts, passwords,
    groups, and other databases. It hides processes, restricts system
    modifications, and blocks unnecessary root capabilities while allowing
    it to reliably provide character-to-ID lookups for the system.
  */

  systemd.services.nscd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges

    # Filesystem & Process Isolation
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    RuntimeDirectory = "nscd";  # Writable /run/nscd for socket and PID file
    PrivateTmp = true;          # Use a private and isolated /tmp directory

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    RestrictNamespaces = true; # Prohibit creation of any new namespaces

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@swap"           # Block swap management
      "~@clock"          # Block clock configuration
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
    ];
  };
}
