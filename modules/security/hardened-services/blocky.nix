{ config, lib, ... }:

{
  /*
    Rampart Blocky Hardening Module

    This module hardens Blocky, a modern DNS proxy and ad-blocker.
    Since DNS is critical for network security and privacy, we isolate
    the service, restrict its networking capabilities to only binding
    ports, and sandbox its execution environment to prevent it from
    accessing sensitive system data.
  */

  systemd.services.blocky.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    # Allow only port binding; no root-level system access
    CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
    AmbientCapabilities = "CAP_NET_BIND_SERVICE";
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem & Process Isolation
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    StateDirectory = "blocky";  # Writable /var/lib/blocky for persistent data
    ProtectHome = true;         # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace
    PrivateDevices = true;      # Deny access to hardware devices
    UMask = "0077";             # Strict file creation permissions

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Protect /proc/sys, /sys, etc.
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    # Blocky needs network access to serve DNS queries
    RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@raw-io"         # Block raw I/O access
      "~@privileged"     # Block most privileged system calls
      "~@keyring"        # Block kernel keyring access
      "~@reboot"         # Block system reboot
      "~@clock"          # Block direct clock manipulation
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@module"         # Block kernel module operations
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "ptrace"           # Explicitly block process tracing
    ];
  };
}
