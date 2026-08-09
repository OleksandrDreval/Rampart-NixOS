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
    CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
    AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem & Process Isolation
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    StateDirectory = "blocky";  # Writable /var/lib/blocky for persistent data
    ProtectHome = true;         # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
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
    RemoveIPC = true;           # Clean up IPC objects on service stop

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    # NOTE: upstream NixOS explicitly requires @chown in SystemCallFilter.
    # Therefore, we block specific privileged groups individually rather than using ~@privileged.
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@module"         # Block kernel module operations
      "~@raw-io"         # Block raw I/O operations
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@mount"          # Block filesystem mounting
      "~@keyring"        # Block kernel keyring access
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@obsolete"       # Block deprecated system calls
      "~@debug"          # Block debugging/tracing syscalls (ptrace, etc.)
    ];

    # Other Security Settings
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
  };
}
