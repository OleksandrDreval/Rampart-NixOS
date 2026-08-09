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
    PrivateMounts = true;       # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    PrivateNetwork = true;      # Zero network access needed (color management is local)
    IPAddressDeny = "any";      # Explicitly deny all IP traffic
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    # Disable network address families
    RestrictAddressFamilies = [
      "AF_UNIX"      # Local IPC (D-Bus)
      "AF_NETLINK"   # Monitoring device hotplug events
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@mount"          # Block filesystem mounting
      "~@module"         # Block kernel module operations
      "~@debug"          # Block debugging syscalls
      "~@reboot"         # Block system reboot
      "~@raw-io"         # Block raw I/O operations
      "~@clock"          # Block clock configuration
      "~@resources"      # Block resource limit changes
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
  };
}
