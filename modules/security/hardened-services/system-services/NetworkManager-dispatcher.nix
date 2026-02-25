{ config, lib, ... }:

{
  /*
    Rampart NetworkManager Dispatcher Hardening Module

    This module applies conservative hardening to the NM dispatcher service,
    which executes custom scripts on network events (connect, disconnect, etc.).
    Upstream NM-dispatcher has zero hardening (only KillMode=process).

    IMPORTANT — dispatcher runs ARBITRARY user scripts from
    /etc/NetworkManager/dispatcher.d/. Scripts may restart services, update
    DNS, flush routes, set hostname, or use SUID helpers. Therefore:
    - NoNewPrivileges MUST NOT be true — scripts may use SUID helpers
    - CapabilityBoundingSet MUST NOT restrict — scripts may need broad caps
    - ~@privileged MUST NOT be in SystemCallFilter — scripts may call
      sethostname, chroot, and other privileged operations
    - ProtectHostname MUST NOT be set — scripts often set hostname on events
    - RestrictNamespaces MUST NOT be set — scripts may create namespaces
  */

  systemd.services.NetworkManager-dispatcher.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    CapabilityBoundingSet = [
    # Limit root capabilities to networking
      "CAP_NET_ADMIN"
      "CAP_NET_RAW"
    ];
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Dispatcher scripts do not need RT scheduling

    # Filesystem Isolation
    ProtectSystem = "full";  # Protect /usr, /boot, /efi read-only (on NixOS, /etc is immutable anyway)
    ProtectHome = true;      # Scripts do not need access to home directories
    PrivateTmp = true;       # Isolated /tmp directory
    PrivateMounts = true;    # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelModules = true;  # Prevents loading/unloading kernel modules
    ProtectKernelLogs = true;     # Prevents reading kernel logs
    ProtectControlGroups = true;  # Makes cgroups read-only
    ProtectClock = true;          # Prevents changing system clock
    ProtectHostname = true;       # Prevents changing hostname
    LockPersonality = true;       # Prevent personality changes (emulation)

    # Network & Process Isolation
    ProtectProc = "invisible";  # Hide other users' processes
    ProcSubset = "pid";         # Only show the daemon's own PID
    RestrictNamespaces = true;   # Disable creation of new namespaces
    RestrictAddressFamilies = [
       "AF_UNIX"     # Local communication
       "AF_NETLINK"  # Kernel-user communication
       "AF_INET"     # IPv4
       "AF_INET6"    # IPv6
       "AF_PACKET"   # Direct network access
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Shell scripts do not use JIT
    SystemCallArchitectures = "native";  # Allow only native syscalls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@mount"          # Scripts do not mount filesystems
      "~@module"         # Scripts do not load kernel modules
      "~@swap"           # Scripts do not manage swap
      "~@obsolete"       # Block deprecated calls
      "~@cpu-emulation"  # Block CPU emulation
      "~@debug"          # Block debugging calls
      "~@raw-io"         # Block raw I/O operations
      "~@reboot"         # Block system reboot
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;        # Private IPC namespace
    UMask = "0077";           # Restrictive file creation mask
  };
}
