{ config, lib, ... }:

{
  /*
    Rampart CUPS Printing Service Hardening Module

    This module hardens the Common Unix Printing System (CUPS). Given that
    CUPS has a long history of security vulnerabilities, we apply systemd
    sandboxing to isolate it from personal files, protect kernel internals,
    and restrict system calls. While it retains network access for network
    printers, its overall attack surface is significantly reduced.
  */

  systemd.services.cups.serviceConfig = {
    # Privilege & Capability Restrictions
    # NoNewPrivileges/RestrictSUIDSGID omitted: CUPS backends/filters may require SUID
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem & Process Isolation
    ProtectSystem = "strict";         # Mount entire filesystem hierarchy read-only
    StateDirectory = "cups";          # Writable /var/lib/cups (NixOS symlinks /etc/cups -> /var/lib/cups)
    LogsDirectory = "cups";           # Writable /var/log/cups for access and error logs
    CacheDirectory = "cups";          # Writable /var/cache/cups for cached data
    RuntimeDirectory = "cups";        # Writable /run/cups for socket and runtime data
    ReadWritePaths = [ "/var/spool/cups" ];  # Writable spool directory for print jobs
    ProtectHome = true;               # Make /home and /root completely inaccessible
    # ProtectProc/ProcSubset omitted: proprietary drivers (HPLIP/Brother) often parse /proc
    PrivateTmp = true;                # Use a private and isolated /tmp directory
    PrivateMounts = true;             # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectHostname = true;        # Prevent changing system hostname
    ProtectClock = true;           # Prevent changing system clock
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local IPC communication
      "AF_NETLINK"  # Kernel-user communication
      "AF_INET"     # Needed for network printers
      "AF_INET6"    # Needed for network printers
      "AF_PACKET"   # Needed for some printer discovery protocols
    ];
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@reboot"         # Block system reboot
      "~@debug"          # Block debugging system calls
      "~@module"         # Block kernel module operations
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@raw-io"         # Block raw I/O port access
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    DevicePolicy = "auto";    # Allow access to opened printer devices
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    # UMask omitted: NixOS handles umask in preStart. Global 0077 breaks PPD readability.
  };
}
