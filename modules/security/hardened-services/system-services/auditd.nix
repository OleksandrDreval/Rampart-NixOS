{ config, lib, ... }:

{
  /*
    Rampart Audit Daemon Hardening Module

    This module hardens auditd, which is responsible for system security
    auditing. Since it collects sensitive logs, it is isolated from the
    network and restricted from modifying kernel internals. We use a
    balanced filesystem protection to ensure it can continuously write its
    audit trails while remaining protected from subversion.
  */

  systemd.services.auditd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Block specific capabilities while keeping those needed for auditing
    CapabilityBoundingSet = [
      "~CAP_CHOWN"
      "~CAP_FSETID"
      "~CAP_SETFCAP"
    ];

    # Filesystem Isolation
    ProtectSystem = "strict";     # Mount entire filesystem hierarchy read-only
    LogsDirectory = "audit";      # Writable /var/log/audit for audit trails
    ProtectHome = true;           # Make /home and /root completely inaccessible
    PrivateTmp = true;            # Use a private and isolated /tmp directory
    PrivateMounts = true;         # Use a private file system namespace
    PrivateDevices = true;        # Make /dev inaccessible (except standard ones)
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg) — auditd uses AUDIT_NETLINK, not /dev/kmsg
    ProtectHostname = true;        # Prevent changing system hostname
    ProtectClock = true;           # Prevent changing system clock
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    PrivateNetwork = true;      # Completely isolate the service from the network
    IPAddressDeny = "any";      # Explicitly deny all IP traffic
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    # Allow-list: only local IPC (journald socket) and audit netlink
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local IPC (systemd-journald)
      "AF_NETLINK"  # Audit netlink interface (AUDIT_NETLINK)
    ];
    RemoveIPC = true;  # Clean up IPC objects on service stop

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@module"         # Block kernel module operations
      "~@mount"          # Block filesystem mounting
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@reboot"         # Block system reboot
      "~@raw-io"         # Block raw I/O access
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Allow access only to pseudo-devices
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
    UMask = "0077";           # Restrictive file creation mask
  };
}
