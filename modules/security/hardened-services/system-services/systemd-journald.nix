{ config, lib, ... }:

{
  /*
    Rampart systemd-journald Hardening Module

    This module hardens the systemd logging service (journald). It restricts
    the visibility of other processes, protects the system hostname, and
    isolates the service mount namespace. These settings ensure that the
    logging system is tamper-resistant while reliably collecting system
    and service logs.
  */

  systemd.services.systemd-journald.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    LockPersonality = true;   # Prevent execution domain changes
    CapabilityBoundingSet = [
      "CAP_MAC_OVERRIDE" "CAP_DAC_OVERRIDE" "CAP_DAC_READ_SEARCH"
      "CAP_SETUID" "CAP_SETGID" "CAP_AUDIT_CONTROL" "CAP_AUDIT_READ"
      "CAP_SYSLOG" "CAP_CHOWN" "CAP_FOWNER" "CAP_SYS_PTRACE"
      "CAP_SYS_ADMIN"
    ]; # Restrict capabilities to those required by journald to read process metadata and logs

    # Process & Identity Isolation
    ProtectHostname = true;     # Prevent changing system hostname
    ProtectClock = true;        # Prevent modification of system clock
    PrivateMounts = true;       # Use a private file system namespace
    IPAddressDeny = "any";      # Explicitly deny all IP traffic (PrivateNetwork breaks audit netlink)

    # Filesystem & Storage
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    LogsDirectory = "journal";  # Writable /var/log/journal for persistent logs
    PrivateTmp = true;          # Use an isolated /tmp and /var/tmp
    ReadWritePaths = [
      "/run/log/journal"      # Writable volatile journal storage
      "/run/systemd/journal"  # Writable journal communication sockets
    ];
    ProtectHome = true;  # Make /home and /root completely inaccessible

    # Kernel & Hardware Protection
    # ProtectKernelLogs intentionally NOT set — journald reads /dev/kmsg
    # for kernel log messages. ProtectKernelLogs=true would make /dev/kmsg
    # inaccessible, overriding even DeviceAllow below.
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only

    # Network & Process Isolation
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local communication (systemd sockets)
      "AF_NETLINK"  # Kernel audit and device events
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions (C daemon, no JIT)
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@module"         # Block kernel module operations
      "~@mount"          # Block filesystem mounting
      "~@obsolete"       # Block deprecated system calls
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@keyring"        # Block kernel keyring access
    ];

    # Device Restrictions
    # journald reads /dev/kmsg for kernel log messages — must be explicitly allowed. PrivateDevices=true breaks this.
    DevicePolicy = "closed";
    DeviceAllow = [ "/dev/kmsg rw" ];

    # Other Security Settings
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;        # Private IPC namespace (journald does not need POSIX IPC)
    UMask = "0077";           # Restrictive file creation mask (systemd-journald manages its own file ACLs)
  };
}
