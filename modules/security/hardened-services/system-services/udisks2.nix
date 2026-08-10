{ config, lib, ... }:

{
  /*
    Rampart udisks2 Service Hardening Module

    This module applies CONSERVATIVE hardening to the UDisks2 disk management
    daemon. udisks2 handles mounting/unmounting filesystems, SMART monitoring,
    and disk partitioning on behalf of desktop users. It requires broad
    access to block devices, mount operations, and filesystem module loading.

    NOTE: This is one of the hardest services to sandbox because its core
    function (mounting filesystems) requires many permissions we typically
    restrict. Most namespace-creating options (ProtectSystem, PrivateTmp,
    PrivateDevices, ProtectHome, etc.) are PROHIBITED because they create
    a private mount namespace — mounts performed by udisks2 would be
    invisible to the rest of the system (desktop file manager, etc.).

    IMPORTANT — do NOT set any of these:
    - ProtectSystem (mount namespace → mounts invisible to host)
    - ProtectHome (mount namespace)
    - PrivateTmp (mount namespace)
    - PrivateDevices (needs block device access)
    - PrivateMounts (mount namespace)
    - PrivateNetwork (blocks udev netlink events + mount namespace)
    - ProtectKernelTunables (needs sysfs writes for disk parameters)
    - ProtectKernelModules (may autoload filesystem modules: ext4, vfat, ntfs)
    - ProtectControlGroups (mount namespace)
    - RestrictSUIDSGID (mount helpers may be setuid)
    - RestrictNamespaces (udisks2 may create mount namespaces)
    - SystemCallFilter ~@mount (mounting IS the core function)
    - SystemCallFilter ~@raw-io (needed for SMART monitoring)
  */

  systemd.services.udisks2.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Also adds MS_NOSUID to mounts (blocks setuid on removable media)
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Kernel & Hardware Protection (seccomp-based only — no mount namespaces)
    ProtectKernelLogs = true;  # Does not read kernel logs (dmesg)
    ProtectClock = true;       # Prevent modification of system clock
    LockPersonality = true;    # Prevent execution domain changes

    # Network & Process Isolation (seccomp/BPF-based — no mount namespaces)
    IPAddressDeny = "any";  # Deny all IP traffic as defense-in-depth
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local communication, D-Bus
      "AF_NETLINK"  # Udev events from kernel
    ];

    # Memory & System Call Filtering (seccomp-based — no mount namespaces)
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@reboot"         # Block system reboot
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@clock"          # Block clock configuration
    ];
  };
}
