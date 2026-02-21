{ config, lib, ... }:

{
  /*
    Rampart Docker Daemon Hardening Module

    This module hardens the Docker daemon. Hardening Docker is challenging
    because it requires extensive privileges to manage containers,
    networking, and filesystems. This configuration strips unnecessary
    capabilities, isolates it from kernel logs/tunables, and restricts
    system calls while preserving the ability to run and manage containers.
  */

  systemd.services.docker.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Block specific capabilities that are highly dangerous or unused by the daemon
    CapabilityBoundingSet = [
      "~CAP_SYS_RAWIO"   # Prevent raw I/O access
      "~CAP_SYS_PTRACE"  # Prevent process tracing
      "~CAP_SYS_BOOT"    # Prevent system reboot
    ];

    # Filesystem & Process Isolation
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallFilter = [
      "~@debug"          # Block debugging system calls
      "~@raw-io"         # Block raw I/O access
      "~@reboot"         # Block system reboot
      "~@clock"          # Block clock configuration
      "~@module"         # Block kernel module operations
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
    ];
  };
}
