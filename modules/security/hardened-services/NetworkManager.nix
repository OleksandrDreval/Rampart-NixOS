{ config, lib, ... }:

{
  /*
    Rampart NetworkManager Hardening Module

    This module applies systemd service hardening to the NetworkManager daemon.
    It isolates the service from sensitive system resources, restricts its
    capabilities to networking-only tasks, and filters system calls to reduce
    the attack surface of this critical network-facing component.
  */

  systemd.services.NetworkManager.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Disable realtime scheduling

    # Filesystem Isolation
    ProtectSystem = "full";  # Mount /usr, /boot, and /etc read-only
    ProtectHome = true;      # Home directory isolation
    PrivateTmp = true;       # Isolated /tmp directory

    # Kernel & Hardware Protection
    ProtectKernelModules = true;  # Prevents loading/unloading kernel modules
    ProtectKernelLogs = true;     # Prevents reading kernel logs
    ProtectControlGroups = true;  # Makes cgroups read-only
    ProtectClock = true;          # Prevents changing system clock
    ProtectHostname = true;       # Prevents changing hostname
    LockPersonality = true;       # Prevent personality changes (emulation)

    # Network & Process Isolation
    ProtectProc = "invisible";   # Restrict access to /proc (other processes invisible)
    RestrictNamespaces = true;   # Disable creation of new namespaces
    RestrictAddressFamilies = [
       "AF_UNIX"     # Local communication
       "AF_NETLINK"  # Kernel-user communication
       "AF_INET"     # IPv4
       "AF_INET6"    # IPv6
       "AF_PACKET"   # Direct network access (required for NM)
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Allow only native syscalls
    SystemCallFilter = [
      "~@mount"          # Filesystem mounting
      "~@module"         # Kernel module operations
      "~@swap"           # Swap management
      "~@obsolete"       # Obsolete calls
      "~@cpu-emulation"  # CPU emulation
      "~@privileged"     # Privileged calls
      "~@clock"          # Clock configuration
      "ptrace"           # Process tracing
    ];
  };
}
