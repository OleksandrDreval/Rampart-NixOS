{ config, lib, ... }:

{
  /*
    Rampart iwd (iNet wireless daemon) Hardening Module

    This module hardens the iwd wireless daemon, the modern wireless backend
    used in Rampart. It restricts the process to essential wireless networking
    capabilities and isolates it from the broader system to ensure secure
    Wi-Fi operations.
  */

  systemd.services.iwd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    CapabilityBoundingSet = "CAP_NET_ADMIN CAP_NET_RAW";  # Limit root capabilities to networking
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Disable realtime scheduling

    # Filesystem Isolation
    ProtectSystem = "strict";  # Mount entire filesystem hierarchy read-only
    StateDirectory = "iwd";    # Writable /var/lib/iwd for network profiles
    ConfigurationDirectory = "iwd";  # Writable /etc/iwd for main.conf and settings
    ProtectHome = true;        # Home directory isolation
    PrivateTmp = true;         # Isolated /tmp directory
    PrivateMounts = true;      # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelModules = true;  # Prevents loading/unloading kernel modules
    ProtectKernelLogs = true;     # Prevents reading kernel logs
    ProtectControlGroups = true;  # Makes cgroups read-only
    ProtectClock = true;          # Prevents changing system clock
    ProtectHostname = true;       # Prevents changing hostname
    LockPersonality = true;       # Prevent personality changes (emulation)
    KeyringMode = "private";      # Isolated kernel keyring

    # Network & Process Isolation
    ProtectProc = "invisible";  # Restrict access to /proc (other processes invisible)
    RestrictNamespaces = true;  # Disable creation of new namespaces
    RestrictAddressFamilies = [
       "AF_UNIX"     # Local communication
       "AF_NETLINK"  # Kernel-user communication
       "AF_INET"     # IPv4
       "AF_INET6"    # IPv6
       "AF_PACKET"   # Direct network access
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Allow only native syscalls
    SystemCallFilter = [
      "~@privileged"     # Block privileged syscalls (includes @chown @clock @module @raw-io @reboot @swap)
      "~@mount"          # Block filesystem mounting
      "~@resources"      # Block resource limit changes
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging/tracing syscalls (ptrace, etc.)
    ];

    # Other Security Settings
    DevicePolicy = "closed";         # Restrict device access to pseudo-devices
    DeviceAllow = "/dev/rfkill rw";  # Allow access to rfkill for Wi-Fi state management
    PrivateIPC = true;  # Private IPC namespace
    RemoveIPC = true;   # Clean up IPC objects on service stop
  };
}
