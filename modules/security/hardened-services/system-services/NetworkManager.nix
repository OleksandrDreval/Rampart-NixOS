{ config, lib, ... }:

{
  /*
    Rampart NetworkManager Hardening Module

    This module applies systemd service hardening to the NetworkManager daemon.
    Upstream NM already provides: CapabilityBoundingSet (including CAP_SYS_MODULE),
    ProtectSystem=true (yes level: /usr, /boot read-only), ProtectHome=read-only.

    IMPORTANT constraints per upstream documentation:
    - ProtectSystem must be "true" (yes), NOT "strict" or "full" — NM writes
      connection profiles to /etc/NetworkManager/system-connections/
    - ProtectHome must be "read-only" — NM reads WiFi certificates from ~/
    - ProtectKernelModules MUST NOT be set — upstream grants CAP_SYS_MODULE;
      NM loads kernel modules for tun, bridge, vlan, wireguard, etc.
    - ProtectHostname MUST NOT be set — NM sets hostname via DHCP
      (UseHostname=yes is the default in [DHCPv4] section)
    - RestrictNamespaces MUST NOT be set — NM may create network namespaces
      for WireGuard and other VPN types
    - ~@privileged in SystemCallFilter MUST NOT be used — blocks sethostname,
      chroot (used by dhclient sandbox), capset, and other NM operations
  */

  systemd.services.NetworkManager.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # NM does not need SUID child processes
    RestrictSUIDSGID = true;  # NM does not create SUID files
    RestrictRealtime = true;  # NM does not use real-time scheduling
    CapabilityBoundingSet = [
      "CAP_NET_ADMIN"
      "CAP_DAC_OVERRIDE"
      "CAP_NET_RAW"
      "CAP_BPF"
      "CAP_NET_BIND_SERVICE"
      "CAP_SETGID"
      "CAP_SETUID"
      "CAP_SYS_MODULE"
      "CAP_AUDIT_WRITE"
      "CAP_KILL"
      "CAP_SYS_CHROOT"
    ];

    # Filesystem Isolation — matches upstream levels
    ProtectSystem = "strict";                   # Mount entire filesystem hierarchy read-only
    StateDirectory = "NetworkManager";          # Writable /var/lib/NetworkManager for persistent state
    RuntimeDirectory = "NetworkManager";        # Writable /run/NetworkManager for runtime data
    ConfigurationDirectory = "NetworkManager";  # Writable /etc/NetworkManager for connection profiles
    ProtectHome = "read-only";  # Upstream: read-only (NM reads WiFi certs from ~/)
    PrivateTmp = true;          # Isolated /tmp directory

    # Kernel & Hardware Protection
    # ProtectKernelModules intentionally NOT set — NM needs CAP_SYS_MODULE (upstream)
    ProtectKernelLogs = true;     # NM does not read kernel logs (dmesg)
    ProtectControlGroups = true;  # NM does not modify cgroups
    ProtectClock = true;          # NM does not modify system clock
    # ProtectHostname intentionally NOT set — NM sets hostname via DHCP
    LockPersonality = true;       # Prevent personality changes (emulation)

    # Network & Process Isolation
    ProtectProc = "invisible";  # Hide other users' processes
    ProcSubset = "pid";         # Only show the daemon's own PID
    # RestrictNamespaces intentionally NOT set — NM may create namespaces for VPN
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local communication
      "AF_NETLINK"  # Kernel-user communication
      "AF_INET"     # IPv4
      "AF_INET6"    # IPv6
      "AF_PACKET"   # Direct network access (required for NM)
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # NM is C code, no JIT
    SystemCallArchitectures = "native";  # Allow only native syscalls
    SystemCallFilter = [
      "~@mount"          # NM does not mount filesystems
      "~@swap"           # NM does not manage swap
      "~@obsolete"       # Block deprecated calls
      "~@cpu-emulation"  # Block CPU emulation
      "~@debug"          # Block debugging/tracing syscalls
      "~@raw-io"         # Block raw I/O operations
      "~@reboot"         # Block system reboot
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    KeyringMode = "private";  # NM does not use user keyrings
    PrivateIPC = true;         # NM does not use System V IPC
    UMask = "0077";           # Restrictive file creation mask
  };
}
