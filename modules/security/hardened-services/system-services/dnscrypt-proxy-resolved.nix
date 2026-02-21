{ config, lib, ... }:

{
  /*
    Rampart dnscrypt-proxy (resolved variant) Hardening Module

    This module hardens the dnscrypt-proxy instance that forwards DNS queries
    for systemd-resolved via DoH/DoT/DNSCrypt. The service is essentially
    stateless — it listens on localhost, encrypts DNS queries, and forwards
    them to upstream resolvers. This allows aggressive sandboxing.

    The base service definition (ExecStart, Restart, etc.) lives in
    modules/networking/dns/resolved.nix. This module adds comprehensive
    systemd sandboxing on top.
  */

  systemd.services.dnscrypt-proxy-resolved.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;                          # Disallow gaining new privileges
    RestrictSUIDSGID = true;                         # Disable SUID/SGID bits
    RestrictRealtime = true;                         # Prevent abuse of real-time scheduling
    CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";  # Only bind to port 53

    # Filesystem Isolation
    ProtectSystem = "strict";  # Mount entire filesystem hierarchy read-only
    ProtectHome = true;        # Make /home and /root completely inaccessible
    PrivateTmp = true;         # Use a private and isolated /tmp directory
    PrivateDevices = true;     # No device access needed
    PrivateMounts = true;      # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"   # Local communication
      "AF_INET"   # IPv4 outbound DNS-over-HTTPS/TLS
      "AF_INET6"  # IPv6 outbound DNS-over-HTTPS/TLS
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@module"         # Block kernel module operations
      "~@mount"          # Block filesystem mounting
      "~@obsolete"       # Block deprecated system calls
      "~@raw-io"         # Block raw I/O operations
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      # NOTE: ~@resources intentionally NOT blocked — Go runtime calls
      # setrlimit(RLIMIT_NOFILE) at startup which is in @resources group
    ];

    DevicePolicy = "closed";  # Allow access only to pseudo-devices
  };
}
