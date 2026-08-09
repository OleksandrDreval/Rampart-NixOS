{ config, lib, ... }:

{
  /*
    Rampart dnsmasq Service Hardening Module

    This module hardens the dnsmasq DNS caching server. In this project
    dnsmasq is used as a local DNS cache with DNSSEC and forwards queries
    to a local dnscrypt-proxy instance. DHCP is not used, but we allow the
    capabilities for future flexibility. The daemon binds to port 53 on
    localhost, so it needs network access but can be isolated from the
    filesystem, kernel, and devices.
  */

  systemd.services.dnsmasq.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    CapabilityBoundingSet = [
      "CAP_NET_BIND_SERVICE"  # Bind to port 53
      "CAP_NET_ADMIN"         # Network administration (DHCP if needed)
      "CAP_NET_RAW"           # Raw sockets (DHCP if needed)
      "CAP_SETUID"            # Drop privileges after binding
      "CAP_SETGID"            # Drop privileges after binding
    ];

    # Filesystem Isolation
    ProtectSystem = true;          # NixOS upstream: only /usr, /boot read-only (dnsmasq preStart writes to /etc)
    StateDirectory = "dnsmasq";    # Writable /var/lib/dnsmasq for lease files
    RuntimeDirectory = "dnsmasq";  # Writable /run/dnsmasq for PID file
    ProtectHome = true;            # Make /home and /root completely inaccessible
    PrivateTmp = true;             # Use a private and isolated /tmp directory
    PrivateDevices = true;         # No device access needed
    PrivateMounts = true;          # Private mount namespace

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
    ProcSubset = "pid";         # Only show the daemon's own PID
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local communication
      "AF_NETLINK"  # Kernel-user network communication
      "AF_INET"     # IPv4 DNS traffic
      "AF_INET6"    # IPv6 DNS traffic
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
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Allow access only to pseudo-devices
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    UMask = "0077";           # Restrictive file creation mask
  };
}
