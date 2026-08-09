{ config, lib, ... }:

{
  /*
    Rampart Name Service Cache Daemon (nscd) Hardening Module

    This module hardens nscd, which caches lookups for hosts, passwords,
    groups, and other databases. It hides processes, restricts system
    modifications, and blocks unnecessary root capabilities while allowing
    it to reliably provide character-to-ID lookups for the system.
  */

  systemd.services.nscd.serviceConfig = {
    # Privilege & Capability Restrictions
    # NixOS uses nsncd (Rust rewrite) which runs as user "nscd" — needs zero capabilities
    NoNewPrivileges = true;      # Disallow gaining new privileges
    RestrictSUIDSGID = true;     # nsncd does not create SUID/SGID files
    RestrictRealtime = true;     # Prevent abuse of real-time scheduling
    CapabilityBoundingSet = "";  # Drop ALL capabilities — nsncd needs none

    # Filesystem & Process Isolation
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    RuntimeDirectory = "nscd";  # Writable /run/nscd for socket and PID file
    ProtectHome = "read-only";   # NixOS upstream: nscd may need to read home for NIS/LDAP user info
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateDevices = true;      # No device access needed for name caching
    PrivateMounts = true;       # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    RestrictNamespaces = true; # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local IPC (nsswitch communication)
      "AF_NETLINK"  # Kernel-user communication
      "AF_INET"     # IPv4 (NIS/LDAP backends if configured)
      "AF_INET6"    # IPv6 (NIS/LDAP backends if configured)
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@swap"           # Block swap management
      "~@clock"          # Block clock configuration
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@reboot"         # Block system reboot
      "~@raw-io"         # Block raw I/O access
      "~@module"         # Block kernel module operations
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Allow access only to pseudo-devices
    KeyringMode = "private";  # Isolated kernel keyring
    # PrivateIPC is intentionally omitted: If NixOS ever falls back to the original glibc
    # nscd (instead of nsncd), PrivateIPC breaks the System V shared memory segment that
    # nscd uses to serve cache lookups extremely fast to client processes without hitting the socket.
    RemoveIPC = true;         # Clean up IPC objects on stop (runs as user "nscd")
    # UMask = "0077" omitted: The nscd daemon creates /run/nscd/socket for all system
    # processes to resolve usernames and hosts. A 0077 mask makes the socket
    # accessible only to the nscd user, completely breaking DNS and user lookups for everyone else.
  };
}
