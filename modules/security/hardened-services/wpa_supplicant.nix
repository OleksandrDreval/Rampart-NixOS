{ config, lib, ... }:

{
  /*
    Rampart wpa_supplicant Hardening Module

    This module hardens wpa_supplicant, which manages WiFi connections.
    Since WiFi is a common entry point for attacks, we restrict its root
    capabilities to only networking tasks, isolate the filesystem, and
    disable most system calls. This ensures that even if it is compromised
    via a malicious radio frame, it cannot easily compromise the rest of
    the system.
  */

  systemd.services.wpa_supplicant.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges

    # Filesystem & Process Isolation
    ProtectSystem = "strict";             # Mount entire filesystem hierarchy read-only
    RuntimeDirectory = "wpa_supplicant";  # Writable /run/wpa_supplicant for control socket
    ProtectHome = true;                   # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace

    # Kernel & Hardware Protection
    ProtectKernelModules = true;  # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;     # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only
    ProtectClock = true;          # Prevent changing system clock
    ProtectHostname = true;       # Prevent changing system hostname
    LockPersonality = true;       # Prevent execution domain changes

    # Network & Process Isolation
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local IPC communication
      "AF_NETLINK"  # Kernel-user communication
      "AF_INET"     # IPv4 network access
      "AF_INET6"    # IPv6 network access
      "AF_PACKET"   # Direct network access for wireless
    ];
    RestrictNamespaces = true; # Prohibit creation of any new namespaces

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@raw-io"         # Block raw I/O access
      "~@privileged"     # Block most privileged system calls
      "~@keyring"        # Block kernel keyring access
      "~@reboot"         # Block system reboot
      "~@module"         # Block kernel module operations
      "~@swap"           # Block swap management
      "~@resources"      # Block resource limit changes
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "ptrace"           # Explicitly block process tracing
    ];
  };
}
