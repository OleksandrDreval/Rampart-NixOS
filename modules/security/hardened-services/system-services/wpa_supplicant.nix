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
    # Limit root capabilities to only those strictly required for wireless networking
    # CAP_CHOWN is required to set the group ownership of the control socket (for wpa_cli access)
    CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_CHOWN" ];
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem
    ProtectSystem = "strict";             # Mount entire filesystem hierarchy read-only
    RuntimeDirectory = "wpa_supplicant";  # Writable /run/wpa_supplicant for control socket
    ProtectHome = true;                   # Make /home and /root completely inaccessible
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
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
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
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@module"         # Block kernel module loading
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@clock"          # Block clock configuration
      "~@keyring"        # Block kernel keyring access
      "~@resources"      # Block resource limit changes
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging/tracing syscalls (ptrace, etc.)
      "~@raw-io"         # Block raw I/O
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Restrict device access to pseudo-devices
    DeviceAllow = "/dev/rfkill rw";  # Allow access to rfkill for Wi-Fi state management
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;        # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    UMask = "0077";           # Restrictive file creation mask
  };
}
