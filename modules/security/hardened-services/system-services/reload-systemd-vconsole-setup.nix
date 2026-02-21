{ config, lib, ... }:

{
  /*
    Rampart reload-systemd-vconsole-setup Hardening Module

    This module hardens the service that reloads virtual console setup.
    It is a short-lived utility service, and we apply strict isolation
    to it, dropping all network access, all root capabilities, and
    blocking access to the kernel and hardware, ensuring it only
    interacts with the virtual console as intended.
  */

  systemd.services.reload-systemd-vconsole-setup.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;      # Disallow gaining new privileges
    CapabilityBoundingSet = "";  # All root capabilities dropped
    RestrictSUIDSGID = true;     # Disable SUID/SGID bits
    RestrictRealtime = true;     # Prevent abuse of real-time scheduling

    # Filesystem & Process Isolation
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    ProtectHome = true;         # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace
    PrivateNetwork = true;      # No network access required
    DevicePolicy = "closed";    # Deny access to most devices

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Protect /proc/sys, /sys, etc.
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    RestrictAddressFamilies = "none";  # No socket access required
    RestrictNamespaces = true;         # Prohibit creation of any new namespaces

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@raw-io"         # Block raw I/O access
      "~@privileged"     # Block most privileged system calls
      "~@keyring"        # Block kernel keyring access
      "~@reboot"         # Block system reboot
      "~@clock"          # Block direct clock manipulation
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@module"         # Block kernel module operations
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "ptrace"           # Explicitly block process tracing
    ];
  };
}
