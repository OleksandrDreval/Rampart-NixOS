{ config, lib, ... }:

{
  /*
    Rampart systemd-ask-password-console Hardening Module

    This module hardens the service responsible for querying passwords
    on the system console (e.g., for encrypted disks). We sandbox the
    process to ensure it can only handle its specific task of password
    entry and cannot be used as a vector to compromise the kernel or
    other processes.
  */

  systemd.services.systemd-ask-password-console.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;      # Disallow gaining new privileges
    CapabilityBoundingSet = "";  # All root capabilities dropped
    RestrictSUIDSGID = true;     # Disable SUID/SGID bits
    RestrictRealtime = true;     # Prevent abuse of real-time scheduling

    # Filesystem & Process Isolation
    ProtectSystem = "strict";                          # Mount entire filesystem hierarchy read-only
    ReadWritePaths = [ "/run/systemd/ask-password" ];  # Writable path for password query responses
    ProtectHome = true;                                # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace
    PrivateDevices = false;     # Needs access to terminal devices
    PrivateNetwork = true;      # No network access needed for console prompts

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
