{ config, lib, ... }:

{
  /*
    Rampart Polkit Service Hardening Module

    This module hardens the PolicyKit authorization daemon (polkitd), which
    makes authorization decisions for D-Bus method calls. Since polkitd is
    a pure policy daemon communicating only via D-Bus, it can be aggressively
    sandboxed: no network, no devices, no kernel access. It reads policy
    files from /usr/share/polkit-1/ and /etc/polkit-1/ (both read-only under
    ProtectSystem=strict) and rarely writes persistent state.

    NOTE: MemoryDenyWriteExecute is safe because NixOS polkit uses duktape
    (not mozjs/SpiderMonkey). If polkit were compiled with mozjs JIT, MDWE
    would break the service.
  */

  systemd.services.polkit.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Daemon does not need privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem Isolation
    ProtectSystem = "strict";  # Mount entire filesystem hierarchy read-only
    ProtectHome = true;        # Make /home and /root completely inaccessible
    PrivateTmp = true;         # Use a private and isolated /tmp directory
    PrivateDevices = true;     # No device access needed for policy decisions
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
    PrivateNetwork = true;      # Zero network access needed (D-Bus uses AF_UNIX)
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [ "AF_UNIX" ];  # Only local D-Bus communication
    IPAddressDeny = "any";      # Deny all IP traffic as defense-in-depth

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Safe with duktape JS engine
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@module"         # Block kernel module operations
      "~@debug"          # Block debugging syscalls
      "~@raw-io"         # Block raw I/O operations
      "~@resources"      # Block resource limit changes
    ];

    DevicePolicy = "strict";  # Match upstream polkit — only explicitly allowed devices
    RemoveIPC = true;         # Remove SysV IPC objects on service stop
    UMask = "0077";           # Restrictive file creation mask
  };
}
