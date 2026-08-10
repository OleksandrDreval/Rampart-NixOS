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
    # Note: CapabilityBoundingSet="" is intentionally omitted here because
    # systemd-ask-password-console needs CAP_SYS_TTY_CONFIG to call vhangup()
    # on the terminal for secure password entry.
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
    IPAddressDeny = "any";      # Defense-in-depth: deny all IP traffic

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Protect /proc/sys, /sys, etc.
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    KeyringMode = "private";       # Allow isolated kernel keyring for password agent
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    RestrictAddressFamilies = [ "AF_UNIX" ];  # Only local IPC for password responses
    RestrictNamespaces = true;         # Prohibit creation of any new namespaces
    ProcSubset = "pid";                # Only show the daemon's own PID

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    # NOTE: @privileged is a superset of @chown, @clock, @module, @raw-io, @reboot, @swap.
    # Only groups NOT included in @privileged are listed separately below.
    SystemCallFilter = [
      "~@privileged"     # Block privileged syscalls (includes @chown @clock @module @raw-io @reboot @swap)
      "~@mount"          # Block filesystem mounting
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@obsolete"       # Block deprecated system calls
      "~@debug"          # Block debugging/tracing syscalls (ptrace, etc.)
    ];

    # Other Security Settings
    RemoveIPC = true;  # Clean up IPC objects on service stop
    UMask = "0077";    # Restrictive file creation mask
  };
}
