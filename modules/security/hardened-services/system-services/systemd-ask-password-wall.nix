{ config, lib, ... }:

{
  /*
    Rampart systemd-ask-password-wall Hardening Module

    This module hardens the service that broadcasts password requests
    to all logged-in users (via 'wall'). We apply strict sandboxing,
    dropping all capabilities and isolating the filesystem, while
    specifically allowing the 'AF_UNIX' family for internal system
    communication.
  */

  systemd.services.systemd-ask-password-wall.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;      # Disallow gaining new privileges
    # Note: CapabilityBoundingSet="" is intentionally omitted here because
    # systemd-ask-password-wall needs capabilities (like CAP_SYS_TTY_CONFIG
    # or CAP_DAC_OVERRIDE) to broadcast messages to users' terminals.
    RestrictSUIDSGID = true;     # Disable SUID/SGID bits
    RestrictRealtime = true;     # Prevent abuse of real-time scheduling

    # Filesystem & Process Isolation
    ProtectSystem = "strict";                          # Mount entire filesystem hierarchy read-only
    ReadWritePaths = [ "/run/systemd/ask-password" ];  # Writable path for password query responses
    ProtectHome = true;                                # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace
    PrivateDevices = false;     # MUST be false: needs access to real user terminals (/dev/pts/*, /dev/tty*) to broadcast wall messages
    PrivateNetwork = true;      # No network access needed for wall alerts
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
    RestrictAddressFamilies = [ "AF_UNIX" ];  # Only local socket for wall notifications
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    ProcSubset = "pid";         # Only show the daemon's own PID

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    # NOTE: @privileged is a superset of @chown, @clock, @module, @raw-io, @reboot, @swap.
    # Only groups NOT included in @privileged are listed separately below.
    SystemCallFilter = [
      "~@privileged"     # Block privileged syscalls (includes @chown @clock @module @raw-io @reboot @swap)
      "~@mount"          # Block filesystem mounting
      # keyring access needed for routing password responses between contexts
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@obsolete"       # Block deprecated system calls
      "~@debug"          # Block debugging/tracing syscalls (ptrace, etc.)
    ];

    # Other Security Settings
    RemoveIPC = true;  # Clean up IPC objects on service stop
    UMask = "0077";    # Restrictive file creation mask
  };
}
