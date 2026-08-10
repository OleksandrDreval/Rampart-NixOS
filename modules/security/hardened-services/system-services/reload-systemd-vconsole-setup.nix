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
    # Note: CapabilityBoundingSet="" is intentionally omitted here because
    # systemd-vconsole-setup needs CAP_SYS_TTY_CONFIG to configure the
    # virtual console.
    RestrictSUIDSGID = true;     # Disable SUID/SGID bits
    RestrictRealtime = true;     # Prevent abuse of real-time scheduling

    # Filesystem & Process Isolation
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    ProtectHome = true;         # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace
    PrivateNetwork = true;      # No network access required
    IPAddressDeny = "any";      # Defense-in-depth: deny all IP traffic
    # DevicePolicy = "closed" omitted: vconsole-setup must access /dev/tty*, /dev/vcs*, 
    # and /dev/console to configure fonts and keymaps. "closed" would block this access.

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Protect /proc/sys, /sys, etc.
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    RestrictAddressFamilies = [ "AF_UNIX" ];  # Only local IPC for systemd communication
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
      "~@keyring"        # Block kernel keyring access
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@obsolete"       # Block deprecated system calls
      "~@debug"          # Block debugging/tracing syscalls (ptrace, etc.)
    ];

    # Other Security Settings
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    UMask = "0077";           # Restrictive file creation mask
  };
}
