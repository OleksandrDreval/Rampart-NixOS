{ config, lib, ... }:

{
  /*
    Rampart SSH Daemon Hardening Module

    This module hardens the OpenSSH daemon (sshd) using systemd sandboxing.
    It restricts access to the kernel and system files while allowing the
    necessary permissions for user logins, session initialization, and
    privilege escalation (via sudo/doas).
  */

  systemd.services.sshd.serviceConfig = {
    # Harden the daemon while allowing transition to session initialization
    NoNewPrivileges = false;  # Allow sudo/doas/run0

    # System resource isolation
    ProtectSystem = "full";   # Make /usr, /boot, /etc read-only
    ProtectHome = false;      # Allow users to write to Home (otherwise SSH is useless)

    # Deny access to deep kernel structures
    ProtectClock = true;           # Prevent changing system clock
    ProtectHostname = true;        # Prevent changing system hostname
    ProtectKernelTunables = true;  # Mount kernel tunables (/proc/sys, ...) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent access to kernel logs
    ProtectControlGroups = true;   # Make cgroups hierarchy read-only
    ProtectProc = "invisible";     # Hide processes not owned by the service

    # Private namespace for /tmp and mounts/devices
    PrivateTmp = true;     # Use a private /tmp directory
    PrivateMounts = true;  # Use a private file system namespace

    # System call restrictions
    SystemCallFilter = [
      "~@module"         # Block loading kernel modules
      "~@obsolete"       # Block obsolete/insecure syscalls
      "~@cpu-emulation"  # Block CPU emulation syscalls
      "~@clock"          # Block changing system time
      "~@keyring"        # Block kernel keyring access
      "~@swap"           # Block swap manipulations
    ];

    SystemCallArchitectures = "native";  # Allow only native syscalls

    # Other restrictions
    RestrictRealtime = true;        # Prevent realtime scheduling
    RestrictSUIDSGID = false;       # Needed for sudo/doas to work correctly
    LockPersonality = true;         # Prevent changing execution domain
    MemoryDenyWriteExecute = true;  # Prevent creating W+X memory regions
    DevicePolicy = "closed";        # Allow access only to standard pseudo-devices
  };
}
