{ config, lib, ... }:

{
  /*
    Rampart systemd-rfkill Hardening Module

    This module adds extra hardening on top of upstream systemd-rfkill.
    Upstream rfkill has minimal hardening: only NoNewPrivileges=yes and
    StateDirectory=systemd/rfkill. rfkill is a simple service that saves
    and restores radio transmitter (WiFi, Bluetooth, etc.) state.

    IMPORTANT — do NOT set:
    - PrivateUsers: creates UID mapping that may cause permission issues
      with rfkill state file persistence in /var/lib/systemd/rfkill/
  */

  systemd.services.systemd-rfkill.serviceConfig = {
    # Privilege & Capability Restrictions (upstream only has NoNewPrivileges)
    RestrictSUIDSGID = true;     # Disable SUID/SGID bits
    RestrictRealtime = true;     # Prevent abuse of real-time scheduling
    CapabilityBoundingSet = "";  # Drop ALL capabilities — rfkill needs none

    # Filesystem Isolation
    ProtectSystem = "strict";          # Mount the entire filesystem read-only
    ProtectHome = true;                # Make /home and /root completely inaccessible
    PrivateTmp = true;                 # Use a private and isolated /tmp directory
    PrivateMounts = true;              # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Does not write to sysfs
    ProtectKernelModules = true;   # Does not load kernel modules
    ProtectKernelLogs = true;      # Does not read kernel logs
    ProtectControlGroups = true;   # Does not modify cgroups
    ProtectClock = true;           # Does not modify system clock
    ProtectHostname = true;        # Does not change hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    PrivateNetwork = true;      # Zero network access needed
    IPAddressDeny = "any";      # Defense-in-depth: deny all IP traffic
    ProtectProc = "invisible";  # Hide processes of other users
    ProcSubset = "pid";         # Only show the daemon's own PID
    RestrictNamespaces = true;  # Does not create namespaces
    RestrictAddressFamilies = [ "AF_UNIX" ];  # Only local IPC

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Simple C daemon, no JIT
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    # NOTE: @privileged is a superset of @chown, @clock, @module, @raw-io, @reboot, @swap.
    # Only groups NOT included in @privileged are listed separately below.
    SystemCallFilter = [
      "~@privileged"     # Block privileged syscalls (includes @chown @clock @module @raw-io @reboot @swap)
      "~@mount"          # Block filesystem mounting
      "~@keyring"        # Block kernel keyring access
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Restrict device access to pseudo-devices
    DeviceAllow = "/dev/rfkill rw";  # Allow access to rfkill for radio state management
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    UMask = "0077";           # Restrictive file creation mask
  };
}
