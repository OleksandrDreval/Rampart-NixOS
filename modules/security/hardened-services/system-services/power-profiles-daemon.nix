{ config, lib, ... }:

{
  /*
    Rampart power-profiles-daemon Hardening Module

    This module hardens the power-profiles-daemon that manages system power
    profiles (performance/balanced/power-saver). It communicates via D-Bus
    and writes to sysfs to change CPU governors, GPU power states, and
    other power-related kernel parameters.

    NOTE: ProtectKernelTunables MUST NOT be set — the daemon writes to
    /sys/devices/system/cpu/ and other sysfs paths to switch power profiles.
    ProtectKernelTunables makes /sys/ read-only, which would break the
    daemon's core functionality.
  */

  systemd.services.power-profiles-daemon.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem Isolation
    ProtectSystem = "strict";  # Mount entire filesystem hierarchy read-only
    ProtectHome = true;        # Make /home and /root completely inaccessible
    PrivateTmp = true;         # Use a private and isolated /tmp directory
    PrivateDevices = true;     # Device nodes not needed; sysfs is separate
    PrivateMounts = true;      # Private mount namespace

    # Kernel & Hardware Protection
    # ProtectKernelTunables intentionally NOT set — daemon WRITES to sysfs
    # for CPU governor, GPU power state, and ACPI settings
    ProtectKernelModules = true;  # Does not load kernel modules
    ProtectKernelLogs = true;     # Does not read kernel logs (dmesg)
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only
    ProtectClock = true;          # Prevent modification of system clock
    ProtectHostname = true;       # Prevent changing system hostname
    LockPersonality = true;       # Prevent execution domain changes

    # Network & Process Isolation
    PrivateNetwork = true;      # Zero network access needed (D-Bus uses AF_UNIX)
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local D-Bus communication
      "AF_NETLINK"  # Kernel-user communication (upstream allows this)
    ];
    IPAddressDeny = "any";  # Deny all IP traffic as defense-in-depth

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
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
      "~@clock"          # Block clock configuration
    ];

    StateDirectory = "power-profiles-daemon";  # Writable state directory
  };
}
