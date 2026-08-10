{ config, lib, ... }:

{
  /*
    Rampart systemd-logind Hardening Module

    This module reinforces hardening for the systemd login manager. logind
    manages user sessions, seats, device ACLs, power buttons, and lid-switch
    actions. Upstream already provides comprehensive sandboxing including:
    ProtectSystem=strict (with ReadWritePaths=/etc /run), ProtectHome,
    ProtectClock, ProtectControlGroups, ProtectKernelModules, ProtectKernelLogs,
    NoNewPrivileges, MemoryDenyWriteExecute, IPAddressDeny=any, etc.

    All settings in this overlay are redundant with upstream and serve as
    explicit documentation of the intended security posture, ensuring they
    persist even if upstream defaults change.

    IMPORTANT constraints — do NOT set:
    - PrivateDevices: logind manages TTY/input device ACLs via DeviceAllow
    - ProtectKernelTunables: logind writes sysfs for backlight/power management
  */

  systemd.services.systemd-logind.serviceConfig = {
    # All settings below match upstream — kept as explicit documentation
    # to ensure they persist even if upstream defaults change

    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    LockPersonality = true;   # Prevent execution domain changes
    CapabilityBoundingSet = [
      "CAP_SYS_ADMIN" "CAP_MAC_ADMIN" "CAP_AUDIT_CONTROL" "CAP_CHOWN"
      "CAP_DAC_READ_SEARCH" "CAP_DAC_OVERRIDE" "CAP_FOWNER"
      "CAP_SYS_TTY_CONFIG" "CAP_LINUX_IMMUTABLE"
    ]; # Explicitly restrict capabilities to logind requirements

    # Filesystem Isolation
    ProtectHome = true;           # No access to /home or /root needed
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only
    ProtectHostname = true;       # Prevent changing system hostname
    PrivateTmp = true;            # Isolate /tmp and /var/tmp from other services/users

    # Kernel & Hardware Protection
    ProtectKernelModules = true;  # Does not load kernel modules
    ProtectKernelLogs = true;     # Does not read kernel logs (dmesg)
    KeyringMode = "private";      # Allow isolated kernel keyring for logind
    ProtectClock = true;          # Does not modify system clock

    # Network & Process Isolation
    IPAddressDeny = "any";      # Zero IP traffic needed (AF_UNIX + AF_NETLINK only)
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local communication (D-Bus)
      "AF_NETLINK"  # Monitoring kernel events
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@module"         # Block kernel module operations
      "~@mount"          # Block filesystem mounting
      "~@obsolete"       # Block deprecated system calls
      "~@raw-io"         # Block raw I/O port access
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
    ];
  };
}
