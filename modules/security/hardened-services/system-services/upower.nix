{ config, lib, ... }:

{
  /*
    Rampart UPower Service Hardening Module

    This module hardens the UPower daemon that provides battery and power
    supply information via D-Bus. UPower reads battery status from sysfs
    device files and stores battery history in /var/lib/upower/. It does
    not need filesystem mounting or kernel modification capabilities.

    NOTE: PrivateDevices is NOT set because UPower may need access to
    HID battery devices (/dev/hidraw*) for Bluetooth keyboard/mouse
    batteries.

    IMPORTANT — do NOT set:
    - ProtectKernelTunables: upstream explicitly sets false — UPower writes
      to /sys/class/leds/ for keyboard backlight control
    - PrivateNetwork: upstream explicitly warns "PrivateNetwork=true would
      block udev's netlink socket" — UPower needs AF_NETLINK for battery
      hotplug detection and power supply state changes
  */

  systemd.services.upower.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;      # Disallow gaining new privileges
    RestrictSUIDSGID = true;     # Disable SUID/SGID bits
    RestrictRealtime = true;     # Prevent abuse of real-time scheduling
    CapabilityBoundingSet = "";  # Drop ALL capabilities (upstream does this)

    # Filesystem Isolation
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    StateDirectory = "upower";  # Writable /var/lib/upower for battery history
    ProtectHome = true;         # Make /home and /root completely inaccessible
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = false;  # UPower WRITES to /sys/class/leds/ for keyboard backlight (upstream = false)
    ProtectKernelModules = true;    # Does not load kernel modules
    ProtectKernelLogs = true;       # Does not read kernel logs (dmesg)
    ProtectControlGroups = true;    # Mount cgroups hierarchy as read-only
    ProtectClock = true;            # Prevent modification of system clock
    ProtectHostname = true;         # Prevent changing system hostname
    LockPersonality = true;         # Prevent execution domain changes

    # Network & Process Isolation
    # PrivateNetwork intentionally NOT set — "would block udev's netlink
    # socket" (upstream UPower comment). UPower needs AF_NETLINK for battery
    # hotplug, power supply state changes, and lid switch events.
    IPAddressDeny = "any";      # Deny all IP traffic as defense-in-depth
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    PrivateUsers = true;        # User namespace isolation (upstream uses this)
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local D-Bus communication
      "AF_NETLINK"  # Udev events for battery hotplug
    ];

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
      "~@resources"      # Block resource limit changes
    ];

    DevicePolicy = "auto";  # Allow reading opened device nodes (HID batteries)
    LimitMEMLOCK = 0;       # Disallow memory locking (upstream uses this)
  };
}
