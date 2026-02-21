{ config, lib, ... }:

{
  /*
    Rampart USBGuard Service Hardening Module

    This module hardens the USBGuard daemon that controls USB device
    authorization. USBGuard monitors USB connections and allows/blocks
    devices based on a policy ruleset. It needs write access to USB sysfs
    attributes for authorization and access to udev netlink events.

    NOTE: ProtectSystem is "full" (not "strict") because USBGuard needs
    write access to /sys/bus/usb/devices/.../authorized sysfs attributes.
    ProtectKernelTunables is NOT set because it makes /sys/ read-only.

    IMPORTANT — do NOT set:
    - PrivateNetwork: USBGuard monitors USB via kernel netlink uevent
      socket; PrivateNetwork creates a new network namespace that isolates
      from host netlink, silently breaking USB device detection
  */

  systemd.services.usbguard.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    CapabilityBoundingSet = [
      "CAP_CHOWN"             # Manage rule file ownership
      "CAP_FOWNER"            # Rule file management
      "CAP_DAC_OVERRIDE"      # Access restricted rule files
      "CAP_DAC_READ_SEARCH"   # Read files bypassing permission checks
      "CAP_AUDIT_WRITE"       # Write audit log entries for USB events
    ];

    # Filesystem Isolation
    ProtectSystem = "full";          # Protect /usr, /boot, /etc (not strict — needs sysfs)
    StateDirectory = "usbguard";     # Writable /var/lib/usbguard for rules and audit
    RuntimeDirectory = "usbguard";   # Writable /run/usbguard for IPC socket
    ProtectHome = true;              # Make /home and /root completely inaccessible
    PrivateTmp = true;               # Use a private and isolated /tmp directory

    # Access to USB sysfs for device authorization
    ReadWritePaths = [
      "/sys/bus/usb"   # USB bus attributes
      "/sys/devices"   # USB device sysfs entries
      "/dev/bus/usb"   # USB device nodes
    ];

    # Device policy
    DevicePolicy = "strict";
    DeviceAllow = [
      "/dev/null rw"
      "/dev/urandom r"
    ];

    # Kernel & Hardware Protection
    ProtectKernelModules = true;   # Does not load kernel modules
    ProtectKernelLogs = true;      # Does not read kernel logs
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    # PrivateNetwork intentionally NOT set — USBGuard monitors USB via kernel
    # netlink uevent socket; PrivateNetwork would isolate from host netlink
    IPAddressDeny = "any";      # Deny all IP traffic as defense-in-depth
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"     # IPC socket for usbguard CLI
      "AF_NETLINK"  # Uevent notifications from kernel
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
      "~@raw-io"         # Block raw I/O operations
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
    ];

    OOMScoreAdjust = -1000;  # Critical security service — never OOM-kill
    UMask = "0077";          # Restrictive file creation mask
  };
}
