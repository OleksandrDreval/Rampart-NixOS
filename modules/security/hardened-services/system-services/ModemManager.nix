{ config, lib, ... }:

{
  /*
    Rampart ModemManager Service Hardening Module

    This module hardens the ModemManager daemon, which manages mobile
    broadband modems and provides a D-Bus API for modem control. It
    communicates with modem hardware via serial ports (/dev/ttyUSB*,
    /dev/cdc-wdm*, /dev/wwan*, /dev/ttyACM*) and uses AF_NETLINK for
    device discovery via udev.

    Upstream unit file provides: ProtectSystem=true, NoNewPrivileges=true,
    CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN,
    RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_QIPCRTR,
    StateDirectory=ModemManager, RuntimeDirectory=ModemManager.
    Score before hardening: 6.3 MEDIUM (systemd-analyze security).

    IMPORTANT — do NOT set:
    - PrivateDevices: ModemManager MUST access modem device nodes
      (/dev/ttyUSB*, /dev/cdc-wdm*, /dev/wwan*, /dev/ttyACM*)
    - DevicePolicy="closed": would block access to modem devices
    - PrivateNetwork: needs AF_NETLINK for udev device events and
      AF_QIPCRTR for Qualcomm QMI modems
    - ~@privileged in SystemCallFilter: MM uses ioctl() extensively for
      modem AT commands and QMI/MBIM protocol control
  */

  systemd.services.ModemManager.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Upstream: NoNewPrivileges=true
    RestrictSUIDSGID = true;  # MM does not create SUID/SGID files
    RestrictRealtime = true;  # MM does not use real-time scheduling
    CapabilityBoundingSet = [
      "CAP_SYS_ADMIN"
      "CAP_NET_ADMIN"
    ];

    # Filesystem Isolation
    ProtectSystem = "strict";           # Mount entire filesystem read-only
    StateDirectory = "ModemManager";    # Writable /var/lib/ModemManager for device state
    RuntimeDirectory = "ModemManager";  # Writable /run/ModemManager for runtime data

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # MM does not write to /proc/sys
    ProtectKernelModules = true;   # MM does not load kernel modules
    ProtectKernelLogs = true;      # MM does not read kernel logs (dmesg)

    # Network & Process Isolation
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
    IPAddressDeny = "any";      # MM does not use IP networking directly
    RestrictNamespaces = true;  # MM does not create namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"     # D-Bus communication
      "AF_NETLINK"  # Udev device discovery
      "AF_QIPCRTR"  # Qualcomm QMI modem protocol (upstream allows this)
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # C daemon, no JIT
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@module"         # Block kernel module operations
      "~@mount"          # Block filesystem mounting
      "~@obsolete"       # Block deprecated system calls
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@keyring"        # Block kernel keyring access
    ];
  };
}
