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
    # Network & Process Isolation
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
    IPAddressDeny = "any";      # MM does not use IP networking directly
    RestrictAddressFamilies = [
      "AF_UNIX"     # D-Bus communication
      "AF_NETLINK"  # Udev device discovery
      "AF_QIPCRTR"  # Qualcomm QMI modem protocol (upstream allows this)
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # C daemon, no JIT
  };
}
