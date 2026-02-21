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
    ProtectHome = true;           # No access to /home or /root needed
    ProtectKernelModules = true;  # Does not load kernel modules
    ProtectKernelLogs = true;     # Does not read kernel logs (dmesg)
    ProtectClock = true;          # Does not modify system clock
    IPAddressDeny = "any";        # Zero IP traffic needed (AF_UNIX + AF_NETLINK only)
  };
}
