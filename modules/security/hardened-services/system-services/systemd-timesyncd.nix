{ config, lib, ... }:

{
  /*
    Rampart systemd-timesyncd Hardening Module

    This module reinforces hardening for the NTP time synchronization daemon.
    Upstream systemd-timesyncd is already one of the best-hardened units
    (ProtectSystem=strict, MemoryDenyWriteExecute, MDWE, etc.). This overlay
    adds a few extra restrictions that upstream omits.

    NOTE: ProtectClock MUST NOT be set — timesyncd's entire purpose is to
    adjust the system clock via CAP_SYS_TIME.
  */

  systemd.services.systemd-timesyncd.serviceConfig = {
    # Filesystem Isolation — upstream omits PrivateMounts
    PrivateMounts = true;  # Private mount namespace

    # Kernel & Hardware Protection — document and reinforce upstream settings
    ProtectKernelLogs = true;     # Does not read kernel logs (dmesg)
    ProtectKernelModules = true;  # Does not load kernel modules
    ProtectHostname = true;       # Does not change system hostname

    # Process & Identity Isolation
    ProtectProc = "invisible";  # Hide processes of other users in /proc
  };
}
