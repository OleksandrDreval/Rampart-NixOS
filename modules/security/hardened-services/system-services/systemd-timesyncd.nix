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
  };
}
