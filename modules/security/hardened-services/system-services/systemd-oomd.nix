{ config, lib, ... }:

{
  /*
    Rampart systemd-oomd Hardening Module

    This module reinforces hardening for the out-of-memory daemon. systemd-oomd
    monitors memory pressure via PSI (Pressure Stall Information) in cgroup
    hierarchy and kills processes when memory runs low. Upstream already
    provides comprehensive sandboxing; this overlay adds a few extra settings.

    IMPORTANT constraints — do NOT set:
    - ProtectControlGroups: oomd MUST read cgroup PSI files and use cgroup.kill
    - ProtectProc = "invisible": oomd must see all processes to make kill decisions
  */

  systemd.services.systemd-oomd.serviceConfig = {
    # Filesystem Isolation — upstream omits PrivateMounts
    PrivateMounts = true;  # Private mount namespace

    # Network & Process Isolation — upstream omits PrivateNetwork
    PrivateNetwork = true;  # Zero network access needed (AF_UNIX only via socket activation)
  };
}
