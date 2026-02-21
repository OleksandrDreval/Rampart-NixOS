{ config, lib, ... }:

{
  /*
    Rampart wpa_supplicant Hardening Module

    This module hardens wpa_supplicant, which manages WiFi connections.
    Since WiFi is a common entry point for attacks, we restrict its root
    capabilities to only networking tasks, isolate the filesystem, and
    disable most system calls. This ensures that even if it is compromised
    via a malicious radio frame, it cannot easily compromise the rest of
    the system.
  */

  systemd.services.wpa_supplicant.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
  };
}
