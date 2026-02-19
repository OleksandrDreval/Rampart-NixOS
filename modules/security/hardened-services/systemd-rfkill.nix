{ config, lib, ... }:

{
  /*
    Rampart systemd-rfkill Hardening Module

    This module hardens the systemd-rfkill service, which is responsible for
    storing and restoring the radio transmitter (WiFi, Bluetooth, etc.)
    state across reboots. It applies extreme sandboxing, including network
    isolation, private user namespaces, and restricted system call filters,
    while ensuring state persistence using a dedicated StateDirectory.
  */

  systemd.services.systemd-rfkill.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges via setuid/setgid
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
  };
}
