{ config, lib, ... }:

{
  /*
    Rampart systemd-journald Hardening Module

    This module hardens the systemd logging service (journald). It restricts
    the visibility of other processes, protects the system hostname, and
    isolates the service mount namespace. These settings ensure that the
    logging system is tamper-resistant while reliably collecting system
    and service logs.
  */

  systemd.services.systemd-journald.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;  # Disallow gaining new privileges
  };
}
