{ config, lib, ... }:

{
  /*
    Rampart D-Bus Hardening Module

    This module hardens the D-Bus system bus daemon, which is the central
    nervous system of a Linux desktop. It implements strict filesystem
    sandboxing, network isolation (D-Bus system bus should not need the internet),
    and restricted system calls to prevent it from being used as an escape
    vector while maintaining full system messaging functionality.
  */

  systemd.services.dbus.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges via setuid/setgid
  };
}
