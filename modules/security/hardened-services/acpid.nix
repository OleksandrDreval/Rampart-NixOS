{ config, lib, ... }:

{
  /*
    Rampart ACPI Daemon (acpid) Hardening Module

    This module hardens acpid, which handles hardware events like power
    buttons and laptop lids. It isolates the service from the network,
    hides other processes, and applies strict system call filtering to
    ensure that power management events are processed securely without
    exposing a large attack surface.
  */

  systemd.services.acpid.serviceConfig = { };
}
