{ config, lib, ... }:

{
  /*
    Rampart systemd-udevd Hardening Module

    This module applies security hardening to the systemd-udevd service, which
    manages device events and nodes in /dev. It implements a strict filesystem
    sandbox, restricts access to kernel logs, and limits process visibility
    and kernel capabilities to minimize the risk of privilege escalation.
  */

  systemd.services.systemd-udevd.serviceConfig = { };
}
