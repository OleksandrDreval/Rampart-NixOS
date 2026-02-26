{ config, lib, ... }:

{
  /*
    Rampart Rescue Service Hardening Module

    This module completely DISABLES the rescue shell service.
    While rescue.service is a recovery mechanism intended to give the
    administrator a single-user root shell, it acts as a local privilege
    escalation vector if physical access or bootloader access is compromised.

    By disabling both the target and the service, the system will refuse
    to drop into a rescue shell, even if requested via kernel parameters.

    IMPORTANT: Any system failure that would normally trigger rescue mode
    will now result in a halt or hang. Recovery will strictly REQUIRE
    booting from a NixOS Live USB or other external media.
  */

  boot.initrd.systemd.services.rescue.enable = lib.mkForce false;
  boot.initrd.systemd.targets.rescue.enable =  lib.mkForce false;

  systemd.services.rescue.enable = lib.mkForce false;
  systemd.targets.rescue.enable = lib.mkForce false;
}
