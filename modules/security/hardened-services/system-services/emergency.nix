{ config, lib, ... }:

{
  /*
    Rampart Emergency Service Hardening Module

    This module completely DISABLES the emergency shell service.
    The emergency shell is the absolute fallback for system repair (e.g.,
    when critical filesystems fail to mount). However, it is a well-known
    attack vector for gaining root access via physical console.

    By disabling both the target and the service, we ensure the system
    fails closed rather than yielding an accessible root shell.

    IMPORTANT: If the system encounters a critical failure during boot
    (like a broken /etc/fstab or missing disk UUID), it will NOT provide
    an emergency prompt. Recovery will strictly REQUIRE a NixOS Live USB.
  */

  systemd.services.emergency.enable = lib.mkForce false;
  systemd.targets.emergency.enable = lib.mkForce false;
}
