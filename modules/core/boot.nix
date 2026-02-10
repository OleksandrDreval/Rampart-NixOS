{ config, pkgs, lib, ... }:

let
  vars = import ./includes/variables.nix;
in
{
  # Bootloader configuration
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.configurationLimit = vars.bootConfigLimit;
  boot.loader.systemd-boot.editor = lib.mkForce false;  # Disable boot parameter editing (prevent init=/bin/sh attacks)
  boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
  boot.loader.timeout = vars.bootTimeout;

  # Boot verbosity configuration (security: minimize information disclosure)
  boot.consoleLogLevel = lib.mkForce 3;     # Show only errors on console (balance security/debugging)
  boot.initrd.verbose = lib.mkForce false;  # Quiet initrd to minimize information disclosure

  # DMA attack mitigation during early boot
  # Blocks Thunderbolt/USB4 access in initrd to protect LUKS keys
  boot.initrd.luks.mitigateDMAAttacks = lib.mkForce true;
}
