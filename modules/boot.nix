{ config, pkgs, ... }:

let
  vars = import ./variables.nix;
in
{
  # Bootloader configuration
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.configurationLimit = vars.bootConfigLimit;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.loader.timeout = vars.bootTimeout;

  # LUKS encryption for swap
  boot.initrd.luks.devices."luks-${vars.luksSwapUUID}".device = "/dev/disk/by-uuid/${vars.luksSwapUUID}";
}
