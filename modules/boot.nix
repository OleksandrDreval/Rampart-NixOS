{ config, pkgs, ... }:

let
  vars = import ./variables.nix;
in
{
  # Bootloader configuration
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.configurationLimit = 3;  # Keep only last 3 configurations
  boot.loader.efi.canTouchEfiVariables = true;
  boot.loader.timeout = 10;  # 10 seconds timeout

  # LUKS encryption for swap
  boot.initrd.luks.devices."luks-${vars.luksSwapUUID}".device = "/dev/disk/by-uuid/${vars.luksSwapUUID}";
}
