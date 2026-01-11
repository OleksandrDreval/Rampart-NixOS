{ config, pkgs, ... }:

let
  vars = import ./variables.nix;
in
{
  # Bootloader configuration
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.configurationLimit = vars.bootConfigLimit;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.loader.timeout = vars.bootTimeout;

  # LUKS encryption for swap
  boot.initrd.luks.devices."luks-${vars.luksSwapUUID}".device = "/dev/disk/by-uuid/${vars.luksSwapUUID}";

  # DMA attack mitigation during early boot
  # Blocks Thunderbolt/USB4 access in initrd to protect LUKS keys
  boot.initrd.luks.mitigateDMAAttacks = true;
}
