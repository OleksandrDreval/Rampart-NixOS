{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in
{
  # Bootloader configuration
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.configurationLimit = vars.bootConfigLimit;
  boot.loader.systemd-boot.editor = false;  # Disable boot parameter editing (prevent init=/bin/sh attacks)
  boot.loader.efi.canTouchEfiVariables = false;
  boot.loader.timeout = vars.bootTimeout;

  # Boot verbosity configuration (security: minimize information disclosure)
  boot.consoleLogLevel = 3;     # Show only errors on console (balance security/debugging)
  boot.initrd.verbose = false;  # Quiet initrd to minimize information disclosure

  # LUKS encryption for swap
  boot.initrd.luks.devices."luks-${vars.luksSwapUUID}".device = "/dev/disk/by-uuid/${vars.luksSwapUUID}";

  # DMA attack mitigation during early boot
  # Blocks Thunderbolt/USB4 access in initrd to protect LUKS keys
  boot.initrd.luks.mitigateDMAAttacks = true;
}
