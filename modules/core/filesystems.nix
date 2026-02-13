{ config, pkgs, lib, ... }:

let
  vars = import ../security/secrets/vars-compat.nix { inherit config lib; };

  # Rampart filesystems-specific sysctl entries. Aggregated by kernel-finalize.
  rampartFilesystemsSysctl = {
    "fs.binfmt_misc.status"   = 0;  # Disable support for miscellaneous binary formats
    "fs.protected_fifos"      = 2;  # Maximum protection for FIFOs in sticky directories
    "fs.protected_hardlinks"  = 1;  # Restrict hardlink creation to file owners
    "fs.protected_regular"    = 2;  # Maximum protection for regular files in sticky directories
    "fs.protected_symlinks"   = 1;  # Restrict symlink following to prevent race conditions
    "fs.suid_dumpable"        = 0;  # Disable core dumps for SUID processes
  };
in

{
  # Filesystem-related security defaults and helpers
  # This module centralises fs-related sysctl hardening and provides
  # a conservative default to install `ntfs3g` for NTFS support.

  # NOTE: NTFS support was previously attempted by forcing `ntfs3g` and
  # requesting the `fuse` kernel module. Those attempts are removed in
  # favor of declaring `boot.supportedFilesystems` below which is the
  # canonical place to request filesystem support for boot/initrd.

  # Declare supported filesystems for boot/initrd. This allows NixOS to
  # include necessary kernel modules and initrd helpers for NTFS/FUSE/etc.
  boot.supportedFilesystems = lib.mkForce [ "ntfs" ];

  # LUKS device mappings
  boot.initrd.luks.devices."luks-${vars.luksRootUUID}".device = "/dev/disk/by-uuid/${vars.luksRootUUID}";

  # LUKS encryption for swap
  boot.initrd.luks.devices."luks-${vars.luksSwapUUID}".device = "/dev/disk/by-uuid/${vars.luksSwapUUID}";

  # Swap devices
  swapDevices = [ { device = "/dev/mapper/luks-${vars.luksSwapUUID}"; } ];

  # Filesystem mount points (migrated from hardware-configuration.nix)
  fileSystems."/" = {
    device = "/dev/mapper/luks-${vars.luksRootUUID}";
    fsType = "btrfs";
    options = [ "subvol=@" ];
  };

  fileSystems."/home" = {
    device = "/dev/mapper/luks-${vars.luksRootUUID}";
    fsType = "btrfs";
    options = [ "subvol=@home" ];
  };

  fileSystems."/boot" = {
    device = "/dev/disk/by-uuid/${vars.bootPartitionUUID}";
    fsType = "vfat";
    options = [ "fmask=0077" "dmask=0077" ];
  };

  # Security: prevent non-root users from using the FUSE `allow_other` mount
  # option. Allowing `allow_other` lets other local users read mounted filesystems,
  # which is a privacy/security risk for encrypted volumes. We force `false` here
  # so this module cannot be overridden by lower-priority modules.
  programs.fuse.userAllowOther = lib.mkForce false;

  # Expose rampart attributes for final aggregation
  rampart = {
    rampartFilesystemsSysctl = rampartFilesystemsSysctl;
  };
}
