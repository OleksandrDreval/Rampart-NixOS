{ config, pkgs, lib, ... }:

let
  vars = import ./includes/variables.nix;

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

  # Provide ntfs support via ntfs3g as a conservative default in system packages.
  environment.systemPackages = lib.mkDefault (with pkgs; [ ntfs3g ] ++ (config.environment.systemPackages or []));

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
