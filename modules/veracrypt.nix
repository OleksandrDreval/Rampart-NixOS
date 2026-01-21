{ config, pkgs, lib, ... }:

let
  vars = import ./includes/variables.nix;
in
{
  # Install VeraCrypt/ntfs3g only for the named user (low priority default).
  # Using `lib.mkDefault` ensures this does not force-overwrite any explicit
  # `users.users.<name>.packages` set elsewhere (for example in `users.nix`).
  users.users.${vars.mainUser}.packages = lib.mkDefault (with pkgs; [ veracrypt ntfs3g ]);

  # Security: prevent non-root users from using the FUSE `allow_other` mount
  # option. Allowing `allow_other` lets other local users read mounted filesystems,
  # which is a privacy/security risk for encrypted volumes. We force `false` here
  # so this module cannot be overridden by lower-priority modules.
  programs.fuse.userAllowOther = lib.mkForce false;
}
