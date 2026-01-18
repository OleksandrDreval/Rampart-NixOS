{ config, pkgs, lib, ... }:

{
  # System packages required for VeraCrypt support.
  environment.systemPackages = with pkgs; [
    veracrypt  # VeraCrypt disk encryption tool
    ntfs3g     # NTFS filesystem support
  ] ++ (config.environment.systemPackages or []);

  # Security: prevent non-root users from using the FUSE `allow_other` mount
  # option. Allowing `allow_other` lets other local users read mounted filesystems,
  # which is a privacy/security risk for encrypted volumes. We force `false` here
  # so this module cannot be overridden by lower-priority modules.
  programs.fuse.userAllowOther = lib.mkForce false;
}
