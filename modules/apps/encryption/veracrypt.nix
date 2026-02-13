{ config, pkgs, lib, ... }:

let
  vars = import ../../security/secrets/vars-compat.nix { inherit config lib; };
in
{
  # allowUnfree is configured in `modules/packages.nix` so package sets
  # are evaluated with the correct policy prior to package selection.
  # Install VeraCrypt only for the named user (low priority default).
  # Using `lib.mkDefault` ensures this does not force-overwrite any explicit
  # `users.users.<name>.packages` set elsewhere (for example in `users.nix`).
  users.users.${vars.mainUser}.packages = lib.mkDefault (with pkgs; [ veracrypt ]);
}
