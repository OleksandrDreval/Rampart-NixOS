{ config, pkgs, lib, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # Ungoogled Chromium - provision only for the named user as a low-priority default
  # This avoids installing Chromium system-wide and respects any explicit
  # `users.users.<name>.packages` set elsewhere.
  users.users.${vars.mainUser}.packages = lib.mkDefault (with pkgs; [ ungoogled-chromium ]);

  # Allow user namespaces for sandboxing
  security.allowUserNamespaces = lib.mkForce true;
}
