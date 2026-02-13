{ config, pkgs, lib, ... }:

let
  vars = import ../../security/secrets/vars-compat.nix { inherit config lib; };
in

{
  # Ungoogled Chromium - provision only for the named user as a low-priority default
  # This avoids installing Chromium system-wide and respects any explicit
  # `users.users.<name>.packages` set elsewhere.
  users.users.${vars.mainUser}.packages = lib.mkDefault (with pkgs; [ ungoogled-chromium ]);

  # Ensure unprivileged namespaces available for sandboxing
  security.unprivilegedUsernsClone = lib.mkForce true;

  # Allow user namespaces for sandboxing
  security.allowUserNamespaces = lib.mkForce true;

  # Optional future settings (disabled by default):
  # - wrapProgram to unset LD_PRELOAD for this binary
  # - additional sandboxing or apparmor rules
}
