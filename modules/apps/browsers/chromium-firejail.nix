{ config, pkgs, lib, ... }:

let
  vars = import ../../security/secrets/vars-compat.nix { inherit config lib; };
in

{
  # Ungoogled Chromium - provision only for the named user as a low-priority default
  # This avoids installing Chromium system-wide and respects any explicit
  # `users.users.<name>.packages` set elsewhere.
  users.users.${vars.mainUser}.packages = lib.mkDefault (with pkgs; [ ungoogled-chromium ]);

  # Firejail-based wrapper for Chromium that hides system preload files
  programs.firejail = {
    enable = true;
    wrappedBinaries = {
      chromium = {
        executable = "${pkgs.ungoogled-chromium}/bin/chromium";
        profile = "${pkgs.firejail}/etc/firejail/chromium.profile";
        extraArgs = [
          "--blacklist=/etc/ld-nix.so.preload"
        ];
      };
    };
  };

  # Ensure unprivileged namespaces available for sandboxing
  security.unprivilegedUsernsClone = lib.mkForce true;

  # Allow user namespaces for sandboxing
  security.allowUserNamespaces = lib.mkForce true;

  # Disable Chromium's SUID sandbox since Firejail provides its own sandboxing
  security.chromiumSuidSandbox.enable = lib.mkForce false;
}
