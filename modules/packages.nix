{ config, pkgs, lib, ... }:

{
  # Allow unfree packages where explicitly requested by lower-priority modules
  # (e.g., VeraCrypt). We set a forced true here only if a module needs it.
  # NOTE: using `lib.mkForce` ensures this is applied before package evaluation.
  nixpkgs.config.allowUnfree = lib.mkForce true;

  # System-wide packages
  environment.systemPackages = lib.mkDefault (with pkgs; [
    # Add your packages here
    # vim
    # wget
  ] ++ (config.environment.systemPackages or []));

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # Enable the OpenSSH daemon
  # services.openssh.enable = true;
}
