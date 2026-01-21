{ config, pkgs, lib, ... }:

{
  # By default, unfree (proprietary/binary-only) packages are disabled.
  # This provides a conservative system-wide default. Other modules can
  # override this setting (for example with `lib.mkDefault` or
  # `lib.mkForce`) if a specific unfree package is required.
  # Example: to allow binary-only packages globally, set
  # `nixpkgs.config.allowUnfree = lib.mkDefault true` in a higher-priority module.
  nixpkgs.config.allowUnfree = lib.mkDefault false;

  # Enable Firefox browser
  programs.firefox.enable = true;

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
