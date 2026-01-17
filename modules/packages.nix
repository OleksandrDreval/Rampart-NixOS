{ config, pkgs, ... }:

{
  # Allow unfree packages
  nixpkgs.config.allowUnfree = true;

  # Enable Firefox browser
  programs.firefox.enable = true;

  # System-wide packages
  environment.systemPackages = (config.environment.systemPackages or []) ++ (with pkgs; [
    # Add your packages here
    # vim
    # wget
  ]);

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
