{ config, pkgs, lib, ... }:

{
  # Allow unfree packages where explicitly requested by lower-priority modules
  # (e.g., VeraCrypt). We set a forced true here only if a module needs it.
  # NOTE: using `lib.mkForce` ensures this is applied before package evaluation.
  nixpkgs.config.allowUnfree = lib.mkForce true;

  # Disable ALL documentation outputs for minimal/hardened system
  # This prevents "attribute 'man' missing" errors caused by NixOS
  # appending "man" to every package's meta.outputsToInstall via
  # documentation.man.enable = true (default), even for packages
  # that don't have a "man" output
  documentation.enable = lib.mkForce false;
  documentation.man.enable = lib.mkForce false;
  documentation.doc.enable = lib.mkForce false;
  documentation.info.enable = lib.mkForce false;
  documentation.dev.enable = lib.mkForce false;
  documentation.nixos.enable = lib.mkForce false;

  # Ensure no extra outputs (man/doc/info/dev) are appended to systemPackages
  environment.extraOutputsToInstall = lib.mkForce [];

  # System-wide packages
  environment.systemPackages = lib.mkDefault (with pkgs; [
    # Essential tools
    git           # Required for flakes
    vim           # Text editor
    wget          # File downloader
    curl          # Another downloader
    htop          # Process monitor
    tree          # Directory structure viewer
    file          # File type detection

    # Compression tools
    unzip
    zip

    # System info
    lshw
    pciutils
    usbutils
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
