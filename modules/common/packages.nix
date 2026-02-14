{ config, pkgs, lib, ... }:

{
  # Allow unfree packages where explicitly requested by lower-priority modules
  # (e.g., VeraCrypt). We set a forced true here only if a module needs it.
  # NOTE: using `lib.mkForce` ensures this is applied before package evaluation.
  nixpkgs.config.allowUnfree = lib.mkForce true;

  # Install only "out" output by default (exclude "man", "doc", etc.)
  # This prevents errors when packages have incorrect meta.outputsToInstall
  # Some packages (especially in GNOME) claim to have "man" output but don't actually provide it
  environment.outputsToInstall = [ "out" ];

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
