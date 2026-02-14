{ config, pkgs, lib, ... }:

{
  # Allow unfree packages where explicitly requested by lower-priority modules
  # (e.g., VeraCrypt). We set a forced true here only if a module needs it.
  # NOTE: using `lib.mkForce` ensures this is applied before package evaluation.
  nixpkgs.config.allowUnfree = lib.mkForce true;

  # Disable man pages, info pages, and documentation
  # Some packages (especially in GNOME) have incorrect meta.outputsToInstall
  # and claim to have "man" output when they don't - this causes build errors
  documentation.man.enable = false;
  documentation.info.enable = false;
  documentation.doc.enable = false;

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
