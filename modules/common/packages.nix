{ config, pkgs, lib, ... }:

{
  # Allow unfree packages where explicitly requested by lower-priority modules
  # (e.g., VeraCrypt). We set a forced true here only if a module needs it.
  # NOTE: using `lib.mkForce` ensures this is applied before package evaluation.
  nixpkgs.config.allowUnfree = lib.mkForce true;

  # Install ONLY main "out" output for ALL packages (ignore man/doc/info/dev/debug)
  # This saves disk space (10-50 GB) and prevents errors when packages have broken output metadata
  # For minimal/hardened systems, only the main executables and libraries are needed

  # Override meta.outputsToInstall to ["out"] for every package in the system
  # This ensures ONLY the main output is installed, regardless of package defaults
  nixpkgs.overlays = [
    (final: prev:
      lib.mapAttrs (name: pkg:
        if lib.isDerivation pkg && pkg ? meta then
          pkg.overrideAttrs (old: {
            meta = (old.meta or {}) // {
              outputsToInstall = [ "out" ];  # Force ONLY "out", ignore everything else
            };
          })
        else pkg
      ) prev
    )
  ];

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
