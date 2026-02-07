# nix-bwrapper system integration
# nix-bwrapper: https://github.com/Naxdy/nix-bwrapper
# Provides mkBwrapper and mkBwrapperFHSEnv functions for creating sandboxed applications
# Documentation: https://naxdy.github.io/nix-bwrapper/

{ config, pkgs, lib, ... }:

let
  # Load nix-bwrapper from GitHub
  # NOTE: For flake-based configurations use:
  # inputs.nix-bwrapper.url = "github:Naxdy/nix-bwrapper";
  # nixpkgs.overlays = [ nix-bwrapper.overlays.default ];
  nix-bwrapper = pkgs.fetchGit {
    url = "https://github.com/Naxdy/nix-bwrapper";
    ref = "main";
    # Use specific commit for stability and reproducibility
    rev = "1248b52f2bd4fe5690c1a36836a1798be21d953b"; # 2026-02-06: chore: update flake deps
  };

  # Import nix-bwrapper module system
  # modules/default.nix exports: bwrapperEval, options-json, evalMod
  bwrapperLib = import "${nix-bwrapper}/modules" {
    inherit pkgs;
    # Use pkgs.path to reference the same nixpkgs as the system
    # This is equivalent to 'inherit nixpkgs' in flake-based configs
    # Required for build-fhsenv-bubblewrap to access buildFHSEnv
    nixpkgs = pkgs.path;
  };

  # Create overlay according to flake.nix structure
  # Source: https://github.com/Naxdy/nix-bwrapper/blob/main/flake.nix#L223-L243
  bwrapperOverlay = final: prev: {
    # bwrapperEval - module configuration evaluator
    bwrapperEval = bwrapperLib.bwrapperEval;

    # mkBwrapper - main function for creating sandboxed packages
    # Takes module configuration and returns package
    mkBwrapper = mod: (final.bwrapperEval mod).config.build.package;

    # mkBwrapperFHSEnv - for packages already using buildFHSEnv
    # Takes module configuration and returns fhsenv function
    mkBwrapperFHSEnv = mod:
      (final.bwrapperEval {
        imports = [ mod ];
        app = {
          package = null;
          isFhsenv = true;
        };
      }).config.build.fhsenv;
  };
in 

{
  # Add overlay to nixpkgs
  # This makes mkBwrapper and mkBwrapperFHSEnv functions available
  nixpkgs.overlays = [ bwrapperOverlay ];

  # SECURITY SETTINGS
  # Required for bubblewrap sandboxing

  # Enable unprivileged user namespaces for bubblewrap
  # This allows regular users to create namespace isolation
  # Source: security.unprivilegedUsernsClone option in NixOS
  security.unprivilegedUsernsClone = lib.mkForce true;

  # Enable user namespaces (required for sandboxing)
  # Without this bubblewrap cannot create isolated environments
  # Source: security.allowUserNamespaces option in NixOS
  security.allowUserNamespaces = lib.mkForce true;

  # SYSTEM PACKAGES
  # NOTE: bubblewrap and xwayland-satellite are automatically added
  # by nix-bwrapper when using corresponding options:
  # - bubblewrap: always included as a dependency
  # - xwayland-satellite: automatically added when sockets.x11 = true
  #
  # No need to add them manually to environment.systemPackages

  # USAGE EXAMPLE
  # environment.systemPackages = [
  #   (pkgs.mkBwrapper {
  #     app = {
  #       package = pkgs.firefox;
  #       runScript = "firefox";
  #     };
  #     sockets.x11 = true;        # Unique X11 server via xwayland-satellite
  #     sockets.wayland = true;    # Wayland socket
  #     sockets.pulseaudio = true; # PulseAudio socket
  #     sockets.pipewire = true;   # PipeWire socket
  #     mounts.privateTmp = true;  # Isolated /tmp
  #     dbus.session.talks = [     # DBus permissions
  #       "org.freedesktop.Notifications"
  #     ];
  #   })
  # ];
}
