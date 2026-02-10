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
  # Using fetchFromGitHub instead of fetchGit (doesn't require git in system)
  nix-bwrapper = pkgs.fetchFromGitHub {
    owner = "Naxdy";
    repo = "nix-bwrapper";
    # Use specific commit for stability and reproducibility
    rev = "1248b52f2bd4fe5690c1a36836a1798be21d953b"; # 2026-02-06: chore: update flake deps
    # Hash verified with: nix-prefetch-url --unpack https://github.com/Naxdy/nix-bwrapper/archive/1248b52f2bd4fe5690c1a36836a1798be21d953b.tar.gz
    sha256 = "sha256-1x79rq1jfbl5akpikmrilnj2y2hbnisjvsf1lsmczqgcz5w8h6sp=";
  };

  # Create overlay according to official flake.nix structure
  # Source: https://github.com/Naxdy/nix-bwrapper/blob/main/flake.nix#L223-L243
  # CRITICAL: bwrapperLib must be created INSIDE overlay with final pkgs
  bwrapperOverlay = final: prev:
    let
      # Import nix-bwrapper module system with overlay-aware pkgs
      # modules/default.nix exports: bwrapperEval, options-json, evalMod
      bwrapperLib = import "${nix-bwrapper}/modules" {
        pkgs = final;  # Use final (overlay-aware) pkgs, not prev!
        # Use final.path to reference the same nixpkgs as the system after overlay
        # This is equivalent to 'inherit nixpkgs' in flake-based configs
        # Required for build-fhsenv-bubblewrap to access buildFHSEnv
        nixpkgs = final.path;
      };
    in {
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
