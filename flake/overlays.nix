# Centralized overlays for package customization
# Overlays allow modifying or adding packages to nixpkgs

{ inputs, ... }:

[
  # Example 1: Add custom packages
  (final: prev: {
    # rampart-scripts = final.callPackage ../packages/rampart-scripts { };
    # custom-tool = final.callPackage ../packages/custom-tool { };
  })

  # Example 2: Modify existing package
  (final: prev: {
    # chromium-hardened = prev.chromium.override {
    #   commandLineArgs = [
    #     "--disable-features=WebRTC"
    #     "--enable-features=UseOzonePlatform"
    #     "--ozone-platform=wayland"
    #   ];
    # };
  })

  # Example 3: Add patch to package
  (final: prev: {
    # gimp-custom = prev.gimp.overrideAttrs (oldAttrs: {
    #   patches = (oldAttrs.patches or []) ++ [
    #     ./patches/gimp-custom.patch
    #   ];
    # });
  })

  # Example 4: Pin package version
  (final: prev: {
    # firefox = prev.firefox-esr;  # Use ESR instead of regular
  })

  # Example 5: Overlay for development tools
  (final: prev: {
    # dev-tools = prev.buildEnv {
    #   name = "rampart-dev-tools";
    #   paths = with final; [
    #     nixfmt-rfc-style
    #     nil
    #     statix
    #     deadnix
    #   ];
    # };
  })

  # If you need to use inputs in overlay:
  # (final: prev: {
  #   my-package = final.callPackage inputs.some-flake.packages.${final.system}.default { };
  # })
]
