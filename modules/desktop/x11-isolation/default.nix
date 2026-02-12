# Example: X11 Isolation modules reorganization
# This file can be used as coordinator for related modules group

{ config, lib, inputs, flakeInputs, ... }:

{
  # Import group modules
  imports = [
    ./auto-isolation.nix
    ./manual-wrappers.nix
  ];

  # Options specific to this modules group
  options.rampart.x11Isolation = {
    enable = lib.mkEnableOption "Enable X11 isolation modules";
    
    useFlakeInput = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Use nix-bwrapper from flake input instead of fetchFromGitHub.
        Recommended for flake-based configurations.
      '';
    };
  };

  # Configuration
  config = lib.mkIf config.rampart.x11Isolation.enable {
    # Add nix-bwrapper overlay from flake input
    nixpkgs.overlays = lib.mkIf config.rampart.x11Isolation.useFlakeInput [
      flakeInputs.nix-bwrapper.overlays.default
    ];
    
    # Security settings for bubblewrap sandboxing
    security.unprivilegedUsernsClone = lib.mkForce true;
    security.allowUserNamespaces = lib.mkForce true;
    
    # Centralized Xwayland settings
    programs.xwayland.enable = lib.mkDefault (
      !config.security.x11AutoIsolation.disableCompositorXwayland &&
      !config.security.x11Isolation.disableXwayland
    );
    
    # Warning if both modes are disabled
    warnings = lib.optional 
      (config.security.x11AutoIsolation.disable && config.security.x11Isolation.disable)
      "Both X11 isolation modes are disabled. Consider enabling at least one.";
  };
}
