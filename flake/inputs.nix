# Centralized flake inputs management
# This file can be imported into other modules for inputs access

{ inputs, ... }:

let
  # Load centralized variables
  vars = import ../includes/variables.nix;
in
{
  # Re-export inputs for use in modules
  _module.args.flakeInputs = inputs;

  # Configure nixpkgs from flake
  nixpkgs.config = {
    allowUnfree = vars.allowUnfree;
    
    # Allow specific unfree packages
    allowUnfreePredicate = pkg: builtins.elem (inputs.nixpkgs.lib.getName pkg) vars.allowUnfreeList;
    
    # Permit insecure packages
    permittedInsecurePackages = vars.permittedInsecurePackages;
  };

  # Nix + Flakes configuration
  nix = {
    # Registry for nix commands (for 'nix run nixpkgs#hello')
    registry = {
      nixpkgs.flake = inputs.nixpkgs;
      self.flake = inputs.self;
    };

    # NIX_PATH for legacy commands
    nixPath = [ "nixpkgs=${inputs.nixpkgs}" ];

    # Flakes settings
    settings = {
      experimental-features = vars.nixExperimentalFeatures;
      
      # Automatically optimize store
      auto-optimise-store = vars.nixAutoOptimiseStore;
      
      # Trusted users for nix daemon
      trusted-users = vars.nixTrustedUsers;
      
      # Substituters (binary caches) - from variables.nix
      substituters = vars.substituters;
      
      # Trusted public keys - from variables.nix
      trusted-public-keys = vars.trustedPublicKeys;
    };

    # Automatic garbage collection - from variables.nix
    gc = {
      automatic = vars.gcAutomatic;
      dates = vars.gcDates;
      options = vars.gcOptions;
    };
  };
}
