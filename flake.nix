{
  description = "Rampart-NixOS: Hardened NixOS configuration with X11 isolation";

  # Inputs - all external dependencies
  inputs = {
    # Main nixpkgs - unstable for latest packages
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    # Alternatively, pin a stable version:
    # nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";

    # nix-bwrapper for X11 isolation
    nix-bwrapper = {
      url = "github:Naxdy/nix-bwrapper";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Lanzaboote for Secure Boot
    lanzaboote = {
      url = "github:nix-community/lanzaboote/v1.0.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # sops-nix for secrets management
    sops-nix = {
      url = "github:Mic92/sops-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Impermanence for ephemeral root (optional)
    # impermanence.url = "github:nix-community/impermanence";
  };

  # Outputs - what this flake provides
  outputs = { self, nixpkgs, nix-bwrapper, lanzaboote, sops-nix, ... }@inputs:
    let
      # Load centralized variables
      vars = import ./modules/includes/variables.nix;

      # System architecture
      system = vars.system;

      # Machine hostName
      hostName = vars.hostName;

      # Common arguments for all configurations
      specialArgs = {
        inherit inputs system hostName vars;
      };

      # Use pkgs with overlays
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };

    in {
      # NixOS configuration
      nixosConfigurations.${hostName} = nixpkgs.lib.nixosSystem {
        inherit system specialArgs;

        modules = [
          # Hardware configuration
          ./modules/core/hardware-configuration.nix

          # sops-nix module for secrets management
          sops-nix.nixosModules.sops

          # Main configuration
          ./configuration.nix

          # Flake-specific modules
          {
            # Configure nixpkgs with overlays and unfree packages
            nixpkgs.config.allowUnfree = true;
            nixpkgs.overlays = [
              nix-bwrapper.overlays.default
            ] ++ overlays;

            # Set hostName
            networking.hostName = hostName;

            # Enable flakes
            nix.settings.experimental-features = [ "nix-command" "flakes" ];
          }
        ];
      };

      # Development shell with useful tools
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          nixfmt-rfc-style  # Nix formatter (RFC 166 style)
          nil               # Nix Language Server
          statix            # Nix linter
          deadnix           # Find dead code in Nix
        ];

        shellHook = ''
          echo "Rampart-NixOS Development Shell"
          echo "Available commands:"
          echo "  nixos-rebuild switch --flake .#${hostName}"
          echo "  nix flake update    # Update dependencies"
          echo "  nix flake check     # Check configuration"
          echo "  nix fmt             # Format Nix files"
        '';
      };

      # Formatter for 'nix fmt' command
      formatter.${system} = pkgs.nixfmt-rfc-style;

      # Configuration checks
      checks.${system} = {
        # Syntax and evaluation check
        configuration = self.nixosConfigurations.${hostName}.config.system.build.toplevel;
      };
    };
}
