{ config, pkgs, lib, ... }:

let
  nix-bwrapper = pkgs.fetchGit {
    url = "https://github.com/Naxdy/nix-bwrapper";
    ref = "main";
    # Use specific commit for stability and reproducibility
    rev = "1248b52f2bd4fe5690c1a36836a1798be21d953b"; # 2026-02-06: chore: update flake deps
  };

  bwrapperLib = import "${nix-bwrapper}/modules" {
    inherit pkgs;
    nixpkgs = import <nixpkgs> { }; # Required for build-fhsenv-bubblewrap
  };

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

{ }
