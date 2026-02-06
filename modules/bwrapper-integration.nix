{ config, pkgs, lib, ... }:

let
  nix-bwrapper = pkgs.fetchGit {
    url = "https://github.com/Naxdy/nix-bwrapper";
    ref = "main";
    # Use specific commit for stability and reproducibility
    rev = "1248b52f2bd4fe5690c1a36836a1798be21d953b"; # 2026-02-06: chore: update flake deps
  };
in 

{ }
