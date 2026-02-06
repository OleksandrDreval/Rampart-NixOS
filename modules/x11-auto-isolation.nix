# Automatic X11 application isolation
# Combined approach: nixpkgs overlay + runtime wrapper
# Documentation: https://github.com/Naxdy/nix-bwrapper

{ config, pkgs, lib, ... }:

with lib;

let
  cfg = config.security.x11AutoIsolation;
in

{ }
