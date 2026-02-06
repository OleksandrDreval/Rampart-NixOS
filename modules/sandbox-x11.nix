# X11 Legacy Application Isolation Module (Manual Configuration Mode)
# Uses nix-bwrapper + xwayland-satellite for per-app X11 isolation
# Documentation: https://github.com/Naxdy/nix-bwrapper
# Options: https://naxdy.github.io/nix-bwrapper/
#
# NOTE: This module is for DETAILED MANUAL configuration of individual X11 applications.
# For AUTOMATIC isolation of all X11 applications use
# x11-auto-isolation.nix (recommended for most cases).
#
# Both modules can be used simultaneously:
# - x11-auto-isolation.nix: automatic isolation of all X11 applications
# - sandbox-x11.nix: detailed configuration of specific applications

{ config, pkgs, lib, ... }:

with lib;

let
  cfg = config.security.x11Isolation;
in

{ }
