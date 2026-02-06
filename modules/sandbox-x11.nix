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

  # Create sandboxed X11 application via nix-bwrapper
  # Each X11 application gets its own Xorg server via xwayland-satellite
  mkSandboxedX11App = appConfig: pkgs.mkBwrapper {
    # Basic application configuration
    app = {
      package = appConfig.package;
      id = appConfig.id;
      env = appConfig.env or {};
      execArgs = appConfig.execArgs or [];
    };

    # X11 isolation: each application gets a separate Xorg via xwayland-satellite
    # This completely isolates X11 applications from each other
    sockets = {
      x11 = true;  # Automatically launches xwayland-satellite per-app + X11 socket isolation
      wayland = appConfig.allowWayland or false;  # Fallback to Wayland if supported
      pulseaudio = appConfig.allowAudio or true;
      pipewire = appConfig.allowAudio or true;
    };
  };
in

{ }
