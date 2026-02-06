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
    # 
    # SECURITY MECHANISM:
    # - sockets.x11 = true activates automatic isolation via nix-bwrapper
    # - nix-bwrapper creates a separate X11 socket only for this application
    # - Program CANNOT SEE other X11 displays (including compositor's Xwayland :0)
    # - Access only to its isolated display via xwayland-satellite
    # - /tmp/.X11-unix contains ONLY this application's socket
    sockets = {
      x11 = true;  # Automatically launches xwayland-satellite per-app + X11 socket isolation
      wayland = appConfig.allowWayland or false;  # Fallback to Wayland if supported
      pulseaudio = appConfig.allowAudio or true;
      pipewire = appConfig.allowAudio or true;
    };

    # Filesystem: minimal access by default
    mounts = {
      # Home directory: read-only by default
      read = appConfig.readOnlyPaths or [];
      readWrite = appConfig.readWritePaths or [
        # Allow writes to sandbox-specific directory
        "$HOME/.bwrapper/${appConfig.id}"
      ];

      # Sandbox directory for isolation (listOf submodule with name/path)
      sandbox = appConfig.sandboxPaths or [
        {
          name = "config";
          path = "$HOME/.config";
        }
        {
          name = "local";
          path = "$HOME/.local";
        }
        {
          name = "cache";
          path = "$HOME/.cache";
        }
      ];

      privateTmp = appConfig.privateTmp or true;
    };

    # D-Bus: restricted access
    dbus = appConfig.dbus or {
      session = {
        talks = [
          "org.freedesktop.portal.*"  # XDG Portals for secure access
        ];
      };
    };
  } // (lib.optionalAttrs (appConfig.useFHS or false) {
    # FHS environment opts for legacy applications
    fhsenv.opts = {
      unshareNet = appConfig.isolateNetwork or false;
      unshareIpc = true;
      unsharePid = true;
      unshareUser = false;  # Usually false for FHS apps
      unshareUts = true;
    };
  });

  # Generate desktop entry for sandboxed application
  generateDesktopEntry = appConfig: wrappedPkg: pkgs.makeDesktopItem {
    name = "${appConfig.id}-isolated";
    desktopName = "${appConfig.desktopName} (X11 Isolated)";
    exec = "${wrappedPkg}/bin/${appConfig.id}";
    icon = appConfig.icon or appConfig.id;
    comment = "Isolated X11 session via xwayland-satellite - ${appConfig.comment or ""}";
    categories = appConfig.categories or [ "Application" ];
    terminal = appConfig.terminal or false;
  };

  # Create wrapped packages for all configured apps
  wrappedApps = map mkSandboxedX11App cfg.isolatedApps;
in

{ }
