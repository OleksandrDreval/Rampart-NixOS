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
  mkSandboxedX11App = appConfig: pkgs.mkBwrapper ({
    # Basic application configuration
    app = {
      package = appConfig.package;
      id = appConfig.id;
      env = appConfig.env or {};
    } // (lib.optionalAttrs ((appConfig.execArgs or []) != []) {
      # Convert list of args to space-separated string
      execArgs = lib.concatStringsSep " " (appConfig.execArgs or []);
    });

    # X11 isolation: each application gets a separate Xorg via xwayland-satellite
    # This completely isolates X11 applications from each other
    #
    # SECURITY MECHANISM:
    # - sockets.x11 = true activates automatic isolation via nix-bwrapper
    # - nix-bwrapper creates a separate X11 socket only for this application
    # - Program CANNOT SEE other X11 displays (including compositor's Xwayland :0)
    # - Access only to its isolated display via xwayland-satellite
    # - /tmp/.X11-unix contains ONLY this application's socket
    #
    # IMPORTANT: xwayland-satellite ITSELF needs wayland socket to create X11 server!
    # Even for X11-only apps, xwayland-satellite requires wayland compositor access
    sockets = {
      x11 = true;  # Automatically launches xwayland-satellite per-app + X11 socket isolation
      wayland = true;  # REQUIRED for xwayland-satellite to work! It's X11→Wayland bridge
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
  }));

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

  # Create desktop entries for all wrapped apps
  desktopEntries = lib.imap0 (i: appConfig:
    generateDesktopEntry appConfig (builtins.elemAt wrappedApps i)
  ) cfg.isolatedApps;

in

{
  # NOTE: nix-bwrapper overlay (mkBwrapper, mkBwrapperFHSEnv) is applied
  # centrally in flake.nix via nix-bwrapper.overlays.default
  # Parent module (x11-isolation-config.nix) does not re-apply the overlay

  options.security.x11Isolation = {
    enable = mkEnableOption "automatic X11 application isolation via nix-bwrapper + xwayland-satellite";

    isolatedApps = mkOption {
      type = types.listOf (types.submodule {
        options = {
          package = mkOption {
            type = types.package;
            description = "Application package to wrap";
            example = literalExpression "pkgs.firefox-esr";
          };

          id = mkOption {
            type = types.str;
            description = "Unique application identifier (used for paths and naming)";
            example = "firefox-esr";
          };

          desktopName = mkOption {
            type = types.str;
            description = "Display name for the application";
            example = "Firefox ESR";
          };

          icon = mkOption {
            type = types.str;
            default = "";
            description = "Icon name";
            example = "firefox-esr";
          };

          comment = mkOption {
            type = types.str;
            default = "";
            description = "Application description";
            example = "Legacy X11 Web Browser";
          };

          categories = mkOption {
            type = types.listOf types.str;
            default = [ "Application" ];
            description = "Desktop entry categories";
            example = [ "Network" "WebBrowser" ];
          };

          terminal = mkOption {
            type = types.bool;
            default = false;
            description = "Run in terminal";
          };

          # Advanced sandboxing options

          env = mkOption {
            type = types.attrsOf types.str;
            default = {};
            description = "Environment variables for the application";
            example = { MOZILLA_USE_XINPUT2 = "1"; };
          };

          execArgs = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Additional command-line arguments";
            example = [ "--no-remote" "--profile" "/custom/profile" ];
          };

          # NOTE: Wayland socket is always enabled for xwayland-satellite
          # xwayland-satellite needs wayland compositor to create isolated X11 servers
          # The X11 application itself only sees X11 (controlled by env vars like GDK_BACKEND)

          allowAudio = mkOption {
            type = types.bool;
            default = true;
            description = "Allow PulseAudio/PipeWire access";
          };

          readOnlyPaths = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Paths to mount read-only";
            example = [ "$HOME/Documents" "/mnt/data" ];
          };

          readWritePaths = mkOption {
            type = types.listOf types.str;
            default = [ "$HOME/.bwrapper/\${id}" ];
            description = "Paths to mount read-write";
            example = [ "$HOME/Downloads" "$HOME/.config/app" ];
          };

          sandboxPaths = mkOption {
            type = types.listOf (types.submodule {
              options = {
                name = mkOption {
                  type = types.str;
                  description = "Directory name created under $HOME/.bwrapper/[app-id]/";
                  example = "config";
                };
                path = mkOption {
                  type = types.str;
                  description = "Path for this directory within the sandbox";
                  example = "$HOME/.config";
                };
              };
            });
            default = [];
            description = ''
              Sandboxed path mappings (name -> path).
              Default includes: config, local, cache
            '';
            example = literalExpression ''
              [
                { name = "config"; path = "$HOME/.config"; }
                { name = "documents"; path = "$HOME/Documents"; }
              ]
            '';
          };

          privateTmp = mkOption {
            type = types.bool;
            default = true;
            description = "Use private /tmp directory";
          };

          dbus = mkOption {
            type = types.attrs;
            default = {
              session = {
                talks = [ "org.freedesktop.portal.*" ];
              };
            };
            description = "D-Bus access configuration";
          };

          useFHS = mkOption {
            type = types.bool;
            default = false;
            description = "Wrap in FHS environment (for non-Nix applications)";
          };

          isolateNetwork = mkOption {
            type = types.bool;
            default = false;
            description = "Isolate network (only when useFHS = true)";
          };
        };
      });
      default = [];
      description = ''
        List of X11 legacy applications that should be automatically isolated.
        Each application gets its own X server via xwayland-satellite, preventing
        X11-based attacks like keylogging, window injection, and screenshots.

        Files are stored in $HOME/.bwrapper/{app.id}/
      '';
      example = literalExpression ''
        [
          {
            package = pkgs.firefox-esr;
            id = "firefox-esr";
            desktopName = "Firefox ESR";
            icon = "firefox-esr";
            comment = "Legacy X11 Web Browser";
            categories = [ "Network" "WebBrowser" ];
            readWritePaths = [ "$HOME/Downloads" ];
            allowAudio = true;
          }
        ]
      '';
    };

    disableXwayland = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Completely disable compositor's Xwayland for maximum security.

        With nix-bwrapper + xwayland-satellite, each X11 app gets its own
        isolated Xorg server, so the compositor's shared Xwayland is not needed.

        Only enable this if ALL your X11 applications are configured in isolatedApps.

        Warning: This will break X11 applications that are not explicitly sandboxed.
      '';
    };
  };

  config = mkIf cfg.enable {
    # Add wrapped applications to system packages
    environment.systemPackages = wrappedApps ++ desktopEntries;

    # NOTE: programs.xwayland.enable is managed by x11-isolation-config.nix
    # to avoid conflicts between multiple isolation modules

    # Security warnings and information
    warnings =
      # Warning: X11 isolation enabled with compositor's Xwayland still active
      lib.optional (cfg.enable && !cfg.disableXwayland && (builtins.length cfg.isolatedApps) > 0) ''
        X11 isolation is enabled via xwayland-satellite (per-app X servers).

        For maximum security, consider disabling the compositor's shared Xwayland:
          security.x11Isolation.disableXwayland = true

        Only do this after configuring ALL X11 applications in isolatedApps.
      ''
      ++
      # Warning: Module enabled but no apps configured
      lib.optional (cfg.enable && (builtins.length cfg.isolatedApps) == 0) ''
        X11 isolation is enabled but no applications are configured.
        Add applications to security.x11Isolation.isolatedApps.
      '';

    # Information about isolated files
    system.activationScripts.x11IsolationInfo = lib.mkIf cfg.enable (
      lib.stringAfter [ "etc" ] ''
        echo "X11 Isolation enabled for ${toString (builtins.length cfg.isolatedApps)} applications"
        echo "Sandboxed data location: \$HOME/.bwrapper/{app-id}/"
        echo "Each X11 app runs in isolated Xorg via xwayland-satellite"
      ''
    );
  };

  meta = {
    maintainers = [ "Rampart-NixOS" ];
    doc = ''
      X11 Legacy Application Isolation Module

      This module provides comprehensive isolation for legacy X11 applications
      that cannot run natively on Wayland. Using nix-bwrapper + xwayland-satellite,
      each X11 application runs in its own isolated environment with:

      Security Features:
      - Per-app X servers via xwayland-satellite (prevents X11 spying)
      - Filesystem sandboxing (private $HOME/.bwrapper/{app-id}/)
      - D-Bus filtering (only portals by default)
      - Network isolation (optional)
      - Private /tmp directory
      - Sandboxed user namespaces

      Architecture:
      - nix-bwrapper: NixOS wrapper for bubblewrap sandboxing
      - xwayland-satellite: Per-application X11 server implementation
      - No shared Xwayland: Each app has dedicated Xorg instance
      - XDG Portals: Controlled resource access (files, screenshots, etc.)

      Advantages over traditional Xpra:
      - Full filesystem and D-Bus sandboxing (not just X11)
      - Declarative NixOS configuration (no shell scripts)
      - Better integration with Wayland compositors
      - Modern sandboxing via bubblewrap (used by Flatpak)
      - Automatic desktop entry generation

      Usage:
      1. Enable the module: security.x11Isolation.enable = true;
      2. Configure X11 apps in isolatedApps with full permissions
      3. Applications get "(X11 Isolated)" desktop entries
      4. Data stored in $HOME/.bwrapper/{app-id}/

      Example Configuration:
        security.x11Isolation = {
          enable = true;
          isolatedApps = [
            {
              package = pkgs.firefox-esr;
              id = "firefox-esr";
              desktopName = "Firefox ESR";
              icon = "firefox-esr";
              comment = "Legacy X11 Web Browser";
              categories = [ "Network" "WebBrowser" ];
              readWritePaths = [ "$HOME/Downloads" ];
              allowAudio = true;
              # NOTE: Wayland socket automatically enabled for xwayland-satellite
              # Use GDK_BACKEND=x11 in env to force X11 backend
            }
          ];
          # Optional: disable shared Xwayland for maximum security
          # disableXwayland = true;
        };

      Advanced Options:
      - env: Custom environment variables (e.g., GDK_BACKEND=x11 to force X11)
      - execArgs: Additional CLI arguments
      - readOnlyPaths/readWritePaths: Fine-grained filesystem access
      - sandboxPaths: Path remapping (e.g., fake $HOME)
      - dbus: D-Bus service access control
      - useFHS: FHS environment for non-Nix binaries
      - isolateNetwork: Complete network isolation

      Security Best Practice:
      After configuring all X11 apps, set disableXwayland = true to completely
      disable the compositor's shared Xwayland server. This prevents any
      unconfigured X11 apps from running and eliminates the X11 attack surface.

      Documentation:
      - GitHub: https://github.com/Naxdy/nix-bwrapper
      - Interactive Options Search: https://naxdy.github.io/nix-bwrapper/
      - README Examples: https://github.com/Naxdy/nix-bwrapper#getting-started
    '';
  };
}
