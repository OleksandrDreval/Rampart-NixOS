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
  
  # Create desktop entries for all wrapped apps
  desktopEntries = lib.imap0 (i: appConfig: 
    generateDesktopEntry appConfig (builtins.elemAt wrappedApps i)
  ) cfg.isolatedApps;

in

{
  # Import nix-bwrapper integration
  imports = [ ./bwrapper-integration.nix ];

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

          allowWayland = mkOption {
            type = types.bool;
            default = false;
            description = "Allow Wayland socket access (fallback if app supports both)";
          };

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

    # Disable compositor's Xwayland if requested (maximum security mode)
    # With xwayland-satellite each X11 application has its own Xorg server
    programs.xwayland.enable = lib.mkDefault (!cfg.disableXwayland);

    # Security warnings and information
    warnings = 
      lib.optional (cfg.enable && !cfg.disableXwayland) ''
        X11 isolation is enabled via xwayland-satellite (per-app X servers).
        
        For maximum security, consider disabling the compositor's shared Xwayland:
          security.x11Isolation.disableXwayland = true
        
        Only do this after configuring ALL X11 applications in isolatedApps.
      ''
      ++
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
}
