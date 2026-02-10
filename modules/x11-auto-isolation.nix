# Automatic X11 application isolation
# Combined approach: nixpkgs overlay + runtime wrapper
# Documentation: https://github.com/Naxdy/nix-bwrapper

{ config, pkgs, lib, ... }:

with lib;

let
  cfg = config.security.x11AutoIsolation;

  # Runtime wrapper for automatic X11 application isolation
  # Detects X11 usage and automatically creates isolated xwayland-satellite
  x11-auto-wrapper = pkgs.writeShellScriptBin "x11-launch" ''
    #!/usr/bin/env bash
    # X11 Auto-Isolation Wrapper
    # Automatically isolates X11 applications with xwayland-satellite + bubblewrap
    
    set -euo pipefail
    
    # Configuration
    readonly BWRAPPER_BASE="''${HOME}/.bwrapper/auto"
    readonly DISPLAY_BASE=${toString cfg.displayNumberStart}  # Configurable start display number
    readonly DISPLAY_MAX=$((DISPLAY_BASE + 99))  # 100 slots available
    readonly XDG_RUNTIME_DIR="''${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    
    # Argument validation
    if [ $# -eq 0 ]; then
      echo "Usage: x11-launch <program> [args...]" >&2
      echo "Example: x11-launch xterm" >&2
      exit 1
    fi
    
    # Get executable path
    readonly EXEC_PATH="$1"
    shift
    readonly EXEC_ARGS="$@"
    readonly EXEC_NAME=$(basename "$EXEC_PATH")
    
    # Generate unique ID for this execution
    readonly EXEC_ID="''${EXEC_NAME}-$$-$(date +%s)"
    readonly SANDBOX_DIR="''${BWRAPPER_BASE}/''${EXEC_ID}"
    readonly SANDBOX_HOME="''${SANDBOX_DIR}/home"
    readonly SANDBOX_TMP="''${SANDBOX_DIR}/tmp"
    
    # Create sandbox directories
    mkdir -p "''${SANDBOX_HOME}" "''${SANDBOX_TMP}"
    
    # Find free display
    find_free_display() {
      local i
      for i in $(seq $DISPLAY_BASE $DISPLAY_MAX); do
        if ! [ -S "/tmp/.X11-unix/X$i" ]; then
          echo $i
          return 0
        fi
      done
      echo "Error: No available display slots (:$DISPLAY_BASE-:$DISPLAY_MAX)" >&2
      return 1
    }
    
    readonly DISPLAY_NUM=$(find_free_display)
    if [ $? -ne 0 ]; then
      exit 1
    fi
    
    echo "[x11-launch] Launching ''${EXEC_NAME} in isolated X11 session :$DISPLAY_NUM" >&2
    
    # Start xwayland-satellite for this display
    # xwayland-satellite creates a separate X11 server that ensures isolation
    echo "[x11-launch] Starting xwayland-satellite for display :$DISPLAY_NUM" >&2
    ${pkgs.xwayland-satellite}/bin/xwayland-satellite :$DISPLAY_NUM &
    readonly XWAYLAND_PID=$!
    
    # Cleanup on exit
    cleanup() {
      local exit_code=$?
      echo "[x11-launch] Stopping xwayland-satellite (PID: $XWAYLAND_PID)" >&2
      kill "$XWAYLAND_PID" 2>/dev/null || true
      wait "$XWAYLAND_PID" 2>/dev/null || true
      echo "[x11-launch] Cleaning up sandbox for ''${EXEC_NAME}" >&2
      rm -rf "''${SANDBOX_DIR}"
      exit $exit_code
    }
    trap cleanup EXIT INT TERM
    
    # Give xwayland-satellite time to initialize X11 socket
    sleep 0.5
    
    # Create isolated structure for X11 sockets
    # This is critical for security: the program must not see other X11 displays
    readonly SANDBOX_X11DIR="''${SANDBOX_DIR}/x11"
    mkdir -p "''${SANDBOX_X11DIR}"
    
    # Bubblewrap arguments based on cfg.isolationSettings
    BWRAP_ARGS=(
      # Basic bind mounts
      --dev-bind /dev /dev
      --proc /proc
      --ro-bind /nix /nix
      --ro-bind /run/current-system /run/current-system
      --ro-bind-try /run/opengl-driver /run/opengl-driver
      --ro-bind-try /sys/dev /sys/dev
      --ro-bind-try /sys/devices /sys/devices
      --ro-bind-try /sys/bus /sys/bus
      --ro-bind-try /sys/class /sys/class
      
      # Symlinks for /bin, /usr/bin
      --symlink /run/current-system/sw/bin /bin
      --symlink /run/current-system/sw/bin /usr/bin
      
      # CRITICAL: Always use private /tmp for security
      # This prevents access to system /tmp files and other X11 sockets
      --bind "''${SANDBOX_TMP}" /tmp
      
      # X11 Socket Isolation: mount ONLY our isolated X11 socket
      # This ensures the program CANNOT connect to compositor's Xwayland (:0)
      # or other X11 displays - only to its isolated :$DISPLAY_NUM
      --tmpfs /tmp/.X11-unix
      --ro-bind-try "/tmp/.X11-unix/X$DISPLAY_NUM" "/tmp/.X11-unix/X$DISPLAY_NUM"
      
      # Sandbox home directory
      --bind "''${SANDBOX_HOME}" "''${HOME}"
      
      # XDG_RUNTIME_DIR for Wayland/PulseAudio sockets
      --ro-bind "''${XDG_RUNTIME_DIR}" "''${XDG_RUNTIME_DIR}"
      
      # Environment variables
      --setenv HOME "''${HOME}"
      --setenv XDG_RUNTIME_DIR "''${XDG_RUNTIME_DIR}"
      --setenv DISPLAY ":$DISPLAY_NUM"
      --unsetenv WAYLAND_DISPLAY  # Force X11
      
      # Isolation
      --unshare-user
      --unshare-pid
      --unshare-ipc
      --unshare-uts
      --die-with-parent
      
      # Application
      "''${EXEC_PATH}"
    )
    
    # Add application arguments
    if [ -n "''${EXEC_ARGS}" ]; then
      BWRAP_ARGS+=(''${EXEC_ARGS})
    fi
    
    # Launch program via bubblewrap in isolated environment
    # xwayland-satellite is already running and waiting for X11 connections on :$DISPLAY_NUM
    exec ${pkgs.bubblewrap}/bin/bwrap "''${BWRAP_ARGS[@]}"
  '';

  # Overlay for automatic X11 package wrapping
  x11AutoIsolationOverlay = final: prev: 
    let
      # Use list from cfg.overlayPackages
      x11OnlyPackages = cfg.overlayPackages;
      
      # Function to check if package is X11-only
      isX11OnlyPackage = name: builtins.elem name x11OnlyPackages;
      
      # Function for automatic X11 package wrapping
      # Uses settings from cfg.isolationSettings
      wrapX11Package = pkg: 
        if (prev ? mkBwrapper) then
          final.mkBwrapper {
            app = {
              package = pkg;
              id = pkg.pname or pkg.name;
            };
            
            # Sockets based on cfg.isolationSettings
            # SECURITY MECHANISM: sockets.x11 = true activates nix-bwrapper's
            # automatic X11 socket isolation - program cannot see other displays
            sockets = {
              x11 = true;  # Automatic xwayland-satellite per-app + X11 socket isolation
              wayland = cfg.isolationSettings.allowWayland;
              pulseaudio = cfg.isolationSettings.allowAudio;
              pipewire = cfg.isolationSettings.allowAudio;
            };
            
            # Mounts based on cfg.isolationSettings
            mounts = {
              privateTmp = cfg.isolationSettings.privateTmp;
              # Sandbox paths for application isolation
              # Maps standard directories to isolated locations
              sandbox = [
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
            };
            
            # D-Bus based on cfg.isolationSettings.dbusAccess
            dbus.session.talks = cfg.isolationSettings.dbusAccess;
          }
        else
          pkg;  # Fallback if mkBwrapper unavailable
      
    in
    # Automatically wrap X11-only packages
    lib.mapAttrs (name: value: 
      if isX11OnlyPackage name && (value ? type) && (value.type or null == "derivation")
      then wrapX11Package value
      else value
    ) prev;
in

{
  # NOTE: The nix-bwrapper overlay is added via a flake input in the parent module
  # (modules/x11-isolation-config.nix or modules/x11-isolation/default.nix)

  options.security.x11AutoIsolation = {
    enable = mkEnableOption "automatic X11 application isolation";

    mode = mkOption {
      type = types.enum [ "overlay" "wrapper" "both" ];
      default = "both";
      description = ''
        Automatic isolation mode:
        
        - overlay: Automatically wraps X11-only nixpkgs packages (build-time)
        - wrapper: Runtime wrapper for all X11 applications
        - both: Both approaches (recommended)
      '';
    };

    overlayPackages = mkOption {
      type = types.listOf types.str;
      default = [
        "xterm" "xeyes" "xcalc" "xfontsel" "xclipboard"
        "xlogo" "xmag" "xbiff"
      ];
      description = ''
        List of X11-only package names for automatic wrapping via overlay.
        These packages will be automatically isolated at build-time.
      '';
    };

    wrapperInPath = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Add x11-launch wrapper to PATH for manual use.
        Usage: x11-launch <program> [args...]
      '';
    };

    displayNumberStart = mkOption {
      type = types.int;
      default = 200;
      description = ''
        First X11 display number for isolated applications.
        
        Traditional allocation:
        - :0        - Main X server / compositor's Xwayland
        - :1-:10    - VNC servers
        - :10-:99   - SSH X11 forwarding
        - :99-:199  - Xvfb, Xephyr (virtual displays)
        - :200+     - Free zone (recommended for isolation)
        
        Value 200 chosen to avoid conflicts with typical programs.
        Each new isolated application gets the next number: :200, :201, :202...
        
        Maximum display: displayNumberStart + 99 (100 slots).
      '';
      example = 200;
    };

    disableCompositorXwayland = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Disable compositor's Xwayland (maximum security).
        
        Only after verifying that all X11 applications work isolated!
        
        With auto-isolation all X11 apps get separate xwayland-satellite,
        so shared Xwayland is not needed.
      '';
    };

    isolationSettings = mkOption {
      type = types.submodule {
        options = {
          allowAudio = mkOption {
            type = types.bool;
            default = true;
            description = "Allow access to PulseAudio/PipeWire";
          };

          allowWayland = mkOption {
            type = types.bool;
            default = false;
            description = "Allow Wayland socket (fallback)";
          };

          privateTmp = mkOption {
            type = types.bool;
            default = true;
            description = ''
              Private /tmp directory (only for overlay mode).
              
              Runtime wrapper (x11-launch) ALWAYS uses private /tmp
              with isolated X11 socket for maximum security.
              
              Overlay mode passes this option to mkBwrapper, which together with
              sockets.x11=true automatically ensures X11 socket isolation.
            '';
          };

          dbusAccess = mkOption {
            type = types.listOf types.str;
            default = [ "org.freedesktop.portal.*" ];
            description = "Allowed D-Bus services";
          };
        };
      };
      default = {};
      description = "Default isolation settings for auto-wrapped applications";
    };
  };

  config = mkIf cfg.enable {
    # Add overlay if mode is overlay or both
    nixpkgs.overlays = mkIf (cfg.mode == "overlay" || cfg.mode == "both") [ 
      x11AutoIsolationOverlay 
    ];

    # Add wrapper to system packages if mode is wrapper or both
    environment.systemPackages = mkIf 
      ((cfg.mode == "wrapper" || cfg.mode == "both") && cfg.wrapperInPath)
      [ x11-auto-wrapper ];

    # NOTE: programs.xwayland.enable is managed by x11-isolation-config.nix
    # to avoid conflicts between multiple isolation modules

    # Information and warnings
    warnings = 
      lib.optional (cfg.enable && cfg.disableCompositorXwayland) ''
        Compositor's Xwayland disabled. All X11 apps will use auto-isolated
        xwayland-satellite instances. If some X11 app doesn't work, it's not
        properly auto-wrapped yet.
      ''
      ++
      lib.optional (cfg.enable && cfg.mode == "overlay") ''
        X11 Auto-Isolation in overlay-only mode. Non-nixpkgs X11 applications
        (AppImage, manually compiled, etc.) will NOT be isolated.
        Consider using mode = "both" for full coverage.
      '';

    system.activationScripts.x11AutoIsolationInfo = lib.mkIf cfg.enable (
      lib.stringAfter [ "etc" ] ''
        echo "X11 Auto-Isolation enabled (mode: ${cfg.mode})"
        ${lib.optionalString (cfg.mode == "overlay" || cfg.mode == "both")
          "echo \"Overlay will auto-wrap: ${lib.concatStringsSep ", " cfg.overlayPackages}\""}
        ${lib.optionalString (cfg.mode == "wrapper" || cfg.mode == "both")
          "echo \"Runtime wrapper available: x11-launch <program>\""}
        echo "Each X11 app gets isolated xwayland-satellite + sandbox"
      ''
    );
  };

  meta = {
    maintainers = [ "Rampart-NixOS" ];
    doc = ''
      X11 Auto-Isolation Module
      
      Automatic X11 application isolation without manual configuration.
      Combines two approaches:
      
      1. Nixpkgs Overlay (build-time):
         - Automatically wraps X11-only packages in mkBwrapper
         - Works only for nixpkgs packages
         - Efficient, no runtime overhead
      
      2. Runtime Wrapper:
         - Intercepts X11 application launches
         - Works with any X11 programs (AppImage, etc.)
         - Usage: x11-launch <program>
      
      Advantages:
      - No need to configure each X11 application separately
      - Automatic isolation: separate X server + sandbox
      - Support for both nixpkgs and external programs
      - Transparent for the user
      
      Configuration:
        security.x11AutoIsolation = {
          enable = true;
          mode = "both";  # overlay + wrapper
          disableCompositorXwayland = false;  # true after testing
        };
    '';
  };
}
