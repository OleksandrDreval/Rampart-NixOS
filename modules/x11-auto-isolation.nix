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
              sandbox = {
                "$HOME" = "$HOME/.bwrapper/${pkg.pname or pkg.name}";
              };
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

{ }
