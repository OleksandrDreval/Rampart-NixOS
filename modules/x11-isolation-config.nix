# X11 Legacy Applications Isolation Configuration
# This module configures automatic and manual X11 application sandboxing
# Uses: nix-bwrapper + xwayland-satellite + bubblewrap
# Documentation: https://github.com/Naxdy/nix-bwrapper

{ config, pkgs, lib, ... }:

{
  imports = [
    ./bwrapper-integration.nix  # Core nix-bwrapper integration (overlay + functions)
    ./x11-auto-isolation.nix    # Automatic X11 isolation module (options + wrapper)
    ./sandbox-x11.nix           # Manual X11 isolation module (options + wrappers)
  ];

  #############################################################################
  # Compositor's Xwayland Management
  #############################################################################
  # Centralized control to avoid conflicts between isolation modules
  # Xwayland is disabled if EITHER module requests it
  
  programs.xwayland.enable = lib.mkDefault (
    !config.security.x11AutoIsolation.disableCompositorXwayland &&
    !config.security.x11Isolation.disableXwayland
  );

  #############################################################################
  # Automatic X11 Isolation - Wrapper Mode
  #############################################################################
  # Provides x11-launch command for runtime isolation of any X11 application
  # Each X11 app gets isolated xwayland-satellite + sandboxed environment
  
  security.x11AutoIsolation = {
    enable = true;
    mode = "wrapper";  # Only runtime wrapper (x11-launch <program>)
                       # Overlay mode disabled to avoid recursive dependencies
    
    disableCompositorXwayland = false;  # Set true after testing all X11 apps
    
    # Default isolation settings for x11-launch wrapper
    isolationSettings = {
      allowAudio = true;           # PulseAudio/PipeWire access
      allowWayland = false;        # Pure X11 mode
      privateTmp = true;           # Isolated /tmp with X11 socket
      dbusAccess = [               # Minimal D-Bus access
        "org.freedesktop.portal.*"
      ];
    };
    
    # NOTE: overlayPackages not used in wrapper mode
    overlayPackages = [ ];
  };
  
  #############################################################################
  # Manual X11 Isolation - Per-Application Configuration
  #############################################################################
  # Detailed sandboxing for specific legacy X11 applications
  # Each app gets custom filesystem access, D-Bus permissions, etc.
  
  security.x11Isolation = {
    enable = true;
    disableXwayland = false;  # Set true after ALL X11 apps configured
    
    isolatedApps = [
      #########################################################################
      # GIMP - GNU Image Manipulation Program
      #########################################################################
      {
        package = pkgs.gimp;
        id = "org.gimp.GIMP";
        desktopName = "GIMP";
        icon = "gimp";
        comment = "GNU Image Manipulation Program (X11 Isolated)";
        categories = [ "Graphics" "2DGraphics" "RasterGraphics" ];
        
        # Force X11 backend (GTK2/X11 more stable than GTK3/Wayland)
        env = {
          GDK_BACKEND = "x11";
        };
        
        # Audio for interface sounds
        allowAudio = true;
        
        # Disable Wayland fallback
        allowWayland = false;
        
        # Filesystem access - read-write for image editing
        readWritePaths = [
          "$HOME/Downloads"
          "$HOME/Pictures"
          "$HOME/Documents"
        ];
        
        # Sandbox directories for GIMP configuration
        # Stored in: $HOME/.bwrapper/org.gimp.GIMP/{config,local,cache}
        sandboxPaths = [
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
        
        # Private /tmp for temporary files
        privateTmp = true;
        
        # D-Bus access for desktop integration
        dbus = {
          session = {
            talks = [
              "org.freedesktop.portal.*"        # XDG Portals
              "org.freedesktop.Notifications"   # Desktop notifications
              "org.gtk.vfs.*"                   # Virtual filesystem
              "org.freedesktop.FileManager1"    # File manager integration
            ];
          };
        };
        
        # FHS environment not needed for nixpkgs GIMP
        useFHS = false;
      }
      
      # Add more X11 legacy applications here
      # Example:
      # {
      #   package = pkgs.inkscape;
      #   id = "org.inkscape.Inkscape";
      #   ...
      # }
    ];
  };
  
  #############################################################################
  # Security Recommendations
  #############################################################################
  # After testing all X11 applications with isolation:
  # 1. Set security.x11AutoIsolation.disableCompositorXwayland = true
  # 2. Set security.x11Isolation.disableXwayland = true
  # This eliminates shared Xwayland and maximizes security
}
