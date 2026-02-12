# Desktop Modules Coordinator
# Manages desktop environments and X11 isolation

{ config, lib, ... }:

{
  options.rampart.desktop = {
    enable = lib.mkEnableOption "Enable desktop environment";
    
    de = lib.mkOption {
      type = lib.types.enum [ "gnome" "kde" "cosmic" "none" ];
      default = "gnome";
      description = "Desktop environment to use";
    };
    
    wayland = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Prefer Wayland over X11 where possible";
    };

    x11Isolation = {
      enable = lib.mkEnableOption "Enable X11 isolation via nix-bwrapper";
      autoIsolation = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable automatic X11 application isolation";
      };
    };
  };

  config = lib.mkIf config.rampart.desktop.enable {
    imports = lib.mkMerge [
      # Desktop Environment (mutually exclusive)
      (lib.mkIf (config.rampart.desktop.de == "gnome") [
        ./environments/gnome.nix
      ])
      (lib.mkIf (config.rampart.desktop.de == "kde") [
        ./environments/plasma.nix
      ])
      (lib.mkIf (config.rampart.desktop.de == "cosmic") [
        ./environments/cosmic.nix
      ])

      # X11 Isolation
      (lib.mkIf config.rampart.desktop.x11Isolation.enable [
        ./x11-isolation/config.nix
      ])
    ];

    # Base desktop services
    services = {
      xserver.enable = lib.mkDefault (config.rampart.desktop.de != "none");
      printing.enable = lib.mkDefault true;
    };
    
    # XDG Portal
    xdg.portal.enable = lib.mkDefault true;
    
    # Fonts
    fonts = {
      enableDefaultPackages = true;
      packages = with config.nixpkgs.pkgs; [
        noto-fonts
        noto-fonts-emoji
        liberation_ttf
      ];
    };
  };
}
