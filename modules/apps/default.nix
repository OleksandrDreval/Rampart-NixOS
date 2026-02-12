# Applications Modules Coordinator
# Manages application modules with conditional imports

{ config, lib, ... }:

{
  options.rampart.apps = {
    browsers = {
      chromium = lib.mkOption {
        type = lib.types.enum [ "none" "standard" "firejail" ];
        default = "none";
        description = ''
          Chromium browser configuration:
          - none: Don't install Chromium
          - standard: Ungoogled Chromium
          - firejail: Chromium with Firejail sandboxing (recommended)
        '';
      };
    };

    encryption = {
      veracrypt = lib.mkEnableOption "Enable VeraCrypt disk encryption";
    };
  };

  config = {
    imports = lib.mkMerge [
      (lib.mkIf (config.rampart.apps.browsers.chromium == "standard") [
        ./browsers/chromium.nix
      ])
      (lib.mkIf (config.rampart.apps.browsers.chromium == "firejail") [
        ./browsers/chromium-firejail.nix
      ])
      (lib.mkIf config.rampart.apps.encryption.veracrypt [
        ./encryption/veracrypt.nix
      ])
    ];
  };
}
