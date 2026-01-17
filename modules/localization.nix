{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in
{
  # Time zone
  time.timeZone = vars.timeZone;

  # Internationalization settings
  i18n.defaultLocale = vars.defaultLocale;

  i18n.extraLocaleSettings = {
    LC_ADDRESS = vars.defaultLocale;
    LC_IDENTIFICATION = vars.defaultLocale;
    LC_MEASUREMENT = vars.defaultLocale;
    LC_MONETARY = vars.defaultLocale;
    LC_NAME = vars.defaultLocale;
    LC_NUMERIC = vars.defaultLocale;
    LC_PAPER = vars.defaultLocale;
    LC_TELEPHONE = vars.defaultLocale;
    LC_TIME = vars.defaultLocale;
  };

  # Console keymap
  console.keyMap = vars.consoleKeyMap;
}
