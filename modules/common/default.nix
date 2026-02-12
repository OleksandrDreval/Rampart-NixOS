# Common Modules Coordinator
# Imports common system modules (audio, localization, users, packages)

{ config, lib, ... }:

{
  imports = [
    ./audio.nix
    ./localization.nix
    ./users.nix
    ./packages.nix
  ];

  options.rampart.common = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable common system modules";
    };
  };

  # All common modules are essential, always imported
}
