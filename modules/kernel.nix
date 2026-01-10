{ config, pkgs, ... }:

{
  # Kernel configuration
  boot.kernelPackages = pkgs.linuxPackages_latest;
  
  # Additional kernel modules can be added here
  # boot.kernelModules = [ ];
  # boot.extraModulePackages = [ ];
}
