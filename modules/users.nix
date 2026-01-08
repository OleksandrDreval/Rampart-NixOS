{ config, pkgs, ... }:

let
  vars = import ./variables.nix;
in
{
  # Define user accounts
  users.users.${vars.mainUser} = {
    isNormalUser = true;
    description = vars.mainUserDescription;
    extraGroups = [ "networkmanager" "wheel" ];
    packages = with pkgs; [
      # Add user-specific packages here
      # thunderbird
    ];
  };
}
