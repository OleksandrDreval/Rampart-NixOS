{ config, pkgs, ... }:

let
  vars = import ./variables.nix;
in
{
  # Immutable users configuration
  # Users can only be managed through NixOS configuration, not via useradd/passwd commands
  # This provides security by preventing unauthorized user modifications
  users.mutableUsers = false;

  # Lock root account - prevent direct root login
  # Root can still be accessed via sudo -i or sudo su
  users.users.root.hashedPassword = "!";

  # Define user accounts
  users.users.${vars.mainUser} = {
    isNormalUser = true;
    description = vars.mainUserDescription;
    hashedPassword = vars.mainUserHashedPassword;  # Password hash from variables
    extraGroups = [ "networkmanager" "wheel" ];
    packages = with pkgs; [
      # Add user-specific packages here
      # thunderbird
    ];
  };

  # Sudo security configuration
  security.sudo = {
    enable = true;
    execWheelOnly = true;  # Only wheel group members can use sudo
    extraConfig = ''
      Defaults insults                                                  # Fun insults for wrong passwords
      Defaults passwd_timeout=${toString vars.sudoPasswdTimeout}        # Time to enter password (seconds)
      Defaults timestamp_timeout=${toString vars.sudoTimestampTimeout}  # Sudo cache duration (minutes)
      Defaults use_pty                                                  # Use PTY for all sudo commands (prevents TTY hijacking)
    '';
  };
}
