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

  # Prevent root login from any TTY (defense in depth with hashedPassword)
  environment.etc.securetty.text = ''
    # /etc/securetty: list of terminals on which root is allowed to login.
    # Empty file = root cannot login from any TTY
    # Root must be accessed via: sudo -i or sudo su
  '';
  
  # PAM securetty enforcement (prevents root login on TTY even if hashedPassword is set)
  security.pam.services.login.rules.auth.securetty = {
    enable = true;
    order = 1;              # First authentication check
    control = "requisite";  # Hard fail if not in securetty list
    modulePath = "${config.security.pam.package}/lib/security/pam_securetty.so";
  };

  # Define user accounts
  users.users.${vars.mainUser} = {
    isNormalUser = true;
    description = vars.mainUserDescription;
    hashedPassword = vars.mainUserHashedPassword;  # Password hash from variables
    extraGroups = [ "networkmanager" "wheel" "libvirtd" ];
    packages = with pkgs; [
      # Add user-specific packages here
      # thunderbird
    ];
  };

  # Sudo security configuration
  security.sudo = {
    enable = true;
    execWheelOnly = true;       # Only wheel group members can use sudo
    wheelNeedsPassword = true;  # Wheel group users must provide password for sudo
    extraConfig = ''
      Defaults insults                                                  # Fun insults for wrong passwords
      Defaults passwd_timeout=${toString vars.sudoPasswdTimeout}        # Time to enter password (seconds)
      Defaults timestamp_timeout=${toString vars.sudoTimestampTimeout}  # Sudo cache duration (minutes)
      Defaults use_pty                                                  # Use PTY for all sudo commands (prevents TTY hijacking)
      Defaults env_reset                                                # Reset environment to secure baseline
      Defaults secure_path="/run/wrappers/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"  # Secure PATH
      Defaults !visiblepw                                               # Never allow sudo if password not required

    # Defaults requiretty                   # Require TTY (prevents some attacks) - COMMENTED: may break systemd services, cron jobs, SSH automation

      Defaults umask=0077                   # Restrictive umask for sudo commands
      Defaults !root_sudo                   # Root cannot use sudo (must already be root)
      Defaults logfile="/var/log/sudo.log"  # Log all sudo usage (basic: command, user, time)
      Defaults !pwfeedback                  # No password feedback (security)
    '';
  };
  
  # Nix daemon access control
  # Limit nix commands to wheel group (sudoers) only
  # Prevents unprivileged users from installing packages or using nix-shell
  nix.settings.allowed-users = [ "@wheel" ];
}
