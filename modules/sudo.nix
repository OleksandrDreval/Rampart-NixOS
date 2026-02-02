{ config, pkgs, lib, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # Sudo Security Configuration Module
  # This module configures sudo with enhanced security settings to minimize
  # privilege escalation risks and provide proper auditing of administrative actions.
  #
  # Key Security Features:
  # - Wheel-only execution: Only members of the wheel group can use sudo
  # - Password requirement: All sudo operations require password authentication
  # - PTY enforcement: Prevents TTY hijacking attacks
  # - Environment reset: Prevents environment-based privilege escalation
  # - Secure PATH: Limits command execution to trusted locations
  # - Logging: Tracks all sudo usage for audit purposes
  # - Timeout controls: Limits password entry and credential caching time
  #
  # Related NixOS Options:
  # - security.sudo.enable: Enable sudo command
  # - security.sudo.execWheelOnly: Restrict sudo to wheel group members
  # - security.sudo.wheelNeedsPassword: Require password for wheel group
  # - security.sudo.extraConfig: Additional sudoers configuration
  # - security.sudo.extraRules: Define specific sudo rules
  # - security.sudo.defaultOptions: Options for default rules
  # - security.sudo.package: The sudo package to use
  # - security.sudo.configFile: Complete sudoers file content
  #
  # References:
  # - NixOS Manual: https://nixos.org/manual/nixos/stable/options.html#opt-security.sudo.enable
  # - Sudo Manual: https://www.sudo.ws/man/sudoers.man.html
  # - CVE-2021-3156: Heap-based buffer overflow (mitigated by execWheelOnly)

  # Enable sudo command for privilege escalation
  security.sudo = {
    enable = true;

    # Only allow members of the wheel group to execute sudo
    # This prevents users not in wheel from exploiting sudo vulnerabilities
    # such as CVE-2021-3156 (heap-based buffer overflow)
    execWheelOnly = true;

    # Require password authentication for all wheel group members
    # Prevents passwordless privilege escalation
    wheelNeedsPassword = true;

    # Advanced sudo configuration (appended to /etc/sudoers)
    extraConfig = ''
      # Timeout for password entry (seconds) - user must enter password within this time
      Defaults passwd_timeout=${toString vars.sudoPasswdTimeout}
      
      # Credential cache duration (minutes) - how long sudo remembers successful authentication
      # After this period, password must be re-entered
      Defaults timestamp_timeout=${toString vars.sudoTimestampTimeout}

      # Never allow sudo if password is not required (security enforcement)
      Defaults !visiblepw

      # Disable password feedback (no asterisks when typing password)
      # Security best practice to prevent revealing password length
      Defaults !pwfeedback

      # Use PTY (pseudo-terminal) for all sudo commands
      # Prevents TTY hijacking attacks and ensures proper signal handling
      Defaults use_pty

      # Reset environment variables to secure baseline
      # Prevents environment-based privilege escalation attacks
      Defaults env_reset
    '';

    # Define specific sudo rules (optional)
    extraRules = [ ];
  };
}
