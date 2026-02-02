{ config, pkgs, lib, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # Sudo Security Configuration Module
  # This module configures sudo with enhanced security settings to minimize
  # privilege escalation risks and provide proper auditing of administrative actions.

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

    '';

    # Define specific sudo rules (optional)
    extraRules = [ ];
  };
}
