{ config, pkgs, lib, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # Doas Security Configuration Module
  #
  # This module configures doas as a more secure and simpler alternative to sudo.
  # Doas (from OpenBSD) is a minimalist privilege escalation tool with a smaller
  # codebase and attack surface compared to sudo.
  #
  # Key Security Features:
  # - Minimal codebase: ~4000 lines vs sudo's ~132,000 lines (smaller attack surface)
  # - Simpler configuration: /etc/doas.conf is much easier to audit than sudoers
  # - Wheel-only execution: Only members of the wheel group can use doas
  # - Password requirement: All doas operations require password authentication
  # - Environment control: Explicit control over which environment variables are kept
  # - Session persistence: Optional credential caching to reduce password prompts
  # - Logging: All executions logged to syslog for auditing
  # - No complex features: Focuses on doing one thing well (privilege escalation)
  #
  # Advantages over sudo:
  # - Smaller attack surface due to minimal codebase
  # - Simpler configuration syntax (easier to audit and maintain)
  # - Better defaults (more secure out of the box)
  # - Designed with security as primary goal (OpenBSD heritage)
  # - Less vulnerable to complex attack vectors
  #
  # Related NixOS Options:
  # - security.doas.enable: Enable doas command
  # - security.doas.wheelNeedsPassword: Require password for wheel group
  # - security.doas.extraRules: Define specific doas rules
  # - security.doas.extraConfig: Additional doas.conf configuration
  # - security.doas.package: The doas package to use
  #
  # Rule Options (per extraRules entry):
  # - users: List of usernames/UIDs this rule applies to
  # - groups: List of group names/GIDs this rule applies to
  # - cmd: Specific command allowed (null = all commands)
  # - args: Required arguments for the command ([] = no args allowed)
  # - runAs: User/group to run as (null = any user)
  # - noPass: Allow execution without password (default: false)
  # - persist: Cache credentials for a time period (default: false)
  # - keepEnv: Keep environment variables (default: false)
  # - setEnv: List of environment variables to keep/set/remove
  # - noLog: Don't log successful executions (default: false)
  #
  # References:
  # - NixOS Manual: https://nixos.org/manual/nixos/stable/options.html#opt-security.doas.enable
  # - doas(1) man page: https://man.openbsd.org/doas
  # - doas.conf(5) man page: https://man.openbsd.org/doas.conf
  # - Original doas: https://github.com/Duncaen/OpenDoas

  # Enable doas as privilege escalation mechanism
  security.doas = {
    enable = true;

    # Require password for all wheel group members
    # Set to false only if you understand the security implications
    wheelNeedsPassword = true;

    # Define access rules for doas
    # Rules are evaluated in order - more specific rules should come after general ones
    extraRules = [
      # Rule 1: General wheel group access with password and credential caching
      #
      # This is the main rule that allows wheel group members to execute any
      # command as root, similar to sudo's behavior for wheel group.
      {
        groups = [ "wheel" ];
        
        # Allow running any command (null = no restriction)
        cmd = null;
        
        # Require password authentication for security
        noPass = false;
        
        # Enable credential persistence (similar to sudo's timestamp_timeout)
        # After successful authentication, don't ask for password again for ~5 minutes
        # This provides convenience while maintaining security
        persist = true;
        
        # Keep only essential environment variables for security
        # SSH_AUTH_SOCK is kept by default for SSH agent forwarding
        # We explicitly define a minimal set of safe variables
        keepEnv = false;
        
        # Explicitly set/keep specific environment variables
        # This provides a more secure environment than keepEnv = true
        setEnv = [
          "SSH_AUTH_SOCK"    # Keep SSH agent socket for SSH operations
          "DISPLAY"          # Keep X11 display for GUI applications
          "WAYLAND_DISPLAY"  # Keep Wayland display for GUI applications
          "XAUTHORITY"       # Keep X11 authority for GUI applications
          "TERM"             # Keep terminal type for proper display
          "LANG"             # Keep language settings
          "LC_ALL"           # Keep locale settings
        ];
        
        # Log all successful executions to syslog for auditing
        noLog = false;
      }
    ];

    extraConfig = ''

    '';
  };

  # Environment Configuration for Doas
  
  # Create doas alias for users familiar with sudo command
  # This provides a smoother transition from sudo to doas
  environment.shellAliases = {
    sudo = "doas";  # Redirect sudo to doas for convenience
  };
}
