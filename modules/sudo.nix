{ config, pkgs, lib, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # Sudo Security Configuration Module
  # This module configures sudo with enhanced security settings to minimize
  # privilege escalation risks and provide proper auditing of administrative actions.
  #
  # ALTERNATIVES: Consider these more secure options:
  #
  # 1. modules/doas.nix - OpenBSD doas (simpler, smaller attack surface)
  #    - Smaller codebase (~4K lines vs sudo's ~132K lines)
  #    - Simpler configuration (easier to audit)
  #    - Better security defaults
  #    - BSD heritage (security-focused)
  #
  # 2. modules/run0.nix - systemd run0 (modern, no SUID binary)
  #    - No SUID binary (eliminates entire class of vulnerabilities)
  #    - systemd integration (leverages existing security features)
  #    - Polkit-based authentication
  #    - Modern Linux security architecture
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
      # Password & Authentication Settings
      
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
      
      # Maximum number of authentication attempts before failing
      # Protects against brute-force attacks on sudo password
      Defaults passwd_tries=${toString vars.sudoPasswdTries}

      # Security Hardening

      # Use PTY (pseudo-terminal) for all sudo commands
      # Prevents TTY hijacking attacks and ensures proper signal handling
      Defaults use_pty
      
      # Reset environment variables to secure baseline
      # Prevents environment-based privilege escalation attacks
      Defaults env_reset
      
      # Define secure PATH for sudo commands
      # Limits command execution to trusted system directories
      Defaults secure_path="/run/wrappers/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
      
      # Restrictive umask for files created by sudo commands
      # Creates files with 600 (rw-------) permissions by default
      Defaults umask=0077
      
      # Prevent root from using sudo (root is already superuser)
      # Reduces attack surface and prevents confusion
      Defaults !root_sudo
      
      # TTY Requirement (COMMENTED - may break automation)

      # Require TTY for sudo execution (prevents some attack vectors)
      # WARNING: This can break systemd services, cron jobs, and SSH automation
      # Uncomment only if you understand the implications:
      # Defaults requiretty
      
      # Auditing & Logging

      # Log all sudo usage to dedicated file
      # Format: timestamp, user, command, working directory
      Defaults logfile="/var/log/sudo.log"

      # User Experience

      # Display humorous insults for incorrect password attempts
      # Provides feedback without revealing whether username is valid
      Defaults insults
    '';

    # Define specific sudo rules (optional)
    # More specific rules should come after general ones
    # Examples:
    # extraRules = [
    #   # Allow backup group to run specific script without password
    #   {
    #     groups = [ "backup" ];
    #     commands = [
    #       {
    #         command = "/usr/local/bin/backup.sh";
    #         options = [ "NOPASSWD" ];
    #       }
    #     ];
    #   }
    #   
    #   # Allow monitoring user to restart specific service
    #   {
    #     users = [ "monitor" ];
    #     commands = [
    #       {
    #         command = "/run/current-system/sw/bin/systemctl restart monitoring.service";
    #         options = [ "NOPASSWD" ];
    #       }
    #     ];
    #   }
    # ];

    extraRules = [ ];

    # Default options for all sudo rules
    # These are applied to the default rules granting wheel group permissions
    # defaultOptions = [ "SETENV" "NOPASSWD" ];  # Example: allow environment passing

    # Alternative: Use sudo-rs (Rust implementation) instead of traditional sudo
    # Provides memory safety but may have fewer features
    # Uncomment to enable:
    # enable = false;  # Disable traditional sudo first
  };

  # Alternative: Enable sudo-rs (Rust implementation of sudo)
  # Provides memory safety and eliminates entire classes of vulnerabilities
  # Trade-off: May have fewer features than traditional sudo
  # security.sudo-rs = {
  #   enable = true;
  #   execWheelOnly = true;
  #   wheelNeedsPassword = true;
  # };

  # Related Security Configurations

  # Note: This module only handles sudo configuration.
  # Related security settings are in other modules:
  #
  # users.nix:
  # - Root account lockdown (hashedPassword = "!")
  # - TTY restrictions for root login
  # - PAM securetty enforcement
  # - Wheel group requirement for su command
  # - User account management
  #
  # For complete privilege escalation protection, ensure:
  # 1. Root is locked and only accessible via sudo
  # 2. Only trusted users are in wheel group
  # 3. Strong password policies are enforced
  # 4. PAM configurations restrict su command
}
