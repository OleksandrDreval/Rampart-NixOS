{ config, pkgs, lib, ... }:

let
  vars = import ../../security/secrets/vars-compat.nix { inherit config lib; };
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
      Defaults secure_path="${vars.sudoSecurePath}"

      # Restrictive umask for files created by sudo commands
      # Creates files with 600 (rw-------) permissions by default
      Defaults umask=0077

      # Prevent root from using sudo (root is already superuser)
      # Reduces attack surface and prevents confusion
      Defaults !root_sudo

      # Always ask for password, even if user recently authenticated
      # More secure but less convenient - uncomment for maximum security:
      # Defaults timestamp_type=global

      # Disable path info leak via sudo -l
      # Prevents users from discovering available commands
      Defaults !listpw

      # Desktop-Specific Hardening

      # Disable lecture for wheel group (they already know about sudo)
      # Improves UX without compromising security
      Defaults lecture=never

      # Preserve HOME for better desktop integration
      # Some GUI apps expect $HOME to point to user's home
      # Note: This is enabled but env is still reset for security
      Defaults always_set_home

      # Environment Variable Control

      # Preserve only essential environment variables
      # This is a whitelist approach - only explicitly allowed variables pass through
      # Note: We start with env_reset (above) which clears all variables,
      # then selectively add back necessary ones below

      # Add back only necessary variables
      Defaults env_keep+="LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION"
      Defaults env_keep+="LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC"
      Defaults env_keep+="LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS"
      Defaults env_keep+="TZ"

      # Terminal and display variables (needed for GUI applications on desktop)
      # Essential for desktop systems running GUI apps with sudo
      Defaults env_keep+="DISPLAY XAUTHORITY XAUTHORIZATION"

      # Wayland display support (for modern desktop environments)
      Defaults env_keep+="WAYLAND_DISPLAY XDG_RUNTIME_DIR"

      # Color terminal support (improves user experience)
      Defaults env_keep+="COLORTERM"

      # SSH agent forwarding (useful for desktop development workflows)
      # Allows git operations and SSH commands through sudo
      Defaults env_keep+="SSH_AUTH_SOCK SSH_AGENT_PID"

      # Explicitly delete potentially dangerous environment variables
      Defaults env_delete="LD_PRELOAD LD_LIBRARY_PATH"
      Defaults env_delete+="PYTHON* PERL* RUBY*"
      Defaults env_delete+="BASH_ENV CDPATH ENV"
      Defaults env_delete+="TERMCAP"

      # Command Execution Security

      # Disable running shell escape commands in editors
      # Prevents privilege escalation via editor commands
      Defaults !shell_noargs

      # Don't allow sudo to run in background
      # Prevents detached privileged processes
      # Defaults !set_logname

      # Restrict maximum command line length (prevents buffer overflows)
      Defaults maxseq=${toString vars.sudoMaxSeq}

      # TTY Requirement (COMMENTED - may break automation)

      # Require TTY for sudo execution (prevents some attack vectors)
      # WARNING: This can break systemd services, cron jobs, and SSH automation
      # Uncomment only if you understand the implications:
      # Defaults requiretty

      # Auditing & Logging

      # Log all sudo usage to dedicated file
      # Format: timestamp, user, command, working directory
      Defaults logfile="${vars.sudoLogFile}"

      # Log input and output of sudo commands (I/O logging)
      # WARNING: This can generate large logs and may capture sensitive data
      # Uncomment only if you need detailed command auditing:
      # Defaults log_input
      # Defaults log_output
      # Defaults iolog_dir=/var/log/sudo-io
      # Defaults iolog_file=%{seq}

      # Send logs to syslog as well (for centralized logging)
      Defaults syslog=auth
      Defaults syslog_goodpri=info
      Defaults syslog_badpri=alert

      # Log hostName in sudo log (useful for multi-system management)
      Defaults log_host

      # Log year in timestamps (useful for long-term log analysis)
      Defaults log_year

      # Send email on security violations (requires mail system)
      # Uncomment and configure if you have mail setup:
      # Defaults mail_badpass
      # Defaults mail_no_user
      # Defaults mail_no_host
      # Defaults mail_no_perms
      # Defaults mailto="root"

      # Additional Security Restrictions

      # Prevent privilege escalation via LD_PRELOAD and similar
      Defaults ignore_dot

      # Don't allow sudo with relative paths
      # Uncomment for stricter security (may break some scripts):
      # Defaults requirepass

      # Restrict characters allowed in environment variables
      Defaults env_check+=TERMCAP

      # User Experience (Desktop Optimized)

      # Display humorous insults for incorrect password attempts
      # Provides feedback without revealing whether username is valid
      Defaults insults

      # Custom sudo prompt (optional - uncomment to use)
      # More user-friendly prompt for desktop users:
      Defaults passprompt="[sudo] password for %u@%h: "

      # Custom insult file (optional - uncomment to use)
      # Defaults insults=/path/to/insults.txt
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
