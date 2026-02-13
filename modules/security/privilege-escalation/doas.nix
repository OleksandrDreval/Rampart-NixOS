{ config, pkgs, lib, ... }:

let
  vars = import ../../security/secrets/vars-compat.nix { inherit config lib; };
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
          "WAYLAND_DISPLAY"  # Keep Wayland display for GUI applications (primary)
          "DISPLAY"          # Keep X11 display for legacy X11 apps via Xwayland
          "XAUTHORITY"       # Keep X11 authority for Xwayland applications
          "TERM"             # Keep terminal type for proper display
          "LANG"             # Keep language settings
          "LC_ALL"           # Keep locale settings
        ];
        
        # Log all successful executions to syslog for auditing
        noLog = false;
      }

      # Example Rule 2: Allow specific command without password (COMMENTED)
      #
      # Uncomment and modify this rule to allow specific commands without password
      # This is useful for automated tasks or specific user workflows
      # 
      # {
      #   users = [ "backup" ];
      #   cmd = "/run/current-system/sw/bin/rsync";
      #   args = null;  # null = allow any arguments
      #   noPass = true;
      #   runAs = "root";
      #   setEnv = [ "SSH_AUTH_SOCK" ];
      # }

      # Example Rule 3: Allow system monitoring without password (COMMENTED)
      #
      # Allow specific users to run system monitoring commands without password
      # 
      # {
      #   groups = [ "monitoring" ];
      #   cmd = "/run/current-system/sw/bin/systemctl";
      #   args = [ "status" ];  # Only allow 'systemctl status'
      #   noPass = true;
      #   runAs = "root";
      # }

      # Example Rule 4: Allow network restart for admins (COMMENTED)
      #
      # {
      #   groups = [ "netadmin" ];
      #   cmd = "/run/current-system/sw/bin/systemctl";
      #   args = [ "restart" "NetworkManager.service" ];
      #   noPass = false;  # Still require password for safety
      #   runAs = "root";
      #   persist = true;
      # }

      # Example Rule 5: Allow specific script execution (COMMENTED)
      #
      # {
      #   users = [ "developer" ];
      #   cmd = "/home/developer/scripts/deploy.sh";
      #   args = [];  # Empty list = command must be run with NO arguments
      #   noPass = false;
      #   runAs = "www-data";
      #   keepEnv = false;
      #   setEnv = [ "-SSH_AUTH_SOCK" "DEPLOY_ENV=production" ];
      # }
    ];

    # Additional raw configuration appended to /etc/doas.conf
    # Use this for advanced configurations not covered by extraRules
    # Note: This cannot override the default rule allowing passwordless root access
    extraConfig = ''
      # Additional Doas Configuration
      #
      # This section is for raw doas.conf directives that don't fit into
      # the structured extraRules format.
      #
      # Syntax: permit|deny [options] identity [as target] [cmd command [args ...]]
      #
      # Options:
      #   nopass       - Don't require password
      #   persist      - Cache credentials
      #   keepenv      - Keep environment variables
      #   setenv {...} - Set specific environment variables
      #   nolog        - Don't log to syslog
      #
      # Examples:
      # permit nopass root as root
      # permit persist :wheel
      # deny :wheel cmd /usr/bin/dangerous-command
      # permit nopass alice cmd /usr/local/bin/backup.sh
      
      # Currently no additional configuration needed
      # All rules are defined in extraRules above for better maintainability
    '';
  };

  # Environment Configuration for Doas
  
  # Create doas alias for users familiar with sudo command
  # This provides a smoother transition from sudo to doas
  environment.shellAliases = {
    sudo = "doas";  # Redirect sudo to doas for convenience
  };

  # Optional: Add helpful message when users type sudo
  # Uncomment if you want to educate users about the doas transition
  # programs.bash.shellAliases = {
  #   sudo = "echo 'Use doas instead of sudo' && doas";
  # };

  # Important Security Notes
  #
  # 1. DISABLE SUDO WHEN USING DOAS
  #    If you enable this module, you should disable sudo in modules/sudo.nix
  #    to avoid confusion and potential security issues:
  #    security.sudo.enable = false;
  #
  # 2. ROOT ACCESS
  #    Ensure root account is locked (configured in modules/users.nix):
  #    users.users.root.hashedPassword = "!";
  #
  # 3. WHEEL GROUP
  #    Only trusted users should be in the wheel group:
  #    users.users.username.extraGroups = [ "wheel" ];
  #
  # 4. TESTING
  #    Before disabling sudo completely, test doas thoroughly:
  #    - Test basic privilege escalation: doas whoami
  #    - Test interactive shell: doas -s
  #    - Test specific commands: doas systemctl status
  #    - Test environment preservation: doas -u username env
  #
  # 5. PERSISTENCE TIMEOUT
  #    The persist option keeps credentials cached. Default is 5 minutes.
  #    This is similar to sudo's timestamp_timeout but less configurable.
  #    If you need stricter security, set persist = false in the rules.
  #
  # 6. ENVIRONMENT VARIABLES
  #    Doas is more restrictive with environment variables than sudo by default.
  #    Only variables listed in setEnv are passed through.
  #    Review and adjust setEnv based on your security requirements.
  #
  # 7. COMMAND PATHS
  #    Always use absolute paths in cmd for security:
  #    cmd = "/run/current-system/sw/bin/systemctl";  # Good
  #    cmd = "systemctl";                             # Bad (relative path)
  #
  # 8. RULE ORDERING
  #    Rules are processed in order. More specific rules should come after
  #    general rules. Use lib.mkBefore or lib.mkAfter to control ordering
  #    when merging configurations from multiple modules.
  #
  # 9. LOGGING
  #    All doas executions are logged to syslog (journald in NixOS).
  #    View logs with: journalctl -t doas
  #
  # 10. COMPATIBILITY
  #     Some scripts may expect sudo-specific features that doas doesn't have:
  #     - No SUDO_USER, SUDO_GID, SUDO_COMMAND environment variables
  #     - No -E flag to preserve all environment (use setEnv instead)
  #     - No visudo equivalent (edit /etc/doas.conf directly in NixOS config)
  #
  # Migration from Sudo to Doas
  #
  # Step 1: Enable this module in configuration.nix
  #         imports = [ ./modules/security/privilege-escalation/doas.nix ];
  #
  # Step 2: Test doas while keeping sudo enabled
  #         $ doas whoami
  #         $ doas -s
  #         $ doas systemctl status
  #
  # Step 3: If everything works, disable sudo in modules/sudo.nix
  #         security.sudo.enable = false;
  #
  # Step 4: Rebuild and test
  #         sudo nixos-rebuild switch  # Last time using sudo!
  #
  # Step 5: Verify sudo is gone
  #         $ which sudo  # Should return nothing or error
  #         $ doas whoami # Should work
  #
  # Step 6: Update documentation and inform users
  #
  # Rollback plan:
  # If you need to rollback to sudo, you can boot into a previous generation
  # or re-enable sudo by setting security.sudo.enable = true and
  # security.doas.enable = false.
  #
  # Related Modules
  #
  # This module should be used instead of, not alongside, modules/sudo.nix
  #
  # Related security configurations in other modules:
  # - modules/users.nix: Root account lockdown, wheel group management
  # - modules/nixos-permissions.nix: Secure /etc/nixos/ permissions
  #
  # For complete privilege escalation protection with doas:
  # 1. Root is locked and only accessible via doas (users.nix)
  # 2. Only trusted users are in wheel group (users.nix)
  # 3. Strong password policies are enforced (users.nix)
  # 4. Doas rules are properly configured (this module)
  # 5. All doas operations are logged and monitored
}
