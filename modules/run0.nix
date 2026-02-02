{ config, pkgs, lib, ... }:

{
  # Run0 Security Configuration Module (systemd-run0)
  #
  # This module configures run0 as a modern, systemd-native alternative to sudo.
  # run0 is part of systemd (introduced in systemd v256) and provides privilege
  # escalation through systemd's service manager infrastructure.
  #
  # What is run0?
  #
  # run0 is systemd's answer to sudo/doas. Instead of being a traditional SUID
  # binary, it leverages systemd's existing privilege escalation mechanisms via
  # systemd-run and polkit. This provides several advantages:
  #
  # Key Differences from Sudo/Doas:
  #
  # 1. NO SUID BINARY: run0 is not a setuid binary, eliminating an entire class
  #    of privilege escalation vulnerabilities associated with SUID programs
  #
  # 2. SYSTEMD INTEGRATION: Uses systemd's service isolation and sandboxing
  #    capabilities for better security boundaries
  #
  # 3. POLKIT AUTHENTICATION: Leverages polkit for authentication and authorization,
  #    providing consistent authentication across the system
  #
  # 4. TRANSIENT SERVICES: Each run0 invocation creates a transient systemd service
  #    unit, providing better process isolation and resource management
  #
  # 5. CLEAN ENVIRONMENT: Provides a fresh, clean environment by default, reducing
  #    the risk of environment-based attacks
  #
  # Security Advantages:
  #
  # - No SUID binary to exploit (major attack vector eliminated)
  # - Integration with systemd's security features (namespaces, cgroups, capabilities)
  # - Consistent with modern Linux security architecture
  # - Built-in audit logging through systemd journal
  # - Process isolation through transient service units
  # - Fine-grained control through polkit policies
  #
  # Trade-offs:
  #
  # - Requires systemd (not available on non-systemd systems)
  # - Newer technology (less battle-tested than sudo)
  # - Different command-line interface (requires user adaptation)
  # - Polkit dependency (adds complexity)
  # - Limited configuration options compared to sudo
  #
  # When to use run0:
  #
  # - Systems where systemd is already used (most modern Linux)
  # - Security-focused environments wanting to eliminate SUID binaries
  # - Systems that value systemd integration and consistency
  # - Environments with simpler privilege escalation needs
  # - When you want modern Linux security architecture
  #
  # Related NixOS Options:
  #
  # - security.run0.wheelNeedsPassword: Require password for wheel group
  # - security.run0.enableSudoAlias: Create 'sudo' alias to 'run0'
  #
  # Additional Configuration:
  #
  # Further customization can be done through:
  # - Polkit rules (security.polkit.extraConfig)
  # - Systemd service defaults (systemd.services.<name>.serviceConfig)
  # - PAM configuration (security.pam.services)
  #
  # References:
  #
  # - systemd run0 documentation: https://www.freedesktop.org/software/systemd/man/latest/run0.html
  # - systemd-run documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html
  # - Polkit documentation: https://www.freedesktop.org/software/polkit/docs/latest/
  # - NixOS Manual: https://nixos.org/manual/nixos/stable/options.html#opt-security.run0.wheelNeedsPassword

  # Enable run0 as privilege escalation mechanism
  # This is a systemd-based alternative to sudo that doesn't use SUID binaries
  security.run0 = {
    # Require password authentication for wheel group members
    # When true: users must authenticate with their password
    # When false: passwordless privilege escalation (NOT RECOMMENDED for security)
    wheelNeedsPassword = true;

    # Create 'sudo' alias that points to 'run0'
    # This provides compatibility for users and scripts expecting 'sudo' command
    # Users can type 'sudo' and it will execute 'run0' instead
    # Useful for smooth transition from sudo to run0
    enableSudoAlias = true;
  };

  # Polkit Configuration for run0
  #
  # run0 uses polkit for authentication and authorization decisions.
  # By default, members of the wheel group are allowed to gain root privileges.
  # Additional polkit rules can be configured here for fine-grained control.
  #
  # Example: Allow specific users to run certain commands without password
  # security.polkit.extraConfig = ''
  #   polkit.addRule(function(action, subject) {
  #     if (action.id == "org.freedesktop.systemd1.manage-units" &&
  #         subject.user == "backup") {
  #       return polkit.Result.YES;
  #     }
  #   });
  # '';

  # Environment Configuration
  
  # Optional: Configure systemd to log all run0 invocations
  # This is automatically handled by systemd journal
  # View logs with: journalctl -t run0
  
  # Optional: Set default environment for run0 sessions
  # run0 provides a clean environment by default
  # You can customize this through systemd environment configuration
  # systemd.extraConfig = ''
  #   DefaultEnvironment="CUSTOM_VAR=value"
  # '';

  # Important Security Notes
  #
  # 1. DISABLE SUDO/DOAS WHEN USING RUN0
  #    Only use one privilege escalation mechanism to avoid confusion:
  #    - Comment out sudo.nix import in configuration.nix
  #    - Comment out doas.nix import in configuration.nix
  #    OR set: security.sudo.enable = false;
  #
  # 2. SYSTEMD REQUIRED
  #    run0 requires systemd. It will not work on non-systemd systems.
  #    This is not an issue for NixOS as it uses systemd by default.
  #
  # 3. ROOT ACCESS
  #    Ensure root account is locked (configured in modules/users.nix):
  #    users.users.root.hashedPassword = "!";
  #
  # 4. WHEEL GROUP
  #    Only trusted users should be in the wheel group:
  #    users.users.username.extraGroups = [ "wheel" ];
  #
  # 5. TESTING
  #    Before disabling sudo completely, test run0 thoroughly:
  #    - Test basic privilege escalation: run0 whoami
  #    - Test interactive shell: run0 bash
  #    - Test specific commands: run0 systemctl status
  #    - Test as different user: run0 --user=username whoami
  #    - Verify environment: run0 env
  #
  # 6. POLKIT AUTHENTICATION
  #    run0 uses polkit for authentication. Ensure polkit is properly configured.
  #    Default polkit configuration allows wheel group members to authenticate.
  #
  # 7. NO SUID
  #    Unlike sudo, run0 is NOT a setuid binary. This eliminates SUID-based
  #    privilege escalation vulnerabilities but means it relies on systemd's
  #    privilege escalation mechanisms instead.
  #
  # 8. ENVIRONMENT HANDLING
  #    run0 provides a clean environment by default. It doesn't preserve user
  #    environment variables like sudo might. Use --setenv to pass specific
  #    variables if needed: run0 --setenv=DISPLAY=:0 command
  #
  # 9. COMMAND LINE DIFFERENCES
  #    run0 has different command-line options than sudo:
  #    - No -i flag (use 'run0 bash' for interactive shell)
  #    - Use --user= instead of -u for user specification
  #    - Use --setenv= to set environment variables
  #    - See 'run0 --help' for full option list
  #
  # 10. JOURNALD LOGGING
  #     All run0 invocations are automatically logged to systemd journal.
  #     View with: journalctl -t run0
  #     This provides comprehensive audit trail without additional configuration.
  #
  # 11. POLKIT POLICIES
  #     Fine-grained access control is done through polkit rules.
  #     Default NixOS configuration allows wheel group full access.
  #     Custom rules can be added via security.polkit.extraConfig
  #
  # 12. COMPATIBILITY
  #     Some scripts may expect sudo-specific features:
  #     - No SUDO_USER, SUDO_GID, SUDO_COMMAND environment variables
  #     - Different command-line syntax
  #     - Use enableSudoAlias to provide 'sudo' command compatibility
  #
  # Migration from Sudo/Doas to run0
  #
  # Step 1: Enable this module in configuration.nix
  #         imports = [ ./modules/run0.nix ];
  #
  # Step 2: Test run0 while keeping sudo/doas enabled
  #         $ run0 whoami
  #         $ run0 bash
  #         $ run0 systemctl status
  #
  # Step 3: If everything works, disable sudo/doas
  #         In configuration.nix, comment out:
  #         # ./modules/sudo.nix
  #         # ./modules/doas.nix
  #         Or set: security.sudo.enable = false;
  #
  # Step 4: Enable sudo alias for compatibility
  #         security.run0.enableSudoAlias = true;
  #
  # Step 5: Rebuild and test
  #         sudo nixos-rebuild switch  # Last time using sudo!
  #         run0 whoami  # Should work
  #         sudo whoami  # Should work (aliased to run0)
  #
  # Step 6: Verify
  #         $ which sudo  # Should show alias or run0
  #         $ run0 whoami # Should work
  #         $ journalctl -t run0  # Check logs
  #
  # Rollback plan:
  # If you need to rollback, you can boot into a previous generation
  # or re-enable sudo/doas by uncommenting the module imports.
  #
  # Command Comparison: sudo vs run0
  #
  # Basic command execution:
  #   sudo command        -  run0 command
  #   sudo -u user cmd    -  run0 --user=user cmd
  #
  # Interactive shell:
  #   sudo -i             -  run0 bash
  #   sudo -u user -i     -  run0 --user=user bash
  #
  # Environment variables:
  #   sudo -E command     -  run0 --setenv=VAR1 --setenv=VAR2 command
  #   sudo VAR=val cmd    -  run0 --setenv=VAR=val command
  #
  # List permissions:
  #   sudo -l             -  (No direct equivalent, check polkit policies)
  #
  # Validate:
  #   sudo -v             -  (No equivalent, polkit handles authentication)
  #
  # Working directory:
  #   sudo command        -  run0 --working-directory=$PWD command
  #   (run0 runs in / by default, unlike sudo which preserves PWD)
  #
  # Advanced run0 Options
  #
  # Process isolation:
  #   run0 --private-tmp command         # Private /tmp
  #   run0 --read-only=/path command     # Read-only mount
  #
  # Resource limits:
  #   run0 --property=MemoryMax=1G command    # Limit memory
  #   run0 --property=CPUQuota=50% command    # Limit CPU
  #
  # Capabilities:
  #   run0 --property=CapabilityBoundingSet=CAP_NET_RAW command
  #
  # Network isolation:
  #   run0 --private-network command     # Isolated network namespace
  #
  # These options leverage systemd's service isolation features,
  # providing security capabilities not available in traditional sudo.
  #
  # Monitoring and Auditing
  #
  # View all run0 invocations:
  #   journalctl -t run0
  #
  # View recent run0 usage:
  #   journalctl -t run0 --since today
  #
  # View run0 failures:
  #   journalctl -t run0 -p err
  #
  # Monitor run0 in real-time:
  #   journalctl -t run0 -f
  #
  # View specific user's run0 usage:
  #   journalctl -t run0 _UID=1000
  #
  # What's logged:
  # - User who invoked run0
  # - Command executed
  # - Target user (if specified)
  # - Timestamp
  # - Success/failure
  # - systemd service unit information
  #
  # Troubleshooting
  #
  # Problem: "Failed to connect to bus: No such file or directory"
  # Solution: Ensure systemd is running (should be automatic in NixOS)
  #
  # Problem: "Authentication failed"
  # Solution: Check user is in wheel group, verify polkit configuration
  #
  # Problem: "Command not found" when using run0
  # Solution: Specify full path or ensure $PATH is set correctly
  #           run0 /run/current-system/sw/bin/command
  #
  # Problem: Working directory is / instead of current directory
  # Solution: Use --working-directory option:
  #           run0 --working-directory=$PWD command
  #
  # Problem: Environment variables not passed
  # Solution: Use --setenv to explicitly pass variables:
  #           run0 --setenv=DISPLAY=$DISPLAY command
  #
  # Problem: Script expects SUDO_USER variable
  # Solution: Scripts need to be adapted for run0, or use 'id -un' to get username
  #
  # Related Modules
  #
  # This module should be used instead of, not alongside:
  # - modules/sudo.nix (traditional sudo)
  # - modules/doas.nix (OpenBSD doas)
  #
  # Related security configurations in other modules:
  # - modules/users.nix: Root account lockdown, wheel group management
  # - modules/nixos-permissions.nix: Secure /etc/nixos/ permissions
  #
  # For complete privilege escalation protection with run0:
  # 1. Root is locked and only accessible via run0 (users.nix)
  # 2. Only trusted users are in wheel group (users.nix)
  # 3. Strong password policies are enforced (users.nix)
  # 4. Polkit rules are properly configured (this module + polkit config)
  # 5. All run0 operations are logged and monitored (systemd journal)
  #
  # Why run0 over sudo/doas?
  #
  # Choose run0 if:
  # - You want to eliminate SUID binaries from your system
  # - You value deep systemd integration
  # - You want modern Linux security architecture
  # - You need systemd's advanced isolation features
  # - You want consistent authentication via polkit
  # - Your privilege escalation needs are straightforward
  #
  # Choose sudo if:
  # - You need complex enterprise policies
  # - You have legacy scripts dependent on sudo
  # - You need LDAP integration
  # - You're on non-systemd systems
  # - You need sudo plugins
  #
  # Choose doas if:
  # - You want minimal codebase (security through simplicity)
  # - You prefer BSD-style tools
  # - You want simple configuration
  # - You don't need systemd integration
  #
  # For Rampart-NixOS:
  # run0 is recommended for modern systemd-based systems that want to leverage
  # systemd's security features and eliminate SUID binaries. However, it's newer
  # and less battle-tested than sudo/doas.
}
