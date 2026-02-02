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
  };
}
