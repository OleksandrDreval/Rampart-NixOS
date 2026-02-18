{ config, pkgs, lib, ... }:

let
  vars = import ../security/secrets/vars-compat.nix { inherit config lib; };
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

  # Restrict use of `su` to members of the `wheel` group.
  # - Purpose: prevent unprivileged users from switching to root with `su`.
  # - Effect: users not in `wheel` will be denied by PAM when invoking `su`.
  # - Rationale: limits local privilege escalation surface and centralizes
  #   administrative access to the wheel group (auditable and easy to revoke).
  security.pam.services.su = {
    # Enforce that only `wheel` members can use `su` (boolean PAM flag).
    requireWheel = true;
  };

  # Restrict use of `su -l` (login shell) to members of the `wheel` group.
  # - Note: `su -l` invokes a login shell and may trigger different PAM
  #   behavior/modules than plain `su`. We treat it explicitly to ensure
  #   identical access controls for login-shell escalation attempts.
  # - Effect: `su -l` will also be denied for non-wheel users.
  security.pam.services."su-l" = {
    requireWheel = true;
  };

  # Define user accounts
  users.users.${vars.mainUser} = {
    isNormalUser = true;
    description = vars.mainUserDescription;
    hashedPassword = vars.mainUserHashedPassword;  # Password hash from variables
    extraGroups = [ "networkmanager" "wheel" "libvirtd" ];
    packages = lib.mkDefault (with pkgs; [
      # Add user-specific packages here
      # thunderbird
    ]);
  };

  # Sudo Configuration

  # Sudo security settings have been moved to a separate module: modules/sudo.nix
  # This provides better organization and maintainability of privilege escalation controls.
  # See modules/sudo.nix for:
  # - Wheel-only sudo execution
  # - Password requirements
  # - Timeout controls
  # - PTY enforcement
  # - Environment hardening
  # - Audit logging

  # Configure number of rounds for the Unix shadow password hashing algorithm.
  # Higher values increase the computational cost of offline hash cracking attacks.
  security.pam.services.passwd.rules.password."unix".settings.rounds = toString vars.shadowHashRounds;

  # Add a delay after failed interactive login attempts to slow brute-force attacks.
  # Value is in microseconds (e.g. 5000000 = 5s) and applies per failed authentication.
  security.pam.services."system-login".failDelay.delay = toString vars.loginFailDelay;

  # Nix daemon access control
  # Limit nix commands to wheel group (sudoers) only
  # Prevents unprivileged users from installing packages or using nix-shell
  nix.settings.allowed-users = vars.nixAllowedUsers;

  # Hardening the user session manager (user@.service)
  # This service manages the user's systemd instance and all session processes.
  # We apply a balanced security profile that doesn't break desktop applications.
  systemd.services."user@".serviceConfig = {
    # Kernel & Hardware Protection
    ProtectClock = true;           # Prevent user from changing system clock
    ProtectHostname = true;        # Prevent user from changing hostname
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)

    # Process & File System Isolation
    ProtectSystem = "full";     # Mount /usr, /boot, and /etc read-only
    ProtectProc = "invisible";  # Hide processes of other users
    PrivateTmp = true;          # Use isolated /tmp for each user session

    # Network & IPC isolation
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local IPC (Wayland/X11/DBus)
      "AF_NETLINK"  # Network status updates
      "AF_INET"     # IPv4 access
      "AF_INET6"    # IPv6 access
    ];

    # Privilege & Capability Restrictions
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits in the session

    # Memory & System Call Filtering
    SystemCallArchitectures = "native";  # Allow only native syscalls (prevents 32-bit exploitation)
    SystemCallFilter = [
      "~@swap"           # Block swap management
      "~@module"         # Block kernel module calls
      "~@obsolete"       # Block deprecated/legacy syscalls
      "~@cpu-emulation"  # Block non-native CPU emulation
    ];
  };

  # Hardening accounts-daemon service
  # This service manages user account information (/var/lib/AccountsService)
  systemd.services.accounts-daemon.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
  };
}
