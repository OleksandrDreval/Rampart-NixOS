{ config, lib, ... }:

{
  /*
    Rampart Getty Terminal Hardening Module

    This module hardens the Getty service, which provides login terminals on
    virtual consoles. It restricts kernel access, blocks network traffic,
    and filters system calls to protect the console login interface.

    IMPORTANT — getty@ spawns login → user shell, all within the SAME
    mount namespace. ProtectSystem="strict" and ProtectHome=true would
    make the user's home directory inaccessible after login.
    ProtectSystem="full" protects /usr, /boot, /efi, /etc while leaving
    /home and /var writable for normal user sessions.

    NoNewPrivileges and RestrictSUIDSGID MUST NOT be true — the user shell
    needs to execute SUID binaries (sudo, doas) for privilege escalation.
    Same logic as sshd.nix. Upstream getty has zero hardening.
  */

  systemd.services."getty@".serviceConfig = {
    # Privilege & Capability Restrictions
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem Isolation
    PrivateMounts = true;         # Use a private file system namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Memory & System Call Filtering
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked calls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@debug"          # Block debugging system calls
      "~@swap"           # Block swap management
      "~@clock"          # Block clock configuration
      "~@cpu-emulation"  # Block non-native CPU emulation
    ];

    # Other Security Settings
    UMask = "0022";  # Ensure console related files stay private
  };
}
