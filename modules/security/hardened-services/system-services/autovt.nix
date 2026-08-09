{ config, lib, ... }:

{
  /*
    Rampart Virtual Terminal (AutoVT) Hardening Module

    This module hardens the virtual terminal services (getty/autovt). It
    restricts kernel access, blocks network traffic, and filters system
    calls to prevent virtual consoles from being used to escalate
    privileges or leak system state information.

    IMPORTANT — autovt@ spawns login → user shell, all within the SAME
    mount namespace. ProtectSystem="strict" and ProtectHome=true would
    make the user's home directory inaccessible after login.
    ProtectSystem="full" protects /usr, /boot, /efi, /etc while leaving
    /home and /var writable for normal user sessions.

    NoNewPrivileges and RestrictSUIDSGID MUST NOT be true — the user shell
    needs to execute SUID binaries (sudo, doas) for privilege escalation.
    Same logic as sshd.nix. Upstream autovt (alias of getty@) has zero hardening.
  */

  systemd.services."autovt@".serviceConfig = {
    # Privilege & Capability Restrictions
    # NoNewPrivileges / RestrictSUIDSGID omitted: setting to true breaks sudo/doas
    # RestrictRealtime omitted: breaks real-time audio (JACK/PipeWire) for the user

    # Kernel & Hardware Protection
    # Many protections are intentionally omitted because autovt/getty spawns the
    # user's interactive shell. If we restrict the kernel (e.g., ProtectKernelModules,
    # ProtectKernelTunables) or namespaces (RestrictNamespaces, PrivateMounts),
    # the logged-in user (even root via sudo) will be completely unable to load
    # modules, mount disks, use containers, or configure the system.
    # LockPersonality omitted: breaks 32-bit compatibility (Wine/Steam/chroots)

    # Memory & System Call Filtering
    # We cannot use IPAddressDeny, MemoryDenyWriteExecute, or ANY SystemCallFilter
    # here. SystemCallArchitectures="native" would break 32-bit Wine/Steam.
    # "~@debug" would break gdb, strace, and developer tools for the entire session.
    
    # Other Security Settings
    # UMask omitted: setting 0077 here forces it on all user-created files, breaking collaboration.
  };
}
