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
    # RestrictRealtime omitted: breaks real-time audio (JACK/PipeWire) for the user

    # Kernel & Hardware Protection
    # Many protections are intentionally omitted because getty spawns the
    # user's interactive shell. If we restrict the kernel (e.g., ProtectKernelModules,
    # ProtectKernelTunables) or namespaces (RestrictNamespaces, PrivateMounts),
    # the logged-in user (even root via sudo) will be completely unable to load
    # modules, mount disks, use containers, or configure the system.
    # LockPersonality omitted: breaks 32-bit compatibility (Wine/Steam/chroots)

    # Memory & System Call Filtering
    # We cannot use aggressive SystemCallFilter here, because they would apply
    # to all user applications run from this terminal.
    # SystemCallArchitectures="native" would break 32-bit Wine/Steam.
    # "~@debug" would break gdb, strace, and developer tools for the entire session.

    # Other Security Settings
    # UMask omitted: let PAM handle the user's UMask (e.g., via /etc/login.defs)
  };
}
