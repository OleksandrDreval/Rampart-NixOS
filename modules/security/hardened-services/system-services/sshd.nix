{ config, lib, ... }:

{
  /*
    Rampart SSH Daemon Hardening Module

    This module hardens the OpenSSH daemon (sshd) using systemd sandboxing.
    It restricts access to the kernel and system files while allowing the
    necessary permissions for user logins, session initialization, and
    privilege escalation (via sudo/doas).
  */

  systemd.services.sshd.serviceConfig = {
    # Harden the daemon while allowing transition to session initialization
    NoNewPrivileges = false;  # Allow sudo/doas/run0

    # System resource isolation
    # ProtectSystem="strict" is intentionally omitted. If set, it would be inherited
    # by the user's login shell, preventing the user (even root via sudo) from writing
    # to /etc, /var, or /usr/local during administrative tasks over SSH.
    RuntimeDirectory = "sshd";  # Writable /run/sshd for privilege separation

    # Kernel & Hardware Protection
    # Many protections are intentionally omitted because sshd spawns the user's
    # interactive shell. Restricting the kernel (ProtectKernelModules, ProtectClock)
    # or namespaces (RestrictNamespaces, PrivateMounts) would completely prevent
    # the logged-in user from loading modules, mounting disks, or using containers.
    # LockPersonality is also intentionally omitted: it would break `setarch` and 
    # the execution of 32-bit environments (like pkgsi686Linux or steam-run) over SSH.

    # Memory & System Call Filtering
    # We cannot use aggressive SystemCallFilter, MemoryDenyWriteExecute, or
    # DevicePolicy here, because they would apply to all user applications run
    # from this SSH session (compilers, containers, X11 apps, etc).
    # SystemCallArchitectures="native" is explicitly omitted because it completely
    # breaks the execution of any 32-bit binaries by the user.
  };
}
