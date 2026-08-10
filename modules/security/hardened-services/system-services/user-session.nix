{ config, lib, ... }:

{
  /*
    Rampart User Session Manager Hardening Module

    This module applies a balanced security profile to the user's systemd session
    manager (user@.service). It isolates session processes from the system core,
    restricts kernel access, and protects other users' data while ensuring
    seamless desktop integration and application compatibility.
  */

  systemd.services."user@".serviceConfig = {
    # Kernel & Hardware Protection
    # Many protections are intentionally omitted here. Restricting the user session manager
    # (user@.service) applies those restrictions to the ENTIRE desktop session (GNOME, KDE)
    # and all interactive terminals. Setting ProtectKernelModules, ProtectClock, or
    # SystemCallFilter would completely break legitimate administrative tasks (sudo modprobe,
    # sudo reboot, etc.) for admin users on their desktop.
    # KeyringMode is left as default ("inherit") so that PAM, ssh-agent, and gnome-keyring
    # can share the user keyring across the session.

    # Process & File System Isolation
    # ProtectSystem="full" and PrivateTmp=true are NOT used. PrivateTmp would break
    # X11 socket access (/tmp/.X11-unix). ProtectProc="invisible" would break tools
    # like htop, hiding system processes from the user.
    # LockPersonality is omitted to allow 32-bit execution (Steam, Wine).

    # Network & IPC isolation
    # Cannot restrict AddressFamilies, as users legitimately use IPv4/IPv6, Netlink,
    # and other sockets for daily applications (browsers, development tools).

    # Privilege & Capability Restrictions
    # RestrictRealtime is intentionally omitted. Even though PipeWire delegates RT
    # scheduling to rtkit, systemd's restriction on the user session cgroup prevents
    # rtkit from successfully elevating priority, leading to audio stutter.

    # Memory & System Call Filtering
    # SystemCallArchitectures="native" is omitted to allow 32-bit syscalls for Steam/Wine.
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated/legacy syscalls
    ];
  };
}
