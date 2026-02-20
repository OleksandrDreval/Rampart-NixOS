{ config, lib, ... }:

{
  /*
    Rampart systemd-udevd Hardening Module

    This module applies security hardening to the systemd-udevd service, which
    manages device events and nodes in /dev. It implements a strict filesystem
    sandbox, restricts access to kernel logs, and limits process visibility
    and kernel capabilities to minimize the risk of privilege escalation.
  */

  systemd.services.systemd-udevd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges via setuid/setgid
    # Block specific capabilities while allowing others for device management
    CapabilityBoundingSet = "~CAP_SYS_PTRACE ~CAP_SYS_PACCT";

    # Filesystem Isolation
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    RuntimeDirectory = "udev";  # Writable /run/udev for device database and runtime state
    ProtectHome = true;         # Make /home and /root completely inaccessible

    # Kernel & Hardware Protection
    ProtectKernelLogs = true;  # Prevent reading kernel messages from dmesg
    ProtectClock = true;       # Prevent modification of system clock or RTC
    # NOTE: ProtectControlGroups intentionally omitted — upstream udevd uses
    # Delegate=pids + DelegateSubgroup=udev for worker cgroup management

    # Process & Identity Isolation
    ProtectProc = "invisible";   # Hidden processes of other users in /proc
    RestrictNamespaces = true;   # Prohibit creation of any new namespaces
  };
}
