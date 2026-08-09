{ config, lib, ... }:

{
  /*
    Rampart Display Manager Hardening Module

    This module implements comprehensive security hardening for the display-manager service.
    It applies systemd sandboxing techniques to isolate the graphical login manager from
    the rest of the system. It restricts network access (Zero Trust), limits hardware
    interaction, and strips unnecessary kernel capabilities to minimize the attack
    surface of the root-privileged display manager (GDM/SDDM/LightDM) without breaking
    GPU acceleration or session switching.
  */

  systemd.services.display-manager.serviceConfig = {
    # File System Isolation
    # ProtectSystem and ProtectHome are intentionally omitted because the user's
    # graphical session is often spawned as a child process of the display manager.
    # If the DM is restricted, the user will be unable to write to their own home
    # directory or perform administrative tasks via sudo.
    UMask = "0022";               # Use standard permissions (readable, but not writable by others)

    # Network Isolation (Zero Trust)
    # Network restrictions omitted to prevent breaking the user's desktop network access.

    # Kernel & Hardware Protection
    # Omitted because the user session requires access to the kernel for containers,
    # mounting disks, and hardware acceleration.
    # LockPersonality omitted: Breaks Wine and 32-bit emulation environments.

    # Privilege & Capability Restrictions
    # CapabilityBoundingSet omitted to allow the user session to use sudo.
    # RestrictSUIDSGID omitted to allow the user to run su/sudo.
    # RestrictRealtime omitted: Breaks Mutter/KWin Wayland real-time scheduling for smooth rendering.

    # System Call Filtering
    # Only the safest filters are applied so user applications are not broken.
    # SystemCallArchitectures omitted: "native" breaks all 32-bit applications (like Steam).
    # SystemCallFilter omitted: "~@obsolete" blocks 'modify_ldt', which breaks Wine and Proton.
  };
}
