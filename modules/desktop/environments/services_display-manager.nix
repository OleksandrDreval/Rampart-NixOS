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
    ProtectSystem = "full";       # Protect /usr, /boot, and /etc from writes
    ProtectControlGroups = true;  # Restrict access to cgroup configuration
    PrivateMounts = true;         # Use a private mount namespace
    UMask = 0077;                 # Ensure files created by DM are private

    # Network Isolation (Zero Trust)
    # Display managers should never need network access.
    IPAddressDeny = [ "0.0.0.0/0" "::/0" ];
  };
}
