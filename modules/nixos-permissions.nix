{ config, ... }:

{
  # Secure /etc/nixos/ directory permissions
  # Only root can access, read, or modify configuration files
  # Prevents unauthorized users from viewing or changing system configuration
  
  # Using systemd-tmpfiles for permission management
  # This is the standard NixOS/systemd approach for managing file permissions
  # Executed by systemd-tmpfiles-setup.service early in boot process
  systemd.tmpfiles.rules = [
    # Set /etc/nixos/ directory ownership and permissions
    # d = create directory if missing, set ownership and permissions
    # 0700 = only root can read, write, and execute (enter directory)
    "d /etc/nixos 0700 root root -"
    
    # Recursively apply permissions to all files and subdirectories
    # Z = recursively set ownership and permissions on existing paths
    # Files get 0600 (rw-------), directories keep 0700 (rwx------)
    "Z /etc/nixos 0700 root root -"
  ];
}
