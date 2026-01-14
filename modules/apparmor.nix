{ config, pkgs, lib, ... }:

{
  # AppArmor Mandatory Access Control (MAC) configuration
  # Provides application-level security by restricting program capabilities
  # based on per-program profiles that define allowed operations
  
  security.apparmor = {
    # Enable AppArmor LSM (Linux Security Module)
    enable = true;
    
    # Kill processes that should be confined but are running unconfined
    # Prevents execution without security profiles when profile exists
    killUnconfinedConfinables = true;
    
    # Include additional AppArmor packages for extended functionality
    packages = with pkgs; [
      apparmor-utils        # aa-status, aa-enforce, aa-complain tools
      apparmor-profiles     # Collection of profiles for common applications
    ];
  };
  
  # Enable AppArmor kernel parameter (redundant with security.apparmor.enable but explicit)
  # Already set in kernel.nix: "apparmor=1" and "audit=1"
  
  # AppArmor profiles are located in:
  # - /etc/apparmor.d/ (system profiles)
  # - /nix/store/*/etc/apparmor.d/ (package-provided profiles)
  
  # Common commands for managing AppArmor:
  # - sudo aa-status              : Show current AppArmor status
  # - sudo aa-enforce <profile>   : Set profile to enforce mode
  # - sudo aa-complain <profile>  : Set profile to complain mode (log only)
  # - sudo aa-disable <profile>   : Disable profile
  # - journalctl | grep apparmor  : View AppArmor audit logs
  
  # To create custom profiles for applications, add them to:
  # environment.etc."apparmor.d/custom-profile".text = ''
  #   profile custom_app /path/to/app {
  #     # Define allowed operations here
  #   }
  # '';
}
