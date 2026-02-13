{ config, pkgs, lib, ... }:

let
  vars = import ../../security/secrets/vars-compat.nix { inherit config lib; };
  
  # Generate rules string from allowed devices list
  rulesString = lib.concatStringsSep "\n" (
    vars.usbguardAllowedDevices ++ [
      # Block all other devices by default
      "reject"
    ]
  );
in
{
  # USBGuard - USB device authorization firewall
  # Protects against BadUSB attacks, unauthorized data copying, and malicious USB devices
  services.usbguard = {
    enable = true;

    # Device authorization rules (provided as a low-priority default elsewhere if needed)
    rules = rulesString;
  };
  
  # Add USBGuard tools to system packages
  environment.systemPackages = lib.mkDefault (with pkgs; [
    usbguard          # USBGuard daemon and CLI tools
    usbguard-notifier # Desktop notifications for USB events (optional)
  ] ++ (config.environment.systemPackages or []));
  
  # Enable audit daemon for USBGuard logging
  security.auditd.enable = lib.mkDefault true;
  
  # Management commands:
  # 
  # List all connected USB devices:
  #   sudo usbguard list-devices
  #
  # Generate policy for currently connected devices:
  #   sudo usbguard generate-policy > /tmp/usbguard-policy.conf
  #
  # Allow device temporarily (until reboot):
  #   sudo usbguard allow-device <device-id>
  #
  # Block device:
  #   sudo usbguard block-device <device-id>
  #
  # View audit log:
  #   sudo journalctl -u usbguard
  #   sudo tail -f /var/log/usbguard/usbguard-audit.log
  #
  # Watch for USB events in real-time:
  #   sudo usbguard watch
  #
  # To add new device permanently:
  #   1. Connect the device
  #   2. Find device ID: sudo usbguard list-devices
  #   3. Generate rule: sudo usbguard generate-policy | grep <device-name>
  #   4. Add rule to allowedDevices list in this file
  #   5. Rebuild: sudo nixos-rebuild switch
}
