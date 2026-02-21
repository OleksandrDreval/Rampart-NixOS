{ config, lib, ... }:

{
  /*
    Rampart Bluetooth Service Hardening Module

    This module hardens the Bluetooth daemon (bluetoothd). It isolates the
    service from kernel internals, hides other system processes, and
    restricts system calls. Given that Bluetooth is a historically frequent
    attack vector, this configuration minimizes the potential impact of
    remote exploits.
  */

  systemd.services.bluetooth.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;  # Disallow gaining new privileges

    # Memory & System Call Filtering
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@swap"           # Block swap management
      "~@reboot"         # Block system reboot
      "~@mount"          # Block filesystem mounting
    ];
  };
}
