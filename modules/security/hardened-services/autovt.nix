{ config, lib, ... }:

{
  /*
    Rampart Virtual Terminal (AutoVT) Hardening Module

    This module hardens the virtual terminal services (getty/autovt). It
    applies strict filesystem isolation, network blocking, and restricts
    system calls to prevent virtual consoles from being used to escalate
    privileges or leak system state information.
  */

  systemd.services."autovt@".serviceConfig = { };
}
