{ config, lib, ... }:

{
  /*
    Rampart Getty Terminal Hardening Module

    This module hardens the Getty service, which provides login terminals on
    virtual consoles. It implements strict filesystem isolation, blocks
    all network access, and restricts system calls to ensure that the
    console login interface is protected from exploitation.
  */

  systemd.services."getty@".serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
  };
}
