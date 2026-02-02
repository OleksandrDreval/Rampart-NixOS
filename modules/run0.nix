{ config, pkgs, lib, ... }:

{
  # Enable run0 as privilege escalation mechanism
  # This is a systemd-based alternative to sudo that doesn't use SUID binaries
  security.run0 = {

  };
}
