{ config, pkgs, lib, ... }:

let
  vars = import ./variables.nix;
  
  # Fetch Lanzaboote from GitHub using pkgs.fetchFromGitHub
  # This is the idiomatic NixOS way - cleaner than builtins.fetchTarball
  lanzaboote = pkgs.fetchFromGitHub {
    owner = "nix-community";
    repo = "lanzaboote";
    rev = "v1.0.0";  # Latest stable release
    sha256 = "17srvx92f0xymayfislm5d87bjd6n1p80s350my8si737iaa16a4";
    # To update: change rev, then run nixos-rebuild and it will show correct hash
  };
in
{ 
  imports = [
    # Import Lanzaboote module
    "${lanzaboote}/nix/modules/lanzaboote.nix"
  ];

  # Disable standard systemd-boot (Lanzaboote replaces it)
  boot.loader.systemd-boot.enable = lib.mkForce false;
  
  # Basic bootloader settings (from boot.nix)
  boot.loader.efi.canTouchEfiVariables = false;
  boot.loader.timeout = vars.bootTimeout;

  # Enable Lanzaboote for Secure Boot
  boot.lanzaboote = {
    enable = true;
    # Path where Secure Boot keys will be stored
    # Keys are generated with: sudo sbctl create-keys
    pkiBundle = "/etc/secureboot";
    
    # Configuration limit (like systemd-boot.configurationLimit)
    configurationLimit = vars.bootConfigLimit;
  };

  # LUKS encryption for swap (WITHOUT TPM)
  boot.initrd.luks.devices."luks-${vars.luksSwapUUID}".device = "/dev/disk/by-uuid/${vars.luksSwapUUID}";

  # DMA attack mitigation during early boot
  # Blocks Thunderbolt/USB4 access in initrd to protect LUKS keys
  boot.initrd.luks.mitigateDMAAttacks = true;

  # Install sbctl for Secure Boot key management
  environment.systemPackages = with pkgs; [
    sbctl  # Secure Boot key manager
  ];

  # IMPORTANT SECURITY NOTES:
  # 
  # 1. NO TPM INTEGRATION
  #    - LUKS password must be entered manually at boot
  #    - More secure: key only in your head, not in hardware
  #    - boot.initrd.luks.devices do NOT have any TPM settings
  # 
  # 2. Secure Boot protects BEFORE LUKS password
  #    - Verifies boot loader signature
  #    - Verifies kernel signature
  #    - Verifies initrd signature
  #    - Prevents bootkit/rootkit attacks
  # 
  # 3. Defense in Depth layers:
  #    - UEFI Secure Boot (boot chain integrity)
  #    - LUKS encryption (disk confidentiality)
  #    - Both keys in your head (no TPM trust)
  # 
  # 4. Lanzaboote automatically signs on every rebuild:
  #    - nixos-rebuild switch → auto-sign kernel/initrd
  #    - No manual sbctl sign needed
}
