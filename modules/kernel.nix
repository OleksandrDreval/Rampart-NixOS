{ config, pkgs, lib, ... }:

{
  # Kernel configuration
  boot.kernelPackages = pkgs.linuxPackages_latest;
  
  # Security-focused kernel parameters
  boot.kernelParams = [
    "amd_iommu=force_isolation"
    "apparmor=1"
    "audit=1"
    "debugfs=off"
    "efi=disable_early_pci_dma"
    "ia32_emulation=0"
    "init_on_alloc=1"
    "init_on_free=1"
    "iommu=force"
    "iommu.passthrough=0"
    "iommu.strict=1"
    "kernel.printk=\"3 4 1 3\""
    "l1tf=full,force"
    "lockdown=confidentiality:integrity"
    "mds=full,nosmt"
    "mitigations=auto,nosmt"
    "module.sig_enforce=1"
    "oops=panic"
    "page_alloc.shuffle=1"
    "page_poison=1"
    "pti=on"
    "quiet"
    "random.trust_bootloader=off"
    "random.trust_cpu=off"
    "randomize_kstack_offset=on"
    # Note: "security=apparmor" removed - use security.apparmor.enable in security module instead
    "slab_nomerge"
    "slub_debug=FZP"
    "spec_store_bypass_disable=on"
    "spectre_v2=on"
    "stf_barrier=on"
    "usercopy=strict"
    "vsyscall=none"
  ];

  # Blacklisted kernel modules for security
  boot.blacklistedKernelModules = [
    # Physical Interfaces with DMA attack vectors
    "bluetooth"    # BlueBorne, KNOB, BLURtooth vulnerabilities
    "thunderbolt"  # Thunderspy, DMA attacks
    
    # Network File Systems with security concerns
    "cifs"         # SMB/CIFS - EternalBlue, WannaCry, numerous CVEs
    "nfs"          # Network File System v2 - weak security
    "nfsv3"        # Network File System v3 - authentication issues
    "nfsv4"        # Network File System v4 - complex, potential vulnerabilities
    
    # Modern but less secure file systems
    "f2fs"         # Flash-Friendly FS - less battle-tested than ext4
  ];

  # Lock kernel module loading after boot
  # Prevents loading new modules after system initialization
  # Only modules in boot.kernelModules can be loaded
  security.lockKernelModules = true;

  # Prevent replacing the running kernel image via kexec
  # Blocks kernel replacement attacks and rootkit injection
  security.protectKernelImage = true;
}
