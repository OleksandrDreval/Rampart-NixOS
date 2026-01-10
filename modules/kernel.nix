{ config, pkgs, lib, ... }:

{
  # Kernel configuration
  boot.kernelPackages = pkgs.linuxPackages_latest;
  
  # Security-focused kernel parameters
  boot.kernelParams = [
    "amd_iommu=force_isolation"           # Force AMD IOMMU isolation to protect devices from DMA attacks
    "apparmor=1"                          # Enable AppArmor mandatory access control
    "audit=1"                             # Enable auditing for AppArmor
    "debugfs=off"                         # Disable debugfs to prevent system information leakage
    "efi=disable_early_pci_dma"           # Disable early PCI DMA to protect against boot-time attacks
    "ia32_emulation=0"                    # Disable 32-bit emulation to reduce attack surface
    "init_on_alloc=1"                     # Initialize memory on allocation to prevent data leaks
    "init_on_free=1"                      # Initialize memory on free to protect confidentiality
    "iommu=force"                         # Force enable IOMMU for I/O device isolation
    "iommu.passthrough=0"                 # Disable IOMMU passthrough mode for additional checks
    "iommu.strict=1"                      # Enable strict IOMMU mode for enhanced memory access control
    "kernel.printk=\"3 4 1 3\""           # Configure kernel logging level to reduce information leakage
    "l1tf=full,force"                     # Full protection against L1 Terminal Fault attacks
    "lockdown=confidentiality:integrity"  # Kernel lockdown mode to maintain confidentiality and integrity
    "mds=full,nosmt"                      # Protection against MDS attacks with SMT disabled
    "mitigations=auto,nosmt"              # Auto-apply vulnerability patches with SMT disabled
    "module.sig_enforce=1"                # Require kernel module signatures for loading
    "oops=panic"                          # Panic on critical error to prevent unsafe operation
    "page_alloc.shuffle=1"                # Randomize page allocation to complicate exploits
    "page_poison=1"                       # Fill freed memory to prevent data recovery
    "pti=on"                              # Page Table Isolation for Meltdown protection
    "quiet"                               # Reduce boot message output
    "random.trust_bootloader=off"         # Disable trust in bootloader for random number generation
    "random.trust_cpu=off"                # Disable trust in CPU for random number generation
    "randomize_kstack_offset=on"          # Randomize kernel stack offset to complicate exploitation
    # Note: "security=apparmor" removed - use security.apparmor.enable in security module instead
    "slab_nomerge"                        # Disable slab merging to prevent cross-object leaks
    "slub_debug=FZP"                      # SLUB debugging to detect memory errors
    "spec_store_bypass_disable=on"        # Protection against Speculative Store Bypass attacks
    "spectre_v2=on"                       # Protection against Spectre v2 attacks
    "stf_barrier=on"                      # Store-to-Load Forwarding barrier for speculative attack protection
    "usercopy=strict"                     # Strict validation of data copying between kernel and user space
    "vsyscall=none"                       # Disable vsyscall to eliminate predictable memory addresses
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
