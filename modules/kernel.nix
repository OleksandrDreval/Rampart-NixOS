{ config, pkgs, lib, ... }:

let
  # Base kernel modules which must always be present. Other modules may add
  # additional entries, but these are considered authoritative and will be
  # preserved by the finalizer.
  rampartBaseKernelModules = [
    # WiFi crypto modules (WPA/WPA2/WPA3 authentication)
    "ccm"          # Counter with CBC-MAC mode for WPA2-CCMP
    "ctr"          # Counter mode for AES
    "gcm"          # Galois/Counter Mode for WPA3
    "aesni_intel"  # AES-NI hardware acceleration (Intel/AMD)
    "crypto_simd"  # SIMD crypto operations
    "cryptd"       # Crypto daemon for async operations
    
    # Additional crypto modules for comprehensive support
    "aes_generic"       # Generic AES implementation (fallback)
    "sha256"            # SHA-256 hash (required for signatures)
    "sha512"            # SHA-512 hash (for enhanced security)
    "hmac"              # HMAC for message authentication
    "ecb"               # ECB mode (used by some crypto operations)
    "cbc"               # CBC mode (legacy but still needed)
    "xts"               # XTS mode (for disk encryption compatibility)
    "pkcs8_key_parser"  # PKCS#8 key parser (for iwd WPA Enterprise EAP-TLS)
    
    # Core network modules
    "af_packet"    # Packet socket support (required for NetworkManager)
    "cfg80211"     # Wireless configuration API
    "mac80211"     # Generic IEEE 802.11 networking stack
    
    # Filesystem modules (if using encrypted partitions)
    "dm_mod"       # Device mapper (for LUKS)
    "dm_crypt"     # Device mapper crypto target (for LUKS)
    
    # Essential system modules
    "loop"         # Loopback device support
    "overlay"      # Overlay filesystem (for containers/nix store)

    "kvm-amd"      # AMD KVM support (hardware virtualisation)
  # "kvm-intel"    # Intel KVM support (hardware virtualisation)
  ];

  # Base kernel params which must always be present on the kernel command line.
  rampartBaseKernelParams = [
    # CPU Vulnerability Mitigations
  # "gather_data_sampling=force"          # Force protection against GDS vulnerability (Intel CPUs)
    "l1tf=full,force"                     # Full protection against L1 Terminal Fault attacks
    "mds=full,nosmt"                      # Protection against MDS attacks with SMT disabled
    "mitigations=auto,nosmt"              # Auto-apply vulnerability patches with SMT disabled
    "spec_store_bypass_disable=on"        # Protection against Speculative Store Bypass attacks
    "spectre_v2=on"                       # Protection against Spectre v2 attacks
    "stf_barrier=on"                      # Store-to-Load Forwarding barrier for speculative attack protection
    "tsx=off"                             # Disable TSX to mitigate TSX Asynchronous Abort vulnerabilities

    # IOMMU & DMA Protection
    "amd_iommu=force_isolation"           # Force AMD IOMMU isolation to protect devices from DMA attacks
    "efi=disable_early_pci_dma"           # Disable early PCI DMA to protect against boot-time attacks
    "iommu=force"                         # Force enable IOMMU for I/O device isolation
    "iommu.passthrough=0"                 # Disable IOMMU passthrough mode for additional checks
    "iommu.strict=1"                      # Enable strict IOMMU mode for enhanced memory access control
  # "intel_iommu=on"                      # Enable Intel IOMMU (for Intel systems, no-op on AMD)

    # Kernel Hardening & Lockdown
    "apparmor=1"                          # Enable AppArmor mandatory access control
    "audit=1"                             # Enable auditing for AppArmor
    "debugfs=off"                         # Disable debugfs to prevent system information leakage
    "ia32_emulation=0"                    # Disable 32-bit emulation to reduce attack surface
    "lockdown=integrity"                  # Kernel lockdown - integrity mode (allows signed modules, crypto operations)
    "module.sig_enforce=1"                # Require kernel module signatures for loading
    "oops=panic"                          # Panic on critical error to prevent unsafe operation
    "panic=-1"                            # Auto-reboot instantly on kernel panic (DoS mitigation + info disclosure prevention)

    # Boot Logging & Information Disclosure
    "efi_pstore.pstore_disable=1"         # Disable EFI persistent storage (prevent crash log leaks)
    "erst_disable"                        # Disable Error Record Serialization Table (prevent error log leaks)
    "kernel.printk=\"3 3 3 3\""           # Configure kernel logging level to reduce information leakage
    "quiet"                               # Reduce boot message output
    "udev.log_level=3"                    # udev errors only (minimize boot information disclosure)
    
    # Resource Control (Cgroups)
    "cgroup_no_v1=all"
    "systemd.unified_cgroup_hierarchy=1"

    # Enable AMD SEV/SEV-ES/SEV-SNP support for virtual machines
    "kvm_amd.sev=1"                       # Enable SEV support
    "kvm_amd.sev_es=1"                    # Enable SEV-ES support
    "kvm_amd.sev_snp=1"                   # Enable SEV-SNP support
  ];

  # Base sysctl keys that must be enforced for filesystem/tty/core-dump hardening.
  # These keys represent Rampart's authoritative defaults; other modules may
  # add keys, but these base keys must not be weakened.
  rampartBaseSysctl = {
    # TTY security
    "dev.tty.ldisc_autoload"             = 0;              # Disable automatic TTY line discipline loading
    
    # Kernel security
    "kernel.core_pattern"                = "|/bin/false";  # Disable core dumps completely
    "kernel.dmesg_restrict"              = 1;              # Restrict dmesg access to root only
    "kernel.ftrace_enabled"              = 0;              # Disable function tracer to prevent debugging
    "kernel.panic"                       = -1;             # Auto-reboot instantly on kernel panic
    "kernel.io_uring_disabled"           = 2;              # Completely disable io_uring to prevent exploits
    "kernel.kexec_load_disabled"         = 1;              # Disable kexec to prevent kernel replacement
    "kernel.kptr_restrict"               = 2;              # Hide kernel pointers even from root
    "kernel.perf_cpu_time_max_percent"   = 1;              # Limit perf CPU time to 1% to prevent DoS
    "kernel.perf_event_max_sample_rate"  = 1;              # Limit perf sampling rate
    "kernel.perf_event_paranoid"         = 3;              # Maximum restrictions for perf events
    "kernel.printk"                      = "3 3 3 3";      # Show only errors (level 3) in kernel logs
    "kernel.sysrq"                       = 0;              # Completely disable SysRq (use hard reset if system hangs)
    "kernel.unprivileged_bpf_disabled"   = 2;              # Disable unprivileged BPF to prevent exploits (permanent disable)

    # Networking security
    "net.core.bpf_jit_harden"            = 2;              # Harden BPF JIT runtime (higher security)
    "net.core.bpf_jit_kallsyms"          = 0;              # Disable publishing JIT symbols to kallsyms
    
    # ptrace restrictions
    "kernel.yama.ptrace_scope"           = 2;              # Maximum ptrace restrictions - admin only

    "kernel.unprivileged_userns_clone"   =1;               # Enable unprivileged user namespaces (required for rootless containers and some sandboxes)
  };
in

{
  # Kernel configuration - hardened kernel with additional security patches
  boot.kernelPackages = pkgs.linuxKernel.packages.linux_hardened;

  # Initrd/kernel module hints detected from hardware config (migrated from hardware-configuration.nix)
  boot.initrd.availableKernelModules = [ "nvme" "xhci_pci" "usbhid" "usb_storage" "sd_mod" "sdhci_pci" ];

  # Core dumps security
  systemd.coredump.extraConfig = ''
    Storage=none
  '';

  # Provide the base values under `rampart.*` so the finalizer module can
  # aggregate additions from other modules and then lock the result.
  rampart = {
    kernelBaseModules = rampartBaseKernelModules;
    kernelBaseParams  = rampartBaseKernelParams;
    kernelBaseSysctl  = rampartBaseSysctl;
  };

  # Blacklisted kernel modules for security (authoritative & forced here)
  # This list is authoritative and must not be weakened by other modules.
  boot.blacklistedKernelModules = lib.mkForce [
    # Physical Interfaces with DMA attack vectors
    "bluetooth"      # BlueBorne, KNOB, BLURtooth vulnerabilities
    "thunderbolt"    # Thunderspy, DMA attacks
    "firewire-core"  # FireWire/IEEE 1394 - DMA attacks via SBP-2
    
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
  # Safe to enable: WiFi crypto modules pre-loaded in boot.kernelModules
  security.lockKernelModules = lib.mkForce true;

  # Prevent replacing the running kernel image via kexec
  # Blocks kernel replacement attacks and rootkit injection
  security.protectKernelImage = lib.mkForce true;
  
  # Disable unprivileged user namespaces
  # Prevents container escape attacks and namespace-based exploits
  # Note: This breaks Flatpak, rootless containers (Podman), and some browser sandboxes
  # If needed, set to true: security.unprivilegedUsernsClone = true;
  security.unprivilegedUsernsClone = lib.mkDefault false;
}
