{ config, pkgs, lib, ... }:

let
  # `rampartKernel` in `configuration.nix` allows users to customize this module's behavior
  # For example: `rampartKernel.extraPatches`, `rampartKernel.kernelParams`, `rampartKernel.customKernel`
  userExtras = config.rampartKernel or {};
  extras = userExtras.extraPatches or [];
  # Default kernel extra config: enable audit support and syscall auditing
  defaultExtraConfig = ''
    BPF_JIT_ALWAYS_ON=y
    USERFAULTFD=n
    EXPERT=y
    AUDIT=y
    AUDITSYSCALL=y
    IKCONFIG=n
    IKHEADERS=n
    KALLSYMS=n
    KALLSYMS_ALL=n
  '';
  combinedExtraConfig = if userExtras.extraConfig then defaultExtraConfig + "\n" + userExtras.extraConfig else defaultExtraConfig;

  # Create a default rampart kernel package by overriding linux_hardened with patches and extraConfig
  # Helper: produce a rampart variant of any kernel package by applying
  # the configured `extras` patches and `combinedExtraConfig`.
  makeRampartPackage = pkgsBase: pkgsBase.overrideAttrs (old: {
    patches = (old.patches or []) ++ extras;
    extraConfig = let
      base = old.extraConfig or "";
      add = combinedExtraConfig;
    in if base == "" then add else if add == "" then base else base + "\n" + add;
  });

  # Build our `rampart` kernel package from linux_hardened and expose it via overlay.
  rampartPackage = makeRampartPackage pkgs.linuxKernel.packages.linux_hardened;

  # Overlay that registers `rampartKernel` in `pkgs` for other imports.
  overlay = final: prev: {
    rampartKernel = makeRampartPackage prev.linuxKernel.packages.linux_hardened;
  };
in

{
  # Register overlay so `pkgs.rampartKernel` becomes available to other imports.
  nixpkgs.overlays = (config.nixpkgs.overlays or []) ++ [ overlay ];

  # Use the built rampart kernel package unconditionally.
  boot.kernelPackages = rampartPackage;

  # Provide convenient defaults for core dumps and typical security settings
  systemd.coredump.extraConfig = userExtras.coredumpExtraConfig or ''
    Storage=none
  '';

  # Merge kernel modules and params with sensible security-focused defaults
  # `boot.kernelModules` is used to force-preload modules that must be loaded before
  # `security.lockKernelModules` prevents loading new modules. The list is minimal
  # and targeted at security/support needs (no WiFi-specific entries).
  boot.kernelModules = let
    existing = config.boot.kernelModules or [];
    # keep only general-purpose modules (avoid WiFi-specific entries here)
    toAdd = userExtras.kernelModules or [
      # Crypto / acceleration
      "aesni_intel"       # AES-NI hardware acceleration (Intel/AMD)
      "crypto_simd"       # SIMD crypto operations used by accelerated crypto
      "cryptd"            # Crypto daemon for async crypto operations
      "aes_generic"       # Generic AES implementation (fallback)

      # Hash / MAC
      "sha256"            # SHA-256 hash (required for signatures)
      "sha512"            # SHA-512 hash (for enhanced security)
      "hmac"              # HMAC for message authentication

      # Filesystem encryption compatibility
      "xts"               # XTS mode (for disk encryption compatibility)
      "pkcs8_key_parser"  # PKCS#8 key parser (for enterprise EAP-TLS and keys)

      # Block device / encryption
      "dm_mod"            # device-mapper (LUKS)
      "dm_crypt"          # device-mapper crypto target (LUKS)

      # General utilities
      "loop"              # Loopback device support
      "overlay"           # Overlay filesystem (for containers / nix store)
    ];
    toAddFiltered = lib.filter (p: !(lib.elem p existing)) toAdd;
  in toAddFiltered ++ existing;

  boot.kernelParams = let
    existing = config.boot.kernelParams or [];
    toAdd = userExtras.kernelParams or [
      "amd_iommu=force_isolation"     # Force AMD IOMMU isolation to protect devices from DMA attacks
      "apparmor=1"                    # Enable AppArmor mandatory access control
      "audit=1"                       # Enable auditing for AppArmor
      "debugfs=off"                   # Disable debugfs to prevent system information leakage
      "efi=disable_early_pci_dma"     # Disable early PCI DMA to protect against boot-time attacks
      "efi_pstore.pstore_disable=1"   # Disable EFI persistent storage (prevent crash log leaks)
      "erst_disable"                  # Disable Error Record Serialization Table (prevent error log leaks)
      "ia32_emulation=0"              # Disable 32-bit emulation to reduce attack surface
      "iommu=force"                   # Force enable IOMMU for I/O device isolation
      "iommu.passthrough=0"           # Disable IOMMU passthrough mode for additional checks
      "iommu.strict=1"                # Enable strict IOMMU mode for enhanced memory access control
      "kernel.printk=\"3 3 3 3\""     # Configure kernel logging level to reduce information leakage
      "l1tf=full,force"               # Full protection against L1 Terminal Fault attacks
      "lockdown=confidentiality"      # Enable kernel lockdown in confidentiality mode
      "mds=full,nosmt"                # Protection against MDS attacks with SMT disabled
      "mitigations=auto,nosmt"        # Auto-apply vulnerability patches with SMT disabled
      "module.sig_enforce=1"          # Require kernel module signatures for loading
      "oops=panic"                    # Panic on critical error to prevent unsafe operation
      "panic=-1"                      # Auto-reboot instantly on kernel panic (DoS mitigation + info disclosure prevention)
      "quiet"                         # Reduce boot message output
      "udev.log_level=3"              # udev errors only (minimize boot information disclosure)
      "spec_store_bypass_disable=on"  # Protection against Speculative Store Bypass attacks
      "spectre_v2=on"                 # Protection against Spectre v2 attacks
      "stf_barrier=on"                # Store-to-Load Forwarding barrier for speculative attack protection
    ];
    toAddFiltered = lib.filter (p: !(lib.elem p existing)) toAdd;
  in toAddFiltered ++ existing;

  # Blacklist risky kernel modules by default (can be overridden via rampartKernel.blacklistedKernelModules)
  boot.blacklistedKernelModules = userExtras.blacklistedKernelModules or [
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

  # Merge sysctl defaults with optional overrides (expanded security defaults)
  boot.kernel.sysctl = lib.mkMerge [ (config.boot.kernel.sysctl or {}) (userExtras.kernelSysctl or {
    # Device and filesystem security
    "dev.tty.ldisc_autoload"             = 0;              # Disable automatic TTY line discipline loading
    "fs.binfmt_misc.status"              = 0;              # Disable support for miscellaneous binary formats
    "fs.protected_fifos"                 = 2;              # Maximum protection for FIFOs in sticky directories
    "fs.protected_hardlinks"             = 1;              # Restrict hardlink creation to file owners
    "fs.protected_regular"               = 2;              # Maximum protection for regular files in sticky directories
    "fs.protected_symlinks"              = 1;              # Restrict symlink following to prevent race conditions
    "fs.suid_dumpable"                   = 0;              # Disable core dumps for SUID processes

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
    "net.core.bpf_jit_harden"            = 2;              # Harden BPF JIT runtime (higher security)
    "net.core.bpf_jit_kallsyms"          = 0;              # Disable publishing JIT symbols to kallsyms
    "kernel.yama.ptrace_scope"           = 2;              # Maximum ptrace restrictions - admin only
  }) ];

  # Security defaults
  security.lockKernelModules = lib.mkForce (userExtras.lockKernelModules or true);
  security.protectKernelImage = lib.mkForce (userExtras.protectKernelImage or true);
  security.unprivilegedUsernsClone = lib.mkForce (userExtras.unprivilegedUsernsClone or false);
}
