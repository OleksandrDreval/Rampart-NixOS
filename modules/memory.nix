{ config, pkgs, lib, ... }:

{
  # Memory allocator configuration
  # GrapheneOS hardened-light provides balance between security and performance
  # Includes zero-on-free, slab canaries, metadata protection, and randomization
  # Performance overhead: approximately 10-15%
  environment.memoryAllocator.provider = lib.mkDefault "graphene-hardened-light";

  # Alternative allocators:
  # "graphene-hardened"  - maximum security, 30-40% performance penalty
  # "scudo"              - Android default, 5-15% overhead
  # "jemalloc"           - best for multi-threaded applications
  # "mimalloc"           - fastest allocator from Microsoft Research
  # "libc"               - standard glibc malloc, not recommended for security

  # Note: Changing allocator may cause instability in some applications.
  # To disable for specific service: systemd.services.<name>.environment.LD_PRELOAD = "";

  # Force Page Table Isolation (Meltdown mitigation)
  # Separates kernel and user page tables to prevent Meltdown attacks
  security.forcePageTableIsolation = lib.mkForce true;

  # Kernel parameters and sysctls related to memory hardening.
  # These options harden allocation, ASLR, and mapping behaviour.
  boot.kernelParams = lib.mkDefault (let
    existing = config.boot.kernelParams or [];
    toAdd = [
      "proc_mem.force_override=ptrace"  # Restrict process memory mapping changes to ptrace workflows
      "init_on_alloc=1"                 # Initialize memory on allocation to prevent data leaks
      "init_on_free=1"                  # Initialize memory on free to protect confidentiality
      "slab_nomerge"                    # Disable slab merging to prevent cross-object leaks
      "slub_debug=FZP"                  # SLUB debugging to detect memory errors
      "page_alloc.shuffle=1"            # Randomize page allocation to complicate exploits
      "page_poison=1"                   # Fill freed memory to prevent data recovery
      "randomize_kstack_offset=on"      # Randomize kernel stack offset to complicate exploitation
      "spec_rstack_overflow=safe-ret"   # AMD RAS return-address-stack overflow protection
      "hardened_usercopy=on"            # Strict validation of usercopy operations
      "vsyscall=none"                   # Disable vsyscall to eliminate predictable memory addresses
      "pti=on"                          # Force Page Table Isolation (Meltdown mitigation)
    ];
  in lib.filter (p: !(lib.elem p existing)) toAdd ++ existing);

  boot.kernel.sysctl = lib.mkDefault (lib.mkMerge [ {
    # Virtual memory and ASLR
    "vm.unprivileged_userfaultfd" = 0;      # Prevent use-after-free via userfaultfd    
    "vm.mmap_min_addr"            = 65536;  # Deny mmap at low addresses (mitigates NULL-deref exploits)

    # Kernel-level ASLR
    "kernel.randomize_va_space"   = 2;      # Full ASLR for all memory regions

    # Stack protection (legacy)
    "kernel.exec-shield"          = 1;      # Stack execution protection
  } ]);
}
