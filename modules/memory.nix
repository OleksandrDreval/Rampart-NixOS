{ config, pkgs, lib, ... }:

{
  # Memory allocator configuration
  # GrapheneOS hardened-light provides balance between security and performance
  # Includes zero-on-free, slab canaries, metadata protection, and randomization
  # Performance overhead: approximately 10-15%
  environment.memoryAllocator.provider = "graphene-hardened-light";

  # Alternative allocators:
  # "graphene-hardened"  - maximum security, 30-40% performance penalty
  # "scudo"              - Android default, 5-15% overhead
  # "jemalloc"           - best for multi-threaded applications
  # "mimalloc"           - fastest allocator from Microsoft Research
  # "libc"               - standard glibc malloc, not recommended for security

  # Note: Changing allocator may cause instability in some applications.
  # To disable for specific service: systemd.services.<name>.environment.LD_PRELOAD = "";
}
