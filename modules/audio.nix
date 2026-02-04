{ config, pkgs, lib, ... }:

{
  # Audio System Module - PipeWire Configuration
  # Modern, secure audio/video server for hardened systems
  #
  # Why PipeWire over PulseAudio:
  # - Native sandboxing support (Flatpak/Snap via portals)
  # - Granular per-object permissions (READ/WRITE/EXECUTE/METADATA)
  # - Data isolation using memfd/DMA-BUF
  # - Per-user instances (no system-wide daemon)
  # - Modern security architecture designed from ground up
  # - Portal-based access control for sandboxed applications
  # - PulseAudio/JACK/ALSA compatibility layers
  #
  # Security Improvements over PulseAudio:
  # 1. Portal Integration: Sandboxed apps connect via XDG portal
  # 2. Permission Model: Fine-grained object-level permissions
  # 3. Data Isolation: Clients cannot access each other's data
  # 4. No System-Wide Mode: Each user has isolated instance
  # 5. Modern Codebase: Built with security-first design
  #
  # Key CVEs in PulseAudio (avoided by using PipeWire):
  # - CVE-2014-3970: Remote DoS vulnerability
  # - CVE-2018-11410: Buffer overflow in RTP module
  # - CVE-2020-16123: Use-after-free vulnerability
  # - Weak DES encryption in network audio (1970s algorithm!)
  #
  # Official Documentation:
  # - https://docs.pipewire.org/
  # - https://gitlab.freedesktop.org/pipewire/pipewire
  #
  # NixOS Manual:
  # - https://nixos.org/manual/nixos/stable/options.html#opt-services.pipewire.enable

  # Disable legacy PulseAudio server
  # PipeWire provides full PulseAudio compatibility via pipewire-pulse
  services.pulseaudio.enable = false;

  # Enable RealtimeKit for low-latency audio
  # Allows PipeWire to acquire realtime scheduling priority
  # This is essential for professional audio and low-latency playback
  security.rtkit.enable = true;

  # PipeWire Audio Server Configuration
  services.pipewire = {
    enable = true;

    # Socket activation (recommended)
    # PipeWire starts automatically when audio is needed
    socketActivation = true;

    # Per-user instances (SECURITY: do not enable system-wide mode)
    # Each user gets their own isolated PipeWire instance
    # System-wide mode is NOT RECOMMENDED by PipeWire developers
    # See: https://github.com/PipeWire/pipewire/blob/master/NEWS
    systemWide = false;

    # ALSA compatibility layer
    # Allows legacy ALSA applications to work with PipeWire
    alsa = {
      enable = true;
      support32Bit = true;  # Enable for 32-bit games/applications
    };

    # PulseAudio compatibility layer
    # Provides drop-in replacement for PulseAudio with PipeWire security
    # All PulseAudio applications work transparently
    pulse.enable = true;

    # JACK compatibility layer (professional audio)
    # Uncomment if you use JACK-based audio production software
    # Examples: Ardour, Reaper, Bitwig Studio, Carla
    # jack.enable = true;

    # WirePlumber session manager
    # Handles device management, routing, and policies
    wireplumber = {
      enable = true;

      # Extra configuration for WirePlumber (optional)
      # extraConfig = {
      #   # Example: Disable camera support if not needed (reduces attack surface)
      #   "10-disable-camera" = {
      #     "wireplumber.profiles" = {
      #       main = {
      #         "monitor.libcamera" = "disabled";
      #       };
      #     };
      #   };
      # };
    };

    # Audio configuration (main PipeWire server)
    extraConfig.pipewire = {
      # Security: Reduce buffer sizes for lower latency
      # Lower values = lower latency but higher CPU usage
      # Adjust based on your hardware capabilities
      "10-clock-rate" = {
        "context.properties" = {
          # Sample rate (44100 or 48000 are standard)
          "default.clock.rate" = 48000;
          
          # Allowed sample rates (PipeWire will resample if needed)
          "default.clock.allowed-rates" = [ 44100 48000 88200 96000 ];
          
          # Quantum (buffer size in samples)
          # Lower = less latency, higher CPU
          # 1024/48000 = ~21ms latency (good balance)
          "default.clock.quantum" = 1024;
          "default.clock.min-quantum" = 256;
          "default.clock.max-quantum" = 2048;
        };
      };

      # Disable network audio module (SECURITY)
      # Network audio increases attack surface
      # Uncomment to disable (recommended for hardened systems)
      # "20-disable-network" = {
      #   "context.modules" = [
      #     { name = "libpipewire-module-raop-discover"; flags = [ "nofail" ]; }
      #     { name = "libpipewire-module-rtp-sink"; flags = [ "nofail" ]; }
      #     { name = "libpipewire-module-rtp-source"; flags = [ "nofail" ]; }
      #   ];
      # };
    };

    # PulseAudio compatibility configuration
    extraConfig.pipewire-pulse = {
      # PulseAudio-specific tweaks
      "10-pulse-config" = {
        "pulse.properties" = {
          # Enable echo cancellation (useful for video calls)
          # "pulse.echo-cancel" = true;
        };
        "stream.properties" = {
          # Resample quality (0-14, higher = better quality but more CPU)
          # 4 = medium quality, good balance
          "resample.quality" = 4;
        };
      };
    };

    # JACK compatibility configuration (if enabled)
    # extraConfig.jack = {
    #   "10-jack-config" = {
    #     "jack.properties" = {
    #       # JACK-specific settings
    #     };
    #   };
    # };
  };

  # Firewall configuration for network audio (if needed)
  # RAOP/Airplay requires specific ports
  # Disabled by default for security
  # services.pipewire.raopOpenFirewall = false;

}
