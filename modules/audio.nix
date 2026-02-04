{ config, pkgs, lib, ... }:

{
  # Audio System Module - PipeWire Configuration
  # Modern, secure audio/video server for hardened systems

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
  };
}
