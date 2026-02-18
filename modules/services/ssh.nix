{ config, pkgs, ... }:

{
  # SSH server configuration
  # Currently disabled for security - enable only if remote access is needed

  services.openssh = {
    enable = false;  # Set to true to enable SSH server
    # Security settings (apply when enabled)
    settings = {
      PermitRootLogin = "no";                      # Disable root login via SSH
      PasswordAuthentication = false;              # Only SSH keys, no passwords
      KbdInteractiveAuthentication = false;        # Disable keyboard-interactive auth
      X11Forwarding = false;                       # Disable X11/Wayland forwarding
      MaxAuthTries = 3;                            # Maximum authentication attempts
      MaxSessions = 2;                             # Limit concurrent sessions per connection
      PubkeyAuthentication = true;                 # Enable public key authentication
      AuthenticationMethods = "publickey";         # Only public key auth allowed
      LogLevel = "VERBOSE";                        # Detailed logging
    #   UsePAM = true;                             # Use PAM for authentication
    #   AllowUsers = [ ];                          # Specify allowed users (empty = all)
    #   DenyUsers = [ ];                           # Specify denied users
    #   AllowGroups = [ ];                         # Specify allowed groups
    #   DenyGroups = [ ];                          # Specify denied groups
      StrictModes = true;                          # Check file permissions for security

      # Security hardening: disable unnecessary features
      AllowTcpForwarding = false;
      PermitTunnel = false;
      AllowAgentForwarding = false;

      # Session timeouts: automatically close inactive connections
      ClientAliveInterval = 300;                   # 5 minutes
      ClientAliveCountMax = 0;                     # Disconnect immediately if client is unresponsive
      TCPKeepAlive = false;

      # Only Encrypt-then-MAC (EtM) to prevent side-channel attacks (Lucky Thirteen)
      Macs = [
        "hmac-sha2-512-etm@openssh.com"
        "hmac-sha2-256-etm@openssh.com"
        "umac-128-etm@openssh.com"
      ];

      # Only Authenticated Encryption (AEAD) ciphers
      Ciphers = [
        "chacha20-poly1305@openssh.com"
        "aes256-gcm@openssh.com"
        "aes128-gcm@openssh.com"
      ];

      # Post-Quantum (PQ) and modern Elliptic Curve (EC) key exchange algorithms
      KexAlgorithms = [
        "mlkem768x25519-sha256"               # NIST ML-KEM post-quantum hybrid
        "sntrup761x25519-sha512@openssh.com"  # NTRU Prime post-quantum hybrid
        "curve25519-sha256"                   # Standard Ed25519
        "curve25519-sha256@libssh.org"
      ];
    };

    # Port configuration (default is 22)
    # ports = [ 22 ];

    # Listen addresses (default is all interfaces)
    # listenAddresses = [
    #   {
    #     addr = "0.0.0.0";
    #     port = 22;
    #   }
    # ];

    # Host keys - using only modern Ed25519
    hostKeys = [
      {
        path = "/etc/ssh/ssh_host_ed25519_key";
        type = "ed25519";
      }
    ];

    # Banner (message displayed before login)
    # banner = ''
    #   Unauthorized access is prohibited.
    #   All connections are logged and monitored.
    # '';
  };

  # Firewall configuration for SSH (when enabled)
  # networking.firewall.allowedTCPPorts = [ 22 ];

  # Fail2ban integration (optional, for SSH protection)
  # services.fail2ban = {
  #   enable = true;
  #   jails.ssh-iptables.settings = {
  #     enabled = true;
  #     filter = "sshd";
  #     action = "iptables[name=SSH, port=22, protocol=tcp]";
  #     maxretry = 3;
  #     findtime = 600;
  #     bantime = 3600;
  #   };
  # };
}
