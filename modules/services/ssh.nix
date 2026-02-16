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
    #   X11Forwarding = false;                     # Disable X11/Wayland forwarding
      MaxAuthTries = 3;                            # Maximum authentication attempts
    #   PubkeyAuthentication = true;               # Enable public key authentication
    #   AuthenticationMethods = "publickey";       # Only public key auth allowed
      LogLevel = "VERBOSE";                        # Detailed logging
    #   UsePAM = true;                             # Use PAM for authentication
    #   AllowUsers = [ ];                          # Specify allowed users (empty = all)
    #   DenyUsers = [ ];                           # Specify denied users
    #   AllowGroups = [ ];                         # Specify allowed groups
    #   DenyGroups = [ ];                          # Specify denied groups
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

    # Host keys (automatically generated if not specified)
    # hostKeys = [
    #   {
    #     path = "/etc/ssh/ssh_host_ed25519_key";
    #     type = "ed25519";
    #   }
    #   {
    #     path = "/etc/ssh/ssh_host_rsa_key";
    #     type = "rsa";
    #     bits = 4096;
    #   }
    # ];

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
