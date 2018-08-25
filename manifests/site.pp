
  class { 'os_hardening': }
#  class { 'ssh_hardening::server': }
#  class { 'ssh_hardening::client': }

  class ssh_hardening(
    $cbc_required          = false,
    $weak_hmac             = false,
    $weak_kex              = false,
    $ports                 = [ 22 ],
    $listen_to             = [],
    $host_key_files        = [
      '/etc/ssh/ssh_host_rsa_key',
      '/etc/ssh/ssh_host_dsa_key',
      '/etc/ssh/ssh_host_ecdsa_key'
      ],
    $client_alive_interval = 600,
    $client_alive_count    = 3,
    $allow_root_with_key   = false,
    $ipv6_enabled          = false,
    $use_pam               = false,
    $allow_tcp_forwarding   = false,
    $allow_agent_forwarding = false,
    $max_auth_retries       = 2,
    $server_options         = {},
    $client_options         = {},
  ) {
    class { 'ssh_hardening::server':
      cbc_required           => $cbc_required,
      weak_hmac              => $weak_hmac,
      weak_kex               => $weak_kex,
      ports                  => $ports,
      listen_to              => $listen_to,
      host_key_files         => $host_key_files,
      client_alive_interval  => $client_alive_interval,
      client_alive_count     => $client_alive_count,
      allow_root_with_key    => $allow_root_with_key,
      ipv6_enabled           => $ipv6_enabled,
      use_pam                => $use_pam,
      allow_tcp_forwarding   => $allow_tcp_forwarding,
      allow_agent_forwarding => $allow_agent_forwarding,
      max_auth_retries       => $max_auth_retries,
      options                => $server_options,
      protocol               => 2,
    }
    class { 'ssh_hardening::client':
      ipv6_enabled => $ipv6_enabled,
      ports        => $ports,
      cbc_required => $cbc_required,
      weak_hmac    => $weak_hmac,
      weak_kex     => $weak_kex,
      options      => $client_options,
    }
  }

#    class { '::cisecurity': }

#  include ::auditd
  include ntp
  class { 'epel': }
  class { 'fail2ban': }
  class { 'osquery': }

  case $facts['os']['name'] {
#    'Solaris':           { include role::solaris } # Apply the solaris class
    'RedHat', 'CentOS':  {
      class { 'rkhunter': }
    }
#    /^(Debian|Ubuntu)$/: { include role::debian  } # Apply the debian class
#    default:             { include role::generic } # Apply the generic class
  }