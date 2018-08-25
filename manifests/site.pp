
  $pkgs_upgradeall = false

  case $facts['os']['name'] {
#    'Solaris':           { include role::solaris } # Apply the solaris class
    'RedHat', 'CentOS':  {

      # required for /etc/modprobe.d
      package { 'kmod':
        provider => 'yum',
        ensure   => 'present',
      }

      if $pkgs_upgradeall {
        exec { "yum-update":
          command => "yum clean all; yum -q -y update --exclude cvs; rm -rf /var/tmp/forceyum",
          path        => ['/bin', '/usr/bin', '/usr/sbin'],
          timeout => 1800,
#          onlyif => "/usr/bin/test `/bin/date +%d` -eq 06 && test `/bin/date +%H` -eq 11 || test -e /var/tmp/forceyum",
        }
      }

      class { 'epel': }
#      class { 'rkhunter': }

    }
    /^(Debian|Ubuntu)$/: {

      $deb_packages = ['apt-transport-https', 'apt-utils', 'dpkg', 'libc-bin', 'kmod' ]
      $deb_packages.each |String $pkg| {
        package { "${pkg}":
          provider => 'apt',
          ensure   => 'present',
        }
      }

      if $pkgs_upgradeall {
        exec { "apt-update":
          command => "apt-get -qy clean; apt-get -qy update; apt-get -qy -o 'Dpkg::Options::=--force-confdef' -o 'Dpkg::Options::=--force-confold' upgrade",
          environment => [ "DEBIAN_FRONTEND=noninteractive" ],
          path        => ['/bin', '/usr/bin', '/usr/sbin', '/sbin' ],
          timeout => 1800,
        }
      }

    }
#    default:             { include role::generic } # Apply the generic class
  }

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
  class { 'fail2ban': }
  class { 'osquery': }

  # FIXME! missing ActionResumeRetryCount, ActionQueueTimeoutEnqueue, ActionQueueSaveOnShutdown
  class { 'rsyslog::server':
    legacy_config   => {

# RedHat normal setup
#       kern_priv_rule => {
#           key => "kern.*",
#           value => "/dev/console"
#        },
        auth_priv_rule => {
            key => "authpriv.*",
            value => "/var/log/secure",
        },
        messages_rule => {
            key => "*.info;mail.none;authpriv.none;cron.none",
            value => "/var/log/messages",
        },
        mail_rule => {
            key => "mail.*",
            value => "-/var/log/maillog",
        },
        cron_rule => {
            key => "cron.*",
            value => "/var/log/cron",
        },
        emergency_rule => {
            key => "*.emerg",
            value => ":omusrmsg:*",
        },
        spooler_rule => {
            key => "uucp,news.crit",
            value => "/var/log/spooler",
        },
        boot_rule => {
            key => "local7.*",
            value => "/var/log/boot.log",
        },
# remote syslog
#         remotesyslog => {
#            key     => "*.*",
#            value   => "@@remotelogserver.name",
#         }
    },
    rulesets    => {
        remotesyslog => {
            parameters => {
                'queue.type' => 'LinkedList',
                'queue.spoolDirectory' => "/var/log/rsyslog/queue",
                'queue.size' => 10000,
                'queue.maxdiskspace' => '1000G',
                'queue.timeoutqueue' => 3,
                'queue.dequeuebatchsize' => 1000,
                'action.resumeRetryCount' => 100,
            },
            rules      => [
                action => {
                    name    => 'test',
                    facility => "*.*",
                    config => {
                        type    => 'omfwd',
                        target  => 'remotelogserver.local',
                        port    => 514,
                        protocol => 'tcp',
                    },
                }
            ],
        }
    }
  }

  file { '/etc/profile.d/security':
    ensure => present,
    source => 'file:///tmp/kitchen/files/profile.erb',
  }
