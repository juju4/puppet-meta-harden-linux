
  $pkgs_upgradeall = false
  $cbc_required          = false
  $weak_hmac             = false
  $weak_kex              = false
  $ports                 = [ 22 ]
  $listen_to             = [ '0.0.0.0' ]
  $host_key_files        = [
    '/etc/ssh/ssh_host_rsa_key',
#    '/etc/ssh/ssh_host_dsa_key',
    '/etc/ssh/ssh_host_ecdsa_key',
    '/etc/ssh/ssh_host_ed25519_key',
    ]
  $client_alive_interval = 300
  $client_alive_count    = 3
  $allow_root_with_key   = false
  $ipv6_enabled          = false
  $use_pam               = false
  $allow_tcp_forwarding   = false
  $allow_agent_forwarding = false
  $max_auth_retries       = 2
  $server_options         = {
    'UsePrivilegeSeparation'    => 'sandbox',
    'KexAlgorithms'             => 'curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256',
    'Ciphers'                   => 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr',
#    'MACs'                      => 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256',
# for vagrant
    'MACs'                      => 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com',
    'Banner'                    => '',
#    'UseRoaming'                => 'no',   # deprecated
  }
  $client_options         = {
    'KexAlgorithms'             => 'curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256',
    'Ciphers'                   => 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr',
    'MACs'                      => 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256',
    'UseRoaming'                => 'no',
  }

  case $facts['os']['name'] {
#    'Solaris':           { include role::solaris } # Apply the solaris class
    'RedHat', 'CentOS':  {

      $bashrc = '/etc/bashrc'
      $user_sudogroups = [
        'wheel',
      ]

      # kmod required for /etc/modprobe.d
      $rpm_packages = ['kmod', 'iptables-services', 'perf', 'openscap-scanner', 'scap-security-guide' ]
      $rpm_packages.each |String $pkg| {
        package { "${pkg}":
          provider => 'yum',
          ensure   => 'present',
        }
      }

      $rpm_remove = ['quota', 'nfs-utils', 'rpcbind' ]
      $rpm_remove.each |String $pkg| {
        package { "${pkg}":
          provider => 'yum',
          ensure   => 'present',
        }
      }

      if $pkgs_upgradeall {
        exec { "yum-update":
          command => "yum clean all; yum -q -y update --exclude cvs; rm -rf /var/tmp/forceyum",
          path        => ['/bin', '/usr/bin', '/usr/sbin'],
          timeout => 1800,
#          onlyif => "/usr/bin/test `/bin/date +%d` -eq 06 && test `/bin/date +%H` -eq 11 || test -e /var/tmp/forceyum",
        }
      }

      # sshd-48: Verifies if strong DH primes are used in /etc/ssh/moduli
      exec { "ssh-moduli-cleaning":
          # just remove weak ones
          command => "awk '\$5 >= 2000' /etc/ssh/moduli > /etc/ssh/moduli.strong && mv /etc/ssh/moduli.strong /etc/ssh/moduli",
          # re-generate. much longer
          #command => "ssh-keygen -G /etc/ssh/moduli.all -b 4096 && ssh-keygen -T /etc/ssh/moduli.safe -f /etc/ssh/moduli.all && mv /etc/ssh/moduli.safe /etc/ssh/moduli"
          path        => ['/bin', '/usr/bin', '/usr/sbin'],
          timeout => 1800,
          onlyif => "/usr/bin/test $(awk '$5 < 2047 && $5 ~ /^[0-9]+$/ { print $5 }' /etc/ssh/moduli | uniq | wc -c) == 0",
      }

      class { 'epel': }
#      class { 'rkhunter': }

    }
    /^(Debian|Ubuntu)$/: {

      $bashrc = '/etc/bash.bashrc'
      $user_sudogroups = [
        'sudo',
      ]

      $deb_packages = ['apt-transport-https', 'apt-utils', 'dpkg', 'libc-bin', 'kmod', 'iptables-persistent', 'libopenscap8' ]
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

  class { ‘::resolvconf’:
    nameservers => [‘8.8.8.8’, ‘8.8.4.4’],
    domains     => [‘domain.tld’, ‘sub.domain.tld’],
  }

  # no user option for puppetlabs/ntp
  include ntp
  class { 'ntp':
    servers   => ['pool.ntp.org'],
    restrict  => [
      'default ignore',
      '-6 default ignore',
      '127.0.0.1',
      '-6 ::1',
      'pool.ntp.org nomodify notrap nopeer noquery',
    ],
  }
  class { 'fail2ban': }
  class { 'osquery': }

  class { 'os_hardening': }

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
#    max_auth_retries       => $max_auth_retries,
    options                => $server_options,
  }
  class { 'ssh_hardening::client':
    ipv6_enabled => $ipv6_enabled,
    ports        => $ports,
    cbc_required => $cbc_required,
    weak_hmac    => $weak_hmac,
    weak_kex     => $weak_kex,
    options      => $client_options,
  }

#    class { '::cisecurity': }

#  include ::auditd

  # FIXME! missing ActionResumeRetryCount, ActionQueueTimeoutEnqueue, ActionQueueSaveOnShutdown
  class { 'rsyslog::server':
    global_config   => {
        'umask' => {
            'value' => '0022',
            'type' => legacy,
            'priority' => 01,
        },
        'PrivDropToUser' => {
            'value' => 'syslog',
            'type' => legacy,
        },
        'PrivDropToGroup' => {
            'value' => 'syslog',
            'type' => legacy,
        },
        'workDirectory' => {
            'value' => '/var/spool/rsyslog',
        },
        'maxMessageSize' => {
            'value' => '64k',
        }
    },
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

  # mailserver
  class { '::smarthost' :
    smarthost   => 'mail.yourprovider.com',
    domain      => 'yourdomain.com',
    mta         => postfix,
  }

  file { '/etc/profile.d/security':
    ensure => present,
    #source => 'file:///tmp/kitchen/files/profile.erb',
    content => "### PUPPET MANAGED BLOCK: bash settings ###
      readonly TMOUT=3600
      export HISTCONTROL=
      export HISTFILE=\$HOME/.bash_history
      export HISTFILESIZE=5000
      export HISTIGNORE=
      export HISTSIZE=3000
      export HISTTIMEFORMAT=\"%a %b %Y %T %z \"
      if [ \"X\$SHELL\" = '/bin/bash' ]; then
        typeset -r HISTCONTROL
        typeset -r HISTFILE
        typeset -r HISTFILESIZE
        typeset -r HISTIGNORE
        typeset -r HISTSIZE
        typeset -r HISTTIMEFORMAT
      fi",
  }
  file_line { 'bashrc-TMOUT':
    path => $bashrc,
    line => 'readonly TMOUT=3600',
  }
  $bash_settings = ['HISTCONTROL=', 'HISTFILE=$HOME/.bash_history', 'HISTFILESIZE=5000', 'HISTIGNORE=', 'HISTSIZE=3000', 'HISTTIMEFORMAT="%a %b %Y %T %z "' ]
  $bash_settings.each |String $line| {
    file_line { "bashrc-${line}":
      path => $bashrc,
      line => "typeset -r ${line}",
    }
  }
  file_line { 'bashrc-PS1':
    path => $bashrc,
    line => 'export PS1="[\A] \u@\h {\W}\\$ "',
  }

  accounts::user { 'jeff':
    comment => 'Jeff McCune',
    groups  => $user_sudogroups,
    uid     => '1112',
    gid     => '1112',
    sshkeys => [
      'ssh-rsa AAAAB3Nza...== jeff@puppetlabs.com',
      'ssh-dss AAAAB3Nza...== jeff@metamachine.net',
    ],
  }

# Firewall
class my_fw::pre {
  Firewall {
    require => undef,
  }
   # Default firewall rules
  firewall { '000 accept all icmp':
    proto  => 'icmp',
    action => 'accept',
  }->
  firewall { '001 accept all to lo interface':
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept',
  }->
  firewall { '002 reject local traffic not on loopback interface':
    iniface     => '! lo',
    proto       => 'all',
    destination => '127.0.0.1/8',
    action      => 'reject',
  }->
  firewall { '003 accept related established rules':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }
}

class my_fw::post {
  firewall { '999 drop all':
    proto  => 'all',
    action => 'drop',
    before => undef,
  }
}

resources { 'firewall':
  purge => true,
}

firewall { '006 Allow inbound SSH (v4)':
  chain      => 'INPUT',
  dport    => 22,
  proto    => tcp,
  source => [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
  ],
  action   => accept,
  provider => 'iptables',
}
firewall { '006 Allow inbound SSH (v6)':
  chain      => 'INPUT',
  dport    => 22,
  proto    => tcp,
  action   => accept,
  provider => 'ip6tables',
}
firewall { '010 Allow icmp echo - IN':
  chain      => 'INPUT',
  proto      => icmp,
  icmp       => 8,
  action     => accept,
  ctstate    => ['NEW', 'ESTABLISHED', 'RELATED'],
}
firewall { '011 Allow icmp net unreachable- IN':
  chain      => 'INPUT',
  proto      => icmp,
  icmp       => 0,
  action     => accept,
  ctstate    => ['NEW', 'ESTABLISHED', 'RELATED'],
}
firewall { '012 Allow icmp echo - OUT':
  chain      => 'OUTPUT',
  proto      => icmp,
  icmp       => 8,
  action     => accept,
  ctstate    => ['NEW', 'ESTABLISHED', 'RELATED'],
}
firewall { '011 Allow icmp net unreachable - OUT':
  chain      => 'OUTPUT',
  proto      => icmp,
  icmp       => 0,
  action     => accept,
  ctstate    => ['NEW', 'ESTABLISHED', 'RELATED'],
}
firewall { '011 Allow icmp destination unreachable - OUT':
  chain      => 'OUTPUT',
  proto      => icmp,
  icmp       => 3,
  action     => accept,
  ctstate    => ['NEW', 'ESTABLISHED', 'RELATED'],
}
firewall { '100 allow dns access - OUT':
  chain  => 'OUTPUT',
  dport  => 53,
  proto  => [tcp, udp],
  action => accept,
}
firewall { '101 allow ntp access - OUT':
  chain  => 'OUTPUT',
  dport  => 123,
  proto  => udp,
  action => accept,
}
firewall { '110 allow http and https access - OUT':
  chain  => 'OUTPUT',
  dport  => [80, 443],
  proto  => tcp,
  action => accept,
}

## tomcat
firewall { '051 Allow http traffic - IN':
  chain      => 'INPUT',
  dport    => 80,
  proto    => tcp,
# TODO: safety-net, default only allow LAN access. Customize to your context
  source => [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
  ],
  action   => accept,
  provider => 'iptables',
}
firewall { '052 Allow https traffic - IN':
  chain      => 'INPUT',
  dport    => 443,
  proto    => tcp,
# TODO: safety-net, default only allow LAN access. Customize to your context
  source => [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
  ],
  action   => accept,
  provider => 'iptables',
}
