
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
      $rpm_packages = ['kmod', 'iptables-services', 'perf', 'openscap-scanner', 'scap-security-guide', 'which' ]
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

      $deb_packages = ['apt-transport-https', 'apt-utils', 'dpkg', 'libc-bin', 'kmod', 'iptables', 'iptables-persistent', 'libopenscap8', 'ifupdown2' ]
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

  class { '::resolvconf':
    nameservers => ['8.8.8.8', '8.8.4.4'],
    domains     => ['domain.tld', 'sub.domain.tld'],
  }

  # no user option for puppetlabs/ntp
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

  class { 'os_hardening':
    umask => "077",
    password_max_age => 182,
    password_min_age => 0,
    password_warn_age => 30,
  }

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
# https://unix.stackexchange.com/questions/103218/add-year-to-entries-generated-by-rsyslogd
# https://github.com/rsyslog/rsyslog/issues/65
    templates        => {
        'FullTimeFormat' => {
            'type'   => string,
            'string' => '"%timestamp:::date-year%-%timestamp:::date-month%-%timestamp:::date-day% %timestamp:::date-hour%:%timestamp:::date-minute%:%timestamp:::date-second% %timestamp:::date-tzoffsdirection%%timestamp:::date-tzoffshour%:%timestamp:::date-tzoffsmin% %HOSTNAME% %syslogtag% %msg%"'
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
#            value   => "@@remotelogserver.name;FullTimeFormat",
#            value   => "@@remotelogserver.name;RSYSLOG_SyslogProtocol23Format",
#         }
    },
# https://www.rsyslog.com/doc/v8-stable/tutorials/reliable_forwarding.html
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/s1-working_with_queues_in_rsyslog
    rulesets    => {
        remotesyslog => {
            parameters => {
                'queue.filename' => 'QueueRemote',
                'queue.type' => 'LinkedList',
                'queue.spoolDirectory' => "/var/log/rsyslog/queue",
                'queue.size' => 10000,
                'queue.maxdiskspace' => '1000G',
                'queue.timeoutqueue' => 3,
                'queue.dequeuebatchsize' => 1000,
                'queue.saveonshutdown' => 'on',
                'queue.timeoutenqueue' => 0,
                'action.resumeRetryCount' => -1,
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
  class { 'postfix':
    #inetinterfaces    => 'all',
    inetinterfaces    => 'loopback-only',
    mynetworks        => [ '127.0.0.1/32' ],
    myhostname        => 'smtp3.systemadmin.es',
    smtpdbanner       => 'smtp3.systemadmin.es ESMTP',
    opportunistictls  => true,
    subjectselfsigned => '/C=UK/ST=Shropshire/L=Telford/O=systemadmin/CN=smtp3.systemadmin.es',
    generatecert      => true,
    syslog_name       => 'private',
    # smarthost
    relayhost => '1.2.3.4',
  },
  postfix::instance { 'smtp':
    chroot            => 'y',
    opts    => {
      'content_filter'               => '',
      'smtpd_helo_restrictions'      => 'permit_mynetworks,reject_non_fqdn_helo_hostname,reject_invalid_helo_hostname,permit',
      'smtpd_sender_restrictions'    => 'permit_mynetworks,reject_non_fqdn_sender,reject_unknown_sender_domain,permit',
      'smtpd_recipient_restrictions' => 'permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination,reject_unknown_recipient_domain,reject_rbl_client cbl.abuseat.org, reject_rbl_client b.barracudacentral.org,reject',
      'mynetworks'                   => '127.0.0.0/8,10.0.2.15/32',
      'receive_override_options'     => 'no_header_body_checks',
      'smtpd_helo_required'          => 'yes',
      'smtpd_client_restrictions'    => '',
      'smtpd_restriction_classes'    => '',
      'disable_vrfy_command'         => 'yes',
      #'strict_rfc821_envelopes'      => 'yes',
      'smtpd_sasl_auth_enable'       => 'yes',
      'smtp_sasl_security_options'   => 'noanonymous',
      #'smtp_sasl_password_maps'      => 'hash:/etc/postfix/smarthost_passwd',
      'syslog_name'                   => 'public',
      'biff'                          => 'no',
      'append_dot_mydomain'           => 'no',
      'default_process_limit'         => 100,
      'smtpd_client_connection_count_limit' => 100,
      'smtpd_client_connection_rate_limit'  => 100,
      'queue_minfree'                 => 20971520,
      'header_size_limit'             => 51200,
      'message_size_limit'            => 10485760,
      'smtpd_recipient_limit'         => 10,
      'smtpd_delay_reject'            => 'yes',
      # https://isc.sans.edu/forums/diary/Hardening+Postfix+Against+FTP+Relay+Attacks/22086/
      'smtpd_forbidden_commands'      => 'CONNECT,GET,POST,USER,PASS',
      # https://cipherli.st/
      'smtp_use_tls'                  => 'yes',
      'smtpd_use_tls'                 => 'yes',
      'smtpd_tls_security_level'      => 'may',
      'smtpd_tls_auth_only'           => 'yes',
      #'smtpd_tls_cert_file'           => '',
      #'smtpd_tls_key_file'            => '',
      'smtpd_tls_session_cache_database' => 'btree:${data_directory}/smtpd_scache',
      'smtpd_tls_mandatory_protocols' => '!SSLv2,!SSLv3,!TLSv1,!TLSv1.1',
      'smtpd_tls_protocols'           => '!SSLv2,!SSLv3,!TLSv1,!TLSv1.1',
      'smtpd_tls_mandatory_ciphers'   => 'medium',
      'tls_medium_cipherlist'         => 'AES128+EECDH:AES128+EDH',
      # https://marc.info/?l=postfix-users&m=140058464921413&w=2
      # https://marc.info/?l=postfix-users&m=140059435225323&w=2
      #if it is *not* a public MX
      'smtpd_tls_exclude_ciphers'      => 'aNULL, eNULL, EXP, MD5, IDEA, KRB5, RC2, SEED, SRP',
      #'smtp_tls_exclude_ciphers'       => 'EXPORT, LOW',
      },
  }

  class { 'postfix::vmail': }

# suggested, RFC2142. TODO: alias to your context
  postfix::vmail::alias { 'webmaster':
    aliasto => [ 'root' ],
  }
  postfix::vmail::alias { 'support':
    aliasto => [ 'root' ],
  }
  postfix::vmail::alias { 'noc':
    aliasto => [ 'root' ],
  }
  postfix::vmail::alias { 'abuse':
    aliasto => [ 'root' ],
  }
  postfix::vmail::alias { 'security':
    aliasto => [ 'root' ],
  }
  postfix::vmail::alias { 'soc':
    aliasto => [ 'root' ],
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
      export HISTSIZE=5000
      export HISTTIMEFORMAT=\"%a %b %Y %T %z\"
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
if !$facts['hypervisors']['docker'] {
  Firewall {
    require => undef,
  }
   # Default firewall rules
  firewall { '001 accept all to lo interface':
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept',
  }->
  firewall { '002 accept all from lo interface':
    chain    => 'OUTPUT',
    proto   => 'all',
    outiface => 'lo',
    action  => 'accept',
  }->
  firewall { '003 reject local traffic not on loopback interface':
    iniface     => '! lo',
    proto       => 'all',
    source      => '127.0.0.0/8',
    action      => 'drop',
  }->
  firewall { '004 accept related established rules':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }
}
}

class my_fw::post {
if !$facts['hypervisors']['docker'] {
  firewall { '999 drop all':
    proto  => 'all',
    action => 'drop',
    before => undef,
  }
}
}

class { ['my_fw::pre', 'my_fw::post']: }

if !$facts['hypervisors']['docker'] {
resources { 'firewall':
  purge => true,
}
Firewall {
  before  => Class['my_fw::post'],
  require => Class['my_fw::pre'],
}
firewall { '005 Allow outbound and established (v4)':
  chain    => 'OUTPUT',
  proto    => [ tcp, udp, icmp ],
  state    => ['NEW', 'ESTABLISHED'],
  action   => accept,
  provider => 'iptables',
}
firewall { '005 Allow inbound and established (v4)':
  chain    => 'INPUT',
  proto    => [ tcp, udp, icmp ],
  state    => ['ESTABLISHED'],
  action   => accept,
  provider => 'iptables',
}
firewall { '006 Allow inbound SSH (v4)':
  chain      => 'INPUT',
  dport    => 22,
  proto    => tcp,
  source   => [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
  ],
  action   => accept,
  provider => 'iptables',
}
# FIXME! above rule only applied to 10/8 so adding another to match inspec check
firewall { '006 Allow inbound SSH (v4)b':
  chain    => 'INPUT',
  dport    => 22,
  proto    => tcp,
  source   => '192.168.0.0/16',
  action   => accept,
  provider => 'iptables',
}
firewall { '006 Allow inbound SSH (v6)':
  chain    => 'INPUT',
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
  ctstate    => ['ESTABLISHED', 'RELATED'],
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
  ctstate    => ['ESTABLISHED', 'RELATED'],
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
firewall { '102 allow smtp access - OUT':
  chain  => 'OUTPUT',
  dport  => 25,
  proto  => tcp,
  action => accept,
}
firewall { '110 allow http and https access - OUT':
  chain  => 'OUTPUT',
  dport  => [80, 443],
  proto  => tcp,
  action => accept,
}
} # if !$facts['hypervisors']['docker']
