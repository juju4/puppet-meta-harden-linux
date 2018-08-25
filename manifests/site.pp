
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

      $user_sudogroups = [
        'wheel',
      ]

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

      $user_sudogroups = [
        'sudo',
      ]

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

  # no user option for puppetlabs/ntp
  include ntp
  class { 'fail2ban': }
  class { 'osquery': }

  # FIXME! missing ActionResumeRetryCount, ActionQueueTimeoutEnqueue, ActionQueueSaveOnShutdown
  class { 'rsyslog::server':
    global_config   => {
        umask => {
            value => '0022',
            type => legacy,
            priority => 01,
        },
#        PrivDropToUser => {
#            value => 'syslog',
#            type => legacy,
#        },
#        PrivDropToGroup => {
#            value => 'syslog',
#            type => legacy,
#        },
        workDirectory => {
            value => '/var/spool/rsyslog',
        },
        maxMessageSize => {
            value => '64k',
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
  class { 'postfix':
    inetinterfaces    => 'all',
    mynetworks        => [ '127.0.0.1/32' ],
    myhostname        => 'smtp3.systemadmin.es',
    smtpdbanner       => 'smtp3.systemadmin.es ESMTP',
    opportunistictls  => true,
    subjectselfsigned => '/C=UK/ST=Shropshire/L=Telford/O=systemadmin/CN=smtp3.systemadmin.es',
    generatecert      => true,
    syslog_name       => 'private',
  }

  class { 'postfix::vmail': }
  postfix::vmail::account { 'systemadmin@systemadmin.es':
    accountname => 'systemadmin',
    domain      => 'systemadmin.com',
    password    => 'systemadmin_secret_passw0rd',
  }

  postfix::instance { '0.0.0.0:2525':
    type    => 'inet',
    private => 'n',
    chroot  => 'n',
    command => 'smtpd',
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
                'smtpd_sasl_auth_enable'       => 'no',
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
                'smtpd_helo_required'           => 'yes',
                # https://isc.sans.edu/forums/diary/Hardening+Postfix+Against+FTP+Relay+Attacks/22086/
                'smtpd_forbidden_commands'      => 'CONNECT,GET,POST,USER,PASS',
                # https://cipherli.st/
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
                #'smtpd_tls_exclude_ciphers'      => 'aNULL, eNULL, EXP, MD5, IDEA, KRB5, RC2, SEED, SRP',
                'smtp_tls_exclude_ciphers'       => 'EXPORT, LOW',
              },
    order   => '99',
  }
  # suggested, RFC2142
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
  class { '::smarthost' :
    smarthost   => 'mail.yourprovider.com',
    domain      => 'yourdomain.com',
    mta         => postfix,
  }

  file { '/etc/profile.d/security':
    ensure => present,
    source => 'file:///tmp/kitchen/files/profile.erb',
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
