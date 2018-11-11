
# TODO: have minimum two
  $resolvconf_nameservers = ['8.8.8.8', '8.8.4.4']
  $resolvconf_domains = ['domain.tld', 'sub.domain.tld']
# TODO: have minimum three
# https://access.redhat.com/solutions/58025
# https://insights.sei.cmu.edu/sei_blog/2017/04/best-practices-for-ntp-services.html
  $ntp_servers = [ 'pool.ntp.org',
    '0.north-america.pool.ntp.org',
    '1.north-america.pool.ntp.org',
    '0.europe.pool.ntp.org',
    '1.europe.pool.ntp.org',
    '0.asia.pool.ntp.org',
    '1.asia.pool.ntp.org'
    ]
  $ntp_restrict = [
      'default ignore',
      '-6 default ignore',
      '127.0.0.1',
      '-6 ::1',
    ]
  $logrotate_days = 90
  $syslog_remotehost = 'remotelogserver.name'
  $syslog_remoteport = 514
  $syslog_dest = "@@${syslog_remotehost}:${syslog_remoteport}"
  #$syslog_dest = '/var/log/custom.log'
  $postfix_myhostname = 'smtp3.systemadmin.es'
  $postfix_selfsignedcert = '/C=UK/ST=Shropshire/L=Telford/O=systemadmin/CN=smtp3.systemadmin.es'
  $postfix_relayhost = '1.2.3.4'
  $postfix_alias_webmaster = [ 'root' ]
  $postfix_alias_noc = [ 'root' ]
  $postfix_alias_security = [ 'root' ]

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
  $my_sysctl_settings = {
    'kernel.kptr_restrict'         => { value => 1 },
    'kernel.core_uses_pid'         => { value => 1 },
# general, but especially for containers
    'kernel.dmesg_restrict'        => { value => 1 },
    'fs.protected_symlinks'        => { value => 1 },
    'fs.protected_hardlinks'       => { value => 1 },
    'vm.mmap_min_addr'             => { value => 65536 },
    'kernel.pid_max'               => { value => 65536 },
# restrict access to perf subsystem
    'kernel.perf_event_paranoid' => { value => 2 },
    'kernel.perf_event_max_sample_rate' => { value => 1 },
    'kernel.perf_cpu_time_max_percent' => { value => 1 },
# https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
    'kernel.kexec_load_disabled'   => { value => 1 },
    'user.max_user_namespaces'     => { value => 0 },
# depending on kernel. (centos7 nok)
#    'kernel.unprivileged_bpf_disabled' => { value => 1 },
#    'net.core.bpf_jit_harden'      => { value => 2 },
  }

  case $facts['os']['name'] {
#    'Solaris':           { include role::solaris } # Apply the solaris class
    'RedHat', 'CentOS':  {

      $bashrc = '/etc/bashrc'
      $user_sudogroups = [
        'wheel',
      ]
      $apache_logdir = '/var/log/httpd'

      # kmod required for /etc/modprobe.d
      $rpm_packages = ['kmod', 'iptables-services', 'perf', 'openscap-scanner', 'scap-security-guide', 'which', 'openssl', 'audit' ]
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
          ensure   => 'purged',
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

      if ($facts['lsbmajdistrelease'] == '7') {
        package { "libpwquality":
          provider => 'yum',
          ensure   => 'present',
        }
        file_line { 'lippwquality: Set Password Minimum Length':
          ensure => present,
          path   => '/etc/security/pwquality.conf',
          line   => 'minlen=15',
          match  => '^minlen=',
        }
      }

      if ($syslog_remoteport != 514) {
        selinux::port { "allow-syslog-${syslog_remoteport}":
          ensure   => 'present',
          seltype  => 'syslogd_port_t',
          protocol => 'tcp',
          port     => $syslog_remoteport,
        }
      }

      # Set Deny For Failed Password Attempts - CCE-27350-8, CCE-26884-7
      # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-hardening_your_system_with_tools_and_services#sect-Security_Guide-Workstation_Security-Account_Locking = Keeping Custom Settings with authconfig
      file { '/etc/pam.d/password-auth-local':
        ensure => present,
        content => "#%PAM-1.0
# /etc/pam.d/password-auth-local
# This file is managed by puppet
auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent even_deny_root deny=3 unlock_time=never fail_interval=900
auth        sufficient    pam_unix.so try_first_pass nullok
auth        [default=die] pam_faillock.so authfail even_deny_root deny=3 unlock_time=never fail_interval=900
auth        required      pam_deny.so

account     required      pam_faillock.so
account     required      pam_unix.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so",
      }
      file { '/etc/pam.d/password-auth':
        ensure => 'link',
        force  => true,
        target => '/etc/pam.d/password-auth-local',
      }
      # CCE-26923-3, CCE-27286-4
      file { '/etc/pam.d/system-auth-local':
        ensure => present,
        content => "#%PAM-1.0
# /etc/pam.d/system-auth-local
# This file is managed by puppet
auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent even_deny_root deny=3 unlock_time=never fail_interval=900
auth        sufficient    pam_unix.so try_first_pass
auth        [default=die] pam_faillock.so authfail even_deny_root deny=3 unlock_time=never fail_interval=900
auth        required      pam_deny.so

account     required      pam_faillock.so
account     required      pam_unix.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so try_first_pass use_authtok sha512 shadow remember=5
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so",
      }
      file { '/etc/pam.d/system-auth':
        ensure => 'link',
        force  => true,
        target => '/etc/pam.d/system-auth-local',
      }
    }
    /^(Debian|Ubuntu)$/: {

      $bashrc = '/etc/bash.bashrc'
      $user_sudogroups = [
        'sudo',
      ]
      $apache_logdir = '/var/log/apache2'

      #$deb_packages = ['apt-transport-https', 'apt-utils', 'dpkg', 'libc-bin', 'kmod', 'iptables', 'iptables-persistent', 'libopenscap8', 'ifupdown2', 'auditd' ]
      $deb_packages = ['apt-utils', 'dpkg', 'libc-bin', 'kmod', 'iptables', 'iptables-persistent', 'libopenscap8', 'ifupdown2' ]
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

  class { 'timezone':
    timezone => 'UTC',
  }

  class { '::resolvconf':
    nameservers => $resolvconf_nameservers,
    domains     => $resolvconf_domains,
  }

  # no user option for puppetlabs/ntp
  class { 'ntp':
    servers   => $ntp_servers,
    restrict  => $ntp_restrict,
  }
  class { 'fail2ban': }
  class { 'osquery': }

  $my_sysctl_settings.each |Array $sysctl| {
    sysctl { $sysctl[0]:
      value => $sysctl[1]['value'],
    }
  }

  class { 'os_hardening':
    umask => "077",
    password_max_age => 182,
    password_min_age => 0,
    password_warn_age => 30,
    ignore_users     => [ 'postfix' ],
  }
  file_line { 'Set Account Expiration Following Inactivity':
    ensure => present,
    path   => '/etc/default/useradd',
    line   => 'INACTIVE=90',
    match  => '^export\ INACTIVE\=',
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
#            value   => "${syslog_dest}",
#            value   => "${syslog_dest};FullTimeFormat",
#            value   => "${syslog_dest};RSYSLOG_SyslogProtocol23Format",
#         }
    },
   inputs => {
        'imfile' => {
            'type'        => "imfile",
            'config'      => {
              'File'      => "${apache_logdir}/access*log",
              'Tag'       => 'apache-access:',
              'StateFile' => 'stat-apache-access',
              'Severity'  => 'info',
              'PersistStateInterval' => 20000,
              'Ruleset'   => "remoteapachelog",
              'Facility'  => "local6",
            }
        }
    },
# https://www.rsyslog.com/doc/v8-stable/tutorials/reliable_forwarding.html
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/s1-working_with_queues_in_rsyslog
    rulesets    => {
        auditsyslog => {
            parameters => {
                'queue.filename' => 'QueueAudit',
                'queue.type' => 'LinkedList',
                'queue.spoolDirectory' => "/var/log/rsyslog/queue",
                'queue.size' => 10000,
                'queue.maxdiskspace' => '10G',
                'queue.timeoutqueue' => 3,
                'queue.dequeuebatchsize' => 1000,
                'queue.saveonshutdown' => 'on',
                'queue.timeoutenqueue' => 0,
                'action.resumeRetryCount' => -1,
            },
            rules      => [
                action => {
                    name    => 'auditlogs',
                    # match /etc/audisp/plugins.d/syslog.conf
                    facility => "info.*",
                    config => {
                        type    => 'omfwd',
                        target  => $syslog_remotehost,
                        port    => $syslog_remoteport,
                        protocol => 'tcp',
                    },
                }
            ],
            stop       => true,
        },
        osquerysyslog => {
            parameters => {
                'queue.filename' => 'QueueOsquery',
                'queue.type' => 'LinkedList',
                'queue.spoolDirectory' => "/var/log/rsyslog/queue",
                'queue.size' => 10000,
                'queue.maxdiskspace' => '10G',
                'queue.timeoutqueue' => 3,
                'queue.dequeuebatchsize' => 1000,
                'queue.saveonshutdown' => 'on',
                'queue.timeoutenqueue' => 0,
                'action.resumeRetryCount' => -1,
            },
            rules      => [
                action => {
                    name    => 'osquerylogs',
                    facility => "local3.*",
                    config => {
                        type    => 'omfwd',
                        target  => $syslog_remotehost,
                        port    => $syslog_remoteport,
                        protocol => 'tcp',
                    },
                }
            ],
            stop       => true,
        },
        remoteapachelog => {
            parameters => {
                'queue.filename' => 'QueueApache',
                'queue.type' => 'LinkedList',
                'queue.spoolDirectory' => "/var/log/rsyslog/queue",
                'queue.size' => 10000,
                'queue.maxdiskspace' => '10G',
                'queue.timeoutqueue' => 3,
                'queue.dequeuebatchsize' => 1000,
                'queue.saveonshutdown' => 'on',
                'queue.timeoutenqueue' => 0,
                'action.resumeRetryCount' => -1,
            },
            rules      => [
                action => {
                    name    => 'apachelogs',
                    facility => "local6.*",
                    config => {
                        type    => 'omfwd',
                        target  => $syslog_remotehost,
                        port    => $syslog_remoteport,
                        protocol => 'tcp',
                    },
                }
            ],
            stop       => true,
        },
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
                        target  => $syslog_remotehost,
                        port    => $syslog_remoteport,
                        protocol => 'tcp',
                    },
                }
            ],
        }
    }
  }
  class { '::logrotate':
    ensure => 'latest',
    config => {
      dateext      => true,
      compress     => true,
      rotate       => $logrotate_days,
      rotate_every => 'daily',
      ifempty      => true,
    }
  }

  # mailserver
  class { 'postfix':
    #inetinterfaces    => 'all',
    inetinterfaces    => 'loopback-only',
    mynetworks        => [ '127.0.0.1/32' ],
    myhostname        => $postfix_myhostname,
    smtpdbanner       => "${postfix_myhostname} ESMTP",
    opportunistictls  => true,
    subjectselfsigned => $postfix_selfsignedcert,
    generatecert      => true,
    syslog_name       => 'private',
    add_default_smtpd_instance => false,
    manage_mastercf   => false,
    readme_directory  => false,
    append_dot_mydomain => false,
    smtpd_helo_required => true,
    disable_vrfy_command => true,
# requires smtp_sasl_password_maps
    smtp_sasl_auth_enable => false,
    smtpd_sasl_auth_enable => true,
    smtpd_use_tls     => true,
    smtpd_tls_protocols => [ '!SSLv2', '!SSLv3', '!TLSv1', '!TLSv1.1' ],
    smtp_use_tls      => true,
    smtp_tls_exclude_ciphers => [ 'aNULL', 'eNULL', 'EXP', 'MD5', 'IDEA', 'KRB5', 'RC2', 'SEED', 'SRP' ],
    # For internet/public-facing system
    #smtp_tls_exclude_ciphers => [ 'EXPORT', 'LOW' ],
    smtpd_tls_mandatory_ciphers => 'medium',
    tls_medium_cipherlist => [ 'AES128+EECDH', 'AES128+EDH' ],
    # smarthost
    relayhost => $postfix_relayhost,
  }
  postfix::instance { 'smtp':
    type    => 'unix',
    command => 'smtp',
# FIXME! rhel: not applied
    chroot  => 'y',
    opts    => {
      'content_filter'               => '',
      'smtpd_helo_restrictions'      => 'permit_mynetworks,reject_non_fqdn_helo_hostname,reject_invalid_helo_hostname,permit',
      'smtpd_sender_restrictions'    => 'permit_mynetworks,reject_non_fqdn_sender,reject_unknown_sender_domain,permit',
      'smtpd_recipient_restrictions' => 'permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination,reject_unknown_recipient_domain,reject_rbl_client cbl.abuseat.org, reject_rbl_client b.barracudacentral.org,reject',
      'mynetworks'                   => '127.0.0.0/8,10.0.0.0/8,192.168.0.0/16',
      'receive_override_options'     => 'no_header_body_checks',
# FIXME! not applied
      'smtpd_helo_required'          => 'yes',
      'smtpd_client_restrictions'    => '',
      'smtpd_restriction_classes'    => '',
# FIXME! not applied
      'disable_vrfy_command'         => 'yes',
      #'strict_rfc821_envelopes'      => 'yes',
# FIXME! not applied
      'smtpd_sasl_auth_enable'       => 'yes',
# FIXME! not applied
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
# FIXME! not applied
      'smtp_use_tls'                  => 'yes',
# FIXME! not applied
      'smtpd_use_tls'                 => 'yes',
      'smtpd_tls_security_level'      => 'may',
      'smtpd_tls_auth_only'           => 'yes',
      #'smtpd_tls_cert_file'           => '',
      #'smtpd_tls_key_file'            => '',
      'smtpd_tls_session_cache_database' => 'btree:${data_directory}/smtpd_scache',
      'smtpd_tls_mandatory_protocols' => '!SSLv2,!SSLv3,!TLSv1,!TLSv1.1',
# FIXME! not applied
      'smtpd_tls_protocols'           => '!SSLv2,!SSLv3,!TLSv1,!TLSv1.1',
      'smtpd_tls_mandatory_ciphers'   => 'medium',
      'tls_medium_cipherlist'         => 'AES128+EECDH:AES128+EDH',
      # https://marc.info/?l=postfix-users&m=140058464921413&w=2
      # https://marc.info/?l=postfix-users&m=140059435225323&w=2
      #if it is *not* a public MX
# FIXME! not applied
      'smtpd_tls_exclude_ciphers'      => 'aNULL, eNULL, EXP, MD5, IDEA, KRB5, RC2, SEED, SRP',
      #'smtp_tls_exclude_ciphers'       => 'EXPORT, LOW',
      },
  }

  class { 'postfix::vmail':
    setup_dovecot => false,
  }

# suggested, RFC2142. TODO: alias to your context
  postfix::vmail::alias { 'webmaster':
    aliasto => $postfix_alias_webmaster,
  }
  postfix::vmail::alias { 'support':
    aliasto => $postfix_alias_webmaster,
  }
  postfix::vmail::alias { 'noc':
    aliasto => $postfix_alias_noc,
  }
  postfix::vmail::alias { 'abuse':
    aliasto => $postfix_alias_security,
  }
  postfix::vmail::alias { 'security':
    aliasto => $postfix_alias_security,
  }
  postfix::vmail::alias { 'soc':
    aliasto => $postfix_alias_security,
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
  firewall { '001 accept all to lo interface (v6)':
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept',
    provider => 'ip6tables',
  }->
  firewall { '002 accept all from lo interface':
    chain    => 'OUTPUT',
    proto   => 'all',
    outiface => 'lo',
    action  => 'accept',
  }->
  firewall { '002 accept all from lo interface (v6)':
    chain    => 'OUTPUT',
    proto   => 'all',
    outiface => 'lo',
    action  => 'accept',
    provider => 'ip6tables',
  }->
  firewall { '003 reject local traffic not on loopback interface':
    iniface     => '! lo',
    proto       => 'all',
    source      => '127.0.0.0/8',
    action      => 'drop',
  }->
  firewall { '003 reject local traffic not on loopback interface (v6)':
    iniface     => '! lo',
    proto       => 'all',
    source      => '::1/128',
    action      => 'drop',
    provider    => 'ip6tables',
  }->
  firewall { '004 accept related established rules':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }->
  firewall { '007 Allow Link-Local addresses (v6)':
    chain       => [ 'INPUT', 'OUTPUT'],
    proto       => 'all',
    source      => 'fe80::/10',
    action      => 'accept',
    provider    => 'ip6tables',
  }->
  firewall { '008 Local DHCP - IN (v6)':
    chain       => 'INPUT',
    proto       => tcp,
    source      => 'fe80::/10',
    dport       => 546,
    action      => 'accept',
    state       => 'NEW',
    provider    => 'ip6tables',
  }
#  firewall { '008 Local DHCP - OUT (v6)':
#    chain       => 'OUTPUT',
#    proto       => udp,
#    destination => '<IPV6_DHCP_SERVER>',
#    sport       => 68,
#    dport       => 67,
#    action      => 'accept',
#    state       => 'NEW',
#    provider    => 'ip6tables',
#  }
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
  proto  => udp,
  action => accept,
}
firewall { '100 allow dns tcp access - OUT':
  chain  => 'OUTPUT',
  dport  => 53,
  proto  => tcp,
  action => accept,
}
firewall { '100 allow dns access - OUT (v6)':
  chain  => 'OUTPUT',
  dport  => 53,
  proto  => udp,
  action => accept,
  provider => 'ip6tables',
}
firewall { '100 allow dns tcp access - OUT (v6)':
  chain  => 'OUTPUT',
  dport  => 53,
  proto  => tcp,
  action => accept,
  provider => 'ip6tables',
}
firewall { '101 allow ntp access - OUT':
  chain  => 'OUTPUT',
  dport  => 123,
  proto  => udp,
  action => accept,
}
firewall { '101 allow ntp access - OUT (v6)':
  chain  => 'OUTPUT',
  dport  => 123,
  proto  => udp,
  action => accept,
  provider => 'ip6tables',
}
firewall { '102 allow smtp access - OUT':
  chain  => 'OUTPUT',
  dport  => 25,
  proto  => tcp,
  action => accept,
}
firewall { '102 allow smtp access - OUT (v6)':
  chain  => 'OUTPUT',
  dport  => 25,
  proto  => tcp,
  action => accept,
  provider => 'ip6tables',
}
firewall { '110 allow http and https access - OUT':
  chain  => 'OUTPUT',
  dport  => [80, 443],
  proto  => tcp,
  action => accept,
}
firewall { '110 allow http and https access - OUT (v6)':
  chain  => 'OUTPUT',
  dport  => [80, 443],
  proto  => tcp,
  action => accept,
  provider => 'ip6tables',
}
firewallchain { 'INPUT:filter:IPv4':
  ensure => present,
  policy => drop,
  before => undef,
}
firewallchain { 'OUTPUT:filter:IPv4':
  ensure => present,
  policy => drop,
  before => undef,
}
firewallchain { 'FORWARD:filter:IPv4':
  ensure => present,
  policy => drop,
  before => undef,
}
firewallchain { 'INPUT:filter:IPv6':
  ensure => present,
  policy => drop,
  before => undef,
}
firewallchain { 'OUTPUT:filter:IPv6':
  ensure => present,
  policy => drop,
  before => undef,
}
firewallchain { 'FORWARD:filter:IPv6':
  ensure => present,
  policy => drop,
  before => undef,
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
} # if !$facts['hypervisors']['docker']

class { '::telegraf':
    hostname => $::hostname,
    outputs  => {
        'influxdb' => {
            'urls'     => [ "http://influxdb0.${::domain}:8086", "http://influxdb1.${::domain}:8086" ],
            'database' => 'telegraf',
            'username' => 'telegraf',
            'password' => 'metricsmetricsmetrics',
            },
        'graphite' => {
            'server'   => [ "localhost:2003" ],
            'prefix'   => 'telegraf',
            'template' => 'host.tags.measurement.field',
            'timeout'  => 2,
            }
        },
    inputs   => {
        'cpu' => {
            'percpu'   => true,
            'totalcpu' => true,
        },
        'mem' => {
        # no configuration
        },
        'io' => {
        },
        'net' => {
            'interfaces' => ["eth*", "enp0s*" ],
        },
        'disk' => {
            'ignore_fs' => ["tmpfs", "devtmpfs", "devfs", "overlay", "aufs", "squashfs", "cgroup", "sysfs", "debugfs"],
        },
#        'diskio' => {
#        },
        'swap' => {
        # no configuration
        },
        'system' => {
        # no configuration
        },
        'kernel' => {
        # no configuration
        },
        'kernel_vmstat' => {
        # no configuration
        },
#        'interrupts' => {
#            'irq' => [ "NET_RX", "TASKLET" ],
#        },
        # iptables: requires CAP_NET_ADMIN and CAP_NET_RAW capabilities for telegraf
#        'iptables' => {
#        },
        # fail2ban: requires command access (root or sudo)
#        'fail2ban' => {
#           'use_sudo'  => true,
#        },
        'puppetagent' => {
        # no configuration
        },
#        'sensors' => {
#        },
        # requires /server-status
#        'apache' => {
#        },
        # requires /manager/status
#        'tomcat' => {
#        },
    }
}
