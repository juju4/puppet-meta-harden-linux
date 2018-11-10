# https://www.ernw.de/download/hardening/ERNW_Checklist_Tomcat7_Hardening.pdf
# https://nvd.nist.gov/ncp/repository?product=Apache+Tomcat&startIndex=0
# https://github.com/autostructure/secure_tomcat, Apr 2017
# https://github.com/autostructure/cis_harden_tomcat, Nov 2017

case $facts['os']['name'] {
    'RedHat', 'CentOS':  {

      $ssl_dir = '/etc/pki/tls/certs'
      $ssl_privatedir = '/etc/pki/tls/private'
      $policycoreutils = 'policycoreutils-python'

      # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/resource_management_guide/sec-cpuset
      # https://developers.redhat.com/blog/2015/09/21/controlling-resources-with-cgroups-for-performance-testing/
      cgroups::groups { "tomcat":
        controllers => {
          cpuset => {
            "cpuset.cpus" => "0,1",
            "cpuset.mems" => "0",
          },
          memory => {
            "memory.limit_in_bytes" => "4G";
          },
        },
      }

    }
    /^(Debian|Ubuntu)$/: {

      $ssl_dir = '/etc/ssl'
      $ssl_privatedir = '/etc/ssl/private'
      $policycoreutils = 'policycoreutils-python-utils'

    }
#    default:             { include role::generic } # Apply the generic class
}

class { 'java': }

tomcat::install { '/opt/tomcat9':
  source_url => 'https://www.apache.org/dist/tomcat/tomcat-9/v9.0.12/bin/apache-tomcat-9.0.12.tar.gz',
  require    => Class['java'],
}
tomcat::instance { 'default':
  catalina_home => '/opt/tomcat9',
  require       => Class['tomcat'],
}
# https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html
tomcat::config::server::connector { 'tomcat9-signature':
  catalina_base         => '/opt/tomcat9',
  port                  => '8080',
  protocol              => 'HTTP/1.1',
  additional_attributes => {
    'server' => 'Apache Tomcat'
  },
  require               => Class['tomcat'],
}
file { [ "/opt/tomcat9/lib", "/opt/tomcat9/lib/org", "/opt/tomcat9/lib/org/apache", "/opt/tomcat9/lib/org/apache/catalina", "/opt/tomcat9/lib/org/apache/catalina/util" ]:
  ensure => directory,
  mode   => '0755',
  owner  => 'tomcat',
  group  => 'tomcat',
  require => Class['tomcat'],
}
file { "/opt/tomcat9/lib/org/apache/catalina/util/ServerInfo.properties":
  ensure => present,
  content => "server.info=Apache Tomcat Version X",
  mode   => '0644',
  owner  => 'tomcat',
  group  => 'tomcat',
  require => [
    Class['tomcat'],
    File['/opt/tomcat9/lib/org/apache/catalina/util'],
    ]
}
# remove default webapps (required for production)
$tomcat_absent_webapps = ['ROOT', 'docs', 'examples', 'host-manager', 'manager' ]
$tomcat_absent_webapps.each |String $d| {
  file { "remove-${d}":
    path    => "/opt/tomcat9/webapps/${d}",
    ensure  => 'present',
    recurse => true,
    purge   => true,
    force   => true,
    require => [
      Class['tomcat'],
      ]
  }
}
file_line { 'tomcat-disable-autodeploy':
  path => '/opt/tomcat9/conf/server.xml',
  line  => ' unpackWARs="true" autoDeploy="false" deployOnStartup="false">$',
  match => ' unpackWARs="true" autoDeploy="true">$',
  require => [
    Class['tomcat'],
    ]
}

Class['tomcat'] -> File['/opt/tomcat9/lib'] -> File['/opt/tomcat9/lib/org/apache/catalina/util'] -> File["/opt/tomcat9/lib/org/apache/catalina/util/ServerInfo.properties"]
Class['tomcat'] ~> File['/opt/tomcat9/webapps/ROOT']
Class['tomcat'] ~> File['/opt/tomcat9/webapps/docs']
Class['tomcat'] ~> File['/opt/tomcat9/webapps/examples']
Class['tomcat'] ~> File['/opt/tomcat9/webapps/host-manager']
Class['tomcat'] ~> File['/opt/tomcat9/webapps/manager']
Class['tomcat'] ~> File_line['tomcat-disable-autodeploy']

package { "${policycoreutils}":
  ensure => installed,
}

package { 'openssl':
  ensure => installed,
}

# TODO: for initial provisioning and to be replaced. update CN and ssl paths. MUST be changed!
# by internal pki or
# by letsencrypt or whatever relevant to organization/policy
exec { 'self_signed_certificate':
  command => "openssl req -x509 -nodes -sha256 -days 90 -newkey rsa:2048 -subj \"/C=US/ST=CA/L=San Francisco/O=Puppet/CN=www.example.com\" -keyout ${ssl_privatedir}/server.key -out ${ssl_dir}/server.crt",
  path    => '/bin:/usr/bin/:/sbin:/usr/sbin',
  require => Package['openssl'],
  creates => "${ssl_dir}/server.crt",
  before  => Class['apache'],
}

class { 'apache':
  default_vhost => false,
  manage_user => false,
}

class { 'apache::mod::security': }

apache::vhost { 'www':
  servername    => undef,
  ip            => '*',
  port          => '80',
  ip_based   => true,
  docroot       => '/var/www/html',
#  server_signature => 'Off',
#  server_tokens => 'Prod',

# TODO: ideally better to redirect to https URL
#  redirect_status => 'permanent',
#  redirect_dest   => 'https://redirect.example.com/'

  proxy_dest    => 'http://localhost:8080',
  error_log_file  => 'default_error.log',
  access_log_file => 'default_access.log',
# Check /var/log/httpd/modsec_audit.log if you believe there is a false-positive block.
# 960017 Host header is a numeric IP address. OK to disable for vagrant/dev
  modsec_disable_ids => [ 960017 ],
}

apache::vhost { 'cert':
  port     => '443',
  ip            => '*',
  ip_based   => true,
  docroot  => '/var/www/html',
  ssl      => true,
  ssl_cert => "${ssl_dir}/server.crt",
  ssl_key  => "${ssl_privatedir}/server.key",

#  server_signature => 'Off',
#  server_tokens => 'Prod',
  ssl_cipher   => 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH',
  ssl_protocol => [ 'all', '-SSLv2', '-SSLv3', '-TLSv1', '-TLSv1.1' ],

  headers   => [
    'set X-Content-Type-Options "nosniff"',
    'set X-Frame-Options "sameorigin"',
    "set Strict-Transport-Security \"max-age=16070400; includeSubDomains\"",
    ## https://www.w3.org/TR/upgrade-insecure-requests/
    "set Upgrade-Insecure-Requests \"1\"",
    "set X-XSS-Protection \"1; mode=block\"",
    #"set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'self'; upgrade-insecure-requests; report-uri /csp/report.php\"",
    "set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'self'; upgrade-insecure-requests;\"",
    "set Referrer-Policy \"origin\"",
    #"set Expect-CT \"max-age=0, report-uri,report-uri=/csp/report.php\"",
    # Note: might break some app... need Apache 2.2.4+
    # https://scotthelme.co.uk/csrf-is-dead/
    #'edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure;SameSite',
    # want to be indexed by search engine?
    'set X-Robots-Tag none',
#    'Set X-Robots-Tag "noindex, noarchive, nosnippet"',
    ],

  redirect_source => ['/security.txt'],
  redirect_dest   => ['/.well-known/security.txt'],

  no_proxy_uris => [
    '/security.txt',
    '/.well-known/security.txt',
    ],
  proxy_dest    => 'http://localhost:8080',

# Check /var/log/httpd/modsec_audit.log if you believe there is a false-positive block.
# 960017 Host header is a numeric IP address. OK to disable for vagrant/dev
  modsec_disable_ids => [ 960017 ],
}


  file { "/var/www/html/.well-known":
    ensure => directory,
    mode   => '0755',
  }

  file { '/var/www/html/.well-known/security.txt':
    ensure => present,
    content => "Contact: mailto:security@nuance.com
Contact: https://www.nuance.com/about-us/security/engage-us.html
Encryption: https://www.nuance.com/security/pgp-key.txt
Signature: https://www.nuance.com/.well-known/security.txt.sig",
  }

#apache::mod::status { 'apache-server-status':
#  allow_from  => ['127.0.0.1','::1'],
#  status_path => '/server-status',
#}

apache::balancer { 'puppet00': }

apache::balancermember { "${::fqdn}-puppet00":
  balancer_cluster => 'puppet00',
  url              => "ajp://${::fqdn}:8009",
  options          => ['ping=5', 'disablereuse=on', 'retry=5', 'ttl=120'],
}

# selinux: allow apache to serve as proxy
exec { 'set_apache_defaults':
  command => 'setsebool -P httpd_can_network_relay on',
  path    => '/bin:/usr/bin/:/sbin:/usr/sbin',
  require => Package["${policycoreutils}"],
}
