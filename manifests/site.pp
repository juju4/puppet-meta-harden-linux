node default {

    class { 'os_hardening': }
    class { 'ssh_hardening::server': }
    class { 'ssh_hardening::client': }

#    class { '::cisecurity': }

}
