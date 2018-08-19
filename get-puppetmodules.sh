#!/bin/sh
export PATH=/usr/local/bin:/usr/bin:/bin
umask 022

m=modules

[ ! -d $m ] && mkdir -p $m
#[ ! -d $m/puppetlabs-stdlib ] && git clone https://github.com/puppetlabs/puppetlabs-stdlib.git $m/puppetlabs-stdlib
#[ ! -d $m/hardening-stdlib ] && git clone https://github.com/dev-sec/puppet-hardening-stdlib $m/hardening-stdlib
#[ ! -d $m/os_hardening ] && git clone https://github.com/dev-sec/puppet-os-hardening $m/hardenining-os_hardening
#[ ! -d $m/ssh_hardening ] && git clone https://github.com/dev-sec/puppet-os-hardening $m/hardening-ssh_hardening
#[ ! -d $m/thias-sysctl ] && git clone https://github.com/thias/puppet-sysctl.git $m/thias-sysctl
#[ ! -d $m/firewall ] && git clone https://github.com/puppetlabs/puppetlabs-firewall $m/puppetlabs-firewall
#[ ! -d $m/cisecurity ] && git clone https://github.com/cohdjn/cisecurity $m/cohdjn-cisecurity

[ ! -d $m/puppetlabs-stdlib ] && git clone https://github.com/puppetlabs/puppetlabs-stdlib.git $m/stdlib
[ ! -d $m/hardening-stdlib ] && git clone https://github.com/dev-sec/puppet-hardening-stdlib $m/hardening-stdlib
[ ! -d $m/os_hardening ] && git clone https://github.com/dev-sec/puppet-os-hardening $m/os_hardening
[ ! -d $m/ssh_hardening ] && git clone https://github.com/dev-sec/puppet-os-hardening $m/ssh_hardening
[ ! -d $m/thias-sysctl ] && git clone https://github.com/thias/puppet-sysctl.git $m/sysctl
[ ! -d $m/firewall ] && git clone https://github.com/puppetlabs/puppetlabs-firewall $m/firewall
#[ ! -d $m/cisecurity ] && git clone https://github.com/cohdjn/cisecurity $m/cohdjn-cisecurity
