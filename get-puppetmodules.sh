#!/bin/sh
export PATH=/usr/local/bin:/usr/bin:/bin
umask 022

m=modules

[ ! -d $m ] && mkdir -p $m
#[ ! -d $m/puppetlabs-stdlib ] && git clone https://github.com/puppetlabs/puppetlabs-stdlib.git $m/puppetlabs-stdlib
#[ ! -d $m/hardening-stdlib ] && git clone https://github.com/dev-sec/puppet-hardening-stdlib $m/hardening-stdlib
#[ ! -d $m/os_hardening ] && git clone https://github.com/dev-sec/puppet-os-hardening $m/hardenining-os_hardening
#[ ! -d $m/ssh_hardening ] && git clone https://github.com/dev-sec/puppet-ssh-hardening $m/hardening-ssh_hardening
#[ ! -d $m/saz-ssh ] && git clone https://github.com/saz/puppet-ssh $m/saz-ssh
#[ ! -d $m/thias-sysctl ] && git clone https://github.com/thias/puppet-sysctl.git $m/thias-sysctl
#[ ! -d $m/firewall ] && git clone https://github.com/puppetlabs/puppetlabs-firewall $m/puppetlabs-firewall
#[ ! -d $m/cisecurity ] && git clone https://github.com/cohdjn/cisecurity $m/cohdjn-cisecurity

[ ! -d $m/stdlib ] && git clone https://github.com/puppetlabs/puppetlabs-stdlib.git $m/stdlib
# https://tickets.puppetlabs.com/browse/MODULES-2145
[ ! -d $m/apt ] && git clone --config transfer.fsckobjects=false --config fetch.fsckobjects=false --config receive.fsckobjects=false https://github.com/puppetlabs/puppetlabs-apt.git $m/apt
[ ! -d $m/hardening-stdlib ] && git clone https://github.com/dev-sec/puppet-hardening-stdlib $m/hardening-stdlib
[ ! -d $m/os_hardening ] && git clone https://github.com/dev-sec/puppet-os-hardening $m/os_hardening
[ ! -d $m/ssh_hardening ] && git clone https://github.com/dev-sec/puppet-ssh-hardening $m/ssh_hardening
[ ! -d $m/ssh ] && git clone https://github.com/saz/puppet-ssh $m/ssh
[ ! -d $m/thias-sysctl ] && git clone https://github.com/thias/puppet-sysctl.git $m/sysctl
[ ! -d $m/firewall ] && git clone https://github.com/puppetlabs/puppetlabs-firewall $m/firewall
#[ ! -d $m/cisecurity ] && git clone https://github.com/cohdjn/cisecurity $m/cisecurity
#[ ! -d $m/auditd ] && git clone https://github.com/kemra102/puppet-auditd.git $m/auditd
[ ! -d $m/auditd ] && git clone https://github.com/GeoffWilliams/puppet-auditd.git $m/auditd
[ ! -d $m/filemagic ] && git clone https://github.com/GeoffWilliams/puppet-filemagic.git $m/filemagic
[ ! -d $m/osquery ] && git clone https://github.com/BIAndrews/puppet-osquery.git $m/osquery
[ ! -d $m/ntp ] && git clone https://github.com/puppetlabs/puppetlabs-ntp $m/ntp
[ ! -d $m/rsyslog ] && git clone https://github.com/voxpupuli/puppet-rsyslog.git $m/rsyslog
[ ! -d $m/puppetlabs-concat ] && git clone https://github.com/puppetlabs/puppetlabs-concat.git $m/concat
[ ! -d $m/epel ] && git clone https://github.com/jordiprats/eyp-epel.git $m/epel
[ ! -d $m/fail2ban ] && git clone https://github.com/voxpupuli/puppet-fail2ban.git $m/fail2ban
[ ! -d $m/extlib ] && git clone https://github.com/voxpupuli/puppet-extlib.git $m/extlib
[ ! -d $m/rkhunter ] && git clone https://github.com/itmanagerro/puppet-rkhunter.git $m/rkhunter
[ ! -d $m/telegraf ] && git clone https://github.com/ouroboros8/puppet-telegraf.git $m/telegraf
[ ! -d $m/postfix ] && git clone https://github.com/NTTCom-MS/eyp-postfix.git $m/postfix
[ ! -d $m/eyplib ] && git clone https://github.com/NTTCom-MS/eyp-eyplib.git $m/eyplib
[ ! -d $m/dovecot ] && git clone https://github.com/NTTCom-MS/eyp-dovecot.git $m/dovecot
[ ! -d $m/smarthost ] && git clone https://github.com/justinjl6/puppet-smarthost.git $m/smarthost
