# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"
ENV['VAGRANT_DEFAULT_PROVIDER'] = 'virtualbox'

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "centos/7"
  config.vm.hostname = "pharden"
  #hardenwin.vm.network "private_network", ip: "192.168.50.100"

  config.vm.define "pharden" do |cfg|
    cfg.vm.hostname = "pharden"
  end

  config.vm.provision "shell", inline: "rpm -Uvh https://yum.puppet.com/puppet5/puppet5-release-el-7.noarch.rpm || true"
  config.vm.provision "shell", inline: "yum install -y puppet-agent"
  # modules fetched from vagrant host
  config.vm.provision "shell", inline: "puppet module list --tree"

  config.vm.provision :puppet do |puppet|
    puppet.manifest_file  = "site.pp"
    puppet.manifests_path  = "manifests"
#    #puppet.module_path = "../"
    puppet.module_path = "modules"
#    puppet.options = "--verbose --debug"
    puppet.options = "--verbose"
    # Need to set the fqdn here as well; see
    # http://www.benjaminoakes.com/2013/04/25/making-puppets-fqdn_rand-play-nice-with-vagrant/
    puppet.facter = { 'fqdn'  => config.vm.hostname }
  end

#  config.vm.synced_folder ".", "/vagrant"

end
