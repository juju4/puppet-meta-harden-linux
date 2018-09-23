[![Build Status - Master](https://travis-ci.org/juju4/puppet-meta-harden-linux.svg?branch=master)](https://travis-ci.org/juju4/puppet-meta-harden-linux)
[![Build Status - Devel](https://travis-ci.org/juju4/puppet-meta-harden-linux.svg?branch=devel)](https://travis-ci.org/juju4/puppet-meta-harden-linux/branches)

# puppet meta harden linux

## Module Description
This module uses a compilation of other modules to do hardening of linux system.
You are advised to use network shares to store files.

It's an example implementation. There are probably many more ways to do it in a cleaner, faster or whatever way. Adapt to your context!

### Operating systems

This module is targeted for linux.

## Continuous integration

you can test this role with Kitchen, Vagrant or Travis.

Once you ensured all necessary roles are present, You can test with:
```
$ gem install kitchen-puppet kitchen-sync kitchen-vagrant kitchen-inspec librarian-puppet
$ cd /path/to/roles/puppet-meta-harden-linux
$ kitchen verify
$ kitchen login
$ KITCHEN_YAML=".kitchen.docker.yml" kitchen verify
```
or
```
$ sh -x get-puppetmodules.sh
$ vagrant up
$ vagrant ssh
```

## Troubleshooting & Known issues

* local puppet module dependencies
```
$ librarian-puppet install --verbose
$ puppet module list --tree --modulepath /path/to/modules
```

* kitchen/docker execution:
It is expected that some tasks will fail in docker context (sysctl, systemd daemons...). Full system (Bare, VM, LXD...) is required for full testing.

## License

BSD 2-clause
