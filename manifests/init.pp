# init.pp
class harden_linux {

  if $facts[osfamily] == 'linux' {
    notice('Running hardening on linux')
    include ::harden_linux
  } else {
    notice('Unsupported osfamily')
  }
}
