- Add plugin support ;-)
SSH Plugin:
- `ssh-agen`t emulation support (see https://github.com/ronf/asyncssh/blob/master/asyncssh/agent.py) so that there is no need to have an ssh-agent running
- Support `ProxyUseFdPass` for performance reasons
- Support proxying over the access proxy (ssh=>HTTPS=>sshd)
- Move config to yaml
