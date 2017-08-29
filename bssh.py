#!/usr/bin/env python

import webbrowser
import hjson as json
import requests
import sys
import secrets
import os
import time

class DotDict(dict):
    '''dict.item notation for dict()'s'''
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value

def debug(msg):
    sys.stderr.write('+++ {}\n'.format(msg))

class Session():
    """
    The Session class contains all necessary session data for bssh,
    such as CLI token, access proxy token, etc.
    """
    _CLI_TOKEN_EXP_DELTA = 2538000 # 30 days
    _CLI_TOKEN_LEN = 64
    _API_REQUEST_TIMEOUT = 60 # 1 minute
    _API_REQUEST_DELAY = 1 # Check API every 1 second

    def __init__(self, cache_path, proxy_url, ssh_host, ssh_port=22):
        self.tokens = DotDict({
            'cli': {'value': '', 'exp': None},
            'access_proxy': {'value': '', 'exp': None}
            })
        try:
            self.load(cache_path)
        except FileNotFoundError:
            debug('No cache found.')
            pass
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.proxy_url = proxy_url

        # Check if we have or need a CLI token
        if self.is_token_expired(self.tokens.cli):
            self.tokens.cli.value = secrets.token_urlsafe(self._CLI_TOKEN_LEN)
            self.tokens.cli.exp = time.time()+ self._CLI_TOKEN_EXP_DELTA
            debug('Generated new CLI token: {}'.format(self.tokens.cli.value))

        # Check if we have or need an Access Proxy token
        if self.is_token_expired(self.tokens.access_proxy):
            self.request_access_proxy_token()
            timeout = time.time()+self._API_REQUEST_TIMEOUT
            while True:
                debug('Polling proxy API for another {} seconds until time out'.format((timeout-time.time())))
                if self.poll_proxy_api():
                    debug('Got new access proxy token value: {}'.format(self.tokens.access_proxy.value))
                    self.get_proxy_token_expiration()
                    debug('Got new access proxy token expiration: {}'.format(self.tokens.access_proxy.exp))
                    return
                else:
                    time.sleep(self._API_REQUEST_DELAY)
                if time.time() >= timeout:
                    print("connect to access proxy host API {}: Connection timed out. Have you authenticated in the web browser window?".format(self.proxy_url))
                    sys.exit(127)
                    return

    def save(self, path):
        with open(path) as fd:
            json.dump(self.tokens)

    def load(self, path):
        with open(path) as fd:
            d = DotDict(json.load(fd))
            self.tokens = d.tokens

    def get_proxy_token_expiration(self):
        """
        Retrieves the access proxy token/session cookie expiration time.
        This can only be done by making a request to ensure we get the real, correct value set in the interative
        user cookie.
        """
        jar = requests.cookies.RequestsCookieJar()
        jar.set('oidc_session', self.tokens.access_proxy.value)
        # Headers are necessary to bypass some dumb library filters of the python-request stock UA
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0'}
        r = requests.get('{}/api/ping'.format(self.proxy_url), headers=headers, cookies=jar)
        if r.status_code != 200:
            debug('get_proxy_token_expiration: HTTP status code: {}, body: {}'.format(r.status_code, r.text))
            self.tokens.access_proxy.exp = -1
            return False

        cookie = jar.get('oidc_session')
        if not cookie:
            debug('get_proxy_token_expiration: Session cookie not found')
            self.tokens.access_proxy.exp = -1
            return False

        try:
            self.tokens.access_proxy.exp = cookie.expires
        except AttributeError:
            debug('get_proxy_token_expiration: could not find expiration')
            self.tokens.access_proxy.exp = -1
        return True

    def poll_proxy_api(self):
        """
        Check if we got a proxy api reply
        """
        # Double / is required in order to access the path that is not protected by the reverse-proxy
        r = requests.get('{}/api/session?cli_token={}'.format(self.proxy_url, self.tokens.cli.value))
        # 202 accepted - means CLI token is not yet authenticated interactively by the user
        if r.status_code == 202:
            return False
        elif r.status_code == 200:
            try:
                auth = r.json().get('cli_token_authenticated')
            except:
                debug('poll_proxy_api: JSON Decoding failed - HTTP status code: {}, body: {}'.format(r.status_code, r.text))
                return False
            # We're in business!
            self.tokens.access_proxy.value = r.json().get('ap_session')
            return True
        else:
            debug('poll_proxy_api: HTTP status code: {}, body: {}'.format(r.status_code, r.text))
            return False

    def request_access_proxy_token(self):
        """
        Requests an Access Proxy token from the .. Access Proxy
        """
        parameters = "?type=ssh&host={}&port={}&cli_token={}".format(self.ssh_host, self.ssh_port,
                                                                     self.tokens.cli.value)
        print("If no browser window was opened, please manually authenticate to the access proxy: {}{}".format(self.proxy_url, parameters))
        webbrowser.open(self.proxy_url+parameters, new=0, autoraise=True)

    def is_token_expired(self, token):
        """
        Return True if expired or invalid. False otherwise.
        """
        if token.exp == None:
            return True

        if len(token.value) != self._CLI_TOKEN_LEN:
            return True

        if token.exp >= time.time()+self._CLI_TOKEN_EXP_DELTA:
            return True

        return False

def usage():
    print("""USAGE: {} remote_hostname:remote_port:remote_user""".format(sys.argv[0]))
    sys.exit(1)

def main():
    # Load config
    with open('bssh.json') as fd:
        config = DotDict(json.load(fd))

    if config.debug != 'true':
        debug = lambda x: None
    else:
        debug = globals()['debug']

    # Get arguments from OpenSSH's ProxyCommand
    # this program is usually called as such:
    # %h: remote hostname, %p: remote port, %r: remote user name
    # ssh -oProxyCommand='/usr/bin/bssh.py %h:%p:%r' kang@myhost.com
    if len(sys.argv) != 2:
        usage()

    try:
        (ssh_host, ssh_port, ssh_user) = sys.argv[1].split(':')
    except NameError:
        usage()

    # Load session (or create new one)
    ses = Session(config.cache, config.proxy_url, ssh_host, ssh_port)

if __name__ == "__main__":
    main()
