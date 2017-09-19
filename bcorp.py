#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: Guillaume Destuynder <gdestuynder@mozilla.com>

import argparse
import array
import json
import logging
import os
import requests
import socket
import sys
import secrets
import time
import webbrowser
import yaml

def setup_logging(stream=sys.stdout, level=logging.DEBUG):
    """
    Setup app logging
    """
    formatstr="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)

    # Enable this to debug the requests module
#    import http.client as http_client
#    http_client.HTTPConnection.debuglevel = 1
#    requests_log = logging.getLogger("requests.packages.urllib3")
#    requests_log.setLevel(logging.DEBUG)
#    requests_log.propagate = True

    return logger

class DotDict(dict):
    """
    dict.item notation for dict()'s
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value

class Session():
    """
    The Session class contains all necessary session data for bcorp,
    such as CLI token, access proxy token, etc.
    """
    _CLI_TOKEN_EXP_DELTA = 2538000 # 30 days
    _CLI_TOKEN_LEN = 48 # 48 bits (~64 chars)
    _API_REQUEST_TIMEOUT = 60 # 1 minute
    _API_REQUEST_DELAY = 1 # Check API every 1 second
    _API_SESSION_NAME ='session'

    def __init__(self, cache_path, proxy_url, ssh_user, ssh_host, ssh_port=22):
        self.tokens = DotDict({
            'cli': {'value': '', 'exp': None},
            'access_proxy': {'value': '', 'exp': None}
            })
        self.cache_path = os.path.expanduser(cache_path)
        try:
            self.load()
        except FileNotFoundError:
            logger.debug('No cache found.')
            pass
        self.ssh_user = ssh_user
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.proxy_url = proxy_url

        # Check if we have or need a CLI token
        self._verify_cli_token()

        # Check if we have or need an Access Proxy token
        self._verify_access_proxy_token()

    def save(self):
        with open(os.open(self.cache_path, os.O_WRONLY|os.O_CREAT, mode=0o600), 'w') as fd:
            json.dump(self.tokens, fd)

    def load(self):
        with open(self.cache_path, 'r') as fd:
            try:
                d = DotDict(json.load(fd))
                self.tokens = d
            except json.decoder.JSONDecodeError:
                logger.error('Cache appears corrupted. Starting with new values.')

    def _get_cookie_jar(self):
        """
        Returns a RequestsCookieJar for the access proxy API
        """
        jar = requests.cookies.RequestsCookieJar()
        jar.set(self._API_SESSION_NAME, self.tokens.access_proxy.value)
        return jar

    def _verify_cli_token(self):
        if self.tokens.cli.exp == None or self.tokens.cli.exp >= time.time() + self._CLI_TOKEN_EXP_DELTA:
            logger.debug('Invalid CLI token, re-generating')
            self.tokens.cli.value = secrets.token_urlsafe(self._CLI_TOKEN_LEN)
            self.tokens.cli.exp = time.time()+ self._CLI_TOKEN_EXP_DELTA
            self.save()
            logger.debug('Generated new CLI token: {}'.format(self.tokens.cli.value))
        else:
            logger.debug('Re-using CLI token: {}'.format(self.tokens.cli.value))

    def _verify_access_proxy_token(self):
        if not self._check_api_authenticated():
            self.request_access_proxy_token()
            timeout = time.time()+self._API_REQUEST_TIMEOUT
            while True:
                logger.debug('Polling proxy API for another {} seconds until time out'.format((timeout-time.time())))
                if self.poll_proxy_api():
                    if self._check_api_authenticated():
                        logger.debug('All tokens are valid')
                        return
                else:
                    time.sleep(self._API_REQUEST_DELAY)
                if time.time() >= timeout:
                    logger.warning("connect to access proxy host API {}: Connection timed out. Have you authenticated in the "
                          "web browser window?".format(self.proxy_url))
                    sys.exit(127)
                    return
        else:
            logger.debug('Re-using access proxy token: {}'.format(self.tokens.access_proxy.value))

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
                logger.debug('cli_token_authenticated is {}'.format(str(auth)))
            except:
                logger.debug('JSON Decoding failed - HTTP status code: {}, body: {}'.format(r.status_code,
                             r.text[0:100]))
                return False
            if not auth:
                return False
            self.tokens.access_proxy.value = r.json().get('ap_session')
            logger.debug('Retrieved new access proxy token: {}'.format(self.tokens.access_proxy.value))
            self.save()
            return True
        else:
            logger.debug('HTTP status code: {}, body: {}'.format(r.status_code, r.text[0:100]))
            return False

    def request_access_proxy_token(self):
        """
        Requests an Access Proxy token from the .. Access Proxy
        """
        parameters = "?type=ssh&host={host}&user={user}&port={port}&cli_token={cli}".format(host = self.ssh_host,
                                                                                            port = self.ssh_port,
                                                                                            user = self.ssh_user,
                                                                                            cli= self.tokens.cli.value)
        logging.info("If no browser window was opened, please manually authenticate to the "
              "access proxy: {}{}".format(self.proxy_url, parameters))
        webbrowser.open(self.proxy_url+parameters, new=0, autoraise=True)

    def _check_api_authenticated(self, r=None):
        """
        Check we got an access proxy session cookie.
        If not, attempt to acquire a new one.
        If all fails, connection to SSH will fail.
        """
        r_src_self = False

        if not r:
            r_src_self = True
            headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0'}
            r = requests.get('{}/api/ping'.format(self.proxy_url), cookies=self._get_cookie_jar(), headers=headers)
            if r.status_code != 200:
                logger.debug('HTTP status code: {}, body: {}'.format(r.status_code, r.text[0:100]))

        cookie = r.cookies.get(self._API_SESSION_NAME)
        if cookie:
            #FIXME set expiration for our records
            #Current access proxy does not support this though, hence the FIXME
            pass

        try:
            tmp = r.json()
        except json.decoder.JSONDecodeError:
            logger.debug('JSON decoding failed. HTTP status code: {}, body: {}'.format(r.status_code, r.text[0:100]))
            return False

        if r_src_self and not tmp.get('PONG'):
            logger.debug('access_proxy token is invalid')
            return False

        # Since we don't get a cookie back, and we got a specific API request forwarded to the function:
        # if we could decode any JSON we consider this is valid
        logger.debug('access_proxy token is still valid')
        return True

    def get_ssh_credentials(self, user):
        """
        Retrieves the certificate and private key from the access proxy.
        """
        creds = DotDict({'private_key': None, 'public_key': None, 'certificate': None})
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0'}
        r = requests.get('{}/api/ssh?cli_token={}'.format(self.proxy_url, self.tokens.cli.value),
                         cookies=self._get_cookie_jar(), headers=headers)
        if not self._check_api_authenticated(r):
            return creds

        if r.status_code != 200:
            logger.debug('HTTP status code: {}, body: {}'.format(r.status_code, r.text[0:100]))
            logger.error('Failed to get SSH credentials, permission will be denied')
            return creds
        try:
            tmp = r.json()
        except json.decoder.JSONDecodeError:
            logger.debug('JSON decoding failed. HTTP status code: {}, body: {}'.format(r.status_code, r.text[0:100]))
            logger.error('Failed to get SSH credentials, permission will be denied')
            return creds

        try:
            creds.private_key = tmp['private_key']
            creds.public_key = tmp['public_key']
            creds.certificate = tmp['certificate']
        except KeyError:
            logger.error('Could not interpret access proxy data')
            return creds
        return creds

def save_ssh_creds(ssh_key_path, creds):
    if (creds.private_key is None):
        logger.error("Saving SSH Credentials failed: No credentials received.")
        return
    ssh_key = os.path.expanduser(ssh_key_path)
    logger.debug('Saving SSH credentials to {}'.format(ssh_key))

    with open(os.open(ssh_key, os.O_WRONLY|os.O_CREAT, mode=0o600), 'w') as fd:
        fd.write(creds.private_key)
    with open(os.open(ssh_key+'.pub', os.O_WRONLY|os.O_CREAT, mode=0o600), 'w') as fd:
        fd.write(creds.public_key)
    with open(os.open(ssh_key+'-cert.pub', os.O_WRONLY|os.O_CREAT, mode=0o600), 'w') as fd:
        fd.write(creds.certificate)

def usage():
    logging.info("""USAGE: {} remote_hostname:remote_port:remote_user""".format(sys.argv[0]))
    sys.exit(1)

def main(args, config):
    global logger

    if not args.verbose:
        level = logging.INFO
    else:
        level = logging.DEBUG
    logger = setup_logging(stream=sys.stderr, level=level)


    # Get arguments from OpenSSH's ProxyCommand
    # this program is usually called as such:
    # %h: remote hostname, %p: remote port, %r: remote user name
    # ssh -oProxyCommand='/usr/bin/bssh.py %h:%p:%r' kang@myhost.com
    try:
        (ssh_host, ssh_port, ssh_user) = args.moduleopts.split(':')
    except NameError:
        usage()

    # Load session (or create new one)
    ses = Session(config.openssh.cache, config.proxy_url, ssh_user, ssh_host, ssh_port)
    creds = ses.get_ssh_credentials(ssh_user)
    logger.debug('SSH credentials data for user {}:\n{}\n{}'.format(ssh_user, creds.public_key, creds.certificate))
    save_ssh_creds(config.openssh.ssh_key_path, creds)
    del(creds)

    # Pass to SSH
    # XXX FIXME figure out ProxyUseFdPass
    #s = socket.create_connection((sys.argv[1], int(sys.argv[2])))
    #fds = array.array("i", [s.fileno()])
    #ancdata = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)]
    #socket.socket(fileno = 1).sendmsg([b'\0'], ancdata)
    #See also https://lists.mindrot.org/pipermail/openssh-unix-dev/2013-June/031483.html
    # https://github.com/solrex/netcat/blob/master/netcat.c#L1246
    # http://www.gabriel.urdhr.fr/2016/08/07/openssh-proxyusefdpass/
    import subprocess
    subprocess.call(['ssh-add', os.path.expanduser('~/.ssh/bcorp_key')])
    s = socket.create_connection((ssh_host, int(ssh_port)))
    import select
    import fcntl
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
    while True:
        (r,w,x)= select.select([sys.stdin,s.fileno()], [], [])
        if s.fileno() in r:
            try:
                sys.stdout.buffer.write(s.recv(8192))
                sys.stdout.flush()
            except BrokenPipeError:
                logger.debug('ProxyCommand closed stdin')
                break
        if sys.stdin in r:
            try:
                s.send(sys.stdin.buffer.read(8192))
            except BrokenPipeError:
                logger.debug('Remote host closed connection')
                break
    s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--type', required=True, choices=['ssh', 'sts'], help='Select type of credentials to request')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debugging / verbose messages')
    parser.add_argument('-c', '--config',  help='Specify a configuration file')
    parser.add_argument('moduleopts', help='Module specific options')
    args = parser.parse_args()

    with open(args.config or 'bcorp.yml') as fd:
        config = DotDict(yaml.load(fd))
        # Ensure we have no double / at the end of the URL as this confuses reverse proxies
        config.proxy_url = config.proxy_url.rstrip('/')

    main(args, config)
