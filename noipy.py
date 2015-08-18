import ConfigParser
import argparse
import base64
from contextlib import closing
from getpass import getpass
import logging
import os
import urllib
import urllib2
import re
import socket
import sys
import time
import signal
import unittest

CONNECT_TIMEOUT = 5
DEFAULT_INTERVAL = 30


class NoipApiException(Exception):
    pass


def is_valid_ipv4_address(address):
    # copied from: http://stackoverflow.com/a/4017219/2113516
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    else:
        return True


def is_valid_hostname(hostname):
    # copied from: http://stackoverflow.com/a/2532344/393304
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def get_public_ip():
    resp = urllib2.urlopen('http://ip1.dynupdate.no-ip.com/')
    ip_addr = resp.read()
    if not is_valid_ipv4_address(ip_addr):
        raise Exception("Invalid IP address %s" % ip_addr)
    return ip_addr


def handle_api_response(response):

    words = response.split()
    if words[0] not in ('good', 'nochg'):
        # error messages copied from: http://www.noip.com/integrate/response
        error_message = {
            'nohost': 'Hostname supplied does not exist under specified account, client exit and require user to enter new login credentials before performing an additional request.',
            'badauth': 'Invalid username password combination',
            'badagent': 'Client disabled. Client should exit and not perform any more updates without user intervention.',
            '!donator': 'An update request was sent including a feature that is not available to that particular user such as offline options.',
            'abuse': 'Username is blocked due to abuse. Either for not following our update specifications or disabled due to violation of the No-IP terms of service. Our terms of service can be viewed here. Client should stop sending updates.',
            '911': 'A fatal error on our side such as a database outage. Retry the update no sooner than 30 minutes.',
        }.get(words[0], 'Unknown response: %s' % response)
        raise NoipApiException(error_message)


def dynamic_update(username, password, hostnames, ipaddress):

    # url as specified here: http://www.noip.com/integrate/request
    url = 'http://dynupdate.no-ip.com/nic/update?%s' % urllib.urlencode({
        'hostname': ','.join(hostnames),
        'myip': ipaddress,
    })
    request = urllib2.Request(url)
    encoded_auth = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
    request.add_header("Authorization", "Basic %s" % encoded_auth)
    request.add_header("User-Agent", "noipy alister@cordiner.net")

    resp = urllib2.urlopen(request)
    body = resp.read()
    for response in body.splitlines():
        handle_api_response(response)


class InterruptableTimer(object):

    def __init__(self, interval, callback):
        self.interval = interval
        self.callback = callback
        self._next_callback_time = 0
        self._is_started = False

    def start(self):
        self._is_started = True
        while self._is_started:
            now = time.time()
            if now >= self._next_callback_time:
                self.callback()
                self._next_callback_time = now + (self.interval * 60)
            time.sleep(1)

    def stop(self):
        self._next_callback_time = 0
        self._is_started = False


class Config(object):

    def __init__(self, filename):
        self.filename = filename
        self.username = self.password = self.hostnames = self.interval = None

    def load(self):
        config_parser = ConfigParser.SafeConfigParser()
        config_parser.read([self.filename])
        try:
            config_items = dict(config_parser.items("noip"))
        except ConfigParser.NoSectionError:
            raise ValueError("Config file is missing a [noip] section")
        try:
            self.username = config_items.pop('username')
            self.password = config_items.pop('password')
            self.hostnames = config_items.pop('hostnames').split()
        except KeyError as ex:
            raise ValueError("Config file is missing '%s'" % ex.args)
        for hostname in self.hostnames:
            if not is_valid_hostname(hostname):
                raise ValueError("Invalid hostname: %r" % hostname)
        try:
            self.interval = int(config_items.pop('interval', DEFAULT_INTERVAL))
        except ValueError:
            raise ValueError("Invalid interval value: %r" % config_items['interval'])
        if config_items:
            raise ValueError("Config file contains unknown item '%s'" % config_items.keys()[0])

    def create(self):

        if os.path.isfile(self.filename):
            resp = None
            while resp != 'y':
                resp = raw_input("Warning: %s already exists. Overwrite? [Yn] " % self.filename).lower() or "y"
                if resp == 'n':
                    return False

        username = None
        while not username:
            username = raw_input("no-ip.com username: ")
        password = None
        while not password:
            password = getpass("no-ip.com password: ")
        hostname = None
        while not hostname:
            hostname = raw_input("no-ip.com hostname (e.g. myhost.no-ip.org): ")

        config = ConfigParser.RawConfigParser()
        config.add_section('noip')
        config.set('noip', 'hostnames', hostname)
        config.set('noip', 'password', password)
        config.set('noip', 'username', username)

        if os.path.isfile(self.filename):
            os.remove(self.filename)
        with closing(os.open(self.filename, os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o600)) as fd:
            with os.fdopen(fd, 'w') as fileobj:
                config.write(fileobj)
        return True


class NoIpy(object):

    def __init__(self, config):
        self.config = config
        self.timer = None
        self.exit_status = 0
        self._last_ipaddress = None

    def timer_callback(self):
        ipaddress = get_public_ip()
        if ipaddress == self._last_ipaddress:
            logging.info("No change of public IP address %s" % ipaddress)
        else:
            logging.info("Updating public IP %s" % ipaddress)
            try:
                dynamic_update(self.config.username, self.config.password, self.config.hostnames, ipaddress)
            except (urllib2.HTTPError, NoipApiException) as ex:
                self.fail(ex.message or str(ex))
            self._last_ipaddress = ipaddress

    def start(self):
        try:
            self.config.load()
        except ValueError as ex:
            self.fail(str(ex))
        else:
            self.timer = InterruptableTimer(self.config.interval, self.timer_callback)
            self.timer.start()
        return self.exit_status

    def stop(self):
        if self.timer is not None:
            self.timer.stop()

    def fail(self, msg, exit_status=1):
        logging.error(msg)
        self.exit_status = exit_status
        self.stop()

    def reload(self):
        self.stop()
        self.start()

    def signal_handler(self, signum, frame):
        if signum == signal.SIGHUP:
            self.reload()
        elif signum == signal.SIGINT:
            self.stop()
        else:
            raise ValueError("Unhandled exception %d" % signum)


class NoipyTestCase(unittest.TestCase):

    def test_load_bad_config(self):
        noipy = NoIpy()


def main(argv=sys.argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='config file (optional)',
                        metavar='filename', dest='config_file', default=os.path.expanduser("~/.noipy.cfg"))
    parser.add_argument('-C', '--create-config', help='create a new config file',
                        action='store_true')
    args = parser.parse_args(argv[1:])

    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(funcName)s:%(lineno)d %(levelname)s - %(message)s")

    logging.debug("Using config file: %s", args.config_file)

    config = Config(args.config_file)
    if args.create_config:
        if config.create():
            print "Created config file %s" % args.config_file
            return 0
        else:
            return 1
    else:
        noipy = NoIpy(config)
        signal.signal(signal.SIGHUP, lambda *_: noipy.reload())
        signal.signal(signal.SIGINT, lambda *_: noipy.stop())
        try:
            exit(noipy.start())
        except Exception as ex:
            logging.exception(ex.message or str(ex) or "Unknown %s" % type(ex).__name__)
            exit(1)


if __name__ == '__main__':
    exit(main())
