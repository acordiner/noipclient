#!/usr/bin/env python

import argparse
import ConfigParser
import base64
from getpass import getpass
import logging
import urllib
import urllib2
import socket
import time
import signal
import sys
import os
import re

import daemonocle

CONNECT_TIMEOUT = 5
DEFAULT_INTERVAL = 30
DEFAULT_PIDFILE = '/tmp/noipy.pid'
DEFAULT_CONFIG_FILES = (
    os.path.expanduser("~/.noipy.cfg"),
    '/etc/noip.cfg',
)
SCRIPT_DIR = os.path.dirname(__file__)
VERBOSE_LOG_FORMATTER = logging.Formatter("pid=%(process) 6d %(asctime)s %(funcName)s:%(lineno)d %(levelname)s - %(message)s")
BRIEF_LOG_FORMATTER = logging.Formatter("%(message)s")


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

    def __init__(self, filenames):
        self.filenames = filenames
        self.username = self.password = self.hostnames = self.interval = self.pidfile = None

    @staticmethod
    def prompt_yes_no(question):
        resp = None
        while resp != 'y':
            resp = raw_input("%s [Yn] " % question).lower() or "y"
            if resp == 'n':
                return False
        return True

    @classmethod
    def from_file(cls, filenames):
        config_parser = ConfigParser.SafeConfigParser()
        if not any(os.path.exists(filename) for filename in filenames):
            if not cls.prompt_yes_no("Config file not found. Create one now?"):
                return None
            elif not cls.create(DEFAULT_CONFIG_FILES[0]):
                return None

        loaded_filenames = config_parser.read(filenames)
        if not loaded_filenames:
            print "Config file could not be loaded: %s" % ', '.join(filenames)
            return None
        config = cls(filenames)
        try:
            config_items = dict(config_parser.items("noip"))
        except ConfigParser.NoSectionError:
            raise ValueError("Config file is missing a [noip] section")
        try:
            config.username = config_items.pop('username')
            config.password = config_items.pop('password')
            config.hostnames = config_items.pop('hostnames').split()
        except KeyError as ex:
            raise ValueError("Config file is missing '%s'" % (ex.args[0],))
        for hostname in config.hostnames:
            if not is_valid_hostname(hostname):
                raise ValueError("Invalid hostname: %r" % hostname)
        try:
            config.interval = int(config_items.pop('interval', DEFAULT_INTERVAL))
        except ValueError:
            raise ValueError("Invalid interval value: %r" % config_items['interval'])
        config.pidfile = config_items.pop('pidfile', DEFAULT_PIDFILE)
        if config_items:
            raise ValueError("Config file contains unknown item '%s'" % (config_items.keys()[0],))
        return config

    @staticmethod
    def create(filename):

        if os.path.isfile(filename):
            resp = None
            while resp != 'y':
                resp = raw_input("Warning: %s already exists. Overwrite? [Yn] " % filename).lower() or "y"
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

        with open(filename, 'w') as fp:
            config.write(fp)
        return True

    def __str__(self):
        return "Config(username=%r, hostnames=%r, interval=%r)" % (
            self.username, self.hostnames, self.interval
        )


class NoIpy(object):

    def __init__(self, config, logger):
        self.logger = logger
        self.config = config
        self.timer = None
        self.exit_status = 0
        self._last_ipaddress = None
        self.logger.debug("Using config: %s", config)

    def timer_callback(self):
        ipaddress = get_public_ip()
        if ipaddress == self._last_ipaddress:
            self.logger.info("No change of public IP address %s" % ipaddress)
        else:
            self.logger.info("Updating public IP %s" % ipaddress)
            # try:
            #     dynamic_update(self.config.username, self.config.password, self.config.hostnames, ipaddress)
            # except (urllib2.HTTPError, NoipApiException) as ex:
            #     self.fail(ex.message or str(ex))
            self._last_ipaddress = ipaddress

    def terminate(self):
        if self.timer is not None:
            self.timer.stop()

    def fail(self, msg, exit_status=1):
        self.logger.error(msg)
        self.exit_status = exit_status
        self.terminate()

    def signal_handler(self, signum, frame):
        if signum == signal.SIGINT or signum == signal.SIGTERM:
            self.terminate()
        else:
            raise ValueError("Unhandled exception %d" % signum)

    def run(self):
        self.logger.debug("Running noipy client")
        self.timer = InterruptableTimer(self.config.interval, self.timer_callback)
        self.timer.start()
        return self.exit_status

    def stop(self, message, code):
        logging.info('self.stopping = %r, self.running = %r, message = %r, code = %r', self.stopping, self.running, message, code)


def main(argv=sys.argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='config file (optional)', metavar='filename', dest='config_files',
                        action='append', default=DEFAULT_CONFIG_FILES)
    subparsers = parser.add_subparsers(dest='action')
    subparser_start = subparsers.add_parser('start')
    subparser_start.add_argument('--no-daemon', action='store_true')
    subparsers.add_parser('stop')
    subparsers.add_parser('status')
    args = parser.parse_args(argv[1:])

    handler_stderr = logging.StreamHandler()
    handler_stderr.setLevel(logging.INFO)
    handler_stderr.setFormatter(BRIEF_LOG_FORMATTER)

    logger = logging.getLogger('noipy')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler_stderr)
    logger.debug("args: %s", args)

    config = Config.from_file(args.config_files)

    handler_file = logging.FileHandler('output.log')  # TODO: log path should be configurable
    handler_file.setLevel(logging.DEBUG)
    handler_file.setFormatter(VERBOSE_LOG_FORMATTER)
    logger.addHandler(handler_file)

    app = NoIpy(config, logger)
    if args.action == 'start' and args.no_daemon:
        app.run()
    else:
        daemon = daemonocle.Daemon(
            worker=app.run,
            shutdown_callback=app.stop,
            pidfile=os.path.join(SCRIPT_DIR, 'daemonocle_example.pid'),
        )
        daemon.do_action(args.action)

if __name__ == '__main__':
    main(sys.argv)