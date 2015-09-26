#!/usr/bin/env python

import argparse
import ConfigParser
import base64
from getpass import getpass
from httplib import UNAUTHORIZED
import logging
import os
import re
from sched import scheduler
import sys
import time
import urllib
import urllib2

import daemonocle

CONNECT_TIMEOUT = 5
DEFAULT_MIN_INTERVAL = 30
DEFAULT_MAX_INTERVAL = 360
DEFAULT_PID_FILE = os.path.expanduser("~/.noipclient.pid")
DEFAULT_CONFIG_FILE = os.path.expanduser("~/.noipclient.cfg")
DEFAULT_LOG_FILE = os.path.expanduser("~/.noipclient.log")
SCRIPT_DIR = os.path.dirname(__file__)
VERBOSE_LOG_FORMATTER = logging.Formatter("pid=%(process) 6d %(asctime)s %(funcName)s:%(lineno)d %(levelname)s - %(message)s")
BRIEF_LOG_FORMATTER = logging.Formatter("%(message)s")
# error messages from: http://www.noip.com/integrate/response
NOIP_ERROR_MESSAGES = {
    'nohost': 'Hostname supplied does not exist under specified account, client exit and require user to enter new login credentials before performing an additional request.',
    'badauth': 'Invalid username password combination',
    'badagent': 'Client disabled. Client should exit and not perform any more updates without user intervention.',
    '!donator': 'An update request was sent including a feature that is not available to that particular user such as offline options.',
    'abuse': 'Username is blocked due to abuse. Either for not following our update specifications or disabled due to violation of the No-IP terms of service. Our terms of service can be viewed here. Client should stop sending updates.',
    '911': 'A fatal error on our side such as a database outage. Retry the update no sooner than 30 minutes.',
}


class NoipApiException(Exception):
    pass


def prompt_yes_no(question):
    resp = None
    while resp != 'y':
        resp = raw_input("%s [Yn] " % question).lower() or "y"
        if resp == 'n':
            return False
    return True


class Config(object):

    def __init__(self):
        self.username = self.password = self.hostnames = self.min_interval = self.max_interval = self.pid_file = self.log_file = None

    @classmethod
    def from_file(cls, filename):
        config_parser = ConfigParser.SafeConfigParser()

        if not config_parser.read(filename):
            print "Config file %s could not be loaded" % filename
            return None
        config = cls()
        try:
            config_items = dict(config_parser.items("noip"))
        except ConfigParser.NoSectionError:
            raise ValueError("Config file %s is missing a [noip] section" % filename)
        try:
            config.username = config_items.pop('username')
            config.password = config_items.pop('password')
            config.hostnames = config_items.pop('hostnames').split()
        except KeyError as ex:
            raise ValueError("Config file %s is missing '%s'" % (filename, ex.args[0]))
        for hostname in config.hostnames:
            if not cls.is_valid_hostname(hostname):
                raise ValueError("Invalid hostname: %r" % hostname)
        try:
            config.min_interval = int(config_items.pop('min_interval', DEFAULT_MIN_INTERVAL))
        except ValueError:
            raise ValueError("Invalid min_interval value: %r" % config_items['min_interval'])
        try:
            config.max_interval = int(config_items.pop('max_interval', DEFAULT_MAX_INTERVAL))
        except ValueError:
            raise ValueError("Invalid max_interval value: %r" % config_items['max_interval'])
        config.pid_file = config_items.pop('pid_file', DEFAULT_PID_FILE)
        config.log_file = config_items.pop('log_file', DEFAULT_LOG_FILE)
        if config_items:
            raise ValueError("Config file %s contains unknown item '%s'" % (filename, config_items.keys()[0]))
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

    @staticmethod
    def is_valid_hostname(hostname):
        # copied from: http://stackoverflow.com/a/2532344/393304
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]  # strip exactly one dot from the right, if present
        allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    def __str__(self):
        return "Config(username=%r, hostnames=%r, min_interval=%r, max_interval=%r)" % (
            self.username, self.hostnames, self.min_interval, self.max_interval
        )


class NoIpClient(object):

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.last_ipaddress = self.last_update_time = None
        self.scheduler = scheduler(time.time, time.sleep)
        sys.excepthook = self.handle_exception

    def run(self):
        self.logger.debug("Started noipclient client")
        self.scheduler.enter(0, 0, self.timer_callback, ())
        self.scheduler.run()

    def timer_callback(self):

        # check if the IP address needs to be updated
        ipaddress = self.get_public_ip()
        self.logger.debug("Public IP address is: %s" % ipaddress)
        update_required = True
        now = time.time()
        if self.last_ipaddress is None:
            self.logger.debug("Update require since this is the first run")
        elif ipaddress != self.last_ipaddress:
            self.logger.debug("Update require since IP address has changed")
        elif self.last_update_time and now >= self.last_update_time + (self.config.max_interval * 60):
            self.logger.debug("Update required since at least %d minutes since the last update", self.config.max_interval)
        else:
            self.logger.debug("Update not required since IP address has not changed")
            update_required = False

        # update IP address using the noip.com API
        if update_required:
            # url as specified here: http://www.noip.com/integrate/request
            url = 'http://dynupdate.no-ip.com/nic/update?%s' % urllib.urlencode({
                'hostname': ','.join(self.config.hostnames),
                'myip': ipaddress,
            })
            request = urllib2.Request(url)
            encoded_auth = base64.encodestring('%s:%s' % (self.config.username, self.config.password)).replace('\n', '')
            request.add_header("Authorization", "Basic %s" % encoded_auth)
            request.add_header("User-Agent", "noipclient alister@cordiner.net")
            try:
                resp = urllib2.urlopen(request)
            except urllib2.HTTPError as ex:
                if ex.code == UNAUTHORIZED:
                    self.logger.error("Incorrect username/password")
                    exit(1)
                self.logger.exception("Unable to update IP address")
            else:
                body = resp.read()
                for response in body.splitlines():
                    self.logger.debug("Received response: %s", response)
                    words = response.split()
                    if words[0] not in ('good', 'nochg'):
                        error_message = NOIP_ERROR_MESSAGES.get(words[0], 'Unknown response: %s' % response)
                        raise NoipApiException(error_message)
                self.last_update_time = now
                self.last_ipaddress = ipaddress

        # schedule the next update
        next_update_time = now + (self.config.min_interval * 60)
        if self.last_update_time:
            next_update_time = min(next_update_time, self.last_update_time + (self.config.max_interval * 60))
        self.scheduler.enterabs(next_update_time, 0, self.timer_callback, ())

    def stop(self, message, code):
        self.logger.debug("Stopped noipclient client: %s", message)
        for event in self.scheduler.queue:
            self.scheduler.cancel(event)

    @staticmethod
    def get_public_ip():
        resp = urllib2.urlopen('http://ip1.dynupdate.no-ip.com/')
        return resp.read()

    def handle_exception(self, *exc_info):
        self.logger.error("Shutting down due to exception", exc_info=exc_info)


def main(argv=sys.argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='config file (default: %(default)s)', metavar='filename',
                        dest='config_file', default=DEFAULT_CONFIG_FILE)
    subparsers = parser.add_subparsers(dest='action')
    subparser_start = subparsers.add_parser('start')
    subparser_start.add_argument('--no-daemon', action='store_true')
    subparsers.add_parser('stop')
    subparsers.add_parser('restart')
    subparsers.add_parser('status')
    args = parser.parse_args(argv[1:])

    handler_stderr = logging.StreamHandler()
    handler_stderr.setLevel(logging.INFO)
    handler_stderr.setFormatter(BRIEF_LOG_FORMATTER)

    logger = logging.getLogger('noipclient')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler_stderr)
    logger.debug("args: %s", args)

    if args.action == 'start' and not os.path.exists(args.config_file):
        if not prompt_yes_no("Config file %s not found. Create one now?" % args.config_file):
            return
        elif not Config.create(args.config_file):
            return
    config = Config.from_file(args.config_file)

    handler_file = logging.FileHandler(config.log_file)
    handler_file.setLevel(logging.DEBUG)
    handler_file.setFormatter(VERBOSE_LOG_FORMATTER)
    logger.addHandler(handler_file)

    app = NoIpClient(config, logger)
    if args.action == 'start' and args.no_daemon:
        app.run()
    else:
        daemon = daemonocle.Daemon(
            worker=app.run,
            shutdown_callback=app.stop,
            pidfile=config.pid_file,
        )
        daemon.do_action(args.action)

if __name__ == '__main__':
    main(sys.argv)
