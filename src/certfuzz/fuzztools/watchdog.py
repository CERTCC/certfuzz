'''
Created on Oct 25, 2010

@organization: cert.org
'''

import logging
import platform

import subprocess


system = platform.system()

supported_systems = ['Linux']

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class WatchDog:
    def __init__(self, f, timeout):
        self.file = f
        self.timeout = timeout

        # we're just going to overwrite /etc/watchdog.conf
        # hope that's okay
        self.template = 'sudo sh -c "echo file={} > /etc/watchdog.conf'
        self.template += ' && echo change={} >> /etc/watchdog.conf'
        self.template += ' && /etc/init.d/watchdog restart"'

        self.cmdline = None

    def __enter__(self):
        self._set_cmdline()
        return self

    def __exit__(self, etype, value, traceback):
        handled = False

        if etype is subprocess.CalledProcessError:
            logger.warning('WatchDog startup failed: %s', value)
            handled = True

        return handled

    def _set_cmdline(self):
        self.cmdline = self.template.format(self.file, self.timeout)

    def go(self):
        '''
        Sets a watchdog timer with <timeout>
        '''
        # short-circuit on unsupported systems
        if not system in supported_systems:
            logger.warning('WatchDog does not support %s', system)
            return

        subprocess.check_call(self.cmdline, shell=True)
