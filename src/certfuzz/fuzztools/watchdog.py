'''
Created on Oct 25, 2010

@organization: cert.org
'''

import logging
import platform

from certfuzz.fuzztools import subprocess_helper as subp


system = platform.system()

supported_systems = ['Linux']

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class WatchDog:
    def __init__(self, file, timeout):
        self.file = file
        self.timeout = timeout
        self.cmdline = self._get_cmdline()

    def _get_cmdline(self):
        # we're just going to overwrite /etc/watchdog.conf
        # hope that's okay
        template = 'sudo sh -c "echo file=%s > /etc/watchdog.conf'
        template += ' && echo change=%s >> /etc/watchdog.conf'
        template += ' && /etc/init.d/watchdog restart"'
        return template % (self.file, self.timeout)

    def go(self):
        '''
        Sets a watchdog timer with <timeout>
        '''
        # short-circuit on unsupported systems
        if not system in supported_systems:
            logger.warning('WatchDog does not support %s', system)
            return

        subp.run_without_timer(self.cmdline)
