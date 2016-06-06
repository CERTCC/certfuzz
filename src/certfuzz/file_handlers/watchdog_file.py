'''
Created on Feb 12, 2014

@author: adh
'''
import os
import logging
from certfuzz.fuzztools.filetools import read_text_file

logger = logging.getLogger(__name__)

_wdf = '/tmp/bff_watchdog'


class Twdf(object):

    def __init__(self):
        # disable watchdog by default
        self.func = self._noop

        self.wdf = _wdf
        self.remote_d = None
        self.use_watchdog = False
        self._enable_iff_compat()

    def enable(self):
        self.func = self._twdf

    def disable(self):
        self.func = self._noop

    def _noop(self, *_args, **_kwargs):
        pass

    def _twdf(self):
        open(self.wdf, 'w').close()

    def remove_wdf(self):
        try:
            os.remove(self.wdf)
        except OSError:
            # No watchdog file to remove
            pass

    def _enable_iff_compat(self):
        '''
        enables watchdog if we're running on ubufuzz
        '''
        hostname = self._check_hostname()
        if 'ubufuzz' in hostname:
            logger.debug('%s is watchdog compatible' % hostname)
            self.use_watchdog = True
            self.enable()

        logger.debug('%s is not watchdog compatible' % hostname)
        self.disable()

    def _check_hostname(self):
        hostname = 'System'
        try:
            hostname = read_text_file('/etc/hostname').rstrip()
        except:
            logger.debug('Error determining hostname')

        return hostname.lower()


TWDF = Twdf()


def touch_watchdog_file():
    TWDF.func()
