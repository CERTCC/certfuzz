'''
Created on Jan 15, 2013

@organization: cert.org
'''
import logging
import os
import time
from traceback import format_tb

from certfuzz.android.avd_mgr.errors import OrphanedProcessError


# from .defaults import POLL_INTERVAL
# store pid and ppid at start up, we'll check them later
# to see if we are an orphan
logger = logging.getLogger(__name__)

def _ping_process(pid):
    try:
        # kill -0 is a null signal
        # it will throw an OSError if the process does not exist
        os.kill(pid, 0)
        return True
    except OSError:
        return False

class OrphanCatcher():
    def __init__(self, avd, interval=5, handled_exceptions=None):
        self.avd = avd
        self.interval = interval
        self.handled_errors = set()
        self.handled_errors.add(OrphanedProcessError)
        self.ppid = os.getppid()

        if handled_exceptions is not None:
            for x in handled_exceptions:
                self.handled_errors.add(x)

    def __enter__(self):
        logger.debug('Enter %s runtime context, ppid=%s', self.__class__.__name__, self.ppid)
        return self

    def _orphaned(self):
        # Yeah, she'll tell you she's an orphan after you meet her family.
        return not _ping_process(self.ppid)

    def _poll_once(self):
        if self._orphaned():
            raise OrphanedProcessError('Parent process %d has disappeared' % self.ppid)

        # will raise an AndroidEmulatorError if it's not
        self.avd.check_child_is_running()

    def poll(self):
        logger.info('Waiting to be orphaned...')
        while True:
            self._poll_once()
            time.sleep(self.interval)

    def __exit__(self, etype, value, tb):
        logger.debug('Exit %s runtime context', self.__class__.__name__)

        handled = etype in self.handled_errors

        if etype:
            if handled:
                logger.debug('Handled...%s: %s', etype, value)
            else:
                logger.debug('Not handled...%s: %s', etype, value)
                for line in format_tb(tb):
                    logger.warning(line)

        return handled
