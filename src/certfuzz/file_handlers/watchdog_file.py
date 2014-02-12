'''
Created on Feb 12, 2014

@author: adh
'''
import os


class Twdf(object):

    def __init__(self):
        self.func = None
        self.wdf = None
        self.remote_d = None

    def enable(self):
        self.func = self._twdf

    def disable(self):
        self.func = self._noop

    def _noop(self, *_args, **_kwargs):
        pass

    def _twdf(self):
        if os.access(self.remote_d, os.W_OK):
            open(self.wdf, 'w').close()

TWDF = Twdf()

touch_watchdog_file = TWDF.func
