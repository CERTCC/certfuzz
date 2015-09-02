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
        open(self.wdf, 'w').close()

TWDF = Twdf()


def touch_watchdog_file():
    TWDF.func()
