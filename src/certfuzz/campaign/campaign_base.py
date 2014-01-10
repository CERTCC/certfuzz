'''
Created on Oct 23, 2012

The certfuzz.campaign package provides modules to manage fuzzing campaigns,
configurations, and iterations.

@organization: cert.org
'''
import abc
import sys
import os

from . import __version__
from ..fuzztools import filetools


def import_module_by_name(name, logger=None):
    if logger:
        logger.debug('Importing module %s', name)
    __import__(name)
    module = sys.modules[name]
    return module


class CampaignBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, config_file, result_dir=None, campaign_cache=None, debug=False):
        self.config_file = config_file
        self.cached_state_file = campaign_cache
        self.debug = debug
        self._version = __version__

    @abc.abstractmethod
    def __enter__(self):
        return self

    @abc.abstractmethod
    def __exit__(self, etype, value, mytraceback):
        pass

    @abc.abstractmethod
    def __getstate__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def __setstate__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _do_interval(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _do_iteration(self):
        raise NotImplementedError

    @abc.abstractmethod
    def _keep_going(self):
        '''
        Returns True if a campaign should proceed. False otherwise.
        '''
        return True

    @abc.abstractmethod
    def _write_version(self):
        version_file = os.path.join(self.outdir, 'version.txt')
        version_string = 'Results produced by %s v%s' % (__name__, __version__)
        filetools.write_file(version_string, version_file)

    @abc.abstractmethod
    def go(self):
        '''
        Executes a fuzzing campaign. Will continue until either we run out of
        iterations or the user issues a KeyboardInterrupt (ctrl-C).
        '''
        while self._keep_going():
            self._do_interval()
