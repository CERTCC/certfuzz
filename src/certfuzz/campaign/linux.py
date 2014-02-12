'''
Created on Feb 12, 2014

@author: adh
'''

import logging
from logging.handlers import RotatingFileHandler
from optparse import OptionParser
import os
import platform
import sys
import time

from .. import debuggers, file_handlers
from ..analyzers import cw_gmalloc, pin_calltrace, stderr, valgrind
from ..analyzers.callgrind import callgrind
from ..analyzers.callgrind.annotate import annotate_callgrind
from ..analyzers.callgrind.annotate import annotate_callgrind_tree
from ..analyzers.callgrind.errors import CallgrindAnnotateEmptyOutputFileError
from ..analyzers.callgrind.errors import CallgrindAnnotateMissingInputFileError
from ..analyzers.errors import AnalyzerEmptyOutputError
from ..campaign.config import bff_config as cfg_helper
from ..crash.bff_crash import BffCrash
from ..debuggers import crashwrangler  # @UnusedImport
from ..debuggers import gdb  # @UnusedImport
from ..file_handlers.seedfile_set import SeedfileSet
from ..file_handlers.tmp_reaper import TmpReaper
from ..fuzztools import bff_helper as z, filetools, performance
from ..fuzztools.object_caching import cache_state, get_cached_state
from ..fuzztools.process_killer import ProcessKiller
from ..fuzztools.seedrange import SeedRange
from ..fuzztools.state_timer import STATE_TIMER
from ..fuzztools.watchdog import WatchDog
from ..fuzztools.zzuf import Zzuf
from ..fuzztools.zzuflog import ZzufLog
from ..minimizer import MinimizerError, UnixMinimizer as Minimizer
from certfuzz.iteration.linux import Iteration
from certfuzz.campaign.errors import CampaignScriptError
from certfuzz.file_handlers.watchdog_file import TWDF, touch_watchdog_file


logger = logging.getLogger(__name__)


class Campaign(object):
    def __init__(self, cfg_path=None, scriptpath=None):
        # Read the cfg file
        self.cfg_path = cfg_path
        logger.info('Reading config from %s', cfg_path)
        self.cfg = cfg_helper.read_config_options(cfg_path)
        self.scriptpath = scriptpath
        self.seedfile_set = None
        self._last_ppid = None
        self.hashes = []

    def __enter__(self):
        # set up local logging
        self._setup_logfile(self.cfg.local_dir,
                            log_basename='bff.log',
                            level=logging.DEBUG,
                            max_bytes=1e8,
                            backup_count=3)

        # set up remote logging
        self._setup_logfile(self.cfg.output_dir,
                            log_basename='bff.log',
                            level=logging.INFO,
                            max_bytes=1e7,
                            backup_count=5)

        self._check_for_script()
        z.setup_dirs_and_files(self.cfg_path, self.cfg)
        self.start_process_killer(self.scriptpath, self.cfg)
        z.set_unbuffered_stdout()
        self._create_seedfile_set()
        if self.cfg.watchdogtimeout:
            self._setup_watchdog()

        # flag to indicate whether this is a fresh script start up or not
        self.first_chunk = True
        # remember our parent process id so we can tell if it changes later
        self._last_ppid = os.getppid()

        return self

    def __exit__(self, etype, value, mytraceback):
        handled = False
        if etype is CampaignScriptError:
            logger.warning("Please configure BFF to fuzz a binary.  Exiting...")
            handled = True

        return handled

    def start_process_killer(self):
        cfg = self.cfg
        # set up and spawn the process killer
        killscript = cfg.get_killscript_path(self.scriptpath)
        ProcessKiller(killscript, cfg.killprocname, cfg.killproctimeout).go()
        logger.debug("Process killer started: %s %s %d", killscript, cfg.killprocname, cfg.killproctimeout)

    def _cache_prg(self):
        sf = self.seedfile_set.next_item()
        # Run the program once to cache it into memory
        z.cache_program_once(self.cfg, sf.path)
        # Give target time to die
        time.sleep(1)

    def touch_watchdog_file(self):
        if self.cfg.watchdogtimeout:
            # this one just checks the permission
            if os.access(self.cfg.remote_dir, os.W_OK):
                # equivalent to 'touch cfg.watchdogfile'
                open(self.cfg.watchdogfile, 'w').close()

    def _setup_watchdog(self):
        # set up the watchdog timeout within the VM and restart the daemon
        watchdog = WatchDog(self.cfg.watchdogfile,
                            self.cfg.watchdogtimeout)
        if self.cfg.watchdogtimeout:
            TWDF.remote_d = self.cfg.remote_dir
            TWDF.wdf = self.cfg.watchdogfile
            TWDF.enable()

        touch_watchdog_file()
        watchdog.go()

    def _create_seedfile_set(self):
        logger.info('Building seedfile set')
        sfs_logfile = os.path.join(self.cfg.seedfile_output_dir, 'seedfile_set.log')
        with SeedfileSet(campaign_id=self.cfg.campaign_id,
                         originpath=self.cfg.seedfile_origin_dir,
                         localpath=self.cfg.seedfile_local_dir,
                         outputpath=self.cfg.seedfile_output_dir,
                         logfile=sfs_logfile,
                         ) as sfset:
            self.seedfile_set = sfset


    def _check_for_script(self):
        if self.cfg.program_is_script():
            logger.warning("Target application is a shell script.")
            raise CampaignScriptError()
            #cfg.disable_verification()
            #time.sleep(10)

    def _check_ppid(self):
        # check parent process id
        _ppid_now = os.getppid()
        if not _ppid_now == self._last_ppid:
            logger.warning('Parent process ID changed from %d to %d', self._last_ppid, _ppid_now)
            self._last_ppid = _ppid_now

    def _do_interval(self):
        s1 = self.s1
        s2 = self.s2
        # interval.go
        logger.debug('Starting interval %d-%d', s1, s2)
        # wipe the tmp dir clean to try to avoid filling the VM disk
        TmpReaper().clean_tmp()

        sf = self.seedfile_set.next_item()
        r = sf.rangefinder.next_item()

        logger.info(STATE_TIMER)

        for s in xrange(s1, s2):
            # Prevent watchdog from rebooting VM.  If /tmp/fuzzing exists and is stale, the machine will reboot
            self.touch_watchdog_file()
            with Iteration(seednum=s, seedfile=sf, r=r) as iteration:
                iteration.go()

    def go(self):
    # campaign.go
        cfg = self.cfg

        for s in xrange(cfg.start_seed, cfg.max_seed, cfg.seed_interval):
            self.s1 = s
            self.s2 = s + cfg.seed_interval
            self._do_interval()
