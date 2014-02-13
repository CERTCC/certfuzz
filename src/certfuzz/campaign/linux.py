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
import shutil
import tempfile
from certfuzz.fuzztools.filetools import mkdir_p
from ..fuzztools import subprocess_helper as subp
import itertools
from certfuzz.fuzztools.ppid_observer import check_ppid
import traceback


logger = logging.getLogger(__name__)


class Campaign(object):
    def __init__(self, cfg_path=None, scriptpath=None):
        # Read the cfg file
        self.cfg_path = cfg_path
        logger.info('Reading config from %s', cfg_path)
        self.cfg = cfg_helper.read_config_options(cfg_path)
        self.scriptpath = scriptpath
        self.seedfile_set = None
        self.hashes = []
        self.working_dir = None
        self.debug = True

    def __enter__(self):
        self._setup_dirs()

        # setup working dir
        self.working_dir = tempfile.mkdtemp(prefix='campaign_', dir=self.cfg.local_dir)
        logger.debug('workdir=%s', self.working_dir)

        # set up local logging
        self._setup_logfile(logdir=self.cfg.local_dir, backup_count=3)

        # set up remote logging
        self._setup_logfile(logdir=self.cfg.output_dir, level=logging.INFO, max_bytes=1e7)

        self._check_for_script()
        self._copy_config()
        self._start_process_killer()
        self._set_unbuffered_stdout()
        self._create_seedfile_set()
        if self.cfg.watchdogtimeout:
            self._setup_watchdog()

        # flag to indicate whether this is a fresh script start up or not
        self.first_chunk = True

        check_ppid()

        return self

    def __exit__(self, etype, value, mytraceback):
        handled = False
        if etype is KeyboardInterrupt:
            logger.warning('Keyboard interrupt - exiting')
            handled = True
        if etype is CampaignScriptError:
            logger.warning("Please configure BFF to fuzz a binary.  Exiting...")
            handled = True

        # if etype not set or if we handled it
        if not etype or handled:
            shutil.rmtree(self.working_dir)
        elif etype:
            logger.debug('Unhandled exception:')
            logger.debug('  type: %s', etype)
            logger.debug('  value: %s', value)
            for l in traceback.format_exception(etype, value, mytraceback):
                logger.debug(l.rstrip())

        if self.debug and etype and not handled:
            # leave it behind if we're in debug mode
            # and there's a problem
            logger.debug('Skipping cleanup since we are in debug mode.')
        else:
            self._cleanup_workdir()

        return handled

    def _cleanup_workdir(self):
        try:
            shutil.rmtree(self.working_dir)
        except:
            pass

        if os.path.exists(self.working_dir):
            logger.warning("Unable to remove campaign working dir: %s", self.working_dir)
        else:
            logger.debug('Removed campaign working dir: %s', self.working_dir)


    def _setup_dirs(self):
        logger.debug('setup dirs')
        paths = [self.cfg.local_dir,
                 self.cfg.cached_objects_dir,
                 self.cfg.seedfile_local_dir,
                 self.cfg.output_dir,
                 self.cfg.seedfile_output_dir,
                 self.cfg.crashers_dir,
                 self.cfg.testscase_tmp_dir,
                 ]

        for d in paths:
            if not os.path.exists(d):
                logger.debug('Creating dir %s', d)
                mkdir_p(d)

    def _setup_logfile(self, logdir, log_basename='bff.log', level=logging.DEBUG,
                      max_bytes=1e8, backup_count=5):
        '''
        Creates a log file in <logdir>/<log_basename> at level <level>
        @param logdir: the directory where the log file should reside
        @param log_basename: the basename of the logfile (defaults to 'bff_log.txt')
        @param level: the logging level (defaults to logging.DEBUG)
        '''
        filetools.make_directories(logdir)
        logfile = os.path.join(logdir, log_basename)
        hdlr = RotatingFileHandler(logfile, maxBytes=max_bytes, backupCount=backup_count)
        formatter = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")

        hdlr.setLevel(level)
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)

        logger.info('Logging %s at %s', logging.getLevelName(level), logfile)

    def _copy_config(self):
        logger.debug('copy config')

        filetools.copy_file(self.cfg_path, self.cfg.output_dir)

    def _set_unbuffered_stdout(self):
        '''
        Reopens stdout with a buffersize of 0 (unbuffered)
        @rtype: none
        '''
        logger.debug('set unbuffered stdout')
        # reopen stdout file descriptor with write mode
        # and 0 as the buffer size (unbuffered)
        sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

    def _start_process_killer(self):
        logger.debug('start process killer')
        # set up and spawn the process killer
        killscript = os.path.abspath(os.path.expanduser('~/bff/killproc.sh'))
        ProcessKiller(killscript, self.cfg.killprocname, self.cfg.killproctimeout).go()
        logger.debug("Process killer started: %s %s %d", killscript, self.cfg.killprocname, self.cfg.killproctimeout)

    def _cache_prg(self):
        logger.debug('cache program')
        sf = self.seedfile_set.next_item()

        # Run the program once to cache it into memory
        fullpathorig = self.cfg.full_path_original(sf.path)
        cmdargs = self.cfg.get_command_list(fullpathorig)
        subp.run_with_timer(cmdargs, self.cfg.progtimeout * 8, self.cfg.killprocname, use_shell=True)

        # Give target time to die
        time.sleep(1)

    def _setup_watchdog(self):
        logger.debug('setup watchdog')
        # set up the watchdog timeout within the VM and restart the daemon
        watchdog = WatchDog(self.cfg.watchdogfile,
                            self.cfg.watchdogtimeout)
        # setup our watchdog file toucher
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
        logger.debug('check for script')
        if self.cfg.program_is_script():
            logger.warning("Target application is a shell script.")
            raise CampaignScriptError()
            #cfg.disable_verification()
            #time.sleep(10)

    def _do_interval(self, s1, s2, first_chunk=False):
        # interval.go
        logger.debug('Starting interval %d-%d', s1, s2)
        # wipe the tmp dir clean to try to avoid filling the VM disk
        TmpReaper().clean_tmp()

        sf = self.seedfile_set.next_item()
        r = sf.rangefinder.next_item()
        qf = not first_chunk

        logger.info(STATE_TIMER)

        for s in xrange(s1, s2):
            # Prevent watchdog from rebooting VM.  If /tmp/fuzzing exists and is stale, the machine will reboot
            touch_watchdog_file()
            with Iteration(cfg=self.cfg, seednum=s, seedfile=sf, r=r, workdirbase=self.working_dir, quiet=qf) as iteration:
                iteration.go()

    def go(self):
    # campaign.go
        cfg = self.cfg

        first_chunk = True
        for s in itertools.count(start=cfg.start_seed, step=cfg.seed_interval):
            s1 = s
            s2 = s + cfg.seed_interval
            self._do_interval(s1, s2, first_chunk)
            first_chunk = False
