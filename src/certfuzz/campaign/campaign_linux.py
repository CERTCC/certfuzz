'''
Created on Feb 12, 2014

@author: adh
'''

import itertools
import logging
import os
import shutil
import sys
import tempfile
import time
import traceback

from certfuzz.campaign.campaign_meta import CampaignMeta
from certfuzz.campaign.config import bff_config as cfg_helper
from certfuzz.campaign.errors import CampaignScriptError
from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.debuggers.registration import verify_supported_platform
from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.file_handlers.tmp_reaper import TmpReaper
from certfuzz.fuzztools import subprocess_helper as subp
from certfuzz.fuzztools.filetools import mkdir_p, copy_file
from certfuzz.fuzztools.process_killer import ProcessKiller
from certfuzz.fuzztools.state_timer import STATE_TIMER
from certfuzz.fuzztools.watchdog import WatchDog
from certfuzz.file_handlers.watchdog_file import TWDF, touch_watchdog_file
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.iteration.linux import Iteration


logger = logging.getLogger(__name__)


class LinuxCampaign(CampaignMeta):
    def __init__(self, config_file=None, result_dir=None, debug=False):
        # Read the cfg file
        self.cfg_path = config_file
        self.result_dir = result_dir
        self.debug = debug
        logger.info('Reading config from %s', config_file)
        self.cfg = cfg_helper.read_config_options(config_file)
        self.seedfile_set = None
        self.hashes = []
        self.workdirbase = self.cfg.testscase_tmp_dir
        self.working_dir = None
        self.crashes_seen = set()

        # give up if we don't have a debugger
        verify_supported_platform()

    def __enter__(self):

        self._setup_dirs()

        # setup working dir
        self.working_dir = tempfile.mkdtemp(prefix='campaign_', dir=self.workdirbase)
        logger.debug('workdir=%s', self.working_dir)

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
        handled = not etype

        if etype is KeyboardInterrupt:
            logger.warning('Keyboard interrupt - exiting')
            handled = True
        if etype is CampaignScriptError:
            logger.warning("Please configure BFF to fuzz a binary.  Exiting...")
            handled = True

        if handled:
            self._cleanup_workdir()
        elif self.debug:
            # Not handled, debug set

            # leave it behind if we're in debug mode
            # and there's a problem
            logger.debug('Skipping cleanup since we are in debug mode.')
        else:
            # Not handled, debug not set

            logger.debug('Unhandled exception:')
            logger.debug('  type: %s', etype)
            logger.debug('  value: %s', value)
            for l in traceback.format_exception(etype, value, mytraceback):
                logger.debug(l.rstrip())

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

    def _copy_config(self):
        logger.debug('copy config')

        copy_file(self.cfg_path, self.cfg.output_dir)

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
        with ProcessKiller(self.cfg.killprocname, self.cfg.killproctimeout) as pk:
            pk.go()

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

    def _crash_is_unique(self, crash_id, exploitability='UNKNOWN'):
        '''
        If crash_id represents a new crash, add the crash_id to crashes_seen
        and return True. Otherwise return False.

        @param crash_id: the crash_id to look up
        @param exploitability: not used at this time
        '''
        if not crash_id in self.crashes_seen:
            self.crashes_seen.add(crash_id)
            logger.debug("%s did not exist in cache, crash is unique", crash_id)
            return True

        logger.debug('%s was found, not unique', crash_id)
        return False

    def __getstate__(self):
        pass

    def __setstate__(self):
        pass

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
            with Iteration(cfg=self.cfg, seednum=s, seedfile=sf, r=r,
                           workdirbase=self.working_dir, quiet=qf,
                           uniq_func=self._crash_is_unique,
                           sf_set=self.seedfile_set,
                           rf=sf.rangefinder) as iteration:
                iteration.go()

    def _do_iteration(self):
        pass

    def _keep_going(self):
        pass

    def _write_version(self):
        pass

    def go(self):
    # campaign.go
        cfg = self.cfg

        first_chunk = True
        for s in itertools.count(start=cfg.start_seed, step=cfg.seed_interval):
            s1 = s
            s2 = s + cfg.seed_interval
            self._do_interval(s1, s2, first_chunk)
            first_chunk = False
