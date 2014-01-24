'''
Created on Jan 13, 2014

@author: adh
'''
__version__ = '2.8'

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
from ..fuzztools.state_timer import StateTimer
from ..fuzztools.watchdog import WatchDog
from ..fuzztools.zzuf import Zzuf
from ..fuzztools.zzuflog import ZzufLog
from ..minimizer import MinimizerError, UnixMinimizer as Minimizer


DEBUG = True

SEED_INTERVAL = 500

#SEED_TS = performance.TimeStamper()
#START_SEED = 0

STATE_TIMER = StateTimer()

logger = logging.getLogger()
logger.name = 'bff'
logger.setLevel(0)


#def get_rate(current_seed):
#    seeds = current_seed - START_SEED
#    rate = seeds / SEED_TS.since_start()
#    return rate


def get_uniq_logger(logfile):
    l = logging.getLogger('uniq_crash')
    if len(l.handlers) == 0:
        hdlr = logging.FileHandler(logfile)
        l.addHandler(hdlr)
    return l


def determine_uniqueness(crash, hashes):
    '''
    Gets the crash signature, then compares it against known crashes.
    Sets crash.is_unique = True if it is new
    '''

    # short-circuit on crashes with no signature
    if not crash.signature:
        logger.warning('Crash has no signature, cleaning up')
        crash.delete_files()
        return

    if crash.signature in hashes:
        crash.is_unique = False
        return

    # fall back to checking if the crash directory exists
    crash_dir_found = filetools.find_or_create_dir(crash.result_dir)

    crash.is_unique = not crash_dir_found


def analyze_crasher(cfg, crash):
    '''
    Runs multiple analyses and collects data about a crash. Returns a list of other crashes
    encountered during the process of analyzing the current crash.
    @param cfg: A BFF config object
    @param crash: A crash object
    @return: a list of Crasher objects
    '''
    other_crashers_found = []

    dbg_out_file_orig = crash.dbg.file
    logger.debug('Original debugger file: %s', dbg_out_file_orig)

    if cfg.minimizecrashers:
        STATE_TIMER.enter_state('minimize_testcase')
        # try to reduce the Hamming Distance between the crasher file and the known good seedfile
        # crash.fuzzedfile will be replaced with the minimized result
        try:
            with Minimizer(cfg=cfg, crash=crash, bitwise=False,
                           seedfile_as_target=True, confidence=0.999,
                           tempdir=cfg.local_dir, maxtime=cfg.minimizertimeout
                           ) as minimizer:
                minimizer.go()
                other_crashers_found.extend(minimizer.other_crashes.values())
        except MinimizerError, e:
            logger.warning('Unable to minimize %s, proceeding with original fuzzed crash file: %s', crash.signature, e)
            minimizer = None

    touch_watchdog_file(cfg)
    # calculate the hamming distances for this crash
    # between the original seedfile and the minimized fuzzed file
    crash.calculate_hamming_distances()

    if cfg.minimize_to_string:
        STATE_TIMER.enter_state('minimize_testcase_to_string')
        # Minimize to a string of 'x's
        # crash.fuzzedfile will be replaced with the minimized result
        try:
            with Minimizer(cfg=cfg, crash=crash, bitwise=False,
                           seedfile_as_target=False, confidence=0.9,
                           tempdir=cfg.local_dir, maxtime=cfg.minimizertimeout
                           ) as min2string:
                min2string.go()
                other_crashers_found.extend(min2string.other_crashes.values())
        except MinimizerError, e:
            logger.warning('Unable to minimize %s, proceeding with original fuzzed crash file: %s', crash.signature, e)
            min2string = None
    touch_watchdog_file(cfg)

    STATE_TIMER.enter_state('analyze_testcase')

    # get one last debugger output for the newly minimized file
    if crash.pc_in_function:
        # change the debugger template
        crash.set_debugger_template('complete')
    else:
        # use a debugger template that specifies fixed offsets from $pc for disassembly
        crash.set_debugger_template('complete_nofunction')
    logger.info('Getting complete debugger output for crash: %s', crash.fuzzedfile.path)
    crash.get_debug_output(crash.fuzzedfile.path)

    if dbg_out_file_orig != crash.dbg.file:
        # we have a new debugger output
        # remove the old one
        filetools.delete_files(dbg_out_file_orig)
        if os.path.exists(dbg_out_file_orig):
            logger.warning('Failed to remove old debugger file %s', dbg_out_file_orig)
        else:
            logger.debug('Removed old debug file %s', dbg_out_file_orig)

    # use the minimized file for the rest of the analyses
    analyzers = [
                 stderr.StdErr,
                 cw_gmalloc.CrashWranglerGmalloc,
                 ]
    if cfg.use_valgrind:
        analyzers.extend([
                          valgrind.Valgrind,
                          callgrind.Callgrind,
                          ])
    if cfg.use_pin_calltrace:
        analyzers.extend([
                          pin_calltrace.Pin_calltrace,
                          ])

    for analyzer in analyzers:
        touch_watchdog_file(cfg)

        analyzer_instance = analyzer(cfg, crash)
        if analyzer_instance:
            try:
                analyzer_instance.go()
            except AnalyzerEmptyOutputError:
                logger.warning('Unexpected empty output from analyzer. Continuing')

    logger.info('Annotating callgrind output')
    try:
        annotate_callgrind(crash)
        annotate_callgrind_tree(crash)
    except CallgrindAnnotateEmptyOutputFileError:
        logger.warning('Unexpected empty output from annotate_callgrind. Continuing')
    except CallgrindAnnotateMissingInputFileError:
        logger.warning('Missing callgrind output. Continuing')

    return other_crashers_found


def verify_crasher(c, hashes, cfg, seedfile_set):
    logger.debug('verifying crash')
    found_new_crash = False

    crashes = []
    crashes.append(c)

    for crash in crashes:
        # loop until we're out of crashes to verify
        logger.debug('crashes to verify: %d', len(crashes))
        STATE_TIMER.enter_state('verify_testcase')

        # crashes may be added as a result of minimization
        crash.is_unique = False
        determine_uniqueness(crash, hashes)
        crash.get_logger()
        if crash.is_unique:
            hashes.append(crash)
            # only toggle it once
            if not found_new_crash:
                found_new_crash = True

            logger.debug("%s did not exist in cache, crash is unique", crash.signature)
            more_crashes = analyze_crasher(cfg, crash)

            if cfg.recycle_crashers:
                logger.debug('Recycling crash as seedfile')
                iterstring = crash.fuzzedfile.basename.split('-')[1].split('.')[0]
                crasherseedname = 'sf_' + crash.seedfile.md5 + '-' + iterstring + crash.seedfile.ext
                crasherseed_path = os.path.join(cfg.seedfile_origin_dir, crasherseedname)
                filetools.copy_file(crash.fuzzedfile.path, crasherseed_path)
                seedfile_set.add_file(crasherseed_path)
            # add new crashes to the queue
            crashes.extend(more_crashes)
            crash.copy_files()

            uniqlogger = get_uniq_logger(cfg.uniq_log)
            uniqlogger.info('%s crash_id=%s seed=%d range=%s bitwise_hd=%d bytewise_hd=%d', crash.seedfile.basename, crash.signature, crash.seednum, crash.range, crash.hd_bits, crash.hd_bytes)
            logger.info('%s first seen at %d', crash.signature, crash.seednum)
        else:
            logger.debug('%s was found, not unique', crash.signature)
        # always clean up after yourself
        crash.clean_tmpdir()

        # clean up
        crash.delete_files()
        # whether it was unique or not, record some details for posterity
        # record the details of this crash so we can regenerate it later if needed
        crash.logger.info('seen in seedfile=%s at seed=%d range=%s outfile=%s', crash.seedfile.basename, crash.seednum, crash.range, crash.fuzzedfile.path)
        crash.logger.info('PC=%s', crash.pc)

        # score this crash for the seedfile
        crash.seedfile.record_success(crash.signature, tries=0)
        if crash.range:
            # ...and for the range
            crash.range.record_success(crash.signature, tries=0)

    return found_new_crash


def check_for_script(cfg):
    if cfg.program_is_script():
        logger.warning("Target application is a shell script.")
        raise
        #cfg.disable_verification()
        #time.sleep(10)


def touch_watchdog_file(cfg):
    if cfg.watchdogtimeout:
        # this one just checks the permission
        if os.access(cfg.remote_dir, os.W_OK):
            # equivalent to 'touch cfg.watchdogfile'
            open(cfg.watchdogfile, 'w').close()


def start_process_killer(scriptpath, cfg):
    # set up and spawn the process killer
    killscript = cfg.get_killscript_path(scriptpath)
    ProcessKiller(killscript, cfg.killprocname, cfg.killproctimeout).go()
    logger.debug("Process killer started: %s %s %d", killscript, cfg.killprocname, cfg.killproctimeout)


def add_log_handler(log_obj, level, hdlr, formatter):
    hdlr.setLevel(level)
    hdlr.setFormatter(formatter)
    log_obj.addHandler(hdlr)


def setup_logging_to_console(log_obj, level):
    hdlr = logging.StreamHandler()
    formatter = logging.Formatter('%(name)s %(message)s')
    add_log_handler(log_obj, level, hdlr, formatter)


#def setup_logfile(logdir, log_basename='bff.log', level=logging.DEBUG,
#                  max_bytes=1e8, backup_count=5):
#    '''
#    Creates a log file in <logdir>/<log_basename> at level <level>
#    @param logdir: the directory where the log file should reside
#    @param log_basename: the basename of the logfile (defaults to 'bff_log.txt')
#    @param level: the logging level (defaults to logging.DEBUG)
#    '''
#    filetools.make_directories(logdir)
#    logfile = os.path.join(logdir, log_basename)
#    handler = RotatingFileHandler(logfile, maxBytes=max_bytes, backupCount=backup_count)
#    formatter = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
#    add_log_handler(logger, level, handler, formatter)
#    logger.info('Logging %s at %s', logging.getLevelName(level), logfile)


def get_config_file(basedir):
    config_dir = os.path.join(basedir, 'conf.d')

    # check for a platform-specific file
    platform_cfg = 'bff-%s.cfg' % platform.system()

    fullpath_platform_cfg = os.path.join(config_dir, platform_cfg)

    if os.path.exists(fullpath_platform_cfg):
        config_file = fullpath_platform_cfg
    else:
        # default if nothing else is around
        config_file = os.path.join(config_dir, "bff.cfg")

    return config_file

class Intervals(object):
    def __init__(self, min=0, max=1e10, interval=1):
        self.min = min
        self.max = max
        self.interval = interval
        self.curr_pos = self.min

    def __iter__(self):
        start = self.curr_pos
        end = self.curr_pos + self.interval
        self.curr_pos += self.interval
        return xrange(start, end)


class CampaignScriptError(Exception):
    pass


class Iteration(object):
    def __init__(self, cfg=None, seednum=None, seedfile=None, r=None):
        self.cfg = cfg
        self.seednum = seednum
        self.seedfile = seedfile
        self.r = r

        # convenience aliases
        self.s1 = self.seednum
        self.s2 = self.s1
        self.sf = self.seedfile

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _fuzz_and_run(self, quiet_flag):
        if self.first_chunk:
            # disable the --quiet option in zzuf
            # on the first chunk only
            quiet_flag = False
            self.first_chunk = False
        else:
            quiet_flag = True

        # do the fuzz
        cmdline = self.cfg.get_command(self.sf.path)

        STATE_TIMER.enter_state('fuzzing')
        zzuf = Zzuf(self.cfg.local_dir, self.s1,
            self.s2,
            cmdline,
            self.sf.path,
            self.cfg.zzuf_log_file,
            self.cfg.copymode,
            self.r.min,
            self.r.max,
            self.cfg.progtimeout,
            quiet_flag)
        saw_crash = zzuf.go()
        return saw_crash, zzuf

    def _log(self):
#        # emit a log entry
        crashcount = z.get_crashcount(self.cfg.crashers_dir)
#        rate = get_rate(self.s1)
#        seed_str = "seeds=%d-%d" % (self.s1, self.s2)
#        range_str = "range=%.6f-%.6f" % (self.r.min, self.r.max)
#        rate_str = "Rate=(%.2f/s %.1f/m %.0f/h %.0f/d)" % (rate, rate * 60, rate * 3600, rate * 86400)
#        expected_density = self.seedfile_set.expected_crash_density
#        xd_str = "expected=%.9f" % expected_density
#        xr_str = 'expected_rate=%.6f uniq/day' % (expected_density * rate * 86400)
#        logger.info('Fuzzing %s %s %s %s %s %s crash_count=%d',
#            self.sf.path, seed_str, range_str, rate_str, xd_str, xr_str, crashcount)
        logger.info('Fuzzing...crash_count=%d', crashcount)

    def go2(self):
        self._fuzz()
        self._run()
        for testcase in self.candidates:
            self.verify(testcase)

        for testcase in self.verified:
            self.analyze(testcase)

        for testcase in self.analyzed:
            self.construct_report(testcase)

    def go(self):
        # Prevent watchdog from rebooting VM.  If /tmp/fuzzing exists and is stale, the machine will reboot
        touch_watchdog_file(self.cfg)
        self._check_ppid()

        saw_crash, zzuf = self._fuzz_and_run(quiet_flag)
        STATE_TIMER.enter_state('checking_results')

        if not saw_crash:
            # we must have made it through this chunk without a crash
            # so go to next chunk
            self.sf.record_tries(tries=1)
            self.r.record_tries(tries=1)
            self._log()
            return

        # we must have seen a crash
        # get the results
        zzuf_log = ZzufLog(self.cfg.zzuf_log_file, self.cfg.zzuf_log_out(self.sf.output_dir))

        # Don't generate cases for killed process or out-of-memory
        # In the default mode, zzuf will report a signal. In copy (and exit code) mode, zzuf will
        # report the exit code in its output log.  The exit code is 128 + the signal number.
        crash_status = zzuf_log.crash_logged(self.cfg.copymode)
        sr.bookmark_s1()
        self.s1 = zzuf_log.seed

        # record the fact that we've made it this far
        try_count = self.s1_delta()
        self.sf.record_tries(tries=try_count)
        self.r.record_tries(tries=try_count)

        new_uniq_crash = False
        if crash_status:
            logger.info('Generating testcase for %s', zzuf_log.line)
            # a true crash
            zzuf_range = zzuf_log.range
            # create the temp dir for the results
            self.cfg.create_tmpdir()
            outfile = self.cfg.get_testcase_outfile(sf.path, sr.s1)
            logger.debug('Output file is %s', outfile)
            testcase = zzuf.generate_test_case(sf.path, sr.s1, zzuf_range, outfile)

            # Do internal verification using GDB / Valgrind / Stderr
            fuzzedfile = file_handlers.basicfile.BasicFile(outfile)

            with BffCrash(self.cfg, sf, fuzzedfile, self.cfg.program, self.cfg.debugger_timeout,
                          self.cfg.killprocname, self.cfg.backtracelevels,
                          self.cfg.crashers_dir, sr.s1, r) as c:
                if c.is_crash:
                    new_uniq_crash = verify_crasher(c, hashes, self.cfg, seedfile_set)

                # record the zzuf log line for this crash
                if not c.logger:
                    c.get_logger()
                c.logger.debug("zzuflog: %s", zzuf_log.line)
                c.logger.info('Command: %s', testcase.cmdline)

            self.cfg.clean_tmpdir()

        sr.increment_seed()

#        # cache objects in case of reboot
#        cache_state(self.cfg.campaign_id, 'seedrange', sr, cfg.cached_seedrange_file)
#        pickled_seedfile_file = os.path.join(cfg.cached_objects_dir, sf.pkl_file())
#        cache_state(cfg.campaign_id, sf.cache_key(), sf, pickled_seedfile_file)
#        cache_state(cfg.campaign_id, 'seedfile_set', seedfile_set, cfg.cached_seedfile_set)

#        if new_uniq_crash:
#            # we had a hit, so break the inner while() loop
#            # so we can pick a new range. This is to avoid
#            # having a crash-rich range run away with the
#            # probability before other ranges have been tried
#            break


class Campaign(object):
    def __init__(self, cfg_path=None, scriptpath=None):
        # Read the cfg file
        self.cfg_path = cfg_path
        logger.info('Reading config from %s', cfg_path)
        self.cfg = cfg_helper.read_config_options(cfg_path)
        self.scriptpath = scriptpath
        self.seedfile_set = None
        self._last_ppid = None

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
        start_process_killer(self.scriptpath, self.cfg)
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

    def _cache_prg(self):
        sf = self.seedfile_set.next_item()
        # Run the program once to cache it into memory
        z.cache_program_once(self.cfg, sf.path)
        # Give target time to die
        time.sleep(1)


    def _setup_watchdog(self):
        # set up the watchdog timeout within the VM and restart the daemon
        watchdog = WatchDog(self.cfg.watchdogfile,
                            self.cfg.watchdogtimeout)
        touch_watchdog_file(self.cfg)
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
        handler = RotatingFileHandler(logfile, maxBytes=max_bytes, backupCount=backup_count)
        formatter = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
        add_log_handler(logger, level, handler, formatter)
        logger.info('Logging %s at %s', logging.getLevelName(level), logfile)

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

    def _do_interval(self, s1, s2):
        # interval.go
        logger.debug('Starting interval %d-%d', s1, s2)
        # wipe the tmp dir clean to try to avoid filling the VM disk
        TmpReaper().clean_tmp()

        sf = self.seedfile_set.next_item()
        r = sf.rangefinder.next_item()

        logger.info(STATE_TIMER)

        for s in xrange(s1, s2):
            with Iteration(seednum=s, seedfile=sf, r=r) as iteration:
                iteration.go()

    def go(self):
    # campaign.go
        cfg = self.cfg
        seedfile_set = self.seedfile_set

        for (s1, s2) in Intervals(min=cfg.start_seed,
                                 max=cfg.max_seed,
                                 interval=cfg.seed_interval):
            self._do_interval(s1, s2)


def main():
#    global START_SEED
    hashes = []

    # give up if we don't have a debugger
    debuggers.verify_supported_platform()

    setup_logging_to_console(logger, logging.INFO)
    logger.info("Welcome to BFF!")

    scriptpath = os.path.dirname(sys.argv[0])
    logger.info('Scriptpath is %s', scriptpath)

    # parse command line options
    logger.info('Parsing command line options')
    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', help='Turn on debugging output', action='store_true')
    parser.add_option('-c', '--config', dest='cfg', help='Config file location')
    (options, args) = parser.parse_args()  #@UnusedVariable

    # Get the cfg file name
    if options.cfg:
        remote_cfg_file = options.cfg
    else:
        remote_cfg_file = get_config_file(scriptpath)

    # die unless the remote config is present
    assert os.path.exists(remote_cfg_file), 'Cannot find remote config file: %s, Please create it or use --config option to specify a different location.' % remote_cfg_file

    # copy remote config to local:
    local_cfg_file = os.path.expanduser('~/bff.cfg')
    filetools.copy_file(remote_cfg_file, local_cfg_file)

    with Campaign(cfg_path=local_cfg_file) as campaign:
        campaign.go()


if __name__ == '__main__':
    main()
