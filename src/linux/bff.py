'''
Created on Oct 15, 2010

@organization: cert.org
'''
__version__ = '2.8'

import os
import sys
from optparse import OptionParser
import time
import logging
import platform
from logging.handlers import RotatingFileHandler

from certfuzz import file_handlers
from certfuzz import debuggers
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.debuggers import crashwrangler  # @UnusedImport

from certfuzz.fuzztools import bff_helper as z
from certfuzz.campaign.config import bff_config as cfg_helper
from certfuzz.fuzztools import filetools
from certfuzz.fuzztools import performance

from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.file_handlers.tmp_reaper import TmpReaper

from certfuzz.crash.bff_crash import BffCrash
from certfuzz.fuzztools.object_caching import get_cached_state
from certfuzz.fuzztools.object_caching import cache_state
from certfuzz.fuzztools.process_killer import ProcessKiller
from certfuzz.fuzztools.seedrange import SeedRange
from certfuzz.fuzztools.watchdog import WatchDog
from certfuzz.fuzztools.zzuf import Zzuf
from certfuzz.fuzztools.zzuflog import ZzufLog

from certfuzz.analyzers import valgrind
from certfuzz.analyzers import cw_gmalloc
from certfuzz.analyzers import stderr
from certfuzz.analyzers import pin_calltrace
from certfuzz.analyzers import AnalyzerEmptyOutputError
from certfuzz.analyzers.callgrind import callgrind
from certfuzz.analyzers.callgrind import CallgrindAnnotateEmptyOutputFileError
from certfuzz.analyzers.callgrind import CallgrindAnnotateMissingInputFileError
from certfuzz.analyzers.callgrind.annotate import annotate_callgrind
from certfuzz.analyzers.callgrind.annotate import annotate_callgrind_tree
from certfuzz.minimizer import UnixMinimizer as Minimizer
from certfuzz.minimizer import MinimizerError


DEBUG = True

SEED_INTERVAL = 500

SEED_TS = performance.TimeStamper()
START_SEED = 0

logger = logging.getLogger()
logger.name = 'bff'
logger.setLevel(0)


def get_rate(current_seed):
    seeds = current_seed - START_SEED
    rate = seeds / SEED_TS.since_start()
    return rate


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


def setup_logfile(logdir, log_basename='bff.log', level=logging.DEBUG,
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


def main():
    global START_SEED
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

    # Read the cfg file
    logger.info('Reading config from %s', local_cfg_file)
    cfg = cfg_helper.read_config_options(local_cfg_file)

    # set up local logging
    setup_logfile(cfg.local_dir, log_basename='bff.log', level=logging.DEBUG,
                  max_bytes=1e8, backup_count=3)

    # set up remote logging
    setup_logfile(cfg.output_dir, log_basename='bff.log', level=logging.INFO,
                  max_bytes=1e7, backup_count=5)

    try:
        check_for_script(cfg)
    except:
        logger.warning("Please configure BFF to fuzz a binary.  Exiting...")
        sys.exit()

    z.setup_dirs_and_files(local_cfg_file, cfg)

    # make sure we cache it for the next run
#    cache_state(cfg.campaign_id, 'cfg', cfg, cfg.cached_config_file)

    sr = get_cached_state('seedrange', cfg.campaign_id, cfg.cached_seedrange_file)
    if not sr:
        sr = SeedRange(cfg.start_seed, cfg.seed_interval, cfg.max_seed)

    # set START_SEED global for timestamping
    START_SEED = sr.s1

    start_process_killer(scriptpath, cfg)

    z.set_unbuffered_stdout()

    # set up the seedfile set so we can pick seedfiles for everything else...
    seedfile_set = get_cached_state('seedfile_set', cfg.campaign_id, cfg.cached_seedfile_set)
    if not seedfile_set:
        logger.info('Building seedfile set')
        sfs_logfile = os.path.join(cfg.seedfile_output_dir, 'seedfile_set.log')
        with SeedfileSet(campaign_id=cfg.campaign_id,
                         originpath=cfg.seedfile_origin_dir,
                         localpath=cfg.seedfile_local_dir,
                         outputpath=cfg.seedfile_output_dir,
                         logfile=sfs_logfile,
                         ) as sfset:
            seedfile_set = sfset

    # set up the watchdog timeout within the VM and restart the daemon
    if cfg.watchdogtimeout:
        watchdog = WatchDog(cfg.watchdogfile, cfg.watchdogtimeout)
        touch_watchdog_file(cfg)
        watchdog.go()

    cache_state(cfg.campaign_id, 'seedfile_set', seedfile_set, cfg.cached_seedfile_set)

    sf = seedfile_set.next_item()

    # Run the program once to cache it into memory
    z.cache_program_once(cfg, sf.path)

    # Give target time to die
    time.sleep(1)

    # flag to indicate whether this is a fresh script start up or not
    first_chunk = True

    # remember our parent process id so we can tell if it changes later
    _last_ppid = os.getppid()

    # campaign.go
    while sr.in_max_range():

        # wipe the tmp dir clean to try to avoid filling the VM disk
        TmpReaper().clean_tmp()

        sf = seedfile_set.next_item()

        r = sf.rangefinder.next_item()
        sr.set_s2()

        while sr.in_range():
            # interval.go
            logger.debug('Starting interval %d-%d', sr.s1, sr.s2)

            # Prevent watchdog from rebooting VM.  If /tmp/fuzzing exists and is stale, the machine will reboot
            touch_watchdog_file(cfg)

            # check parent process id
            _ppid_now = os.getppid()
            if not _ppid_now == _last_ppid:
                logger.warning('Parent process ID changed from %d to %d', _last_ppid, _ppid_now)
                _last_ppid = _ppid_now

            # do the fuzz
            cmdline = cfg.get_command(sf.path)

            if first_chunk:
                # disable the --quiet option in zzuf
                # on the first chunk only
                quiet_flag = False
                first_chunk = False
            else:
                quiet_flag = True

            zzuf = Zzuf(cfg.local_dir,
                        sr.s1,
                        sr.s2,
                        cmdline,
                        sf.path,
                        cfg.zzuf_log_file,
                        cfg.copymode,
                        r.min,
                        r.max,
                        cfg.progtimeout,
                        quiet_flag,
                        )
            saw_crash = zzuf.go()

            if not saw_crash:
                # we must have made it through this chunk without a crash
                # so go to next chunk
                try_count = sr.s1_s2_delta()
                sf.record_tries(tries=try_count)
                r.record_tries(tries=try_count)

                # emit a log entry
                crashcount = z.get_crashcount(cfg.crashers_dir)
                rate = get_rate(sr.s1)
                seed_str = "seeds=%d-%d" % (sr.s1, sr.s2)
                range_str = "range=%.6f-%.6f" % (r.min, r.max)
                rate_str = "Rate=(%.2f/s %.1f/m %.0f/h %.0f/d)" % (rate, rate * 60, rate * 3600, rate * 86400)
                expected_density = seedfile_set.expected_crash_density
                xd_str = "expected=%.9f" % expected_density
                xr_str = 'expected_rate=%.6f uniq/day' % (expected_density * rate * 86400)
                logger.info('Fuzzing %s %s %s %s %s %s crash_count=%d',
                    sf.path, seed_str, range_str, rate_str, xd_str, xr_str, crashcount)

                # set s1 to s2 so that as soon as we continue we'll break out of the sr.in_range() loop
                sr.set_s1_to_s2()
                continue

            # we must have seen a crash

            # get the results
            zzuf_log = ZzufLog(cfg.zzuf_log_file, cfg.zzuf_log_out(sf.output_dir))

            # Don't generate cases for killed process or out-of-memory
            # In the default mode, zzuf will report a signal. In copy (and exit code) mode, zzuf will
            # report the exit code in its output log.  The exit code is 128 + the signal number.
            crash_status = zzuf_log.crash_logged(cfg.copymode)
            sr.bookmark_s1()
            sr.s1 = zzuf_log.seed

            # record the fact that we've made it this far
            try_count = sr.s1_delta()
            sf.record_tries(tries=try_count)
            r.record_tries(tries=try_count)

            new_uniq_crash = False
            if crash_status:
                logger.info('Generating testcase for %s', zzuf_log.line)
                # a true crash
                zzuf_range = zzuf_log.range
                # create the temp dir for the results
                cfg.create_tmpdir()
                outfile = cfg.get_testcase_outfile(sf.path, sr.s1)
                logger.debug('Output file is %s', outfile)
                testcase = zzuf.generate_test_case(sf.path, sr.s1, zzuf_range, outfile)

                # Do internal verification using GDB / Valgrind / Stderr
                fuzzedfile = file_handlers.basicfile.BasicFile(outfile)

                with BffCrash(cfg, sf, fuzzedfile, cfg.program, cfg.debugger_timeout,
                              cfg.killprocname, cfg.backtracelevels,
                              cfg.crashers_dir, sr.s1, r) as c:
                    if c.is_crash:
                        new_uniq_crash = verify_crasher(c, hashes, cfg, seedfile_set)

                    # record the zzuf log line for this crash
                    if not c.logger:
                        c.get_logger()
                    c.logger.debug("zzuflog: %s", zzuf_log.line)
                    c.logger.info('Command: %s', testcase.cmdline)

                cfg.clean_tmpdir()

            sr.increment_seed()

            # cache objects in case of reboot
            cache_state(cfg.campaign_id, 'seedrange', sr, cfg.cached_seedrange_file)
            pickled_seedfile_file = os.path.join(cfg.cached_objects_dir, sf.pkl_file())
            cache_state(cfg.campaign_id, sf.cache_key(), sf, pickled_seedfile_file)
            cache_state(cfg.campaign_id, 'seedfile_set', seedfile_set, cfg.cached_seedfile_set)

            if new_uniq_crash:
                # we had a hit, so break the inner while() loop
                # so we can pick a new range. This is to avoid
                # having a crash-rich range run away with the
                # probability before other ranges have been tried
                break

if __name__ == '__main__':
    main()
