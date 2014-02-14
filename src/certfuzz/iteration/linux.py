'''
Created on Feb 12, 2014

@author: adh
'''
import logging

from .. import file_handlers
from ..analyzers import cw_gmalloc, pin_calltrace, stderr, valgrind
from ..analyzers.callgrind import callgrind
from ..analyzers.callgrind.annotate import annotate_callgrind
from ..analyzers.callgrind.annotate import annotate_callgrind_tree
from ..analyzers.callgrind.errors import CallgrindAnnotateEmptyOutputFileError
from ..analyzers.callgrind.errors import CallgrindAnnotateMissingInputFileError
from ..analyzers.errors import AnalyzerEmptyOutputError
from ..crash.bff_crash import BffCrash
from ..debuggers import crashwrangler  # @UnusedImport
from ..debuggers import gdb  # @UnusedImport
from ..fuzztools import bff_helper as z, filetools
from ..fuzztools.state_timer import STATE_TIMER
from ..fuzztools.zzuf import Zzuf
from ..fuzztools.zzuflog import ZzufLog
from ..minimizer import MinimizerError, UnixMinimizer as Minimizer
import os
from certfuzz.file_handlers.watchdog_file import touch_watchdog_file
import tempfile
import shutil
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.iteration.iteration_base3 import IterationBase3

logger = logging.getLogger(__name__)


#def determine_uniqueness(crash, hashes):
#    '''
#    Gets the crash signature, then compares it against known crashes.
#    Sets crash.is_unique = True if it is new
#    '''
#
#    # short-circuit on crashes with no signature
#    if not crash.signature:
#        logger.warning('Crash has no signature, cleaning up')
#        crash.delete_files()
#        return
#
#    if crash.signature in hashes:
#        crash.is_unique = False
#        return
#
#    # fall back to checking if the crash directory exists
#    crash_dir_found = filetools.find_or_create_dir(crash.result_dir)
#
#    crash.is_unique = not crash_dir_found

def get_uniq_logger(logfile):
    l = logging.getLogger('uniq_crash')
    if len(l.handlers) == 0:
        hdlr = logging.FileHandler(logfile)
        l.addHandler(hdlr)
    return l


class Iteration(IterationBase3):
    def __init__(self, cfg=None, seednum=None, seedfile=None, r=None, workdirbase=None, quiet=True, uniq_func=None):
        IterationBase3.__init__(self, workdirbase)
        self.cfg = cfg
        self.seednum = seednum
        self.seedfile = seedfile
        self.r = r
        self.quiet_flag = quiet

        if uniq_func is None:
            self.uniq_func = lambda _tc_id: True
        else:
            self.uniq_func = uniq_func

        self._setup_analyzers()

        # convenience aliases
        self.s1 = self.seednum
        self.s2 = self.s1
        self.sf = self.seedfile

    def __enter__(self):
        IterationBase3.__enter__(self)
        check_ppid()
        return self

    def __exit__(self, etype, value, traceback):
        IterationBase3.__exit__(self, etype, value, traceback)
        self.cfg.clean_tmpdir()

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

    def _setup_analyzers(self):
        self.analyzer_classes.append(stderr.StdErr)
        self.analyzer_classes.append(cw_gmalloc.CrashWranglerGmalloc)

        if self.cfg.use_valgrind:
            self.analyzer_classes.append(valgrind.Valgrind)
            self.analyzer_classes.append(callgrind.Callgrind)

        if self.cfg.use_pin_calltrace:
            self.analyzer_classes.append(pin_calltrace.Pin_calltrace)

    def _pre_run(self):
        IterationBase3._pre_run(self)
        # do the fuzz
        cmdline = self.cfg.get_command(self.sf.path)

        STATE_TIMER.enter_state('fuzzing')
        self.zzuf = Zzuf(self.cfg.local_dir, self.s1,
            self.s1,
            cmdline,
            self.sf.path,
            self.cfg.zzuf_log_file,
            self.cfg.copymode,
            self.r.min,
            self.r.max,
            self.cfg.progtimeout,
            self.quiet_flag)

    def _run(self):
        IterationBase3._run(self)
        self.zzuf.go()

    def _post_run(self):
        IterationBase3._post_run(self)

        STATE_TIMER.enter_state('checking_results')
            # we must have made it through this chunk without a crash
            # so go to next chunk
        self.sf.record_tries(tries=1)
        self.r.record_tries(tries=1)
        if not self.zzuf.saw_crash:
            self._log()
            return

        # we must have seen a crash
        # get the results
        zzuf_log = ZzufLog(self.cfg.zzuf_log_file, self.cfg.zzuf_log_out(self.sf.output_dir))

        # Don't generate cases for killed process or out-of-memory
        # In the default mode, zzuf will report a signal. In copy (and exit code) mode, zzuf will
        # report the exit code in its output log.  The exit code is 128 + the signal number.
        crash_status = zzuf_log.crash_logged(self.cfg.copymode)

        if not crash_status:
            return

        logger.info('Generating testcase for %s', zzuf_log.line)
        # a true crash
        zzuf_range = zzuf_log.range
        # create the temp dir for the results
        self.cfg.create_tmpdir()
        outfile = self.cfg.get_testcase_outfile(self.seedfile.path, self.s1)
        logger.debug('Output file is %s', outfile)
        self.zzuf.generate_test_case(self.seedfile.path, self.s1, zzuf_range, outfile)

        # Do internal verification using GDB / Valgrind / Stderr
        fuzzedfile = file_handlers.basicfile.BasicFile(outfile)

        testcase = BffCrash(cfg=self.cfg,
                            seedfile=self.seedfile,
                            fuzzedfile=fuzzedfile,
                            program=self.cfg.program,
                            debugger_timeout=self.cfg.debugger_timeout,
                            killprocname=self.cfg.killprocname,
                            backtrace_lines=self.cfg.backtracelevels,
                            crashers_dir=self.cfg.crashers_dir,
                            workdir_base=self.working_dir,
                            seednum=self.s1,
                            range=self.r)

            # record the zzuf log line for this crash
        if not testcase.logger:
            testcase.get_logger()

        testcase.logger.debug("zzuflog: %s", zzuf_log.line)
#        testcase.logger.info('Command: %s', testcase.cmdline)

        self.candidates.append(testcase)

    def _verify(self, testcase):
        '''
        Confirms that a test case is interesting enough to pursue further analysis
        :param testcase:
        '''
        STATE_TIMER.enter_state('verify_testcase')
        IterationBase3._verify(self, testcase)

        # if you find more testcases, append them to self.candidates
        # verified crashes append to self.verified

        logger.debug('verifying crash')
        with testcase as tc:
            if tc.is_crash:

                tc.is_unique = self.uniq_func(tc.signature)

                if tc.is_unique:
                    logger.info('%s first seen at %d', tc.signature, tc.seednum)
                    self.dbg_out_file_orig = testcase.dbg.file
                    logger.debug('Original debugger file: %s', self.dbg_out_file_orig)

                    new_testcases = self._minimize(tc)
                    # add any new candidates for verification to the candidates list
                    self.candidates.extend(new_testcases)

                    # we're ready to proceed with this testcase
                    # so add it to the verified list
                    self.verified.append(tc)
                else:
                    logger.debug('%s was found, not unique', tc.signature)

    def _minimize(self, testcase):
        other_crashers_found = []

        if self.cfg.minimizecrashers:
            STATE_TIMER.enter_state('minimize_testcase')
            # try to reduce the Hamming Distance between the crasher file and the known good seedfile
            # crash.fuzzedfile will be replaced with the minimized result
            try:
                with Minimizer(cfg=self.cfg, crash=testcase, bitwise=False,
                               seedfile_as_target=True, confidence=0.999,
                               tempdir=self.cfg.local_dir, maxtime=self.cfg.minimizertimeout
                               ) as minimizer:
                    minimizer.go()
                    other_crashers_found.extend(minimizer.other_crashes.values())
            except MinimizerError, e:
                logger.warning('Unable to minimize %s, proceeding with original fuzzed crash file: %s', testcase.signature, e)
                minimizer = None

        touch_watchdog_file()
        # calculate the hamming distances for this crash
        # between the original seedfile and the minimized fuzzed file
        testcase.calculate_hamming_distances()

        if self.cfg.minimize_to_string:
            STATE_TIMER.enter_state('minimize_testcase_to_string')
            # Minimize to a string of 'x's
            # crash.fuzzedfile will be replaced with the minimized result
            try:
                with Minimizer(cfg=self.cfg, crash=testcase, bitwise=False,
                               seedfile_as_target=False, confidence=0.9,
                               tempdir=self.cfg.local_dir, maxtime=self.cfg.minimizertimeout
                               ) as min2string:
                    min2string.go()
                    other_crashers_found.extend(min2string.other_crashes.values())
            except MinimizerError, e:
                logger.warning('Unable to minimize %s, proceeding with original fuzzed crash file: %s', testcase.signature, e)
                min2string = None
        touch_watchdog_file()

        return other_crashers_found

    def _pre_analyze(self, testcase):
        IterationBase3._pre_analyze(self, testcase)

        STATE_TIMER.enter_state('analyze_testcase')

        # get one last debugger output for the newly minimized file
        if testcase.pc_in_function:
            # change the debugger template
            testcase.set_debugger_template('complete')
        else:
            # use a debugger template that specifies fixed offsets from $pc for disassembly
            testcase.set_debugger_template('complete_nofunction')
        logger.info('Getting complete debugger output for crash: %s', testcase.fuzzedfile.path)
        testcase.get_debug_output(testcase.fuzzedfile.path)

        if self.dbg_out_file_orig != testcase.dbg.file:
            # we have a new debugger output
            # remove the old one
            filetools.delete_files(self.dbg_out_file_orig)
            if os.path.exists(self.dbg_out_file_orig):
                logger.warning('Failed to remove old debugger file %s', self.dbg_out_file_orig)
            else:
                logger.debug('Removed old debug file %s', self.dbg_out_file_orig)

    def _post_analyze(self, testcase):
        IterationBase3._post_analyze(self, testcase)

        logger.info('Annotating callgrind output')
        try:
            annotate_callgrind(testcase)
            annotate_callgrind_tree(testcase)
        except CallgrindAnnotateEmptyOutputFileError:
            logger.warning('Unexpected empty output from annotate_callgrind. Continuing')
        except CallgrindAnnotateMissingInputFileError:
            logger.warning('Missing callgrind output. Continuing')

        if self.cfg.recycle_crashers:
            logger.debug('Recycling crash as seedfile')
            iterstring = testcase.fuzzedfile.basename.split('-')[1].split('.')[0]
            crasherseedname = 'sf_' + testcase.seedfile.md5 + '-' + iterstring + testcase.seedfile.ext
            crasherseed_path = os.path.join(self.cfg.seedfile_origin_dir, crasherseedname)
            filetools.copy_file(testcase.fuzzedfile.path, crasherseed_path)
            seedfile_set.add_file(crasherseed_path)

        # score this crash for the seedfile
        testcase.seedfile.record_success(testcase.signature, tries=0)
        if testcase.range:
            # ...and for the range
            testcase.range.record_success(testcase.signature, tries=0)

    def _pre_report(self, testcase):
        uniqlogger = get_uniq_logger(self.cfg.uniq_log)
        uniqlogger.info('%s crash_id=%s seed=%d range=%s bitwise_hd=%d bytewise_hd=%d', testcase.seedfile.basename, testcase.signature, testcase.seednum, testcase.range, testcase.hd_bits, testcase.hd_bytes)
        logger.info('%s first seen at %d', testcase.signature, testcase.seednum)

        # whether it was unique or not, record some details for posterity
        # record the details of this crash so we can regenerate it later if needed
        testcase.logger.info('seen in seedfile=%s at seed=%d range=%s outfile=%s', testcase.seedfile.basename, testcase.seednum, testcase.range, testcase.fuzzedfile.path)
        testcase.logger.info('PC=%s', testcase.pc)

    def _report(self, testcase):
        testcase.copy_files()

    def _post_report(self, testcase):
        # always clean up after yourself
        testcase.clean_tmpdir()
        # clean up
        testcase.delete_files()
