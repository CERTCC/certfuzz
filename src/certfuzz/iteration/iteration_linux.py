'''
Created on Feb 12, 2014

@author: adh
'''
import logging
import os

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.analyzers import cw_gmalloc, pin_calltrace, stderr, valgrind
from certfuzz.analyzers.callgrind import callgrind
from certfuzz.analyzers.callgrind.annotate import annotate_callgrind, \
    annotate_callgrind_tree
from certfuzz.analyzers.callgrind.errors import \
    CallgrindAnnotateEmptyOutputFileError, CallgrindAnnotateMissingInputFileError
from certfuzz.crash.bff_crash import BffCrash
from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.file_handlers import seedfile_set
from certfuzz.fuzztools import bff_helper as z, filetools
from certfuzz.fuzztools.state_timer import STATE_TIMER
from certfuzz.fuzztools.zzuf import Zzuf, ZzufTestCase
from certfuzz.fuzztools.zzuflog import ZzufLog
from certfuzz.minimizer import MinimizerError, UnixMinimizer as Minimizer

from certfuzz.file_handlers.watchdog_file import touch_watchdog_file
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.iteration.iteration_base3 import IterationBase3


logger = logging.getLogger(__name__)


def get_uniq_logger(logfile):
    l = logging.getLogger('uniq_crash')
    if len(l.handlers) == 0:
        hdlr = logging.FileHandler(logfile)
        l.addHandler(hdlr)
    return l


class Iteration(IterationBase3):
    def __init__(self, cfg=None, seednum=None, seedfile=None, r=None, workdirbase=None, quiet=True, uniq_func=None,
                 sf_set=None, rf=None, outdir=None):
        IterationBase3.__init__(self, workdirbase)
        self.cfg = cfg
        self.seednum = seednum
        self.seedfile = seedfile
        self.r = r
        self.quiet_flag = quiet
        self.sf_set = sf_set
        self.rf = rf
        self.outdir = outdir

        self.testcase_base_dir = os.path.join(self.outdir, 'crashers')

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
        handled = IterationBase3.__exit__(self, etype, value, traceback)

        self.cfg.clean_tmpdir()
        return handled

    def record_success(self):
        self.sf_set.record_success(key=self.seedfile.md5)
        self.rf.record_success(key=self.r.id)

    def record_failure(self):
        self.record_tries()

    def record_tries(self):
        self.sf_set.record_tries(key=self.seedfile.md5, tries=1)
        self.rf.record_tries(key=self.r.id, tries=1)

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

        self.record_tries()

        if not self.zzuf.saw_crash:
            logger.debug('No crash seen')
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

        with ZzufTestCase(seedfile=self.seedfile, seed=self.s1,
                           range=zzuf_range,
                           working_dir=self.working_dir) as ztc:
            ztc.generate()

        fuzzedfile = BasicFile(ztc.outfile)

        testcase = BffCrash(cfg=self.cfg,
                            seedfile=self.seedfile,
                            fuzzedfile=fuzzedfile,
                            program=self.cfg.program,
                            debugger_timeout=self.cfg.debugger_timeout,
                            killprocname=self.cfg.killprocname,
                            backtrace_lines=self.cfg.backtracelevels,
                            crashers_dir=self.testcase_base_dir,
                            workdir_base=self.working_dir,
                            seednum=self.s1,
                            range=self.r)

        # record the zzuf log line for this crash
        testcase.get_logger()

        testcase.logger.debug("zzuflog: %s", zzuf_log.line)
#        testcase.logger.info('Command: %s', testcase.cmdline)

        self.candidates.put(testcase)

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

                is_new_to_campaign = self.uniq_func(tc.signature)

                # fall back to checking if the crash directory exists
                #
                crash_dir_found = filetools.find_or_create_dir(tc.result_dir)

                tc.is_unique = is_new_to_campaign and not crash_dir_found

                self.dbg_out_file_orig = testcase.dbg.file
                logger.debug('Original debugger file: %s', self.dbg_out_file_orig)

                if tc.is_unique:
                    logger.info('%s first seen at %d', tc.signature, tc.seednum)
                    self.dbg_out_file_orig = tc.dbg.file
                    logger.debug('Original debugger file: %s', self.dbg_out_file_orig)
                    self._minimize(tc)

                    # we're ready to proceed with this testcase
                    # so add it to the verified list
                    self.verified.put(tc)
                else:
                    logger.debug('%s was found, not unique', tc.signature)
                    if self.cfg.keep_duplicates:
                        logger.debug('Analyzing %s anyway because keep_duplicates is set', tc.signature)
                        self.verified.append(tc)

    def _minimize(self, testcase):
        if self.cfg.minimizecrashers:
            self._mininimize_to_seedfile(testcase)
        if self.cfg.minimize_to_string:
            self._minimize_to_string(testcase)

    def _mininimize_to_seedfile(self, testcase):
        self._minimize_generic(testcase, sftarget=True, confidence=0.999)
        # calculate the hamming distances for this crash
        # between the original seedfile and the minimized fuzzed file
        testcase.calculate_hamming_distances()

    def _minimize_to_string(self, testcase):
        self._minimize_generic(testcase, sftarget=False, confidence=0.9)

    def _minimize_generic(self, testcase, sftarget=True, confidence=0.999):
        touch_watchdog_file()

        STATE_TIMER.enter_state('minimize_testcase')
        # try to reduce the Hamming Distance between the crasher file and the known good seedfile
        # crash.fuzzedfile will be replaced with the minimized result
        try:
            with Minimizer(cfg=self.cfg,
                           crash=testcase,
                           bitwise=False,
                           seedfile_as_target=sftarget,
                           confidence=confidence,
                           tempdir=self.cfg.local_dir,
                           maxtime=self.cfg.minimizertimeout
                           ) as m:
                m.go()
                for new_tc in m.other_crashes.values():
                    self.candidates.put(new_tc)
        except MinimizerError as e:
            logger.warning('Unable to minimize %s, proceeding with original fuzzed crash file: %s', testcase.signature, e)
            m = None

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

# TODO
#        if self.cfg.recycle_crashers:
#            logger.debug('Recycling crash as seedfile')
#            iterstring = testcase.fuzzedfile.basename.split('-')[1].split('.')[0]
#            crasherseedname = 'sf_' + testcase.seedfile.md5 + '-' + iterstring + testcase.seedfile.ext
#            crasherseed_path = os.path.join(self.cfg.seedfile_origin_dir, crasherseedname)
#            filetools.copy_file(testcase.fuzzedfile.path, crasherseed_path)
#            seedfile_set.add_file(crasherseed_path)

#        # score this crash for the seedfile
#        testcase.seedfile.record_success(testcase.signature, tries=0)
#        if testcase.range:
#            # ...and for the range
#            testcase.range.record_success(testcase.signature, tries=0)
        # TODO: make sure this is scoring the right thing.
        # in older code (see above) we kept track of specific crashes seen per seedfile
        # & range. Should we still do that?
        self.record_success()

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
