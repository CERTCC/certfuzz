'''
Created on Jul 16, 2014

@organization: cert.org
'''
import logging
import os
import platform

from certfuzz.analyzers.callgrind.annotate import annotate_callgrind
from certfuzz.analyzers.callgrind.annotate import annotate_callgrind_tree
from certfuzz.analyzers.callgrind.errors import CallgrindAnnotateEmptyOutputFileError
from certfuzz.analyzers.callgrind.errors import CallgrindAnnotateMissingInputFileError
from certfuzz.file_handlers.watchdog_file import touch_watchdog_file
from certfuzz.fuzztools import filetools
from certfuzz.minimizer.unix_minimizer import UnixMinimizer
from certfuzz.tc_pipeline.tc_pipeline_base import TestCasePipelineBase
from certfuzz.reporters.copy_files import CopyFilesReporter
from certfuzz.reporters.testcase_logger import TestcaseLoggerReporter
from certfuzz.analyzers.drillresults import LinuxDrillResults
from certfuzz.analyzers.drillresults import DarwinDrillResults
from certfuzz.analyzers.pin_calltrace import Pin_calltrace
from certfuzz.analyzers.callgrind.callgrind import Callgrind
from certfuzz.analyzers.valgrind import Valgrind
from certfuzz.analyzers.cw_gmalloc import CrashWranglerGmalloc
from certfuzz.analyzers.stderr import StdErr

logger = logging.getLogger(__name__)


def get_uniq_logger(logfile):
    l = logging.getLogger('uniq_crash')
    if len(l.handlers) == 0:
        hdlr = logging.FileHandler(logfile)
        l.addHandler(hdlr)
    return l


class LinuxTestCasePipeline(TestCasePipelineBase):
    _minimizer_cls = UnixMinimizer

    def _setup_analyzers(self):
        self.analyzer_classes.append(StdErr)
        self.analyzer_classes.append(CrashWranglerGmalloc)

        if self.options.get('use_valgrind'):
            self.analyzer_classes.append(Valgrind)
            self.analyzer_classes.append(Callgrind)

        if self.options.get('use_pin_calltrace'):
            self.analyzer_classes.append(Pin_calltrace)

        plat = platform.system()
        if plat == 'Darwin':
            self.analyzer_classes.append(DarwinDrillResults)
        else:
            self.analyzer_classes.append(LinuxDrillResults)

    def _verify(self, testcase):
        '''
        Confirms that a test case is interesting enough to pursue further analysis
        :param testcase:
        '''
        TestCasePipelineBase._verify(self, testcase)

        # if you find more testcases, append them to self.tc_candidate_q
        # tc_verified_q crashes append to self.tc_verified_q

        logger.debug('verifying crash')
        with testcase as tc:
            if tc.is_crash:

                is_new_to_campaign = self.uniq_func(tc.signature)

                # fall back to checking if the crash directory exists
                #
                crash_dir_found = filetools.find_or_create_dir(tc.target_dir)

                keep_all = self.cfg['runoptions'].get('keep_duplicates', False)

                tc.should_proceed_with_analysis = keep_all or (
                    is_new_to_campaign and not crash_dir_found)

                if tc.should_proceed_with_analysis:
                    logger.info('%s is new', tc.signature)
                    self.dbg_out_file_orig = tc.dbg.file
                    logger.debug(
                        'Original debugger file: %s', self.dbg_out_file_orig)
                    self.success = True
                else:
                    logger.info(
                        'Testcase signature %s was already seen, skipping further analysis', tc.signature)
            else:
                logger.debug('not a crash, continuing')

    def _pre_minimize(self, testcase):
        touch_watchdog_file()

    def _pre_analyze(self, testcase):
        # get one last debugger output for the newly minimized file
        if self.cfg['debugger']['ctt_compat']:
            # CERT Triage Tools compatible gdb vrsion
            if testcase.pc_in_function:
                # change the debugger template
                testcase.set_debugger_template('complete')
            else:
                # use a debugger template that specifies fixed offsets from $pc for
                # disassembly
                testcase.set_debugger_template('complete_nofunction')
        else:
            # gdb version not compatible with CERT Triage Tools
            if testcase.pc_in_function:
                # change the debugger template
                testcase.set_debugger_template('noctt_complete')
            else:
                # use a debugger template that specifies fixed offsets from $pc for
                # disassembly
                testcase.set_debugger_template('noctt_complete_nofunction')

        logger.info(
            'Getting complete debugger output for crash: %s', testcase.fuzzedfile.path)
        testcase.get_debug_output(testcase.fuzzedfile.path)

        if self.dbg_out_file_orig != testcase.dbg.file:
            # we have a new debugger output
            # remove the old one
            filetools.delete_files(self.dbg_out_file_orig)
            if os.path.exists(self.dbg_out_file_orig):
                logger.warning(
                    'Failed to remove old debugger file %s', self.dbg_out_file_orig)
            else:
                logger.debug(
                    'Removed old debug file %s', self.dbg_out_file_orig)

    def _post_analyze(self, testcase):
        if self.options.get('use_valgrind'):
            logger.info('Annotating callgrind output')
            try:
                annotate_callgrind(testcase)
                annotate_callgrind_tree(testcase)
            except CallgrindAnnotateEmptyOutputFileError:
                logger.warning(
                    'Unexpected empty output from annotate_callgrind. Continuing')
            except CallgrindAnnotateMissingInputFileError:
                logger.warning('Missing callgrind output. Continuing')

    def _pre_report(self, testcase):
        uniqlogger = get_uniq_logger(self.options.get('uniq_log'))
        if testcase.hd_bits is not None:
            # We know HD info, since we minimized
            uniqlogger.info('%s crash_id=%s bitwise_hd=%d bytewise_hd=%d', testcase.seedfile.basename,
                            testcase.signature, testcase.hd_bits, testcase.hd_bytes)
        else:
            # We don't know the HD info
            uniqlogger.info(
                '%s crash_id=%s', testcase.seedfile.basename, testcase.signature)

    def _report(self, testcase):
        with CopyFilesReporter(testcase, self.tc_dir) as reporter:
            reporter.go()

        with TestcaseLoggerReporter(testcase) as reporter:
            reporter.go()

    def _post_report(self, testcase):
        # always clean up after yourself
        testcase.clean_tmpdir()
        # clean up
        testcase.delete_files()
