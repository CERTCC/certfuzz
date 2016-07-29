'''
Created on Jul 16, 2014

@organization: cert.org
'''
import logging
import os

from certfuzz.minimizer.win_minimizer import WindowsMinimizer
from certfuzz.tc_pipeline.tc_pipeline_base import TestCasePipelineBase
from certfuzz.reporters.copy_files import CopyFilesReporter
from certfuzz.analyzers.stderr import StdErr
from certfuzz.analyzers.drillresults import WindowsDrillResults


logger = logging.getLogger(__name__)


class WindowsTestCasePipeline(TestCasePipelineBase):
    _minimizer_cls = WindowsMinimizer

    def _setup_analyzers(self):
        # self.analyzer_classes.append(StdErr)
        self.analyzer_classes.append(WindowsDrillResults)

    def _pre_verify(self, testcase):
        # pretty-print the testcase for debugging
        logger.debug('Testcase:')
        from pprint import pformat
        formatted = pformat(testcase.__dict__)
        for line in formatted.splitlines():
            logger.debug('... %s', line.rstrip())

    def _verify(self, testcase):
        keep_it, reason = self.keep_testcase(testcase)

        if not keep_it:
            if self.options['null_runner'] and reason == 'not a crash':
                # Don't be too chatty about rejecting a null runner crash
                pass
            else:
                logger.info('Candidate testcase rejected: %s', reason)
            testcase.should_proceed_with_analysis = False
            return

        logger.debug('Keeping testcase (reason=%s)', reason)
        testcase.should_proceed_with_analysis = True
        logger.info("Crash confirmed: %s Exploitability: %s Faulting Address: %s",
                    testcase.crash_hash, testcase.exp, testcase.faddr)
        # if self.options['minimizable']:
        #    testcase.should_proceed_with_analysis = True
        self.success = True

    def _report(self, testcase):
        with CopyFilesReporter(testcase, keep_duplicates=self.options['keep_duplicates']) as reporter:
            reporter.go()

    def keep_testcase(self, testcase):
        '''Given a testcase, decide whether it is a keeper. Returns a tuple
        containing a boolean indicating whether to keep the testcase, and
        a string containing the reason for the boolean result.
        @param testcase: a testcase object
        @return (bool,str)
        '''
        if testcase.is_crash:
            if self.options['keep_duplicates']:
                return (True, 'keep duplicates')
            elif self.uniq_func(testcase.signature):
                # Check if crasher directory exists already
                target_dir = testcase._get_output_dir(self.outdir)
                if os.path.exists(target_dir):
                    if len(os.listdir(target_dir)) > 0:
                        return (False, 'skip duplicate %s' % testcase.signature)
                    else:
                        return(True, 'Empty output directory')
                else:
                    return (True, 'unique')
            else:
                return (False, 'skip duplicate %s' % testcase.signature)
        elif self.options['null_runner']:
            return (False, 'not a crash')
        elif self.options['keep_heisenbugs']:
            return (True, 'heisenbug')
        else:
            return (False, 'skip heisenbugs')
