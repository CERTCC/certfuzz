'''
Created on Jul 16, 2014

@organization: cert.org
'''
import logging
import os

from certfuzz.minimizer.win_minimizer import WindowsMinimizer as Minimizer
from certfuzz.tc_pipeline.tc_pipeline_base import TestCasePipelineBase
from certfuzz.fuzztools import filetools
from certfuzz.minimizer.errors import MinimizerError
from certfuzz.reporters.copy_files import CopyFilesReporter
from certfuzz.fuzztools.command_line_templating import get_command_args_list
from certfuzz.analyzers import stderr
from certfuzz.analyzers.errors import AnalyzerEmptyOutputError


logger = logging.getLogger(__name__)


class WindowsTestCasePipeline(TestCasePipelineBase):
    def _setup_analyzers(self):
        pass
        #self.analyzer_classes.append(stderr.StdErr)

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
        logger.info("Crash confirmed: %s Exploitability: %s Faulting Address: %s", testcase.crash_hash, testcase.exp, testcase.faddr)
        if self.options['minimizable']:
            testcase.should_proceed_with_analysis = True
        self.success = True

    def _minimize(self, testcase):
        logger.info('Minimizing testcase %s', testcase.signature)
        logger.debug('config = %s', self.cfg)

        kwargs = {'cfg': self.cfg,
                  'crash': testcase,
                  'seedfile_as_target': True,
                  'bitwise': False,
                  'confidence': 0.999,
                  'tempdir': self.working_dir,
                  'maxtime': self.cfg['runoptions']['minimizer_timeout']
                  }

        try:
            with Minimizer(**kwargs) as minimizer:
                minimizer.go()

                # minimizer found other crashes, so we should add them
                # to our list for subsequent processing
                for tc in minimizer.other_crashes.values():
                    self.tc_candidate_q.put(tc)
        except MinimizerError as e:
            logger.error('Caught MinimizerError: {}'.format(e))

    def _post_minimize(self, testcase):
        if self.cfg['runoptions']['recycle_crashers']:
            logger.debug('Recycling crash as seedfile')
            iterstring = testcase.fuzzedfile.basename.split('-')[1].split('.')[0]
            crasherseedname = 'sf_' + testcase.seedfile.md5 + '-' + iterstring + testcase.seedfile.ext
            crasherseed_path = os.path.join(self.cfg['directories']['seedfile_dir'], crasherseedname)
            filetools.copy_file(testcase.fuzzedfile.path, crasherseed_path)
            self.sf_set.add_file(crasherseed_path)

    def _report(self, testcase):
        with CopyFilesReporter(testcase, self.tc_dir) as reporter:
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
                    return (False, 'skip duplicate %s' % testcase.signature)
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
