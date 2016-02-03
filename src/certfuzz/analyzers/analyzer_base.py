'''
Created on Oct 23, 2012

@organization: cert.org
'''
import logging
import os

from certfuzz.fuzztools import subprocess_helper as subp
from certfuzz.analyzers.errors import AnalyzerOutputMissingError, AnalyzerEmptyOutputError
from certfuzz.fuzztools.command_line_templating import get_command_args_list

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Analyzer(object):
    '''
    classdocs
    '''
    def __init__(self, cfg, testcase, outfile=None, timeout=None, **options):
        logger.debug('Initializing %s', self.__class__.__name__)
        self.cfg = cfg
        self.testcase = testcase

        self.cmdargs = get_command_args_list(self.cfg['target']['cmdline_template'], testcase.fuzzedfile.path)[1]
        self.outfile = outfile
        self.timeout = float(timeout)
        self.progname = self.cmdargs[1]
        self.options = options

        self.preserve_stderr = False
        self.tmpdir = testcase.fuzzedfile.dirname

        # child classes should explicitly set this to True if they need it:
        self.empty_output_ok = False
        self.missing_output_ok = False

        # keep track of retries
        self.retry_count = 0
        self.max_retries = 3

        # catch stderr if we're not already redirecting it
        # typically outfile is just going into a temp dir so we'll
        # drop a stderr file there (so it will just get deleted when
        # bff does its normal cleanup). It's really only useful if
        # there is a problem that raises an exception, which therefore
        # leaves the temp dir behind.
        if self.options.get('stderr'):
            self.preserve_stderr = True
        else:
            self._set_stderrpath()

    def _stderrfile(self):
        return '%s-%d.%s' % (self.__class__.__name__, self.retry_count, 'stderr')

    def _set_stderrpath(self):
        self.options['stderr'] = os.path.join(self.tmpdir, self._stderrfile())

    def _get_cmdline(self):
        raise NotImplementedError

    def _analyzer_exists(self, f):
        f = f.replace('"', '')
        if os.path.exists(f):
            return True
        else:
            # does it exist anywhere in the path?
            for path in os.environ["PATH"].split(":"):
                if os.path.exists(os.path.join(path, f)):
                    return True
            return False

    def go(self):
        '''
        Generates analysis output for <cmd> into <outfile>.
        If analysis process fails to complete before <timeout>,
        attempt to _kill analyzer and progname.
        '''
        logger.info('Running %s', self.__class__.__name__)
        # build the command line in a separate function so we can unit test
        # it without actually running the command
        args = self._get_cmdline()
        logger.debug('%s cmd: [%s]', self.__class__.__name__, ' '.join(args))

        # short-circuit if analyzer is missing
        analyzer = str(args[0])  # make a copy of the string so we don't mess up args[0]
        if (not self._analyzer_exists(analyzer)):
            logger.warning('Skipping analyzer %s: Not found in path.', analyzer)
            return

        subp.run_with_timer(args, self.timeout, self.progname, **self.options)
        if not self.missing_output_ok and not os.path.exists(self.outfile):
            raise AnalyzerOutputMissingError(self.outfile)
        if not self.empty_output_ok and not os.path.getsize(self.outfile):
            # try again?
            self.retry_count += 1
            if self.retry_count < self.max_retries:
                logger.warning('Empty output file on attempt %d of %d', self.retry_count, self.max_retries)
                # get a new name for the stderr output if we can
                if not self.preserve_stderr:
                    self._set_stderrpath()
                # Give the analyzer twice as much time to produce output
                self.timeout *= 2
                self.go()
            else:
                logger.warning('Unable to produce output after %d tries', self.retry_count)
                raise AnalyzerEmptyOutputError(self.outfile)
        else:
            # delete the stderr file since we didn't need it
            stderrfile = self._stderrfile()
            if os.path.exists(stderrfile):
                os.remove(stderrfile)
