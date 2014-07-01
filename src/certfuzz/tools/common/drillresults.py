'''
Created on Jun 30, 2014

@organization: cert.org
'''
import os
import cPickle as pickle
import abc
import logging
import argparse
from certfuzz.tools.common.errors import DrillResultsError
from certfuzz.fuzztools.filetools import read_text_file, read_bin_file

logger = logging.getLogger(__name__)


registers = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi',
             'edi', 'eip')

registers64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi',
               'rdi', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13',
               'r14', 'r15')

reg_set = set(registers)
reg64_set = set(registers64)


def _build_arg_parser():
    usage = "usage: %prog [options]"
    parser = argparse.ArgumentParser(usage)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--debug', dest='debug', action='store_true',
                      help='Set logging to DEBUG and enable additional debuggers if available')
    group.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                      help='Set logging to INFO level')


    parser.add_argument('-d', '--dir',
                      help='directory to look for results in. Default is "results"',
                      dest='resultsdir',
                      default='../results',
                      type=str)
    parser.add_argument('-j', '--ignorejit', dest='ignorejit',
                      action='store_true',
                      help='Ignore PC in unmapped module (JIT)',
                      default=False)
    parser.add_argument('-f', '--force', dest='force',
                      action='store_true',
                      help='Force recalculation of results')

    return parser


def root_logger_to_console(args):
    root_logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    root_logger.addHandler(hdlr)

    set_log_level(root_logger, args)


def set_log_level(log_obj, args):
    if args.debug:
        log_obj.setLevel(logging.DEBUG)
        log_obj.debug('Log level = DEBUG')
    elif args.verbose:
        log_obj.setLevel(logging.INFO)
        log_obj.info('Log level = INFO')
    else:
        log_obj.setLevel(logging.WARNING)


def parse_args():
    parser = _build_arg_parser()
    return parser.parse_args()


def carve(string, token1, token2):
    startindex = string.find(token1)
    if startindex == -1:
        # can't find token1
        return ""
    startindex = startindex + len(token1)
    endindex = string.find(token2, startindex)
    if endindex == -1:
        # can't find token2
        return ""
    return string[startindex:endindex]


# Todo: fix this up.  Was added to bring gdb support
def carve2(string):
    delims = [("Exception Faulting Address: ", "\n"),
              ("si_addr:$2 = (void *)", "\n")]
    for token1, token2 in delims:
        substring = carve(string, token1, token2)
        if len(substring):
            # returns the first matching substring
            return substring
    # if we got here, no match was found, just return empty string
    return ""


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


class TestCaseBundle(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, dbg_outfile, testcase_file, crash_hash, re_set, ignore_jit=False):
        self.dbg_outfile = dbg_outfile
        self.testcase_file = testcase_file
        self.crash_hash = crash_hash
        self.re_set = re_set
        self.ignore_jit = ignore_jit

        self.reporttext = read_text_file(self.dbg_outfile)
        # Read in the fuzzed file
        self.crasherdata = read_bin_file(self.testcase_file)
        self.current_dir = os.path.dirname(self.dbg_outfile)

        self.details = {'reallyexploitable': False,
                        'exceptions': {}}
        self.score = 100
        self._64bit_debugger = False

        # See if we're dealing with 64-bit debugger or target app
        self._check_64bit()
        self._check_report()
        self._score_testcase()

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        pass

    @abc.abstractmethod
    def _check_64bit(self):
        pass

    @abc.abstractmethod
    def _check_report(self):
        pass

    @abc.abstractmethod
    def _score_testcase(self):
        pass


class ResultDriller(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self,
                 ignore_jit=False,
                 base_dir='../results',
                 force_reload=False):
        self.ignore_jit = ignore_jit
        self.base_dir = base_dir
        self.tld = None
        self.force = force_reload

        self.pickle_file = os.path.join('fuzzdir', 'drillresults.pkl')
        self.cached_testcases = None
        self.testcase_bundles = []
#        self.results = {}
#        self.crash_scores = {}

        self._64bit_debugger = False
        self.re_set = set(self.really_exploitable)

    @abc.abstractproperty
    def really_exploitable(self):
        return []

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        handled = False

        if etype is DrillResultsError:
            print "{}: {}".format(etype.__name__, value)
            handled = True

        return handled

    @abc.abstractmethod
    def _platform_find_testcases(self, crash_hash):
        pass

    def process_testcases(self):
        '''
        Crawls self.tld looking for crash directories to process. Puts a list
        of tuples into self.testcase_bundles.
        '''
        # Walk the results directory
        for root, dirs, files in os.walk(self.tld):
            logger.debug('Looking for testcases in %s', root)
            dir_basename = os.path.basename(root)
            self._platform_find_testcases(dir_basename, files, root)

    def _check_dirs(self):
        check_dirs = [self.base_dir, 'results', 'crashers']
        for d in check_dirs:
            if os.path.isdir(d):
                self.tld = d
                logger.debug('found dir: %s', self.tld)
                return
        # if you got here, none of them exist
        raise DrillResultsError('None of {} appears to be a dir'.format(check_dirs))

    def load_cached(self):
        if self.force:
            logger.info('--force option used, ignoring cached results')
            return

        try:
            with open(self.pickle_file, 'rb') as pkl_file:
                self.cached_testcases = pickle.load(pkl_file)
        except IOError:
            # No cached results
            pass

    @property
    def crash_scores(self):
        return dict([(tcb.crash_hash, tcb.score) for tcb in self.testcase_bundles])

    def print_crash_report(self, crash_key, score, details):
#        details = self.results[crash_key]
        print '\n%s - Exploitability rank: %s' % (crash_key, score)
        print 'Fuzzed file: %s' % details['fuzzedfile']
        for exception in details['exceptions']:
            shortdesc = details['exceptions'][exception]['shortdesc']
            eiftext = ''
            efa = '0x' + details['exceptions'][exception]['efa']
            if details['exceptions'][exception]['EIF']:
                eiftext = " *** Byte pattern is in fuzzed file! ***"
            print 'exception %s: %s accessing %s  %s' % (exception, shortdesc, efa, eiftext)
            if details['exceptions'][exception]['instructionline']:
                print details['exceptions'][exception]['instructionline']
            module = details['exceptions'][exception]['pcmodule']
            if module == 'unloaded':
                if not self.ignorejit:
                    print 'Instruction pointer is not in a loaded module!'
            else:
                print 'Code executing in: %s' % module

    @property
    def sorted_crashes(self):
        return sorted(self.crash_scores.iteritems(), key=lambda(k, v): (v, k))

    def print_reports(self):
        results = dict([(tcb.crash_hash, tcb.details) for tcb in self.testcase_bundles])
        print "--- Interesting crashes ---\n"
        for crash_key, score in self.sorted_crashes:
            details = results[crash_key]
            try:
                self.print_crash_report(crash_key, score, details)
            except KeyError as e:
                logger.warning('Tescase %s is missing information: %s', crash_key, e)

    def cache_results(self):
        pkldir = os.path.dirname(self.pickle_file)
        if not os.path.exists(pkldir):
            os.makedirs(pkldir)
        with open(self.pickle_file, 'wb') as pkl_file:
            pickle.dump(self.testcase_bundles, pkl_file, -1)

    def drill_results(self):
        logger.debug('drill_results')
        self._check_dirs()
        self.load_cached()
        self.process_testcases()
        self.print_reports()
        self.cache_results()
