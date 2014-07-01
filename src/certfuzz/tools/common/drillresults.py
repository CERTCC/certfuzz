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


def read_file(textfile):
    '''
    Read text file
    '''
    with open(textfile, 'r') as f:
        return f.read()


def read_bin_file(textfile):
    '''
    Read binary file
    '''
    f = open(textfile, 'rb')
    text = f.read()
    return text


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

    def __init__(self, dbg_outfile, testcase_file, crash_hash, re_set):
        self.dbg_outfile = dbg_outfile
        self.testcase_file = testcase_file
        self.crash_hash = crash_hash
        self.re_set = re_set

        self.reporttext = read_file(self.dbg_outfile)
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
        self.cached_results = None
        self.dbg_out = []
        self.results = {}
        self.crash_scores = {}

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
    def check_64bit(self, reporttext):
        '''
        Check if the debugger and target app are 64-bit
        '''
        pass

    @abc.abstractmethod
    def _platform_find_dbg_output(self, crash_hash):
        pass

    def find_dbg_output(self):
        '''
        Crawls self.tld looking for crash directories to process. Puts a list
        of tuples into self.dbg_out.
        '''
        # Walk the results directory
        for root, dirs, files in os.walk(self.tld):
            dir_basename = os.path.basename(root)
            self._platform_find_dbg_output(dir_basename, files, root)

    @abc.abstractmethod
    def _check_report(self, dbg_file, crash_file, crash_hash, cached_results):
        pass

    def _check_dirs(self):
        check_dirs = [self.base_dir, 'results', 'crashers']
        for d in check_dirs:
            if os.path.isdir(d):
                self.tld = d
                return
        # if you got here, none of them exist
        raise DrillResultsError('None of {} appears to be a dir'.format(check_dirs))

    def load_cached(self):
        if self.force:
            logger.info('--force option used, ignoring cached results')
            return

        try:
            with open(self.pkl_filename, 'rb') as pkl_file:
                self.cached_results = pickle.load(pkl_file)
        except IOError:
            # No cached results
            pass

    def check_reports(self):
        for dbg_file, crash_file, crash_hash in self.dbg_out:
            self._check_report(dbg_file, crash_file, crash_hash, self.cached_results)

    def _score_crasher(self, details):
        scores = [100]
        if details['reallyexploitable'] == True:
        # The crash summary is a very interesting one
            for exception in details['exceptions']:
                module = details['exceptions'][exception]['pcmodule']
                if module == 'unloaded' and not self.ignorejit:
                    # EIP is not in a loaded module
                    scores.append(20)
                if details['exceptions'][exception]['shortdesc'] in self.re_set:
                    efa = '0x' + details['exceptions'][exception]['efa']
                    if details['exceptions'][exception]['EIF']:
                    # The faulting address pattern is in the fuzzed file
                        if '0x000000' in efa:
                            # Faulting address is near null
                            scores.append(30)
                        elif '0x0000' in efa:
                            # Faulting address is somewhat near null
                            scores.append(20)
                        elif '0xffff' in efa:
                            # Faulting address is likely a negative number
                            scores.append(20)
                        else:
                            # Faulting address has high entropy.  Most exploitable.
                            scores.append(10)
                    else:
                        # The faulting address pattern is not in the fuzzed file
                        scores.append(40)
        else:
            # The crash summary isn't necessarily interesting
            for exception in details['exceptions']:
                efa = '0x' + details['exceptions'][exception]['efa']
                module = details['exceptions'][exception]['pcmodule']
                if module == 'unloaded' and not self.ignorejit:
                    scores.append(20)
                elif module.lower() == 'ntdll.dll' or 'msvcr' in module.lower():
                    # likely heap corruption.  Exploitable, but difficult
                    scores.append(45)
                elif '0x00120000' in efa or '0x00130000' in efa or '0x00140000' in efa:
                    # non-continued potential stack buffer overflow
                    scores.append(40)
                elif details['exceptions'][exception]['EIF']:
                # The faulting address pattern is in the fuzzed file
                    if '0x000000' in efa:
                        # Faulting address is near null
                        scores.append(70)
                    elif '0x0000' in efa:
                        # Faulting address is somewhat near null
                        scores.append(60)
                    elif '0xffff' in efa:
                        # Faulting address is likely a negative number
                        scores.append(60)
                    else:
                        # Faulting address has high entropy.
                        scores.append(50)
        return min(scores)

    def score_reports(self):
        # Assign a ranking to each crash report.  The lower the rank, the higher
        # the exploitability
        if self.results:
            print "--- Interesting crashes ---\n"
            # For each of the crash ids in the results dictionary, apply ranking
            for crash_key, crash_details in self.results.iteritems():
                try:
                    self.crash_scores[crash_key] = self._score_crasher(crash_details)
                except KeyError:
                    print "Error scoring crash %s" % crash_key
                    continue

    def print_crash_report(self, crash_key, score):
        details = self.results[crash_key]
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
        for crash_key, score in self.sorted_crashes:
            self.print_crash_report(crash_key, score)

    def cache_results(self):
        pkldir = os.path.dirname(self.pkl_filename)
        if not os.path.exists(pkldir):
            os.makedirs(pkldir)
        with open(self.pkl_filename, 'wb') as pkl_file:
            pickle.dump(self.results, pkl_file, -1)

    def drill_results(self):
        self._check_dirs()
        self.load_cached()
        self.find_dbg_output()
        self.check_reports()
        self.score_reports()
        self.print_reports()
        self.cache_results()
