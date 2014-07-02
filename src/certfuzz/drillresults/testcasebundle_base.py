'''
Created on Jul 2, 2014

@organization: cert.org
'''
import abc
import logging
import os

from certfuzz.fuzztools.filetools import read_text_file

from certfuzz.drillresults.common import read_bin_file
from certfuzz.drillresults.errors import TestCaseBundleError


logger = logging.getLogger(__name__)


class TestCaseBundle(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, dbg_outfile, testcase_file, crash_hash, ignore_jit=False):
        self.dbg_outfile = dbg_outfile
        self.testcase_file = testcase_file

        self._find_testcase_file()

        self._verify_files_exist()

        self.crash_hash = crash_hash
        self.ignore_jit = ignore_jit

        self.re_set = set(self.really_exploitable)

        self.regdict = {}

        self.reporttext = read_text_file(self.dbg_outfile)
        # Read in the fuzzed file
        self.crasherdata = read_bin_file(self.testcase_file)
        self.current_dir = os.path.dirname(self.dbg_outfile)

        self.details = {'reallyexploitable': False,
                        'exceptions': {},
                        'fuzzedfile': self.testcase_file}

        self.score = 100
        self._64bit_debugger = False
        self.classification = None
        self.shortdesc = None

        # See if we're dealing with 64-bit debugger or target app
        self._check_64bit()
        self._get_classification()
        self._get_shortdesc()
        self._parse_testcase()
        self._score_testcase()

    @abc.abstractproperty
    def really_exploitable(self):
        return []

    def _verify_files_exist(self):
        for f in [self.dbg_outfile, self.testcase_file]:
            if not os.path.exists(f):
                raise TestCaseBundleError('File not found: {}'.format(f))
            else:
                logger.debug('Found file: %s', f)

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _find_testcase_file(self):
        if not os.path.isfile(self.testcase_file):
            # Can't find the crasher file
            raise TestCaseBundleError('Cannot find testcase file %s', self.testcase_file)

    @abc.abstractmethod
    def _get_classification(self):
        pass

    @abc.abstractmethod
    def _get_shortdesc(self):
        pass

    @abc.abstractmethod
    def _check_64bit(self):
        pass

    @abc.abstractmethod
    def _parse_testcase(self):
        pass

    def get_ex_num(self):
        '''
        Override this method for platforms where exceptions can be continued
        '''
        return 0

    def _record_exception_info(self, exceptionnum):
        if self.classification:
            # Create a new exception dictionary to add to the crash
            exception = {}
            self.details['exceptions'][exceptionnum] = exception
            self.details['exceptions'][exceptionnum]['classification'] = self.classification
        if self.shortdesc:
            # Set !exploitable Short Description for the exception
            self.details['exceptions'][exceptionnum]['shortdesc'] = self.shortdesc # Flag the entire crash ID as really exploitable if this is a good
            # exception
            self.details['reallyexploitable'] = self.shortdesc in self.re_set

    def _score_testcase(self):
        logger.debug('Scoring testcase: %s', self.crash_hash)
        details = self.details
        scores = [100]
        if details['reallyexploitable'] == True:
        # The crash summary is a very interesting one
            for exception in details['exceptions']:
                module = details['exceptions'][exception]['pcmodule']
                if module == 'unloaded' and not self.ignore_jit:
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
                if module == 'unloaded' and not self.ignore_jit:
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
        self.score = min(scores)
