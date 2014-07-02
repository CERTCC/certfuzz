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
import binascii
import struct


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

    @abc.abstractproperty
    def _64bit_target_app(self):
        return self._64bit_debugger

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
        '''
        Check if the debugger and target app are 64-bit
        '''

    def _parse_testcase(self):
        '''
        Parse the debugger output file
        '''
        # TODO move this back to ResultDriller class
#        if self.cached_testcases:
#            if self.cached_testcases.get(self.crash_hash):
#                self.results[self.crash_hash] = self.cached_testcases[self.crash_hash]
#                return

        exceptionnum = self.get_ex_num()
        self._record_exception_info(exceptionnum)

        faultaddr = self.get_fault_addr()
        instraddr = self.get_instr_addr()

        # No faulting address means no crash.
        if not faultaddr:
            raise TestCaseBundleError('No faulting address means no crash')

        if not instraddr:
            raise TestCaseBundleError('No instraddr address means no crash')

        instraddr, faultaddr = self._64bit_addr_fixup(faultaddr, instraddr)

        if instraddr:
            self.details['exceptions'][exceptionnum]['pcmodule'] = self.pc_in_mapped_address(instraddr)

        # Get the cdb line that contains the crashing instruction
        instructionline = self.get_instr(instraddr)
        self.details['exceptions'][exceptionnum]['instructionline'] = instructionline
        if instructionline:
            faultaddr = self.fix_efa_offset(instructionline, faultaddr)

        # Fix faulting pattern endian
        faultaddr = faultaddr.replace('0x', '')

        self.details['exceptions'][exceptionnum]['efa'] = faultaddr

        if self._64bit_target_app:
            # 64-bit target app
            faultaddr = faultaddr.zfill(16)
            efaptr = struct.unpack('<Q', binascii.a2b_hex(faultaddr))
            efapattern = hex(efaptr[0]).replace('0x', '')
            efapattern = efapattern.replace('L', '')
            efapattern = efapattern.zfill(16)
        else:
            # 32-bit target app
            faultaddr = faultaddr.zfill(8)
            efaptr = struct.unpack('<L', binascii.a2b_hex(faultaddr))
            efapattern = hex(efaptr[0]).replace('0x', '')
            efapattern = efapattern.replace('L', '')
            efapattern = efapattern.zfill(8)

        # If there's a match, flag this exception has having Efa In File
        if binascii.a2b_hex(efapattern) in self.crasherdata:
            self.details['exceptions'][exceptionnum]['EIF'] = True
        else:
            self.details['exceptions'][exceptionnum]['EIF'] = False

    @abc.abstractmethod
    def _64bit_addr_fixup(self, faultaddr, instraddr):
        '''
        Some platforms need extra help with 64 bit addresses.
        Do that here before we really need to start using faultaddr
        and instraddr.
        :param faultaddr:
        :param instraddr:
        '''

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
