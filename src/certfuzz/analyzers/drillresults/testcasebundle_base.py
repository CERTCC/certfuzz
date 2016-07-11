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
from certfuzz.drillresults.common import reg64_set
from certfuzz.drillresults.common import reg_set
from certfuzz.drillresults.common import is_number
from certfuzz.drillresults.common import carve2


logger = logging.getLogger(__name__)


class TestCaseBundle(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, dbg_outfile, testcase_file, crash_hash, ignore_jit=False):
        self.dbg_outfile = dbg_outfile
        self.testcase_file = testcase_file

        self.crash_hash = crash_hash
        self.ignore_jit = ignore_jit

        self.re_set = set(self.really_exploitable)

        self.regdict = {}

        if not os.path.exists(self.dbg_outfile):
            raise TestCaseBundleError(
                'Debugger file not found: {}'.format(self.dbg_outfile))

        self.reporttext = read_text_file(self.dbg_outfile)
        self._find_testcase_file()
        self._verify_files_exist()
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
        self.reg_set = reg_set

    def go(self):
        # See if we're dealing with 64-bit debugger or target app
        self._check_64bit()

        if self._64bit_target_app:
            self.reg_set = reg64_set

        self._get_classification()
        self._get_shortdesc()
        self._parse_testcase()
        self._score_testcase()

    @abc.abstractproperty
    def really_exploitable(self):
        '''
        List of strings indicating debugger descriptions of particular interest
        '''
        return []

    @abc.abstractproperty
    def _64bit_target_app(self):
        '''
        Returns true if the target app is 64-bit.
        '''
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
        # Explicitly remove crasherdata to prevent runaway memory usage
        self.crasherdata = ''
        pass

    def _find_testcase_file(self):
        if not os.path.isfile(self.testcase_file):
            # Can't find the crasher file
            raise TestCaseBundleError(
                'Cannot find testcase file %s', self.testcase_file)

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

    @abc.abstractmethod
    def get_instr(self, instraddr):
        '''
        Find the disassembly line for the current (crashing) instruction
        '''

    @abc.abstractmethod
    def get_instr_addr(self):
        '''
        Find the address for the current (crashing) instruction
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
            # raise TestCaseBundleError('No faulting address means no crash')
            return

        if not instraddr:
            # raise TestCaseBundleError('No instraddr address means no crash')
            return

        faultaddr, instraddr = self._64bit_addr_fixup(faultaddr, instraddr)

        if instraddr:
            self.details['exceptions'][exceptionnum][
                'pcmodule'] = self.pc_in_mapped_address(instraddr)

        # Get the cdb line that contains the crashing instruction
        instructionline = self.get_instr(instraddr)
        self.details['exceptions'][exceptionnum][
            'instructionline'] = instructionline
        if instructionline:
            self.instructionpieces = instructionline.split()
            faultaddr = self._prefix_0x(faultaddr)
            faultaddr = self.fix_efa_offset(instructionline, faultaddr)
            if self.shortdesc == 'ReturnAv':
                faultaddr = self.fix_return_efa(faultaddr)

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
    def _look_for_loaded_module(self, instraddr, line):
        '''
        If the line contains loaded module info, see if instraddr is in the module.
        If it is, return the module name, otherwise return None
        :param instraddr:
        :param line:
        '''

    def format_addr(self, faultaddr):
        '''
        Format a 64- or 32-bit memory address to a fixed width
        '''
        logger.debug('formatting address [%s]', faultaddr)
        if not faultaddr:
            return

        faultaddr = faultaddr.strip().replace('0x', '')

        if self._64bit_target_app:
            # Due to a bug in !exploitable, the Exception Faulting Address is
            # often wrong with 64-bit targets
            if len(faultaddr) < 16:
                # pad faultaddr if it's shorter than 64 bits
                logger.debug('addr < 64 bits: pad')
                return faultaddr.zfill(16)
        else:
            # if faultaddr is longer than 32 bits, truncate it
            if len(faultaddr) > 8:
                logger.debug('addr > 32 bits: truncate')
                return faultaddr[-8:]

            # if faultaddr is shorter than 32 bits, pad it
            if len(faultaddr) < 8:
                # pad faultaddr
                logger.debug('addr < 32 bits: pad')
                return faultaddr.zfill(8)

        return faultaddr

    def pc_in_mapped_address(self, instraddr):
        '''
        Check if the instruction pointer is in a loaded module
        '''
        if not instraddr:
            # The debugger file doesn't have anything in it that'll tell us
            # where the PC is.
            return ''

        logger.debug('checking if %s is mapped', instraddr)
        for line in self.reporttext.splitlines():
            module_name = self._look_for_loaded_module(instraddr, line)
            if module_name is not None:
                # short circuit as soon as we find a mapped module
                logger.debug('module found: %s', module_name)
                return module_name
        # if you got here, instraddr is not in a loaded module
        logger.debug('addr %s is not in loaded module', instraddr)
        return 'unloaded'

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

    def _match_rgx(self, rgx, return_value_func):
        for line in self.reporttext.splitlines():
            n = rgx.match(line)
            if n:
                return return_value_func(n, line)

    def _record_exception_info(self, exceptionnum):
        if self.classification:
            # Create a new exception dictionary to add to the crash
            self.details['exceptions'][exceptionnum] = {
                'classification': self.classification}

        if not self.shortdesc:
            logger.debug('no short description')
            return

        # Set !exploitable Short Description for the exception
        self.details['exceptions'][exceptionnum]['shortdesc'] = self.shortdesc
        # Flag the entire crash ID as really exploitable if this is a good
        # exception
        self.details['reallyexploitable'] = self.shortdesc in self.re_set

    def _score_interesting(self):
        scores = []
        exceptions = self.details['exceptions']

        for exception in exceptions.itervalues():
            module, efa, eif = self._get_efa_mod_eif(exception)

            if module == 'unloaded' and not self.ignore_jit:
                # EIP is not in a loaded module
                scores.append(20)

            if exception['shortdesc'] in self.re_set:
                if eif:
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

        return scores

    def _get_efa_mod_eif(self, exception):
        try:
            efa = '0x' + exception['efa']
        except KeyError:
            logger.error('Exception has no value set for efa.')
            efa = ''
        try:
            module = exception['pcmodule']
        except KeyError:
            logger.error('Exception has no value set for pcmodule')
            module = ''
        try:
            eif = exception['EIF']
        except KeyError:
            logger.error('Exception has no value set for EIF')
            eif = False

        return module, efa, eif

    def _score_less_interesting(self):
        scores = []
        exceptions = self.details['exceptions']

        for exception in exceptions.itervalues():
            module, efa, eif = self._get_efa_mod_eif(exception)

            if module == 'unloaded' and not self.ignore_jit:
                scores.append(20)
            elif module.lower() == 'ntdll.dll' or 'msvcr' in module.lower():
                # likely heap corruption.  Exploitable, but difficult
                scores.append(45)
            elif '0x00120000' in efa or '0x00130000' in efa or '0x00140000' in efa:
                # non-continued potential stack buffer overflow
                scores.append(40)
            elif eif:
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

        return scores

    def _score_testcase(self):
        logger.debug('Scoring testcase: %s', self.crash_hash)
        details = self.details
        scores = [100]
        if details['reallyexploitable'] == True:
            # The crash summary is a very interesting one
            scores.extend(self._score_interesting())
        else:
            # The crash summary isn't necessarily interesting
            scores.extend(self._score_less_interesting())
        logger.debug('accumulated scores: %s', scores)
        self.score = min(scores)

    def _prefix_0x(self, addr):
        if addr.startswith('0x'):
            return addr
        else:
            return '0x{}'.format(addr)

    def fix_return_efa(self, faultaddr):
        '''
        The faulting address on Linux on a ReturnAV is reported as null
        We can figure out what it actually is based on the backtrace
        '''
        if int(faultaddr, base=16) == 0:
            derived_faultaddr = self.get_return_addr()
            logger.debug(
                'New faulting address derived from backtrace: %s' % derived_faultaddr)
            if derived_faultaddr is not None:
                faultaddr = derived_faultaddr
        return faultaddr

    @abc.abstractmethod
    def get_return_addr(self):
        '''
        Get return address based on backtrace
        '''

    def fix_efa_offset(self, instructionline, faultaddr):
        '''
        Adjust faulting address for instructions that use offsets
        Currently only works for instructions like CALL [reg + offset]
        '''

        try:
            index = self.instructionpieces.index('call')
        except ValueError:
            return faultaddr

        # CALL instruction
        try:
            address = self.instructionpieces[index + 3]
        except IndexError:
            # CALL to just a register.  No offset
            return faultaddr

        if not '+' in address:
            return faultaddr

        splitaddress = address.split('+')
        reg = splitaddress[0]
        reg = reg.replace('[', '')

        if reg not in self.reg_set:
            return faultaddr

        offset = splitaddress[1]
        offset = offset.replace('h', '')
        offset = offset.replace(']', '')

        if not is_number(offset):
            return faultaddr

        offset = self._prefix_0x(offset)

        if int(offset, 16) > int(faultaddr, 16):
            # TODO: fix up negative numbers
            return faultaddr

        # Subtract offset to get actual interesting pattern
        faultaddr = hex(eval(faultaddr) - eval(offset))
        faultaddr = self.format_addr(faultaddr.replace('L', ''))
        return faultaddr

    def get_fault_addr(self):
        faultaddr = carve2(self.reporttext)
        logger.debug('carved fault address: %s', faultaddr)
        return self.format_addr(faultaddr)
