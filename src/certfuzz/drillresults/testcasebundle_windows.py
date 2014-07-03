'''
Created on Jul 2, 2014

@organization: cert.org
'''
import logging
import os
import re

from certfuzz.drillresults.common import carve
from certfuzz.drillresults.common import carve2
from certfuzz.drillresults.common import is_number
from certfuzz.drillresults.common import reg_set
from certfuzz.drillresults.common import reg64_set
from certfuzz.drillresults.testcasebundle_base import TestCaseBundle


logger = logging.getLogger(__name__)

# compile our regular expresssions once
RE_64BIT_DEBUGGER = re.compile('^Microsoft.*AMD64$')
RE_SYSWOW64 = re.compile('ModLoad:.*syswow64.*', re.IGNORECASE)
RE_MAPPED_ADDRESS = re.compile('^ModLoad: ([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)')
RE_MAPPED_ADDRESS64 = re.compile('^ModLoad: ([0-9a-fA-F]+`[0-9a-fA-F]+)\s+([0-9a-fA-F]+`[0-9a-fA-F]+)\s+(.+)'),


class WindowsTestCaseBundle(TestCaseBundle):
    # These !exploitable short descriptions indicate a very interesting crash
    really_exploitable = [
                      'ReadAVonIP',
                      'TaintedDataControlsCodeFlow',
                      'ReadAVonControlFlow',
                      'DEPViolation',
                      'IllegalInstruction',
                      'PrivilegedInstruction',
                      ]

    def __init__(self, dbg_outfile, testcase_file, crash_hash, re_set,
                 ignore_jit):
        if self.testcase_file == '':
            # Old FOE version that didn't do multiple exceptions or rename msec
            # file with exploitability
            testcase_file, _junk = os.path.splitext(dbg_outfile)

        TestCaseBundle(self, dbg_outfile, testcase_file, crash_hash, re_set,
                 ignore_jit)
        self.wow64_app = False

    def _get_classification(self):
        self.classification = carve(self.reporttext, "Exploitability Classification: ", "\n")
        logger.debug('Classification: %s', self.classification)

    def _get_shortdesc(self):
        self.shortdesc = carve(self.reporttext, "Short Description: ", "\n")
        logger.debug('Short Description: %s', self.shortdesc)

    def _check_64bit(self):
        for line in self.reporttext.splitlines():
            n = re.match(RE_64BIT_DEBUGGER, line)
            if n:
                self._64bit_debugger = True

            if self._64bit_debugger:
                n = re.match(RE_SYSWOW64, line)
                if n:
                    self.wow64_app = True

    def _find_testcase_file(self):
        # Tries a little harder than the base class to find a test case file to
        # work with

        # Check if the expected crasher file (fuzzed file) exists
        current_dir = os.path.dirname(self.dbg_outfile)
        if not os.path.isfile(self.testcase_file):
            # It's not there, so try to extract the filename from the cdb
            # commandline
            commandline = carve(self.reporttext, "CommandLine: ", "\n")
            args = commandline.split()
            for arg in args:
                if "sf_" in arg:
                    self.testcase_file = os.path.basename(arg)
                    if "-" in self.testcase_file:
                        # FOE 2.0 verify mode puts a '-<iteration>' part on the
                        # filename when invoking cdb, however the resulting file
                        # is really just 'sf_<hash>.<ext>'
                        fileparts = self.testcase_file.split('-')
                        m = re.search('\..+', fileparts[1])
                        # Recreate the original file name, minus the iteration
                        self.testcase_file = os.path.join(current_dir, fileparts[0] + m.group(0))
                    else:
                        self.testcase_file = os.path.join(current_dir, self.testcase_file)

        TestCaseBundle._find_testcase_file(self)

    def _64bit_addr_fixup(self, faultaddr, instraddr):
        if self._64bit_target_app and instraddr: # Put backtick into instruction address for pattern matching
            instraddr = ''.join([instraddr[:8], '`', instraddr[8:]])
            if self.shortdesc != 'DEPViolation':
                faultaddr = self.fix_efa_bug(instraddr, faultaddr)
        return instraddr, faultaddr

    @property
    def _64bit_target_app(self):
        return self._64bit_debugger and not self.wow64_app

    def _look_for_loaded_module(self, instraddr, line):
        '''
        Returns a string containing the module location if found, None otherwise
        :param instraddr:
        :param line:
        '''
        pattern = RE_MAPPED_ADDRESS
        if self._64bit_debugger:
            pattern = RE_MAPPED_ADDRESS64

        # convert to an int as hex
        instraddr = instraddr.replace('`', '')
        instraddr = int(instraddr, 16)

        n = re.match(pattern, line)
        if n:
            # Strip out backticks present on 64-bit systems
            begin_address = int(n.group(1).replace('`', ''), 16)
            end_address = int(n.group(2).replace('`', ''), 16)
            module_name = n.group(3)
            if begin_address < instraddr < end_address:
                logger.debug('Matched: %x in %x %x %s', instraddr,
                             begin_address, end_address, module_name)
                # as soon as we find this, we're done
                return module_name

    def fix_efa_offset(self, instructionline, faultaddr):
        '''
        Adjust faulting address for instructions that use offsets
        Currently only works for instructions like CALL [reg + offset]
        '''
        if self._64bit_target_app:
            reg_set = reg64_set

        if '0x' not in faultaddr:
            faultaddr = '0x' + faultaddr
        instructionpieces = instructionline.split()
        if '??' not in instructionpieces[-1]:
            # The av is on the address of the code called, not the address
            # of the call
            return faultaddr
        for index, piece in enumerate(instructionpieces):
            if piece == 'call':
                # CALL instruction
                if len(instructionpieces) <= index + 3:
                    # CALL to just a register.  No offset
                    return faultaddr
                address = instructionpieces[index + 3]
                if '+' in address:
                    splitaddress = address.split('+')
                    reg = splitaddress[0]
                    reg = reg.replace('[', '')
                    if reg not in reg_set:
                        return faultaddr
                    offset = splitaddress[1]
                    offset = offset.replace('h', '')
                    offset = offset.replace(']', '')
                    if is_number(offset):
                        if '0x' not in offset:
                            offset = '0x' + offset
                        if int(offset, 16) > int(faultaddr, 16):
                            # TODO: fix up negative numbers
                            return faultaddr
                        # Subtract offset to get actual interesting pattern
                        faultaddr = hex(eval(faultaddr) - eval(offset))
                        faultaddr = self.format_addr(faultaddr.replace('L', ''))
        return faultaddr

    def get_ex_num(self):
        '''
        Get the exception number by counting the number of continues
        '''
        if self.wow64_app:
            pattern = re.compile('^[0-9]:[0-9][0-9][0-9]:x86> (.*)')
        else:
            pattern = re.compile('^[0-9]:[0-9][0-9][0-9]> (.*)')

        exception = 0

        for line in self.reporttext.splitlines():
            n = re.match(pattern, line)
            if n:
                cdbcmd = n.group(1)
                cmds = cdbcmd.split(';')
                exception += cmds.count('g')

        return exception

    def get_instr(self, instraddr):
        '''
        Find the disassembly line for the current (crashing) instruction
        '''
        regex = re.compile('^%s\s.+.+\s+' % instraddr)
        for line in self.reporttext.splitlines():
            n = regex.match(line)
            if n:
                return line

    def fix_efa_bug(self, instraddr, faultaddr):
        '''
        !exploitable often reports an incorrect EFA for 64-bit targets.
        If we're dealing with a 64-bit target, we can second-guess the reported EFA
        '''
        instructionline = self.get_instr(instraddr)
        if not instructionline or "=" not in instructionline:
            # Nothing to fix
            return faultaddr
        if 'ds:' in instructionline:
            # There's a target address in the msec file
            if '??' in instructionline:
                # The AV is on dereferencing where to call
                ds = carve(instructionline, "ds:", "=")
            else:
                # The AV is on accessing the code location
                ds = instructionline.split("=")[-1]
        else:
            # AV must be on current instruction
            ds = instructionline.split(' ')[0]
        if ds:
            faultaddr = ds.replace('`', '')
        return faultaddr

    def get_instr_addr(self):
        instraddr = carve(self.reporttext, "Instruction Address:", "\n")
        return self.format_addr(instraddr)

    def get_fault_addr(self):
        faultaddr = carve2(self.reporttext)
        return self.format_addr(faultaddr)

#    def get_regs(self):
#        '''
#        Populate the register dictionary with register values at crash
#        '''
#        for line in self.reporttext.splitlines():
#            if RE_regs1'].match(line) or regex['regs2.match(line):
#                regs1 = line.split()
#                for reg in regs1:
#                    if "=" in reg:
#                        splitreg = reg.split("=")
#                        self.regdict[splitreg[0]] = splitreg[1]
