'''
This script looks for interesting crashes and rate them by potential exploitability
'''

import binascii
import logging
import os
import re
import struct

from certfuzz.tools.common.drillresults import ResultDriller
from certfuzz.tools.common.drillresults import TestCaseBundle
from certfuzz.tools.common.drillresults import carve
from certfuzz.tools.common.drillresults import carve2
from certfuzz.tools.common.drillresults import is_number
from certfuzz.tools.common.drillresults import main as _main
from certfuzz.tools.common.drillresults import read_bin_file
from certfuzz.tools.common.drillresults import reg64_set
from certfuzz.tools.common.drillresults import reg_set


logger = logging.getLogger(__name__)


regex = {
        '64bit_debugger': re.compile('^Microsoft.*AMD64$'),
        'first_msec': re.compile('^sf_.+-\w+-0x.+.-[A-Z]'),
        'mapped_address': re.compile('^ModLoad: ([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)'),
        'mapped_address64': re.compile('^ModLoad: ([0-9a-fA-F]+`[0-9a-fA-F]+)\s+([0-9a-fA-F]+`[0-9a-fA-F]+)\s+(.+)'),
        'msec_report': re.compile('.+.msec$'),
        'regs1': re.compile('^eax=.+'),
        'regs2': re.compile('^eip=.+'),
        'syswow64': re.compile('ModLoad:.*syswow64.*', re.IGNORECASE),
        }


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
        TestCaseBundle(self, dbg_outfile, testcase_file, crash_hash, re_set,
                 ignore_jit)
        self.wow64_app = False

    def _check_64bit(self):
        '''
        Check if the debugger and target app are 64-bit
        '''
        for line in self.reporttext.splitlines():
            n = re.match(regex['64bit_debugger'], line)
            if n:
                self._64bit_debugger = True

            if self._64bit_debugger:
                n = re.match(regex['syswow64'], line)
                if n:
                    self.wow64_app = True

    def _parse_testcase(self, tcb):
        '''
        Parse the msec file
        '''
        reportfile = tcb.dbg_outfile
        crasherfile = tcb.testcase_file
        crash_hash = tcb.crash_hash

        if self.cached_testcases:
            if self.cached_testcases.get(crash_hash):
                self.results[crash_hash] = self.cached_testcases[crash_hash]
                return

        crashid = self.results[crash_hash]

        if crasherfile == '':
            # Old FOE version that didn't do multiple exceptions or rename msec
            # file with exploitability
            crasherfile, _junk = os.path.splitext(reportfile)

        self.get_regs()
        current_dir = os.path.dirname(reportfile)
        exceptionnum = self.get_ex_num()
        classification = carve(self.reporttext, "Exploitability Classification: ", "\n")
        try:
            if classification:
                # Create a new exception dictionary to add to the crash
                exception = {}
                crashid['exceptions'][exceptionnum] = exception
        except KeyError:
            # Crash ID (crash_hash) not yet seen
            # Default it to not being "really exploitable"
            crashid['reallyexploitable'] = False
            # Create a dictionary of exceptions for the crash id
            exceptions = {}
            crashid['exceptions'] = exceptions
            # Create a dictionary for the exception
            crashid['exceptions'][exceptionnum] = exception

        # Set !exploitable classification for the exception
        if classification:
            crashid['exceptions'][exceptionnum]['classification'] = classification

        shortdesc = carve(self.reporttext, "Short Description: ", "\n")
        if shortdesc:
            # Set !exploitable Short Description for the exception
            crashid['exceptions'][exceptionnum]['shortdesc'] = shortdesc
            # Flag the entire crash ID as really exploitable if this is a good
            # exception
            crashid['reallyexploitable'] = shortdesc in self.re_set
        # Check if the expected crasher file (fuzzed file) exists
        if not os.path.isfile(crasherfile):
            # It's not there, so try to extract the filename from the cdb
            # commandline
            commandline = carve(self.reporttext, "CommandLine: ", "\n")
            args = commandline.split()
            for arg in args:
                if "sf_" in arg:
                    crasherfile = os.path.basename(arg)
                    if "-" in crasherfile:
                        # FOE 2.0 verify mode puts a '-<iteration>' part on the
                        # filename when invoking cdb, however the resulting file
                        # is really just 'sf_<hash>.<ext>'
                        fileparts = crasherfile.split('-')
                        m = re.search('\..+', fileparts[1])
                        # Recreate the original file name, minus the iteration
                        crasherfile = os.path.join(current_dir, fileparts[0] + m.group(0))
                    else:
                        crasherfile = os.path.join(current_dir, crasherfile)
        if not os.path.isfile(crasherfile):
            # Can't find the crasher file
            return
        # Set the "fuzzedfile" property for the crash ID
        crashid['fuzzedfile'] = crasherfile
        # See if we're dealing with 64-bit debugger or target app
        faultaddr = carve2(self.reporttext)
        instraddr = carve(self.reporttext, "Instruction Address:", "\n")
        faultaddr = self.format_addr(faultaddr)
        instraddr = self.format_addr(instraddr)

        # No faulting address means no crash.
        if not faultaddr or not instraddr:
            return

        if self._64bit_debugger and not self.wow64_app and instraddr:
            # Put backtick into instruction address for pattern matching
            instraddr = ''.join([instraddr[:8], '`', instraddr[8:]])
            if shortdesc != 'DEPViolation':
                faultaddr = self.fix_efa_bug(instraddr, faultaddr)

    #    pc_module = pc_in_mapped_address(reporttext, instraddr)
        crashid['exceptions'][exceptionnum]['pcmodule'] = self.pc_in_mapped_address(self.reporttext, instraddr, self._64bit_debugger)

        # Get the cdb line that contains the crashing instruction
        instructionline = self.get_instr(self.reporttext, instraddr)
        crashid['exceptions'][exceptionnum]['instructionline'] = instructionline
        if instructionline:
            faultaddr = self.fix_efa_offset(instructionline, faultaddr)

        # Fix faulting pattern endian
        faultaddr = faultaddr.replace('0x', '')
        crashid['exceptions'][exceptionnum]['efa'] = faultaddr
        if self._64bit_debugger and not self.wow64_app:
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

        # Read in the fuzzed file
        crasherdata = read_bin_file(crasherfile)

        # If there's a match, flag this exception has having Efa In File
        if binascii.a2b_hex(efapattern) in crasherdata:
            crashid['exceptions'][exceptionnum]['EIF'] = True
        else:
            crashid['exceptions'][exceptionnum]['EIF'] = False

    def pc_in_mapped_address(self, instraddr):
        '''
        Check if the instruction pointer is in a loaded module
        '''
        ma_regex = 'mapped_address'
        mapped_module = 'unloaded'
        if self._64bit_debugger:
            ma_regex = 'mapped_address64'

        instraddr = instraddr.replace('`', '')
        instraddr = int(instraddr, 16)
        for line in self.reporttext.splitlines():
            n = re.match(regex[ma_regex], line)
            if n:
                # Strip out backticks present on 64-bit systems
                begin_address = int(n.group(1).replace('`', ''), 16)
                end_address = int(n.group(2).replace('`', ''), 16)
                if begin_address < instraddr < end_address:
                    mapped_module = n.group(3)
        return mapped_module

    def format_addr(self, faultaddr):
        '''
        Format a 64- or 32-bit memory address to a fixed width
        '''
        if not faultaddr:
            return

        faultaddr = faultaddr.strip().replace('0x', '')

        if self._64bit_debugger and not self.wow64_app:
            # Due to a bug in !exploitable, the Exception Faulting Address is
            # often wrong with 64-bit targets
            if len(faultaddr) < 10:
                # pad faultaddr
                return faultaddr.zfill(16)

        if len(faultaddr) > 10:
            # 0x12345678 = 10 chars
            return faultaddr[-8:]

        if len(faultaddr) < 10:
            # pad faultaddr
            return faultaddr.zfill(8)

    def fix_efa_offset(self, instructionline, faultaddr):
        '''
        Adjust faulting address for instructions that use offsets
        Currently only works for instructions like CALL [reg + offset]
        '''
        if self._64bit_debugger and not self.wow64_app:
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

    def get_regs(self):
        '''
        Populate the register dictionary with register values at crash
        '''
        for line in self.reporttext.splitlines():
            if regex['regs1'].match(line) or regex['regs2'].match(line):
                regs1 = line.split()
                for reg in regs1:
                    if "=" in reg:
                        splitreg = reg.split("=")
                        self.regdict[splitreg[0]] = splitreg[1]


class WindowsResultDriller(ResultDriller):
    def _platform_find_testcases(self, crash_hash, files, root):
        if "0x" in crash_hash:
            # Create dictionary for hashes in results dictionary
            hash_dict = {}
            hash_dict['hash'] = crash_hash
            self.results[crash_hash] = hash_dict
            crasherfile = ''
            # Check each of the files in the hash directory
            for current_file in files:
                # If it's exception #0, strip out the exploitability part of
                # the file name. This gives us the crasher file name
                if regex['first_msec'].match(current_file):
                    crasherfile, reportfileext = os.path.splitext(current_file)
                    crasherfile = crasherfile.replace('-EXP', '')
                    crasherfile = crasherfile.replace('-PEX', '')
                    crasherfile = crasherfile.replace('-PNE', '')
                    crasherfile = crasherfile.replace('-UNK', '')
            for current_file in files:
                # Go through all of the .msec files and parse them
                if regex['msec_report'].match(current_file):
                    msecfile = os.path.join(root, current_file)
                    if crasherfile and root not in crasherfile:
                        crasherfile = os.path.join(root, crasherfile)
                    tcb = TestCaseBundle(msecfile, crasherfile, crash_hash,
                                         self.ignore_jit)
                    self.testcase_bundles.append(tcb)


def main():
    _main(driller_class=WindowsResultDriller)

if __name__ == '__main__':
    main()
