'''
Created on Jul 2, 2014

@organization: cert.org
'''
import binascii
import logging
import os
import re
import struct

from certfuzz.drillresults.common import carve
from certfuzz.drillresults.common import carve2
from certfuzz.drillresults.common import reg_set
from certfuzz.drillresults.errors import LinuxTestCaseBundleError
from certfuzz.drillresults.testcasebundle_base import TestCaseBundle
from certfuzz.drillresults.errors import TestCaseBundleError


logger = logging.getLogger(__name__)

regex = {
        '64bit_debugger': re.compile(r'^Microsoft.*AMD64$'),
        'bt_addr': re.compile(r'(0x[0-9a-fA-F]+)\s+.+$'),
        'current_instr': re.compile(r'^=>\s(0x[0-9a-fA-F]+)(.+)?:\s+(\S.+)'),
        'dbg_prompt': re.compile(r'^[0-9]:[0-9][0-9][0-9]> (.*)'),
        'frame0': re.compile(r'^#0\s+(0x[0-9a-fA-F]+)\s.+'),
        'gdb_report': re.compile(r'.+.gdb$'),
        'mapped_address': re.compile(r'^ModLoad: ([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)'),
        'mapped_address64': re.compile(r'^ModLoad: ([0-9a-fA-F]+`[0-9a-fA-F]+)\s+([0-9a-fA-F]+`[0-9a-fA-F]+)\s+(.+)'),
        'mapped_frame': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+(/.+)'),
        'regs1': re.compile(r'^eax=.+'),
        'regs2': re.compile(r'^eip=.+'),
        'syswow64': re.compile(r'ModLoad:.*syswow64.*', re.IGNORECASE),
        'vdso': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+\[vdso\]'),
        }


class LinuxTestCaseBundle(TestCaseBundle):
    really_exploitable = [
                  'SegFaultOnPc',
                  'BranchAv',
                  'StackCodeExection',
                  'BadInstruction',
                  'ReturnAv',
                  ]

    def _get_classification(self):
        self.classification = carve(self.reporttext, "Classification: ", "\n")
        logger.debug('Classification: %s', self.classification)

    def _get_shortdesc(self):
        self.shortdesc = carve(self.reporttext, "Short description: ", " (")
        logger.debug('Short Description: %s', self.shortdesc)

    def _check_64bit(self):
        for line in self.reporttext.splitlines():
            m = re.match(regex['bt_addr'], line)
            if m:
                start_addr = m.group(1)
                if len(start_addr) > 10:
                    self._64bit_debugger = True
                    logger.debug()

    def _64bit_addr_fixup(self, faultaddr, instraddr):
        return faultaddr, instraddr

    @property
    def _64bit_target_app(self):
        return TestCaseBundle._64bit_target_app(self)

    def pc_in_mapped_address(self, instraddr):
        '''
        Check if the instruction pointer is in a loaded module
        '''
        if not instraddr:
            # The gdb file doesn't have anything in it that'll tell us
            # where the PC is.
            return ''
    #    print 'checking if %s is mapped...' % instraddr
        mapped_module = 'unloaded'

        instraddr = int(instraddr, 16)
    #    print 'instraddr: %d' % instraddr
        for line in self.reporttext.splitlines():
            #print 'checking: %s for %s' % (line,regex['mapped_frame'])
            n = re.search(regex['mapped_frame'], line)
            if n:
    #            print '*** found mapped address regex!'
                # Strip out backticks present on 64-bit systems
                begin_address = int(n.group(1).replace('`', ''), 16)
                end_address = int(n.group(2).replace('`', ''), 16)
                if begin_address < instraddr < end_address:
                    mapped_module = n.group(4)
                    #print 'mapped_module: %s' % mapped_module
            else:
                # [vdso] still counts as a mapped module
                n = re.search(regex['vdso'], line)
                if n:
                    begin_address = int(n.group(1).replace('`', ''), 16)
                    end_address = int(n.group(2).replace('`', ''), 16)
                    if begin_address < instraddr < end_address:
                        mapped_module = '[vdso]'

        return mapped_module

    def format_addr(self, faultaddr):
        '''
        Format a 64- or 32-bit memory address to a fixed width
        '''

        if not faultaddr:
            return
        else:
            faultaddr = faultaddr.strip()
        faultaddr = faultaddr.replace('0x', '')

        if self._64bit_debugger:
            # Due to a bug in !exploitable, the Exception Faulting Address is
            # often wrong with 64-bit targets
            if len(faultaddr) < 10:
                # pad faultaddr
                faultaddr = faultaddr.zfill(16)
        else:
            if len(faultaddr) > 10:  # 0x12345678 = 10 chars
                faultaddr = faultaddr[-8:]
            elif len(faultaddr) < 10:
                # pad faultaddr
                faultaddr = faultaddr.zfill(8)

        return faultaddr

    def fix_efa_offset(self, instructionline, faultaddr):
        '''
        Adjust faulting address for instructions that use offsets
        Currently only works for instructions like CALL [reg + offset]
        '''
        if '0x' not in faultaddr:
            faultaddr = '0x' + faultaddr
        instructionpieces = instructionline.split()
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
                    if '0x' not in offset:
                        offset = '0x' + offset
                    if int(offset, 16) > int(faultaddr, 16):
                        # TODO: fix up negative numbers
                        return faultaddr
                    # Subtract offset to get actual interesting pattern
                    faultaddr = hex(eval(faultaddr) - eval(offset))
                    faultaddr = self.format_addr(faultaddr.replace('L', ''))
        return faultaddr

    def get_instr(self, instraddr):
        '''
        Find the disassembly line for the current (crashing) instruction
        '''
        rgx = regex['current_instr']
        for line in self.reporttext.splitlines():
            n = rgx.match(line)
            if n:
                return n.group(3)
        return ''

    def fix_efa_bug(self, instraddr, faultaddr):
        '''
        !exploitable often reports an incorrect EFA for 64-bit targets.
        If we're dealing with a 64-bit target, we can second-guess the reported EFA
        '''
        instructionline = self.get_instr(instraddr)
        if not instructionline:
            return faultaddr
        ds = carve(instructionline, "ds:", "=")
        if ds:
            faultaddr = ds.replace('`', '')
        return faultaddr

    def get_instr_addr(self):
        '''
        Find the address for the current (crashing) instruction
        '''
        instraddr = None
        for line in self.reporttext.splitlines():
            #print 'checking: %s' % line
            n = re.match(regex['current_instr'], line)
            if n:
                instraddr = n.group(1)
                #print 'Found instruction address: %s' % instraddr
        if not instraddr:
            for line in self.reporttext.splitlines():
                #No disassembly. Resort to frame 0 address
                n = re.match(regex['frame0'], line)
                if n:
                    instraddr = n.group(1)
                    #print 'Found instruction address: %s' % instraddr
        return self.format_addr(instraddr)

    def get_fault_addr(self):
        faultaddr = carve2(self.reporttext)
        return self.format_addr(faultaddr)
