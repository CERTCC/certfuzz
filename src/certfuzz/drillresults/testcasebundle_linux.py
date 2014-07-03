'''
Created on Jul 2, 2014

@organization: cert.org
'''
import logging
import re

from certfuzz.drillresults.common import carve
from certfuzz.drillresults.common import carve2
from certfuzz.drillresults.common import reg_set
from certfuzz.drillresults.testcasebundle_base import TestCaseBundle


logger = logging.getLogger(__name__)

# compile our regular expresssions once
RE_BT_ADDR = re.compile(r'(0x[0-9a-fA-F]+)\s+.+$')
RE_MAPPED_FRAME = re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+(/.+)')
RE_VDSO = re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+(\[vdso\])')
RE_CURRENT_INSTR = re.compile(r'^=>\s(0x[0-9a-fA-F]+)(.+)?:\s+(\S.+)')
RE_FRAME_0 = re.compile(r'^#0\s+(0x[0-9a-fA-F]+)\s.+')


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
            m = re.match(RE_BT_ADDR, line)
            if m:
                start_addr = m.group(1)
                if len(start_addr) > 10:
                    self._64bit_debugger = True
                    logger.debug()

    def _64bit_addr_fixup(self, faultaddr, instraddr):
        return faultaddr, instraddr

    @property
    def _64bit_target_app(self):
        return TestCaseBundle._64bit_target_app

    def _look_for_loaded_module(self, instraddr, line):
        # convert to an int as hex
        instraddr = int(instraddr, 16)

        for pattern in [RE_MAPPED_FRAME, RE_VDSO]:
            n = re.search(pattern, line)
            if n:
                # Strip out backticks present on 64-bit systems
                begin_address = int(n.group(1).replace('`', ''), 16)
                end_address = int(n.group(2).replace('`', ''), 16)
                module_name = n.group(4)
                logger.debug('%x %x %s %x', begin_address, end_address, module_name, instraddr)
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
        rgx = RE_CURRENT_INSTR
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
            n = re.match(RE_CURRENT_INSTR, line)
            if n:
                instraddr = n.group(1)
                #print 'Found instruction address: %s' % instraddr
        if not instraddr:
            for line in self.reporttext.splitlines():
                #No disassembly. Resort to frame 0 address
                n = re.match(RE_FRAME_0, line)
                if n:
                    instraddr = n.group(1)
                    #print 'Found instruction address: %s' % instraddr
        return self.format_addr(instraddr)

    def get_fault_addr(self):
        faultaddr = carve2(self.reporttext)
        return self.format_addr(faultaddr)
