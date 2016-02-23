'''
Created on Jul 2, 2014

@organization: cert.org
'''
import logging
import re

from certfuzz.drillresults.common import carve
from certfuzz.analyzers.drillresults.testcasebundle_base import TestCaseBundle


logger = logging.getLogger(__name__)

# compile our regular expresssions once
RE_BT_ADDR = re.compile(r'(0x[0-9a-fA-F]+)\s+.+$')
RE_CURRENT_INSTR = re.compile(r'^=>\s(0x[0-9a-fA-F]+)(.+)?:\s+(\S.+)')
RE_FRAME_0 = re.compile(r'^#0\s+(0x[0-9a-fA-F]+)\s.+')
RE_MAPPED_FRAME = re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+(/.+)')
RE_VDSO = re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+(\[vdso\])')
RE_RETURN_ADDR = re.compile(r'^#1\s.(0x[0-9a-fA-F]+)\s')

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
                    logger.debug('Using a 64-bit debugger')

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

    def get_instr(self, instraddr):
        rvfunc = lambda x, l: x.group(3)
        rgx = RE_CURRENT_INSTR

        return self._match_rgx(rgx, rvfunc)

    def get_return_addr(self):
        rvfunc = lambda x, l: x.group(1)
        rgx = RE_RETURN_ADDR

        return self._match_rgx(rgx, rvfunc)

    def get_instr_addr(self):
        '''
        Find the address for the current (crashing) instruction
        '''
        instraddr = None
        for line in self.reporttext.splitlines():
            # print 'checking: %s' % line
            n = re.match(RE_CURRENT_INSTR, line)
            if n:
                instraddr = n.group(1)
                # print 'Found instruction address: %s' % instraddr
        if not instraddr:
            for line in self.reporttext.splitlines():
                # No disassembly. Resort to frame 0 address
                n = re.match(RE_FRAME_0, line)
                if n:
                    instraddr = n.group(1)
                    # print 'Found instruction address: %s' % instraddr
        return self.format_addr(instraddr)
