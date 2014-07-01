'''
This script looks for interesting crashes and rate them by potential exploitability
'''

import os
import struct
import binascii
import re

import sys
import logging
sys.path.insert(0, '/Users/adh/git/bff/src')

from certfuzz.tools.common.drillresults import carve, carve2, \
    reg_set, ResultDriller, parse_args, TestCaseBundle, \
    root_logger_to_console

logger = logging.getLogger(__name__)

regex = {
        'gdb_report': re.compile(r'.+.gdb$'),
        'current_instr': re.compile(r'^=>\s(0x[0-9a-fA-F]+)(.+)?:\s+(\S.+)'),
        'frame0': re.compile(r'^#0\s+(0x[0-9a-fA-F]+)\s.+'),
        'regs1': re.compile(r'^eax=.+'),
        'regs2': re.compile(r'^eip=.+'),
        'bt_addr': re.compile(r'(0x[0-9a-fA-F]+)\s+.+$'),
        '64bit_debugger': re.compile(r'^Microsoft.*AMD64$'),
        'syswow64': re.compile(r'ModLoad:.*syswow64.*', re.IGNORECASE),
        'mapped_frame': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+(/.+)'),
        'vdso': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0(x0)?\s+\[vdso\]'),
        'mapped_address': re.compile(r'^ModLoad: ([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)'),
        'mapped_address64': re.compile(r'^ModLoad: ([0-9a-fA-F]+`[0-9a-fA-F]+)\s+([0-9a-fA-F]+`[0-9a-fA-F]+)\s+(.+)'),
        'syswow64': re.compile(r'ModLoad:.*syswow64.*', re.IGNORECASE),
        'dbg_prompt': re.compile(r'^[0-9]:[0-9][0-9][0-9]> (.*)'),
        }


def pc_in_mapped_address(reporttext, instraddr):
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
    for line in reporttext.splitlines():
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


def fix_efa_bug(reporttext, instraddr, faultaddr):
    '''
    !exploitable often reports an incorrect EFA for 64-bit targets.
    If we're dealing with a 64-bit target, we can second-guess the reported EFA
    '''
    instructionline = get_instr(reporttext, instraddr)
    if not instructionline:
        return faultaddr
    ds = carve(instructionline, "ds:", "=")
    if ds:
        faultaddr = ds.replace('`', '')
    return faultaddr


def get_ex_num(reporttext):
    '''
    Get the exception number by counting the number of continues
    '''
    exception = 0
    for line in reporttext.splitlines():
        n = re.match(regex['dbg_prompt'], line)
        if n:
            cdbcmd = n.group(1)
            cmds = cdbcmd.split(';')
            for cmd in cmds:
                if cmd == 'g':
                    exception = exception + 1
    return exception


def get_instr_addr(reporttext):
    '''
    Find the address for the current (crashing) instruction
    '''
    instraddr = None
    for line in reporttext.splitlines():
        #print 'checking: %s' % line
        n = re.match(regex['current_instr'], line)
        if n:
            instraddr = n.group(1)
            #print 'Found instruction address: %s' % instraddr
    if not instraddr:
        for line in reporttext.splitlines():
            #No disassembly. Resort to frame 0 address
            n = re.match(regex['frame0'], line)
            if n:
                instraddr = n.group(1)
                #print 'Found instruction address: %s' % instraddr
    return instraddr


def get_instr(reporttext, instraddr):
    '''
    Find the disassembly line for the current (crashing) instruction
    '''
    rgx = regex['current_instr']
    for line in reporttext.splitlines():
        n = rgx.match(line)
        if n:
            return n.group(3)
    return ''


def format_addr(faultaddr, _64bit_debugger):
    '''
    Format a 64- or 32-bit memory address to a fixed width
    '''

    if not faultaddr:
        return
    else:
        faultaddr = faultaddr.strip()
    faultaddr = faultaddr.replace('0x', '')

    if _64bit_debugger:
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


def fix_efa_offset(instructionline, faultaddr, _64bit_debugger):
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
                faultaddr = format_addr(faultaddr.replace('L', ''), _64bit_debugger)
    return faultaddr


class LinuxTestCaseBundle(TestCaseBundle):
    def _check_report(self):
        '''
        Parse the gdb file
        '''
        crasherfile = self.testcase_file
        reporttext = self.reporttext
        _64bit_debugger = self._64bit_debugger
        crasherdata = self.crasherdata

    #    global _64bit_debugger

        # TODO move this back to ResultDriller class
#        if self.cached_results:
#            if self.cached_results.get(crash_hash):
#                self.results[crash_hash] = self.cached_results[crash_hash]
#                return

        details = self.details

        exceptionnum = 0
        classification = carve(reporttext, "Classification: ", "\n")
        #print 'classification: %s' % classification
        try:
            if classification:
                # Create a new exception dictionary to add to the crash
                exception = {}
                details['exceptions'][exceptionnum] = exception
        except KeyError:
            # Crash ID (crash_hash) not yet seen
            # Default it to not being "really exploitable"
            details['reallyexploitable'] = False
            # Create a dictionary of exceptions for the crash id
            exceptions = {}
            details['exceptions'] = exceptions
            # Create a dictionary for the exception
            details['exceptions'][exceptionnum] = exception

        # Set !exploitable classification for the exception
        if classification:
            details['exceptions'][exceptionnum]['classification'] = classification

        shortdesc = carve(reporttext, "Short description: ", " (")
        #print 'shortdesc: %s' % shortdesc
        if shortdesc:
            # Set !exploitable Short Description for the exception
            details['exceptions'][exceptionnum]['shortdesc'] = shortdesc
            # Flag the entire crash ID as really exploitable if this is a good
            # exception
            details['reallyexploitable'] = shortdesc in self.re_set

        if not os.path.isfile(crasherfile):
            # Can't find the crasher file
            #print "WTF! Cannot find %s" % crasherfile
            return
        # Set the "fuzzedfile" property for the crash ID
        details['fuzzedfile'] = crasherfile
        faultaddr = carve2(reporttext)
        instraddr = get_instr_addr(reporttext)
        faultaddr = format_addr(faultaddr, _64bit_debugger)
        instraddr = format_addr(instraddr, _64bit_debugger)

        # No faulting address means no crash.
        if not faultaddr:
            return

        if instraddr:
            details['exceptions'][exceptionnum]['pcmodule'] = pc_in_mapped_address(reporttext, instraddr)

        # Get the cdb line that contains the crashing instruction
        instructionline = get_instr(reporttext, instraddr)
        details['exceptions'][exceptionnum]['instructionline'] = instructionline
        if instructionline:
            faultaddr = fix_efa_offset(instructionline, faultaddr, _64bit_debugger)

        # Fix faulting pattern endian
        faultaddr = faultaddr.replace('0x', '')
        details['exceptions'][exceptionnum]['efa'] = faultaddr
        if _64bit_debugger:
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
        if binascii.a2b_hex(efapattern) in crasherdata:
            details['exceptions'][exceptionnum]['EIF'] = True
        else:
            details['exceptions'][exceptionnum]['EIF'] = False

    def _check_64bit(self):
        '''
        Check if the debugger and target app are 64-bit
        '''
        for line in self.reporttext.splitlines():
            m = re.match(regex['bt_addr'], line)
            if m:
                start_addr = m.group(1)
                if len(start_addr) > 10:
                    self._64bit_debugger = True
                    logger.debug()

    def _score_testcase(self):
        logger.debug('Scoring testcase: %s', self.crash_hash)
        details = self.details
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
        self.score = min(scores)


class LinuxResultDriller(ResultDriller):
    really_exploitable = [
                      'SegFaultOnPc',
                      'BranchAv',
                      'StackCodeExection',
                      'BadInstruction',
                      'ReturnAv',
                      ]

    def _platform_find_testcases(self, crash_hash, files, root):
                # Only use directories that are hashes
        # if "0x" in crash_hash:
            # Create dictionary for hashes in results dictionary
        crasherfile = ''
        # Check each of the files in the hash directory
        for current_file in files:
            # Go through all of the .gdb files and parse them
            if current_file.endswith('.gdb'):
#            if regex['gdb_report'].match(current_file):
                #print 'checking %s' % current_file
                gdbfile = os.path.join(root, current_file)
                logger.debug('found gdb file: %s', gdbfile)
                crasherfile = gdbfile.replace('.gdb', '')
                #crasherfile = os.path.join(root, crasherfile)
                tcb = LinuxTestCaseBundle(gdbfile, crasherfile, crash_hash, self.re_set)
                self.testcase_bundles.append(tcb)


def main():
    args = parse_args()

    root_logger_to_console(args)

    with LinuxResultDriller(ignore_jit=args.ignorejit,
                            base_dir=args.resultsdir,
                            force_reload=args.force) as rd:
        rd.drill_results()


if __name__ == '__main__':
    main()
