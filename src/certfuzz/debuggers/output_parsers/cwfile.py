'''
Created on Jul 1, 2011

Provides the cwfile class for analyzing CrashWrangler output.

@organization: cert.org
'''
import hashlib
import logging
from optparse import OptionParser
import os
import re


logger = logging.getLogger(__name__)

registers = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi',
             'edi', 'eip', 'cs', 'ss', 'ds', 'es', 'fs', 'gs']
registers64 = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp',
               'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14',
               'r15', 'rip', 'rfl', 'cr2')

regex = {
    'code_type': re.compile('Code Type:\s+(.+)'),
    'exception_line': re.compile('^exception=.+instruction_address=(0x[0-9a-zA-Z][0-9a-zA-Z]+)'),
    'bt_thread': re.compile('^Thread.+'),
    'bt_line_basic': re.compile('^\d'),
    'bt_line': re.compile('^\d+\s+(\S+)\s+0x[0-9a-zA-Z][0-9a-zA-Z]+\s+(.*)$'),
    'bt_function': re.compile('.+\s+(\S+)\s+(\S+)\s'),
    'bt_at': re.compile('.+\s+at\s+(\S+)'),
    'bt_tab': re.compile('.+\t'),
    'bt_space': re.compile('.+\s'),
    'bt_addr': re.compile('(0x[0-9a-fA-F]+)\s'),
    'signal': re.compile('Program\sreceived\ssignal\s+([^,]+)'),
    'exit_code': re.compile('Program exited with code (\d+)'),
    'bt_line_from': re.compile(r'\bfrom\b'),
    'bt_line_at': re.compile(r'\bat\b'),
    'register': re.compile('\s\s\s?[0-9a-zA-Z]+:\s(0x[0-9a-zA-Z][0-9a-zA-Z]+)'),
    'exploitability': re.compile('exception=.+:is_exploitable=( no|yes):'),
    'faddr': re.compile('exception=.+:access_address=(0x[0-9a-zA-Z][0-9a-zA-Z]+):'),
}

# There are a number of functions that are typically found in crash backtraces,
# yet are side effects of a crash and are not directly relevant to identifying
# the uniqueness of the crash. So we explicitly blocklist them so they won't be
# used in determining the crash backtrace hash.
blocklist = ('__kernel_vsyscall', 'abort', 'raise', 'malloc', 'free',
             '*__GI_abort', '*__GI_raise', 'malloc_printerr', '__libc_message',
             '__kill', '_sigtramp'
             )

# These libraries should be used in the uniqueness determination of a crash
blocklist_libs = ('libSystem.B.dylib', 'libsystem_malloc.dylib'
                  )


class CWfile:

    def __init__(self, f, keep_uniq_faddr=False):
        '''
        Create a GDB file object from the gdb output file <file>
        @param lines: The lines of the gdb file
        @param is_crash: True if gdb file represents a testcase
        @param is_assert_fail: True if gdb file represents an assert_fail
        @param is_debugbuild: True if gdb file contains source code lines
        '''
        logger.debug('initializing %s', f)
        self.file = f
        self.lines = self._read_file()

        # collect data about the gdb output
        self.backtrace = []
        self.backtrace_without_questionmarks = []
        self.registers = {}
        # make a copy of registers list we're looking for
        self.registers_sought = list(registers)
        self.registers_hex = {}
        self.hashable_backtrace = []
        self.hashable_backtrace_string = ''
        self.exit_code = None
        self.signal = None
        self.is_corrupt_stack = False
        self.debugger_missed_stack_corruption = False
        self.total_stack_corruption = False
        self.is_crash = True
        self.is_assert_fail = False
        self.is_debugbuild = False
        self.crashing_thread = False
        self.pc_in_function = True
        self.pc_name = 'eip'
        self.keep_uniq_faddr = keep_uniq_faddr
        self.faddr = None
        self.exp = None

        self._process_lines()

        self._backtrace_without_questionmarks()
        self._hashable_backtrace()

    def _hashable_backtrace(self):
        logger.debug('_hashable_backtrace')
        hashable = []
        line_0 = ''
        if not self.hashable_backtrace:
            for bt in self.backtrace:

                logger.debug("checking backtrace line")
                # skip blocklisted functions
                if bt in blocklist:
                    continue
                else:
                    hashable.append(bt)

            if not hashable:
                if self.exit_code:
                    hashable.append(self.exit_code)
                elif line_0:
                    # if we got here, it's because
                    # (a) there were no usable backtrace lines, AND
                    # (b) there was no exit code
                    # so we'll use whatever value was in the first line
                    # even if it would have been otherwise discarded
                    hashable.append(line_0)
                else:
                    # if we have nothing at all to hash, then
                    # even the first line must have been empty
                    # so this can't be a crash
                    self.is_crash = False
            self.hashable_backtrace = hashable
            logger.debug("hashable_backtrace: %s", self.hashable_backtrace)
        return self.hashable_backtrace

    def _hashable_backtrace_string(self, level):
        self.hashable_backtrace_string = ' '.join(
            self.hashable_backtrace[:level]).strip()
        if self.keep_uniq_faddr:
            try:
                self.hashable_backtrace_string = self.hashable_backtrace_string + \
                    ' ' + self.faddr
            except:
                logger.debug('Cannot use PC in hash')
        logger.warning(
            '_hashable_backtrace_string: %s', self.hashable_backtrace_string)
        return self.hashable_backtrace_string

    def _backtrace_without_questionmarks(self):
        logger.debug('_backtrace_without_questionmarks')
        if not self.backtrace_without_questionmarks:
            self.backtrace_without_questionmarks = [
                bt for bt in self.backtrace if not '??' in bt]
        return self.backtrace_without_questionmarks

    def backtrace_line(self, idx, l):
        self._look_for_crashing_thread(l)
        m = re.match(regex['bt_line'], l)
        if m and self.crashing_thread:
            library = m.group(1)
            item = m.group(2)  # sometimes gdb splits across lines
            # so get the next one if it looks like '<anything> at <foo>' or
            # '<anything> from <foo>'
            next_idx = idx + 1
            while next_idx < len(self.lines):
                nextline = self.lines[next_idx]
                if re.match(regex['bt_line_basic'], nextline):
                    break
                elif re.search(regex['bt_line_from'], nextline) or re.search(regex['bt_line_at'], nextline):
                    item = ' '.join((item, nextline))
                next_idx += 1

            if library not in blocklist_libs:
                self.backtrace.append(item)
                logger.debug('Appending to backtrace: %s', item)

    def _read_file(self):
        '''
        Reads the gdb file into memory
        '''
        logger.debug('_read_file')
        gdb = ""
        if os.path.exists(self.file):
            with open(self.file, 'r') as f:
                gdb = [s.rstrip() for s in f.readlines()]
        return gdb

    def _process_lines(self):
        logger.debug('_process_lines')

        for idx, line in enumerate(self.lines):

            self.backtrace_line(idx, line)

            if not self.exit_code:
                self._look_for_exit_code(line)

            if not self.signal:
                self._look_for_signal(line)

            if self.is_crash:
                self._look_for_crash(line)

            if not self.is_assert_fail:
                self._look_for_assert_fail(line)

            if not self.is_debugbuild:
                self._look_for_debug_build(line)

            if not self.is_corrupt_stack:
                self._look_for_corrupt_stack(line)

            if not self.exp:
                self._look_for_exploitability(line)

            if not self.faddr:
                self._look_for_faddr(line)

            self._look_for_registers(line)

        # if we found that the stack was corrupt,
        # we can no longer trust the last backtrace line
        # so remove it
        if self.is_corrupt_stack and len(self.backtrace):
            removed_bt_line = self.backtrace.pop()
            logger.debug(
                "Corrupt stack found. Removing backtrace line: %s", removed_bt_line)

    def _look_for_crashing_thread(self, line):
        m = re.match(regex['bt_thread'], line)
        if m and 'Crashed' in line:
            self.crashing_thread = True
        elif m:
            self.crashing_thread = False

    def _look_for_64bit(self, line):
        '''
        Check for 64-bit process by looking at address of bt frame addresses
        '''
        if self.is_64bit:
            return

        m = re.match(regex['code_type'], line)
        if m:
            code_type = m.group(0)
            if 'X86-64' in code_type:
                self.is_64bit = True
                logger.debug('Target process is 64-bit')
                self.pc_name = 'rip'
                self.registers_sought = list(registers64)

    # TODO: CrashWrangler equivalents of the below
    def _look_for_corrupt_stack(self, line):
        if 'corrupt stack' in line:
            self.is_corrupt_stack = True

    def _look_for_exit_code(self, line):
        m = re.match(regex['exit_code'], line)
        if m:
            self.exit_code = m.group(1)

    def _look_for_faddr(self, line):
        if self.faddr:
            return
        m = re.match(regex['faddr'], line)
        if m:
            self.faddr = m.group(1)

    def _look_for_signal(self, line):
        m = re.match(regex['signal'], line)
        if m:
            self.signal = m.group(1)

    def _look_for_exploitability(self, line):
        if self.exp:
            return

        m = re.match(regex['exploitability'], line)
        if m:
            exploitable = m.group(1)
            if exploitable == 'yes':
                self.exp = 'EXPLOITABLE'
            else:
                self.exp = 'UNKNOWN'
            logger.debug('Exploitable: %s', self.exp)

    def _look_for_crash(self, line):
        if 'SIGKILL' in line:
            self.is_crash = False
        elif 'SIGHUP' in line:
            self.is_crash = False
        elif 'Program exited normally' in line:
            self.is_crash = False

    def _look_for_assert_fail(self, line):
        if '__assert_fail' in line:
            self.is_assert_fail = True

    def _look_for_debug_build(self, line):
        if ' at ' in line:
            self.is_debugbuild = True

    def _look_for_registers(self, line):
        '''
        Look for register name/value pairs in CrashWrangler output.
        Unlike gdb, CrashWrangler lists more than one register per line
        '''
        # short-circuit if we're out of registers to look for
        if not len(self.registers_sought):
            return
        # short-circuit if the first thing in the line isn't a register
        m = re.match(regex['register'], line)
        if not m:
            return
        line = line.lstrip()
        regpairs = line.split('  ')
        # short-circuit if line doesn't split
        if not len(regpairs):
            logger.debug('Non-splittable line')
            return
        # short-circuit if the first thing in the line isn't a register
        for regpair in regpairs:
            regpairlist = regpair.split(': ')
            r = regpairlist[0].strip()
            if not r in self.registers_sought:
                continue
            regval = regpairlist[1]
            self.registers_hex[r] = regval
            self.registers_sought.remove(r)
            logger.debug('Register %s=%s', r, self.registers_hex[r])

    def get_testcase_signature(self, backtrace_level):
        '''
        Determines if a crash is unique. Depending on <backtrace_level>,
        it may look at a number of source code lines in the gdb backtrace, or simply
        just the memory location of the crash.
        '''
        logger.debug('get_testcase_signature')
        backtrace_string = self._hashable_backtrace_string(backtrace_level)
        if bool(backtrace_string):
            return hashlib.md5(backtrace_string).hexdigest()
        else:
            return False

if __name__ == '__main__':
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true',
                      help='Enable debug messages (overrides --verbose)')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)

    for path in args:
        g = CWfile(path)
        print g.get_testcase_signature(5)
