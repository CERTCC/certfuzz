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
logger.setLevel(logging.WARNING)

# for use with 'info all-registers' in GDB
#registers = ['eip', 'eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'edi', 'esi',
#            'eflags', 'cs', 'ss', 'ds', 'es', 'fs', 'gs', 'st0', 'st1', 'st2', 'st3',
#            'st4', 'st5', 'st6', 'st7', 'fctrl', 'fstat', 'ftag', 'fiseg', 'fioff',
#            'fooff', 'fop']

# for use with 'info registers' in GDB
registers = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi',
             'edi', 'eip', 'cs', 'ss', 'ds', 'es', 'fs', 'gs']

regex = {
        'bt_thread': re.compile('^Thread.+'),
        'bt_line_basic': re.compile('^\d'),
        'bt_line': re.compile('^\d+\s+(.*)$'),
        'bt_function': re.compile('.+\s+(\S+)\s+(\S+)\s'),
        'bt_at': re.compile('.+\s+at\s+(\S+)'),
        'bt_tab': re.compile('.+\t'),
        'bt_space': re.compile('.+\s'),
        'bt_addr': re.compile('(0x[0-9a-fA-F]+)\s'),
        'signal': re.compile('Program\sreceived\ssignal\s+([^,]+)'),
        'exit_code': re.compile('Program exited with code (\d+)'),
        'bt_line_from': re.compile(r'\bfrom\b'),
        'bt_line_at': re.compile(r'\bat\b'),
        'register': re.compile('(0x[0-9a-zA-Z]+)\s+(.+)$'),
         }

# There are a number of functions that are typically found in crash backtraces,
# yet are side effects of a crash and are not directly relevant to identifying
# the uniqueness of the crash. So we explicitly blacklist them so they won't be
# used in determining the crash backtrace hash.
blacklist = ('__kernel_vsyscall', 'abort', 'raise', 'malloc', 'free',
             '*__GI_abort', '*__GI_raise', 'malloc_printerr', '__libc_message',
             '__kill', '_sigtramp'
             )

class CWfile:
    def __init__(self, f):
        '''
        Create a GDB file object from the gdb output file <file>
        @param lines: The lines of the gdb file
        @param is_crash: True if gdb file represents a crash
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
        self.pc_name = ''
        self.keep_uniq_faddr = False
        self.faddr = None

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
                # skip blacklisted functions
                x = re.match(regex['bt_function'], bt)
                if x and x.group(1) in blacklist:
                    continue

                if '???' in bt:
                    logger.debug('Unmapped frame, skipping')
                    continue

                m = re.match(regex['bt_tab'], bt)
                s = re.sub(regex['bt_tab'], "", bt)
                t = re.sub(regex['bt_addr'], "", s)
                if m:
                    logger.debug("found tab: %s" % t)
                    val = t
                    # remember the value for the first line in case we need it later
                    if not line_0:
                        line_0 = val

                    # skip anything in /sysdeps/ since they're
                    # typically part of the post-crash
                    if '/sysdeps/' in val:
                        logger.debug('Found sysdeps, skipping')
                        continue

                    hashable.append(val)
#                elif n:
#                    val = n.group(1)
#                    # remember the value for the first line in case we need it later
#                    if not line_0: line_0 = val
#                    hashable.append(val)
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
        self.hashable_backtrace_string = ' '.join(self.hashable_backtrace[:level]).strip()
        logger.warning('_hashable_backtrace_string: %s', self.hashable_backtrace_string)
        return self.hashable_backtrace_string

    def _backtrace_without_questionmarks(self):
        logger.debug('_backtrace_without_questionmarks')
        if not self.backtrace_without_questionmarks:
            self.backtrace_without_questionmarks = [bt for bt in self.backtrace if not '??' in bt]
        return self.backtrace_without_questionmarks

    def backtrace_line(self, idx, l):
        self._look_for_crashing_thread(l)
        m = re.match(regex['bt_line'], l)
        if m  and self.crashing_thread:
            item = m.group(1)  # sometimes gdb splits across lines
            # so get the next one if it looks like '<anything> at <foo>' or '<anything> from <foo>'
            next_idx = idx + 1
            while next_idx < len(self.lines):
                nextline = self.lines[next_idx]
                if re.match(regex['bt_line_basic'], nextline):
                    break
                elif re.search(regex['bt_line_from'], nextline) or re.search(regex['bt_line_at'], nextline):
                    item = ' '.join((item, nextline))
                next_idx += 1

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
                gdb = [s.strip() for s in f.readlines()]
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

            self._look_for_registers(line)

        # if we found that the stack was corrupt,
        # we can no longer trust the last backtrace line
        # so remove it
        if self.is_corrupt_stack and len(self.backtrace):
            removed_bt_line = self.backtrace.pop()
            logger.debug("Corrupt stack found. Removing backtrace line: %s", removed_bt_line)

    def _look_for_crashing_thread(self, line):
        m = re.match(regex['bt_thread'], line)
        if m and 'Crashed' in line:
            self.crashing_thread = True
        elif m:
            self.crashing_thread = False

    #TODO: CrashWrangler equivalents of the below
    def _look_for_corrupt_stack(self, line):
        if 'corrupt stack' in line:
            self.is_corrupt_stack = True

    def _look_for_exit_code(self, line):
        m = re.match(regex['exit_code'], line)
        if m:
            self.exit_code = m.group(1)

    def _look_for_signal(self, line):
        m = re.match(regex['signal'], line)
        if m:
            self.signal = m.group(1)

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
        # short-circuit if we're out of registers to look for
        if not len(registers):
            return

        parts = line.split()

        # short-circuit if line doesn't split
        if not len(parts):
            return
        # short-circuit if the first thing in the line isn't a register
        if not parts[0] in registers:
            return

        r = parts[0]
        mystr = ' '.join(parts[1:])
        m = re.match(regex['register'], mystr)

        # short-circuit when no match
        if not m:
            return

        self.registers_hex[r] = m.group(1)
        self.registers[r] = m.group(2)
        # once we've found the register, we don't have to look for it anymore
        registers.remove(r)

    def get_crash_signature(self, backtrace_level):
        '''
        Determines if a crash is unique. Depending on <backtrace_level>,
        it may look at a number of source code lines in the gdb backtrace, or simply
        just the memory location of the crash.
        '''
        logger.debug('get_crash_signature')
        backtrace_string = self._hashable_backtrace_string(backtrace_level)
        if bool(backtrace_string):
            return hashlib.md5(backtrace_string).hexdigest()
        else:
            return False

if __name__ == '__main__':
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)

    for path in args:
        g = CWfile(path)
        print g.get_crash_signature(5)
