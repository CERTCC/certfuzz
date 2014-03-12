'''
Created on Mar 14, 2012

@author: adh
'''
import logging

from certfuzz.debuggers.output_parsers import DebuggerFile

logger = logging.getLogger(__name__)

required_checks = ['crash_hash', 'exploitability']


class MsecFile(DebuggerFile):
    '''
    classdocs
    '''
    _key = 'msec'

    def __init__(self, *args, **kwargs):
        self.crash_hash = None
        self.exp = None
        self.faddr = None
        self.secondchance = False

        # add our callbacks
        self.line_callbacks = [
                               self._find_exploitability,
                               self._find_efa,
                               self._find_hash,
                               self._find_secondchance,
                               ]

        self.passed = set()
        # initialize our parent class
        DebuggerFile.__init__(self, *args, **kwargs)

        # override the default from DebuggerFile
        self.is_crash = False

        required_checks = ['crash_hash', 'exploitability']
        checks_passed = [x in self.passed for x in required_checks]
        self.is_crash = all(checks_passed)

#        if self.lines:
#            self.debugger_output = '\n'.join(self.lines)

    def _process_backtrace(self):
        pass

    def _hashable_backtrace(self):
        pass

    def get_crash_signature(self, backtrace_level):
        return self.crash_hash

    def _find_exploitability(self, line):
        if line.startswith('Exploitability Classification'):
            exploitability = self.split_and_strip(line)

            # Count it as a crash as long as it has a classification
            if exploitability and exploitability != 'NOT_AN_EXCEPTION':
                self.passed.add('exploitability')

            self.exp = exploitability
            self.line_callbacks.remove(self._find_exploitability)

    def _find_efa(self, line):
        if line.startswith('Exception Faulting Address'):
            efa = self.split_and_strip(line)
            # turn it into a properly formatted string
            self.faddr = '0x%08x' % int(efa, 16)
            self.line_callbacks.remove(self._find_efa)

    def _find_hash(self, line):
        if line.startswith('Exception Hash'):
            crash_hash = self.split_and_strip(line)
            # count it as a crash as long as it has a hash
            if crash_hash:
                self.passed.add('crash_hash')

            self.crash_hash = crash_hash
            self.line_callbacks.remove(self._find_hash)

    def _find_secondchance(self, line):
        if '!!! second chance !!!' in line:
            self.secondchance = True
            self.line_callbacks.remove(self._find_secondchance)

    def split_and_strip(self, line, delim=':'):
        '''
        Return the second half of the line after the delimiter, stripped of
        whitespace
        @param line:
        @param delim: defaults to ":"
        '''
        return line.split(delim)[1].strip()
