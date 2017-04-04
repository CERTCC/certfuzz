'''
Created on Oct 22, 2010

Provides support for analyzing zzuf log files.

@organization: cert.org
'''
import logging
import re

from . import filetools


logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

KILL_INDICATORS = ['signal 9', 'SIGXFSZ', 'Killed', 'exit 137']
OUT_OF_MEMORY_INDICATORS = ['signal 15', 'exit 143']


class ZzufLog:
    def __init__(self, infile):
        '''
        Reads in <logfile> and parses *the last line*.
        @param logfile: the zzuf log file to analyze
        '''
        self.infile = infile
        self.line = self._get_last_line()

        # parsed will get set True in _parse_line if we successfully parse the line
        self.parsed = False
        (self.seed, self.range, self.result) = self._parse_line()

        filetools.delete_files(self.infile)

        self.exitcode = ''
        self._set_exitcode()

        self.signal = ''
        self._set_signal()

    def _set_signal(self):
        m = re.match('signal\s+(\d+)', self.result)
        if m:
            self.signal = m.group(1)

    def _set_exitcode(self):
        m = re.match('exit\s+(\d+)', self.result)
        if m:
            self.exitcode = int(m.group(1))

    def _get_last_line(self):
        '''
        Reads the zzuf log contained in <file> and returns the seed,
        range, result, and complete line from the last line of the file.
        @return: string, string, string, string
        '''
        try:
            with open(self.infile, 'r') as f:
                line = list(f)[-1]
        except IndexError:
            # e.g., if infile is empty
            line = ''

        # when you get here line contains the last line read from the file
        return line.strip()

    def _parse_line(self):
        seed = False
        rng = False
        result = ''
        m = re.match('^zzuf\[s=(\d+),r=([^\]]+)\]:\s+(.+)$', self.line)
        if m:
            (seed, rng, result) = (int(m.group(1)), m.group(2), m.group(3))
            self.parsed = True  # set a flag that we parsed successfully
        return seed, rng, result

    def crash_logged(self):
        '''
        Analyzes zzuf output log to figure out if this was a crash.
        Returns 0 if it's not really a crash. 1 if it's a crash we
        want. 2 if we're at a seed chunk boundary.
        '''
        # if we couldn't parse the log, just skip it and move on
        if not self.parsed:
            return False

        # not a crash if killed
        if self.was_killed:
            return False

        # not a crash if out of memory
        if self.was_out_of_memory:
            return False

        # if you got here, consider it a crash
        return True


    @property
    def was_killed(self):
        return self._any_indicators_in_result(KILL_INDICATORS)

    @property
    def was_out_of_memory(self):
        return self._any_indicators_in_result(OUT_OF_MEMORY_INDICATORS)

    def _any_indicators_in_result(self, indicator_list):
        return(any(indicator in self.result for indicator in indicator_list))
