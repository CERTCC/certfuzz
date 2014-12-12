'''
Created on Oct 22, 2010

Provides support for analyzing zzuf log files.

@organization: cert.org
'''
import logging
import os
import re

import filetools


logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


class ZzufLog:
    def __init__(self, infile, outfile):
        '''
        Reads in <logfile> and parses *the last line*.
        @param logfile: the zzuf log file to analyze
        '''
        self.infile = infile
        self.outfile = outfile
        self.line = self._get_last_line()

        # parsed will get set True in _parse_line if we successfully parse the line
        self.parsed = False
        (self.seed, self.range, self.result) = self._parse_line()

        self.was_killed = self._was_killed()
        self.was_out_of_memory = self._was_out_of_memory()

        try:
            fp = open(self.outfile, 'a')
            fp.write("%s\n" % self.line)
        except Exception, e:
            logger.warning('Error writing to %s: %s', self.outfile, e)
        finally:
            fp.close()

        filetools.delete_files(self.infile)
        assert not os.path.exists(self.infile)

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
        with open(self.infile, 'r') as f:
            for line in f:
                # don't do anything, just iterate through until we're done with lines
                pass
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

    def crash_logged(self, checkexit):
        '''
        Analyzes zzuf output log to figure out if this was a crash.
        Returns 0 if it's not really a crash. 1 if it's a crash we
        want. 2 if we're at a seed chunk boundary.
        '''
        # if we couldn't parse the log, just skip it and move on
        if not self.parsed:
            return False

        if checkexit and 'exit' in self.result:
            return False

        # not a crash if killed
        if self.was_killed:
            return False

        # not a crash if out of memory
        if self.was_out_of_memory:
            return False

        # if you got here, consider it a crash
        return True

    def _was_killed(self):
        for kill_indicator in ['signal 9', 'SIGXFSZ', 'Killed', 'exit 137']:
            if kill_indicator in self.result:
                return True
        return False

    def _was_out_of_memory(self):
        for out_of_memory_indicator in ['signal 15', 'exit 143']:
            if out_of_memory_indicator in self.result:
                return True
        return False
