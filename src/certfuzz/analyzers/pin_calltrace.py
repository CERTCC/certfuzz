'''
Created on Oct 25, 2010

Provides a wrapper around valgrind.

@organization: cert.org
'''

import logging
import os
from certfuzz.analyzers.analyzer_base import Analyzer

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

OUTFILE_EXT = "calltrace"

get_file = lambda x: '%s.%s' % (x, OUTFILE_EXT)


class Pin_calltrace(Analyzer):
    def __init__(self, cfg, crash):
        outfile = get_file(crash.fuzzedfile.path)
        timeout = cfg['analyzer']['valgrind_timeout'] * 10

        Analyzer.__init__(self, cfg, crash, outfile, timeout)
        self.empty_output_ok = True
        self.missing_output_ok = True

    def _get_cmdline(self):
        pin = os.path.expanduser('~/pin/pin')
        pintool = os.path.expanduser('~/pintool/calltrace.so')
        args = [pin, '-injection', 'child', '-t', pintool, '-o', self.outfile, '--']
        args.extend(self.cmdargs)
        return args
