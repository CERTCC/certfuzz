'''
Created on Oct 25, 2010

Provides a wrapper around callgrind.

@organization: cert.org
'''

import logging
from .. import Analyzer

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

OUTFILE_EXT = "callgrind"

get_file = lambda x: '%s.%s' % (x, OUTFILE_EXT)


class Callgrind(Analyzer):
    def __init__(self, cfg, crash):
        outfile = get_file(crash.fuzzedfile.path)
        timeout = cfg.valgrindtimeout

        super(Callgrind, self).__init__(cfg, crash, outfile, timeout)
        self.empty_output_ok = True
        self.missing_output_ok = True

    def _get_cmdline(self):
        args = ['valgrind', '--tool=callgrind', '--callgrind-out-file=%s' % self.outfile]
        args.extend(self.cmdargs)
        return args
