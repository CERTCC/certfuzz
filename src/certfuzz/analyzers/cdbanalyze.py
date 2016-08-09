'''
Created on Aug 5, 2011

@organization: cert.org
'''
import platform
import os.path
from certfuzz.analyzers.analyzer_base import Analyzer

_platforms = ['Windows']
_platform_is_supported = platform.system() in _platforms


OUTFILE_EXT = "analyze"
get_file = lambda x: '%s.%s' % (x, OUTFILE_EXT)


class CdbAnalyze(Analyzer):
    '''
    classdocs
    '''

    def __init__(self, cfg, testcase):
        '''
        Constructor
        '''
        if not _platform_is_supported:
            return None

        self.outfile = get_file(testcase.fuzzedfile.path)
        # !analyze takes longer to complete than !exploitable. Give it 2x the time
        self.timeout = cfg['runner']['runtimeout'] * 2
        self.watchcpu = cfg['debugger']['watchcpu']

        Analyzer.__init__(self, cfg, testcase, self.outfile, self.timeout)

    def go(self):
        if not _platform_is_supported:
            return None

        prg = self.cmdargs[0]
        args = self.cmdargs[1:]

        from ..debuggers.msec import MsecDebugger
        MsecDebugger(
            program=prg, cmd_args=args, outfile_base=self.outfile, timeout=self.timeout, watchcpu=self.watchcpu, exception_depth=0, debug_heap=self.cfg['debugger']['debugheap'], cdb_command='!analyze -v').go()
