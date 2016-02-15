'''
Created on Aug 5, 2011

@organization: cert.org
'''
import platform
import os.path
from certfuzz.analyzers.analyzer_base import Analyzer

_platforms = ['Darwin']
_platform_is_supported = platform.system() in _platforms


OUTFILE_EXT = "gmalloc"
get_file = lambda x: '%s.%s' % (x, OUTFILE_EXT)


class CrashWranglerGmalloc(Analyzer):
    '''
    classdocs
    '''

    def __init__(self, cfg, crash):
        '''
        Constructor
        '''
        if not _platform_is_supported:
            return None
        elif not os.path.isfile('/usr/lib/libgmalloc.dylib'):
            return None

        outfile = get_file(crash.fuzzedfile.path)
        timeout = cfg['debugger']['runtimeout']

        Analyzer.__init__(self, cfg, crash, outfile, timeout)

    def go(self):
        if not _platform_is_supported:
            return None
        elif not os.path.isfile('/usr/lib/libgmalloc.dylib'):
            return None

        prg = self.cmdargs[0]
        args = self.cmdargs[1:]

        from ..debuggers.crashwrangler import CrashWrangler
        CrashWrangler(prg, args, self.outfile, self.timeout, self.progname).go()
