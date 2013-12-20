'''
Created on Oct 25, 2010

Provides wrapper facilities for zzuf

@organization: cert.org
'''
import logging
from . import subprocess_helper as subp

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class ZzufTestCase:
    def __init__(self, seedfile, seed, range, outfile):
        '''
        @param seedfile: The original seed file to use
        @param seed: The zzuf seed number to use
        @param range: 
        @param outfile:
        '''
        self.seedfile = seedfile
        self.seed = seed
        self.range = range
        self.outfile = outfile

        self._set_cmdline()

    def _set_cmdline(self):
        self.cmdline = 'cat %s | zzuf -s%s -r%s > %s' % (self.seedfile, self.seed, self.range, self.outfile)

    def generate(self):
        subp.run_without_timer(self.cmdline)

class Zzuf:
    def __init__(self, dir, s1, s2, cmd, seedfile, file, copymode, ratiomin, ratiomax, timeout, quiet=True):
        '''
        
        @param dir:
        @param s1: The starting seed
        @param s2: The ending seed
        @param cmd: The command to run
        @param file: The zzuf output file
        @param copymode: 
        @param ratiomin: 
        @param ratiomax:
        @param timeout: A float timeout
        '''
        self.dir = dir
        self.s1 = s1
        self.s2 = s2
        self.cmd = cmd
        self.include = seedfile
        self.file = file
        self.copymode = copymode
        self.ratiomin = ratiomin
        self.ratiomax = ratiomax
        self.timeout = timeout
        self.quiet = quiet

        self.zzuf_args = self._get_zzuf_args()
        self.saw_crash = False

    def _get_go_fuzz_cmdline(self):
        if self.quiet:
            # if we are in quiet mode (default), redirect stderr to self.file
            template = "cd %s && zzuf %s %s 2> %s"
        else:
            # if we are not in quiet mode, then we want both stderr and stdout
            # on the console, but only stderr goes to self.file
            template = "cd %s && zzuf %s %s 3>&1 1>&2 2>&3 | tee %s"
        cmdline = template % (self.dir, self.zzuf_args, self.cmd, self.file)
        logger.info(cmdline)
        return cmdline

    def go(self):
        '''
        Changes directory to <dir> then starts a zzuf run with the 
        given parameters.
        '''
        command = self._get_go_fuzz_cmdline()
        retcode = subp.run_without_timer(command)
        if retcode:
            self.saw_crash = True
        return self.saw_crash

    def generate_test_case(self, seedfile, seed, range, outfile):
        '''
        Generates the test case for the given <seedfile>, <seed>, 
        and <range>, storing the result in <outfile>
        '''

        testcase = ZzufTestCase(seedfile, seed, range, outfile)
        testcase.generate()
        return testcase

    def _get_zzuf_args(self):
        '''
        Builds an argument string for zzuf based on the passed parameters.
        @rtype: string
        '''
        parts = []
        if self.quiet:
            parts.append("quiet")
        parts.append('include=%s' % self.include)
        parts.append("signal")
        parts.append("max-crashes=1")
        parts.append("ratio=%6f:%6f" % (self.ratiomin, self.ratiomax))
        parts.append("max-usertime=%.2f" % self.timeout)

        # zzuf supports a "copy" mode, where LD_PRELOAD is not used to hook into the
        # target process. If zzuf.cfg specifies copy mode, then the appropriate options
        # will be added to the zzuf command line to enable this mode.
        # Some applications do not behave properly with zzuf loaded via LD_PRELOAD.
        # Those applications should be fuzzed in copy mode, which also specifies the option
        # to look at the process exit code to indicate failures.  This works well for 
        # programs that are launched by a shell script.
        if (self.copymode):
            parts.append("opmode=copy")

        parts.append("seed=%d:%d" % (self.s1, self.s2))

        # prefix everything with a "--" then build the string
        return " ".join(["--%s" % p for p in parts])
