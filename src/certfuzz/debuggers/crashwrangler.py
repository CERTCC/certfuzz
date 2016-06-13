'''
Created on Jul 1, 2011

Provides a wrapper around CrashWrangler.

@organization: cert.org
'''
import logging
import os.path
import platform
import re

from certfuzz.debuggers.debugger_base import Debugger
from certfuzz.debuggers.output_parsers.cwfile import CWfile
from certfuzz.fuzztools import subprocess_helper as subp


logger = logging.getLogger(__name__)

myplatform = platform.platform()
if re.match('Darwin-9', myplatform):
    cwapp = 'exc_handler_leopard'
elif re.match('Darwin-10', myplatform):
    cwapp = 'exc_handler_snowleopard'
elif re.match('Darwin-11', myplatform):
    cwapp = 'exc_handler_lion'
elif re.match('Darwin-12', myplatform):
    cwapp = 'exc_handler_mountain_lion'
elif re.match('Darwin-13', myplatform):
    cwapp = 'exc_handler_mavericks'
elif re.match('Darwin-14', myplatform):
    cwapp = 'exc_handler_yosemite'
elif re.match('Darwin-15', myplatform):
    cwapp = 'exc_handler_elcapitan'
elif re.match('Darwin-16', myplatform):
    cwapp = 'exc_handler_sierra'
else:
    cwapp = 'exc_handler'


class CrashWrangler(Debugger):
    _platform = 'Darwin'
    _key = 'cw'
    _ext = 'cw'

    def __init__(self, program, cmd_args, outfile, timeout, template=None, exclude_unmapped_frames=True, **options):
        Debugger.__init__(self, program, cmd_args, outfile, timeout)

    def _get_crashwrangler_cmdline(self):
        if (self.program == cwapp):
            args = [self.program]
        else:
            args = [cwapp, self.program]
        args.extend(self.cmd_args)
        return args

    def debugger_app(self):
        '''
        Returns the name of the debugger application to use in this class
        '''
        return cwapp

    def debugger_test(self):
        '''
        Returns a command line (as list) that can be run via subprocess.call
        to confirm whether the debugger is on the path.
        '''
        return [self.debugger_app()]

    def go(self):
        '''
        Generates CrashWrangler output for <cmd> into <logfile>.
        If crashwrangler fails to complete before <timeout>,
        attempt to _kill crashwrangler and program.
        '''
        # build the command line in a separate function so we can unit test
        # it without actually running the command
        args = self._get_crashwrangler_cmdline()

        # set up the environment for crashwrangler
        my_env = dict(os.environ)
        my_env['CW_LOG_PATH'] = self.outfile
        my_env['CW_LOG_INFO'] = 'Found_with_CERT_BFF_2.8'
        my_env['CW_NO_CRASH_REPORTER'] = '1'
        if re.search('gmalloc', self.outfile):
            my_env['CW_USE_GMAL'] = '1'

        subp.run_with_timer(args, self.timeout, self.program, env=my_env)

        # We're not guaranteed that CrashWrangler will create an output file:
        if not os.path.exists(self.outfile):
            open(self.outfile, 'w').close()

        return CWfile(self.outfile)
