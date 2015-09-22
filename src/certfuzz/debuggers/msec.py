"""This module runs cdb on a process and !exploitable on any exceptions.
"""
import ctypes
import logging
import os
from pprint import pformat
from subprocess import Popen
from threading import Timer
import time

from certfuzz.debuggers.debugger_base import Debugger as DebuggerBase
from certfuzz.debuggers.output_parsers.msec_file import MsecFile
from certfuzz.debuggers.registration import register
from certfuzz.helpers import check_os_compatibility

import wmi


logger = logging.getLogger(__name__)

check_os_compatibility('Windows', __name__)


def factory(options):
    return MsecDebugger(options)


class MsecDebugger(DebuggerBase):
    _platform = 'Windows'
    _key = 'msec'
    _ext = 'msec'

    def __init__(self, program, cmd_args, outfile_base, timeout, killprocname, watchcpu, exception_depth=0, hideoutput=False, **options):
        DebuggerBase.__init__(self, program, cmd_args, outfile_base, timeout, killprocname, **options)
        self.exception_depth = exception_depth
        self.watchcpu = watchcpu
        self.hideoutput = hideoutput

    def kill(self, pid, returncode):
        """kill function for Win32"""
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(1, 1, pid)
        ret = kernel32.TerminateProcess(handle, returncode)
        kernel32.CloseHandle(handle)
        return (0 != ret)

    def debugger_app(self):
        '''
        Returns the name of the debugger application to use in this class
        '''
        typical = "C:\\Program Files\\Debugging Tools for Windows (x86)\\cdb.exe"
        if os.path.exists(typical):
            return typical
        return 'cdb'

    def debugger_test(self):
        '''
        Returns a command line (as list) that can be run via subprocess.call
        to confirm whether the debugger is on the path.
        '''
        return [self.debugger_app(), '-version']

    def _get_cmdline(self, outfile):
        cdb_command = '$$Found_with_CERT_BFF_2.8;r;!exploitable -v;q'
        args = []
        args.append(self.debugger_app())
        args.append('-amsec.dll')
        if hasattr(self, 'debugheap') and self.debugheap:
            # do not use hd, xd options if debugheap is set
            pass
        else:
            args.extend(('-hd', '-xd', 'gp'))
        args.extend(('-logo', outfile))
        args.extend(('-xd', 'bpe', '-xd', 'wob', '-o', '-G', '-c'))
        for self.exception_depth in xrange(0, self.exception_depth):
            cdb_command = 'g;' + cdb_command
        args.append(cdb_command)
        args.append(self.program)
        args.extend(self.cmd_args[1:])
        for l in pformat(args).splitlines():
            logger.debug('dbg_args: %s', l)
        return args

    def run_with_timer(self):
        # TODO: replace this with subp.run_with_timer()
        targetdir = os.path.dirname(self.program)
        exename = os.path.basename(self.program)
        process_info = {}
        _id = None
        done = False
        started = False
        wmiInterface = None
        retrycount = 0
        foundpid = False

        args = self._get_cmdline(self.outfile)
        p = Popen(args, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'),
                      universal_newlines=True)

        if self.watchcpu == True:
            wmiInterface = wmi.WMI()
            while retrycount < 5 and not foundpid:
                for process in wmiInterface.Win32_Process(name=exename):
                    # TODO: What if there's more than one?
                    _id = process.ProcessID
                    logger.debug('Found %s PID: %s', exename, _id)
                    foundpid = True
                if not foundpid:
                    logger.debug('%s not seen yet. Retrying...', exename)
                    retrycount += 1
                    time.sleep(0.1)
            if not _id:
                logger.debug('Cannot find %s child process! Bailing.', exename)
                self.kill(p.pid, 99)
                return

        # create a timer that calls kill() when it expires
        t = Timer(self.timeout, self.kill, args=[p.pid, 99])
        t.start()
        if self.watchcpu == True:
            # This is a race.  In some cases, a GUI app could be done before we can even measure it
            # TODO: Do something about it
            while p.poll() is None and not done and _id:
                for proc in wmiInterface.Win32_PerfRawData_PerfProc_Process(IDProcess=_id):
                    n1, d1 = long(proc.PercentProcessorTime), long(proc.Timestamp_Sys100NS)
                    n0, d0 = process_info.get(_id, (0, 0))
                    try:
                        percent_processor_time = (float(n1 - n0) / float(d1 - d0)) * 100.0
                    except ZeroDivisionError:
                        percent_processor_time = 0.0
                    process_info[_id] = (n1, d1)
                    logger.debug('Process %s CPU usage: %s', _id, percent_processor_time)
                    if percent_processor_time < 0.01:
                        if started:
                            logger.debug('killing %s due to CPU inactivity', p.pid)
                            done = True
                            self.kill(p.pid, 99)
                    else:
                        # Detected CPU usage. Now look for it to drop near zero
                        started = True

                if not done:
                    time.sleep(0.2)
        else:
            p.wait()
        t.cancel()

    def go(self):
        """run cdb and process output"""
        # For exceptions beyond the first one, put the handled exception number in the name
        if self.exception_depth > 0:
            self.outfile = os.path.splitext(self.outfile)[0] + '.e' + str(self.exception_depth) + os.path.splitext(self.outfile)[1]
        self.run_with_timer()
        if not os.path.exists(self.outfile):
            # touch it if it doesn't exist
            open(self.outfile, 'w').close()

        parsed = MsecFile(self.outfile)

        for l in pformat(parsed.__dict__).splitlines():
            logger.debug('parsed: %s', l)
        return parsed
# END MsecDebugger

# register this class as a debugger
register(MsecDebugger)
