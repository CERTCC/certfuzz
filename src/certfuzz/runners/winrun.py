from ..helpers import check_os_compatibility

check_os_compatibility('Windows')

import platform
from . import RunnerPlatformVersionError

if not platform.version().startswith('5.'):
    raise RunnerPlatformVersionError('Incompatible OS: winrun only works on Windows XP and 2003')

from killableprocess import Popen
from threading import Timer
from _winreg import OpenKey, SetValueEx, HKEY_LOCAL_MACHINE, REG_SZ, KEY_ALL_ACCESS, QueryValueEx  # @UnresolvedImport
import ctypes
import os
import logging
import sys
import wmi
import time
from .errors import RunnerArchitectureError, RunnerRegistryError
from .errors import RunnerError
from ..campaign.config.foe_config import get_command_args_list
from ..fuzztools.filetools import find_or_create_dir

logger = logging.getLogger(__name__)

try:
    # if we have win32api, use its GetShortPathName
    from win32api import GetShortPathName  # @UnresolvedImport
except ImportError:
    # we don't have win32api, try ctypes
    def GetShortPathName(longname):
        buf = ctypes.create_unicode_buffer(512)
        if ctypes.windll.kernel32.GetShortPathNameW(longname, buf, ctypes.sizeof(buf)):  # @UndefinedVariable
            return buf.value
        else:
            # but don't panic if we can't do that either
            return longname

from . import Runner as RunnerBase
from ..debuggers import jit as dbg


def _get_reg_value(hive=None, branch=None, rname=None):
    k = OpenKey(hive, branch, 0, KEY_ALL_ACCESS)
    return QueryValueEx(k, rname)


def _set_reg_value(hive=None, branch=None, rname=None, rval=None):
    k = OpenKey(hive, branch, 0, KEY_ALL_ACCESS)
    SetValueEx(k, rname, 0, REG_SZ, rval)
    k.Close()
    logger.debug('Set registry: %s\%s\%s=%s', hive, branch, rname, rval)


def kill(p):
    logger.debug('kill %s', p)
    p.kill(group=True)


class WinRunner(RunnerBase):
    def __init__(self, options, cmd_template, fuzzed_file, workingdir_base):
        RunnerBase.__init__(self, options, cmd_template, fuzzed_file, workingdir_base)

        logger.debug('Initialize Runner')
        self.runtimeout = None
        self.exceptions = []

        self.watchcpu = options.get('watchcpu', False)
        try:
            self.exceptions = options['exceptions']
        except KeyError:
            raise RunnerError('At least one exception code must be specified in runner config.')

#        self._parse_options()
        self.saw_crash = False

        self.workingdir = workingdir_base

        (self.cmd, self.cmdlist) = get_command_args_list(cmd_template, fuzzed_file)
        logger.debug('Command: %s', self.cmd)

        find_or_create_dir(self.workingdir)

        self.t = None
        self.returncode = None
        self.remembered = []

        if not hasattr(self, 'verify_architecture'):
            # check the architecture unless our options have already set it
            self.verify_architecture = True

    def _store_existing_values(self, hive, branch, rname):
        try:
            val = _get_reg_value(hive, branch, rname)[0]
            restorable = (hive, branch, rname, val)
            self.remembered.append(restorable)
        except OSError:
            # _get_reg_value could cause a WindowsError to be thrown
            # (WindowsError inherits from OSError)
            # If that happens, we simply don't have anything to restore
            # but it's not worth crashing over.
            return

    def __enter__(self):
        if self.verify_architecture:
            self._verify_architecture('32')

        # check various system options
        # register hook dll
        # TODO make path configurable
        hive = HKEY_LOCAL_MACHINE
        branch = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
        rname = "AppInit_DLLs"

        self._store_existing_values(hive, branch, rname)

        # assume hook dll is at ../hooks/winxp/Release/hook.dll relative to
        # the location of this module
        my_path = os.path.dirname(__file__)
        relative_path_to_hook_dll = os.path.join(my_path, '..', "hooks", "winxp", "Release", "hook.dll")
        rval = GetShortPathName(os.path.abspath(relative_path_to_hook_dll))

        try:
            _set_reg_value(hive, branch, rname, rval)
        except OSError, e:
            logger.error('Unable to set registry: %s\%s\%s=%s', hive, branch, rname, rval)
            raise RunnerRegistryError(e)

        # register jit debugger (or lack thereof)
        branch = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"

        # Find location of python executable
        python_path = sys.executable
        if not python_path:
            python_path = 'c:\python27\python.exe'
            logger.warning('No path to python exec in sys.executable, using default of %s', python_path)
        # Find our preferred debugger module
        dbg_path = dbg.__file__
    #    dbg_path = 'calc.exe'
        rname = "Debugger"

        self._store_existing_values(hive, branch, rname)

        rval = '"%s" "%s" %%ld' % (python_path, dbg_path)
        try:
            _set_reg_value(hive, branch, rname, rval)
        except OSError:
            logger.error('Unable to set registry: %s\%s\%s=%s', hive, branch, rname, rval)
            raise RunnerRegistryError(e)

        # enable auto debugger invocation
        rname = "Auto"

        self._store_existing_values(hive, branch, rname)

        rval = "1"
        try:
            _set_reg_value(hive, branch, rname, rval)
        except OSError:
            logger.error('Unable to set registry: %s\%s\%s=%s', hive, branch, rname, rval)
            raise RunnerRegistryError(e)

        # check cdb path

        # check to see if windbg exists

        return self

    def __exit__(self, etype, value, traceback):
        if self.t:
            logger.debug('Canceling timer...')
            self.t.cancel()
        # restore registry entries in reverse order
        self.remembered.reverse()
        for registry_entry in self.remembered:
            (hive, branch, rname, rval) = registry_entry
            try:
                _set_reg_value(hive, branch, rname, rval)
            except OSError:
                logger.warning('Unable to set registry: %s\%s\%s=%s', hive, branch, rname, rval)

    def _verify_architecture(self, expected_bits=None):
        '''
        Returns true if the first value returned by platform.architecture
        starts with the string given in expected_bits.
        @param expected_bits: '32' or '64'
        '''
        if not expected_bits or not expected_bits in ['32', '64']:
            raise ValueError('Expected bits must be one of "32" or "64"')

        program = self.cmdlist[0]
        bits = platform.architecture(executable=program)[0]
        if not bits.startswith(expected_bits):
            raise RunnerArchitectureError('Platform.architecture returns "%s", %s \
                expects %s' % (bits, self.__class__.__name__, expected_bits))

    def kill(self, p):
        kill(p)

    def run(self):
        '''
        Runs the command in self.cmdlist from self.workingdir with a timer
        bounded by self.runtimeout
        '''
        logger.debug('Running: %s %s', self.cmdlist, self.workingdir)
        targetdir = os.path.dirname(self.cmdlist[0])
        logger.debug('from directory: %s', targetdir)
        process_info = {}
        id = None
        done = False
        started = False
        wmiInterface = None
        # set timeout(s)
        # run program
        if self.hideoutput:
            p = Popen(self.cmdlist, cwd=targetdir, stdout=open(os.devnull), stderr=open(os.devnull))
        else:
            p = Popen(self.cmdlist, cwd=targetdir)

        if self.watchcpu == True:
            # Initialize things used for CPU monitoring
            logger.debug('Initializing WMI...')
            wmiInterface = wmi.WMI()
            id = p.pid

        logger.debug('...Timer: %f', self.runtimeout)
        t = Timer(self.runtimeout, kill, args=[p])
        self.t = t
        logger.debug('...timer start')
        t.start()
        if self.watchcpu == True:
            # This is a race.  In some cases, a GUI app could be done before we can even measure it
            # TODO: Do something about it
            while p.poll() is None and not done and id:
                for proc in wmiInterface.Win32_PerfRawData_PerfProc_Process(IDProcess=id):
                    n1, d1 = long(proc.PercentProcessorTime), long(proc.Timestamp_Sys100NS)
                    n0, d0 = process_info.get(id, (0, 0))
                    try:
                        percent_processor_time = (float(n1 - n0) / float(d1 - d0)) * 100.0
                    except ZeroDivisionError:
                        percent_processor_time = 0.0
                    process_info[id] = (n1, d1)
                    logger.debug('Process %s CPU usage: %s', id, percent_processor_time)
                    if percent_processor_time < 0.01:
                        if started:
                            logger.debug('killing %s due to CPU inactivity', id)
                            done = True
                            kill(p)
                    else:
                        # Detected CPU usage. Now look for it to drop near zero
                        started = True

                if not done:
                    time.sleep(0.2)
        else:
            p.wait()
        # probably racy
        logger.debug('...timer stop')
        t.cancel()

        self.returncode = ctypes.c_uint(p.returncode).value
        logger.debug('...Returncode: raw=%s cast=%s', p.returncode, self.returncode)
        logger.debug('...Exceptions: %s', self.exceptions)
        if self.returncode in self.exceptions:
            self.saw_crash = True
        logger.debug('...Saw_crash: %s', self.saw_crash)

_runner_class = WinRunner
