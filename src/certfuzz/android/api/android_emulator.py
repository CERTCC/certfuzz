'''
Created on Jan 4, 2013

@organization: cert.org
'''
import logging
import socket
import subprocess
import time
import os

from . import sdk_tool
from .adb_cmd import AdbCmd, AdbCmdError
from .log_helper import pfunc
from .android_cmd import AndroidCmd
from .defaults import inifile, avddir
# from .defaults import TIMERS

from .errors import AndroidEmulatorError

emulator = sdk_tool('emulator')

# string formatters
avddir_basename = '{}.avd'.format
inifile_basename = '{}.ini'.format
socket_str = 'tcp:{:d}'.format
emu_handle = 'emulator-{:d}'.format

logger = logging.getLogger(__name__)


class AndroidEmulator(object):
    @pfunc(logger=logger)
    def __init__(self, emu_opts, no_window=False):
        self.avd = emu_opts['avd_name']
        self.avd_home = emu_opts['avd_home']
        self.timers = emu_opts['timers']

        self.no_window = no_window

        self.handle = None
        self.socket = None
        self.port = None
        self.args = None

        self._started = False
        self._ready = False

        self.child_proc = None
        self.destroy_on_kill = False

    @pfunc(logger=logger)
    def __enter__(self):
        logger.debug('Enter %s runtime context', self.__class__.__name__)
        return self

    @pfunc(logger=logger)
    def __exit__(self, etype, evalue, traceback):
        logger.debug('Exit %s runtime context', self.__class__.__name__)

        if etype is not None:
            logger.info('Caught exception %s: %s', etype.__name__, evalue)
            logger.debug('Attempting to kill %s', self.handle)
            try:
                self.kill()
            except AndroidEmulatorError as e:
                logger.warning('Emulator kill failed: %s', e)
        # no return value since we want to allow upstream contexts
        # to do their thing if they so desire

    @pfunc(logger=logger)
    def _bind_port(self):
        # create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        self.socket = s
        self.port = self.socket.getsockname()[1]
        logger.debug('listen on port %d', self.port)

    @pfunc(logger=logger)
    def _construct_args(self):
        args = [emulator,
        '-no-boot-anim',
        ]
        if self.no_window:
            args.append('-no-window')
        if self.port:
            args.extend(['-report-console', socket_str(self.port)])

        args.extend(['-avd', self.avd])

        self.args = args
        logger.debug('args: %s', args)

    def check_child_is_running(self):
        if self.child_proc.poll() is not None:
            # child proc exited, time to die
            raise AndroidEmulatorError('Child process terminated')

    @pfunc(logger=logger)
    def _start(self):
        # get a port number for the emulator to report back to
        self._bind_port()
        self._construct_args()
        self.child_proc = subprocess.Popen(self.args)
        self._get_handle()

    def _check_for_kill(self):
        # killed handle should be gone from device list
        expire = time.time() + self.timers['kill_timeout']
        while time.time() <= expire:
            if self.handle in AdbCmd().devices().keys():
                time_remaining = expire - time.time()
                logger.debug('%s still in device list, expires in %d',
                             self.handle, time_remaining)
                time.sleep(self.timers['device_retry'])
            else:
                # it's gone, get out of here
                return
        else:
            # if you got here, your timer expired and it's still in the list
            raise AndroidEmulatorError('Failed to kill emulator %s'
                                       % self.handle)

    @pfunc(logger=logger)
    def kill(self):
        if not self.handle:
            raise AndroidEmulatorError('emu kill called when handle is undefined')

        try:
            AdbCmd(self.handle).emu_kill()
        except AdbCmdError as e:
            logger.info('AdbCmdError: %s', e)

        self._check_for_kill()

        if self.destroy_on_kill:
            self.delete()

    @pfunc(logger=logger)
    def delete(self):
        if not self.avd:
            raise AndroidEmulatorError('android delete called when avd undefined')

        AndroidCmd().delete(self.avd)

        # check to see if ini file and avd dir have been removed
        for f in (inifile(self.handle), avddir(self.handle)):
            if os.path.exists(f):
                raise AndroidEmulatorError('failed to remove %s' % f)

    @pfunc(logger=logger)
    def start(self):
        if not self.avd:
            raise AndroidEmulatorError('Android Virtual Device not specified')

        logger.info('Starting emulator %s', self.avd)
        self._start()
        self._started = True
        AdbCmd().restart()
        AdbCmd(self.handle).wait_for_device()
        self._ready = True

    @pfunc(logger=logger)
    def _wait_for_handle(self):
        expire = time.time() + self.timers['handle_timeout']
        while time.time() <= expire:
            known_handles = AdbCmd().devices().keys()
            logger.debug('known emulator handles: %s', known_handles)
            if self.handle in known_handles:
                logger.debug('found handle in list')
                return
            else:
                time_left = int(expire - time.time())
                logger.debug('waiting for device, expire in %d', time_left)
                time.sleep(self.timers['device_retry'])
                AdbCmd().restart()
        else:
            raise AndroidEmulatorError('Handle [{}] not in device list'.format(self.handle))

    @pfunc(logger=logger)
    def _get_handle(self):
        logger.debug('listen to socket %s', self.socket)
        self.socket.listen(1)
        conn, addr = self.socket.accept()
        data = conn.recv(32)
        logger.debug('read data %s', data)
        conn.close()
        self.socket.close()
        logger.debug('socket closed')
        self.socket = None

        emu_port = int(data)
        self.handle = emu_handle(emu_port)

        logger.debug('Received emulator handle: %s', self.handle)
        self._wait_for_handle()
