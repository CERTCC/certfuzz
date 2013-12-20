'''
Created on Jan 4, 2013

@organization: cert.org
'''
import subprocess
import logging
from .defaults import sdk_platform_tool
from .log_helper import pfunc
from .errors import AdbCmdError
import functools
import signal
from ...fuzztools.command_line_callable import CommandLineCallable

adb = sdk_platform_tool('adb')

logger = logging.getLogger(__name__)

def _terminate_and_raise(p, signum, frame):
    '''
    signal handler for use when a process p times out
    :param p:
    :param signum:
    :param frame:
    '''
    p.terminate()
    raise AdbCmdError()

class AdbCmd(CommandLineCallable):
    @pfunc(logger=logger)
    def __init__(self, handle=None):
        CommandLineCallable.__init__(self, ignore_result=False)

        self.handle = None
        if handle is not None:
            self.handle = handle.strip()  # make sure there's no newlines
        arg_pfx = [adb]
        if self.handle:
            arg_pfx.extend(['-s', self.handle])
        self.arg_pfx = arg_pfx

    @pfunc(logger=logger)
    def __enter__(self):
        return self

    @pfunc(logger=logger)
    def __exit__(self, etype, evalue, traceback):
        if etype is AdbCmdError:
            logger.warning('Caught AdbCmdError: %s', evalue)

    @pfunc(logger=logger)
    def bugreport(self):
        self.call(['bugreport'])

    @pfunc(logger=logger)
    def devices(self):
        self.call(['devices'])
        devices = {}
        for line in self.stdout.splitlines()[1:]:
            chunks = line.split()
            if len(chunks) == 2:
                handle, state = chunks
                devices[handle] = state
        return devices

    @pfunc(logger=logger)
    def emu_kill(self):
        self.call(['emu', 'kill'])
        if self.stderr:
            raise AdbCmdError(self.stderr)

    @pfunc(logger=logger)
    def get_serialno(self):
        self.call('get-serialno')

    @pfunc(logger=logger)
    def get_state(self):
        self.call('get-state')

    @pfunc(logger=logger)
    def install(self, path_to_apk):
        self.call(['install', path_to_apk])

    @pfunc(logger=logger)
    def reinstall(self, path_to_apk):
        self.call(['install', 'r', path_to_apk])

    @pfunc(logger=logger)
    def jdwp(self):
        self.call(['jdwp'])

    @pfunc(logger=logger)
    def kill_server(self):
        self.call(['kill-server'])

    @pfunc(logger=logger)
    def pull(self, remote, local):
        self.call(['pull', remote, local])
        if self.stderr:
            # normal result looks like
            # 29 KB/s (10000 bytes in 0.332s)
            if 'bytes in' in self.stderr:
                logger.info(self.stderr.strip())
            else:
                raise AdbCmdError(self.stderr)

    @pfunc(logger=logger)
    def push(self, local, remote):
        self.call(['push', local, remote])
        if self.stderr:
            # normal result looks like
            # 858 KB/s (10000 bytes in 0.011s)
            if 'bytes in' in self.stderr:
                logger.info(self.stderr.strip())
            else:
                raise AdbCmdError(self.stderr)

    @pfunc(logger=logger)
    def restart(self):
        self.kill_server()
        self.start_server()

    @pfunc(logger=logger)
    def shell(self, args):
        _args = ['shell']
        _args.extend(args)
        self.call(_args)
        logger.debug(self.stdout)

    @pfunc(logger=logger)
    def clear_logs(self):
        args = ['logcat', '-c']
        self.shell(args)

    @pfunc(logger=logger)
    def start_server(self):
        self.call(['start-server'])

    @pfunc(logger=logger)
    def wait_for_device(self):
        logger.info('Waiting for device %s', self.handle)
        self.call(['wait-for-device'])

    @pfunc(logger=logger)
    def wait_for_sdcard(self, sdcart_timeout=600):
        # TODO: make sure the sdcard isn't already mounted and ready
        logger.info('Waiting for sdcard to become available on %s', self.handle)

        args = self.arg_pfx + ['logcat', '-s', 'StorageNotification:I']

        logger.debug(' '.join(args))
        p = subprocess.Popen(args,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

        alarm_handler = functools.partial(_terminate_and_raise, p)
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(sdcart_timeout)

        # p.poll() returns None while p is still running.
        while p.poll() is None:
            while True:
                line = p.stdout.readline().strip()
                logger.debug('adb log: %s', line)
                # we are watching for a log message like:
                # I/StorageNotification(  256): Media {/mnt/sdcard}
                # state changed from {checking} -> {mounted}
                if line.endswith('{mounted}'):
                    # got a a match!
                    p.terminate()
                    signal.alarm(0)  # unset alarm
                    return
