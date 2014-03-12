'''
Created on Jan 10, 2013

@organization: cert.org
'''
import atexit
import logging
import os
import random
import signal
import sys
import time

from certfuzz.android.api import AdbCmd
from certfuzz.android.api.log_helper import log_formatter
from certfuzz.android.avd_mgr.main import avd_manager

from certfuzz.iteration.iteration_android import emu as iteration_emu


logger = logging.getLogger(__name__)


def _reset_root_logger():
    rl = logging.getLogger()
    # remove the other handlers
    rl.handlers = []
    logfilename = 'worker-%d.log' % os.getpid()
    logfilepath = os.path.join('log', logfilename)
    filehdlr = logging.FileHandler(filename=logfilepath, mode='w')
    filehdlr.setFormatter(log_formatter())
    rl.addHandler(filehdlr)


def _setup_child(emu_opts, pipe_in, pipe_out):
    # we are the child
    _reset_root_logger()
    logger.debug('%d child fork success', os.getpid())
    # reseed the random number generator for this process (avoids having
    # all peer processes with the same PRNG state)
    random.seed()

    os.close(pipe_in)

    # wait for a few secs before proceeding to avoid having many avds
    # spinning up simultaneously
    naptime = random.randint(0, 30)
    logger.debug('Pausing for %d seconds before proceeding', naptime)
    time.sleep(naptime)
    avd_manager(emu_opts, hide=False, pipe=pipe_out)


def _setup_parent(pipe_in, pipe_out, child_pid, emu_opts, apk_dir):
    # we are the parent
    atexit.register(_on_exit)
    signal.signal(signal.SIGTERM, _clean_exit)
    signal.signal(signal.SIGINT, _clean_exit)

    os.close(pipe_out)
    pipe_in = os.fdopen(pipe_in)
    logger.debug('Waiting for emulator handle from child process %d',
                 child_pid)
    handle = pipe_in.readline().strip()
    logger.info('Received emulator handle from child process %d: %s',
                child_pid, handle)
    pipe_in.close()

    iteration_emu.handle = handle

    with AdbCmd(handle) as adbcmd:
        adbcmd.wait_for_sdcard(emu_opts['timers']['sdcard_timeout'])
    logger.info('%s (ppid=%d pid=%d) ready',
                handle, os.getpid(), child_pid)

    # Install any APKS
    _install_apks(handle, apk_dir)

    return handle


def start_emulator(emu_opts, apk_dir=None):
    logger.info('starting emulator (pid=%d)', os.getpid())
    logger.debug('Opening pipe')
    pipe_in, pipe_out = os.pipe()
    logger.debug('forking child to spawn emulator')
    child_pid = os.fork()

    if child_pid != 0:
        # we are the parent
        return _setup_parent(pipe_in, pipe_out, child_pid, emu_opts, apk_dir)

    # we must be the child
    _setup_child(emu_opts, pipe_in, pipe_out)


def _stop_emulator(handle):
    with AdbCmd() as adbcmd:
        devices = adbcmd.devices()

    if handle in devices:
        logger.warning('%d Emulator still in device list %s: %s',
                       os.getpid(),
                       handle,
                       devices[handle]
                       )
        # TODO: kill the emu here if it's still around


def _on_exit(*args, **kwargs):
    '''
    Exit handler
    '''
    # TODO: fix or delete.  We are currently calling _stop_emulator in AndroidCampaign.__exit__()
    # _stop_emulator()
    pass


def _clean_exit(signum, stack_frame):
    logger.info('Exiting on signal %d', signum)
    logger.debug('Stack frame: %s', stack_frame)
    sys.exit()


def _install_apks(handle, apk_dir=None):
    # short circuit if no apk_dir given
    if apk_dir == None:
        return

    if not os.path.exists(apk_dir):
        logger.warning('APK installation directory \'%s\' not found. ' % apk_dir +
                               'Unable to install APKs.')
        return

    # if we got here, apk_dir exists, so try to install stuff...
    with AdbCmd(handle) as adbcmd:
        apks = [apk for apk in os.listdir(apk_dir) if apk.lower().endswith('.apk')]
        for apk in apks:
            adbcmd.install('/'.join([apk_dir, apk]))
