'''
Created on Jan 4, 2013

@organization: cert.org
'''
import logging
import os

from api.android_emulator import AndroidEmulator
from api.adb_cmd import AdbCmd

logger = logging.getLogger(__name__)

class EmulatorRunnerError(Exception):
    pass


class EmulatorRunner(object):
    def __init__(self, avd):
        self.avd = avd
        self.hide = False
        self.wait_time = 120
        self.handle = None

    def __enter__(self):
        logger.debug('Enter context %s, avd=%s', self, self.avd)
        self._start_emu()
        logger.info("got device! %s" , self.handle)
        return self

    def __exit__(self, etype, evalue, traceback):
        logger.debug('Exiting context %s', self)
#        self._stop_emu()
        pass

    def _start_emu(self):
        with AndroidEmulator(self.avd, no_window=self.hide) as emu:
            emu.start()
        self.handle = emu.handle

    def _stop_emu(self):
        if self.handle:
            AdbCmd(self.handle).emu_kill()

    def run(self):
        if not self.handle:
            raise EmulatorRunnerError('emulator handle not found')

        shell_cmd = "date; uptime"

        with AdbCmd(self.handle) as adb:
            adb.shell([shell_cmd])
            if adb.stdout:
                outfile = 'emu-%d.out' % os.getpid()
                with open(outfile, 'w') as f:
                    f.writelines(adb.stdout)
            if adb.stderr:
                outfile = 'emu-%d.err' % os.getpid()
                with open(outfile, 'w') as f:
                    f.writelines(adb.stderr)



