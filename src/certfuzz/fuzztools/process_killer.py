'''
Created on Oct 25, 2010

@organization: cert.org
'''
import logging
import subprocess
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class ProcessKiller:
    def __init__(self, killprocname, killproctimeout):
        self.script = os.path.abspath(os.path.expanduser('~/bff/killproc.sh'))
        self.killprocname = killprocname
        self.killproctimeout = killproctimeout

        # if you don't have xterm...
        # template = "bash %s %s %s &" etc
        self.template = "xterm -geometry +0-0 -e bash {} {} {} &"

        self.cmdline = None

    def __enter__(self):
        self._set_cmdline()
        return self

    def __exit__(self, etype, value, traceback):
        handled = False

        if etype is subprocess.CalledProcessError:
            logger.warning('ProcessKiller startup failed: %s', value)
            handled = True
        elif etype is None:
            logger.debug("Process killer started: %s %s %d", self.script,
                         self.killprocname, self.killproctimeout)

        return handled

    def _set_cmdline(self):
        self.cmdline = self.template.format(self.script, self.killprocname,
                                            self.killproctimeout)

    def go(self):
        '''
        Spawns a separate process to kill out of control processes.
        '''
        logger.debug('Running [%s]', self.cmdline)
        pk_pid = subprocess.Popen(self.cmdline, shell=True).pid
        return pk_pid
