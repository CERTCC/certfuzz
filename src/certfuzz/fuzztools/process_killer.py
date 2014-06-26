'''
Created on Oct 25, 2010

@organization: cert.org
'''
import logging
import subprocess

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class ProcessKiller:
    def __init__(self, script, killprocname, killproctimeout):
        self.script = script
        self.killprocname = killprocname
        self.killproctimeout = killproctimeout

    def _get_cmdline(self):
        # if you don't have xterm...
#        template = "bash %s %s %s &" etc
        template = "xterm -geometry +0-0 -e bash %s %s %s &"
        return template % (self.script, self.killprocname, self.killproctimeout)

    def go(self):
        '''
        Spawns a separate process to kill out of control processes.
        '''
        command = self._get_cmdline()
        logger.debug('Running [%s]', command)
        subprocess.call(command, shell=True)
