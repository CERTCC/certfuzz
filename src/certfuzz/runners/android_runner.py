'''
Created on Apr 4, 2013

@organization: cert.org
'''
from . import Runner
from . import AndroidRunnerError
from ..android.api.adb_cmd import AdbCmd
from ..android.api.activity_manager import ActivityManager
from ..android.api.errors import AdbCmdError
# from ..db.couchdb.datatypes import TestCaseDoc
# from ..db.couchdb.db import TestCaseDb
# from ..helpers.misc import random_str
# from ..fuzztools.filetools import find_or_create_dir

import logging
import os
import tempfile
import shutil
import time

logger = logging.getLogger(__name__)

class AndroidRunner(Runner):
    '''
    Runner object for Android platform
    '''
    def __init__(self, handle, src_file, dst_file, campaign_id, intent=None,
                 workingdir_base=None, options=None):
        Runner.__init__(self, options, workingdir_base)
        self.handle = handle
        self.src = src_file
        self.dst = dst_file
        self.campaign_id = campaign_id
        self.outdir = os.path.expanduser('~/bff-results')
        self.intent = intent

        if self.intent is None:
            raise AndroidRunnerError('Cannot run task without intent')
        else:
            self.intent.data_uri = self._fuzzed_file_uri

        self.testcases = []

    def __enter__(self):
        Runner.__enter__(self)
        return self

    def _copy_file_to_device(self):
        with AdbCmd(handle=self.handle) as adbcmd:
            adbcmd.push(self.src, self.dst)

    def _clean_tombstones(self):
        cmd = ['rm', '-r', '/data/tombstones']
        with AdbCmd(handle=self.handle) as adbcmd:
            adbcmd.shell(cmd)

    def _clean_log(self):
        with AdbCmd(handle=self.handle) as adbcmd:
            adbcmd.clear_logs()

    def _spoof_result(self):
        '''
        Intended for debugging/testing purposes only.

        Places a dummy tombstone file into the /data/tombstones dir of the
        emulator given by <handle>. Gives _wait_for_result_dir something to find.
        :param handle:
        '''
        # write a tempfile with some dummy text
        fd, fname = tempfile.mkstemp(prefix='fake_tombstone_', text=True)
        for c in 'ABCDE':
            line = c * 80 + '\n'
            os.write(fd, line)
        os.close(fd)

        # copy the tempfile to the emulator
        basename = os.path.basename(fname)
        with AdbCmd(handle=self.handle) as adbcmd:
            adbcmd.push(fname, '/data/tombstones/' + basename)

    def _wait_for_result_dir(self):
        '''
        1. Create a temp dir inside work_dir.
        2. Set a timer
        3. Until the timer expires, attempt to pull tombstone data from the
           emulator specified in handle
        4. If anything is found, short circuit and return.
        5. If the timer expires, clean up and return nothing.
        '''
        self.result_dir = None
        check_for_result_dir_naptime = 1
        d = tempfile.mkdtemp(dir=self.workingdir)
        expire_at = time.time() + self.runtimeout
        while time.time() <= expire_at:
            try:
                with AdbCmd(handle=self.handle) as adbcmd:
                    adbcmd.pull('/data/tombstones', d)
            except AdbCmdError as e:
                # errors are okay, we'll just try again
                logger.debug('Caught error getting tombstone, will retry: %s',
                             e)

            if len(os.listdir(d)):
                self.result_dir = d
                self.saw_crash = True
                # shortcut if we got something
                return
            else:
                time.sleep(check_for_result_dir_naptime)

        # if you got here, then the timer ran out and there's nothing in d
        shutil.rmtree(d, ignore_errors=True)

    def _check_result(self):
        '''
        Returns result dir if tombstone found, None otherwise.
        :param handle:
        :param work_dir:
        '''
        # TODO: remove call to _spoof_result once we know check_result works
        #self._spoof_result()

        self._wait_for_result_dir()

        if self.saw_crash:
            logger.warning('Found crash tombstone')
        else:
            logger.debug('No tombstones found')


    @property
    def _fuzzed_file_uri(self):
        return 'file://{}'.format(self.dst)

    def _prerun(self):
        self._copy_file_to_device()
        self._clean_tombstones()
        self._clean_log()

    def _run(self):
        logger.debug('runner %d: %s', os.getpid(), self.handle)
        logger.debug('intent: %s', self.intent)
        ActivityManager(self.handle).start(self.intent, wait_for_launch=True)

    def _postrun(self):
        self._check_result()
        ActivityManager(self.handle).force_stop(self.intent.component)
        # TODO: kill_all may not be necessary
        ActivityManager(self.handle).kill_all()
        logger.debug('Stopped %s' % self.intent.component)
