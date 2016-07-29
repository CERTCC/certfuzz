'''
Created on Jan 12, 2016

@author: adh
'''
import logging
import os
import shutil

from certfuzz.fuzztools import filetools
from certfuzz.reporters.errors import ReporterError
from certfuzz.reporters.reporter_base import ReporterBase


logger = logging.getLogger(__name__)


class CopyFilesReporter(ReporterBase):
    '''
    Copies files to a location
    '''

    def __init__(self, testcase, keep_duplicates):
        '''
        Constructor
        '''
        ReporterBase.__init__(self, testcase)

        self.target_dir = testcase.target_dir
        self.keep_duplicates = keep_duplicates

    def go(self):
        dst_dir = self.target_dir
        if len(dst_dir) > 130:
            # Don't make a path too deep.  Windows won't support it
            dst_dir = dst_dir[:130] + '__'
        # ensure target dir exists already (it might because of crash logging)
        filetools.mkdir_p(dst_dir)
        if (len(os.listdir(dst_dir)) > 0 and not self.keep_duplicates):
            logger.debug(
                'Output path %s already contains output. Skipping.' % dst_dir)
            return

        src_dir = self.testcase.tempdir
        if not os.path.exists(src_dir):
            raise ReporterError('Testcase tempdir not found: %s', src_dir)

        src_paths = [os.path.join(src_dir, f) for f in os.listdir(src_dir)]

        for f in src_paths:
            logger.debug('Copy %s -> %s', f, dst_dir)
            shutil.copy2(f, dst_dir)
