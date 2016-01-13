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

    def __init__(self, testcase, target_dir):
        '''
        Constructor
        '''
        ReporterBase.__init__(self, testcase)

        self.target_dir = target_dir

    def go(self):
        dst_dir = os.path.join(self.target_dir, self.testcase.signature)
        # ensure target dir exists already (it might because of crash logging)
        filetools.mkdir_p(dst_dir)

        src_dir = self.testcase.tempdir
        if not os.path.exists(src_dir):
            raise ReporterError('Testcase tempdir not found: %s', src_dir)

        src_paths = [os.path.join(src_dir, f) for f in os.listdir(src_dir)]

        for f in src_paths:
            logger.debug('Copy %s -> %s', f, dst_dir)
            shutil.copy2(f, dst_dir)
