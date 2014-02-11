'''
Created on Feb 11, 2014

@author: adh
'''
import logging
from ..build_base2 import Build

logger = logging.getLogger(__name__)


class LinuxBuild(Build):
    def package(self):
        '''
        Creates a zip file containing the code
        '''
        Build.package(self)

        tmpzip = self._create_zip()
        self._move_to_target(tmpzip)
