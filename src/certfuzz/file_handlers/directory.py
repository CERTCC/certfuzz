'''
Created on Mar 18, 2011

@organization: cert.org
'''
import logging
import os

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.file_handlers.errors import DirectoryError
from certfuzz.fuzztools import filetools


logger = logging.getLogger(__name__)


blocklist = ['.DS_Store', ]


class Directory(object):
    def __init__(self, mydir, create=False):
        self.dir = mydir

        if create and not os.path.isdir(self.dir):
            if not os.path.exists(self.dir) and not os.path.islink(self.dir):
                filetools.make_directories(self.dir)
            else:
                raise DirectoryError('Cannot create dir %s - the path already exists, but is not a dir.' % self.dir)

        self._verify_dir()

        self.files = []
        self.refresh()

    def _verify_dir(self):
        if not os.path.exists(self.dir):
            raise DirectoryError('%s does not exist' % self.dir)
        if not os.path.isdir(self.dir):
            raise DirectoryError('%s is not a dir' % self.dir)

    def refresh(self):
        '''
        Gets all the file paths from self.dir then
        creates corresponding BasicFile objects in self.files
        '''
        self._verify_dir()

        dir_listing = [os.path.join(self.dir, f) for f in os.listdir(self.dir) if not f in blocklist]
        self.files = [BasicFile(path) for path in dir_listing if os.path.isfile(path)]

    def paths(self):
        '''
        Convenience function to get just the paths to the files
        instead of the file objects
        '''
        return [f.path for f in self.files]

    def __iter__(self):
        self.refresh()
        for f in self.files:
            yield f
