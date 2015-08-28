'''
Created on Apr 21, 2011

@organization: cert.org
'''
import logging
import os
import platform
import shutil
import tempfile

from certfuzz.fuzztools.filetools import delete_contents_of


logger = logging.getLogger(__name__)


class TmpReaper(object):
    '''
    classdocs
    '''
    def __init__(self):
        '''
        Constructor
        '''
        logger.debug('Reaping tmp...')
        self.tmp_dir = tempfile.gettempdir()
        if platform.system() == 'Windows':
            self.clean_tmp = self.clean_tmp_windows
        else:
            self.clean_tmp = self.clean_tmp_unix

    def clean_tmp_windows(self, extras=[]):
        '''
        Removes as many of the contents of tmpdir as possible. Logs skipped
        files but otherwise won't block on the failure to delete something.
        '''
        paths_to_clear = set(extras)
        paths_to_clear.add(self.tmp_dir)
        skipped = delete_contents_of(paths_to_clear)
        for (skipped_item, reason) in skipped:
            logger.debug('Failed to delete %s: %s', skipped_item, reason)

    def clean_tmp_unix(self, extras=[]):
        '''
        Starts at the top level of tmpdir and deletes files, directories
        and symlinks owned by the same uid as the current process.
        '''
        my_uid = os.getuid()

        for basename in os.listdir(self.tmp_dir):
            path = os.path.join(self.tmp_dir, basename)
            try:
                if os.path.islink(path):
                    path_uid = os.lstat(path).st_uid
                else:
                    path_uid = os.stat(path).st_uid
                if my_uid == path_uid:
                    if os.path.isfile(path):
                        os.remove(path)
                    elif os.path.islink(path):
                        os.unlink(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path)
            except (IOError, OSError):
                # we don't mind these exceptions as they're usually indicative
                # of a file that got deleted before we could do the same
                continue
