'''
Created on Apr 12, 2011

@organization: cert.org
'''
import logging
import os

from certfuzz.file_handlers.directory import Directory
from certfuzz.file_handlers.errors import SeedFileError, SeedfileSetError
from certfuzz.file_handlers.seedfile import SeedFile
from certfuzz.fuzztools import filetools

# Using a generic name here so we can easily swap out other MAB
# implementations if we want to
from certfuzz.scoring.multiarmed_bandit.bayesian_bandit import BayesianMultiArmedBandit as MultiArmedBandit

logger = logging.getLogger(__name__)


class SeedfileSet(MultiArmedBandit):
    '''
    classdocs
    '''

    def __init__(self, campaign_id=None, originpath=None, localpath=None,
                 outputpath='.', logfile=None):
        '''
        Constructor
        '''
        MultiArmedBandit.__init__(self)
#         self.campaign_id = campaign_id
        self.seedfile_output_base_dir = outputpath

        self.originpath = originpath
        self.localpath = localpath
        # TODO: merge self.outputpath with self.seedfile_output_base_dir
        self.outputpath = outputpath

        self.origindir = None
        self.localdir = None
        self.outputdir = None

        if logfile:
            hdlr = logging.FileHandler(logfile)
            logger.addHandler(hdlr)

        logger.debug(
            'SeedfileSet output_dir: %s', self.seedfile_output_base_dir)

    def __enter__(self):
        self._setup()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _setup(self):
        self._set_directories()
        self._copy_files_to_localdir()
        self._add_local_files_to_set()

    def _set_directories(self):
        if self.originpath:
            self.origindir = Directory(self.originpath)
        if self.localpath:
            self.localdir = Directory(self.localpath, create=True)
        if self.outputpath:
            self.outputdir = Directory(self.outputpath, create=True)

    def _copy_files_to_localdir(self):
        for f in self.origindir:
            self.copy_file_from_origin(f)

    def _add_local_files_to_set(self):
        self.localdir.refresh()
        files_to_add = [f.path for f in self.localdir]
        self.add_file(*files_to_add)

    def add_file(self, *files):
        for f in files:
            try:
                seedfile = SeedFile(self.seedfile_output_base_dir, f)
            except SeedFileError:
                logger.warning('Skipping empty file %s', f)
                continue
            logger.info('Adding file to set: %s', seedfile.path)
            self.add_item(seedfile.md5, seedfile)

    def remove_file(self, seedfile):
        logger.info('Removing file from set: %s', seedfile.basename)
        self.del_item(seedfile.md5)

    def copy_file_from_origin(self, f):
        if (os.path.basename(f.path) == '.DS_Store'):
            return 0

        # convert the local filenames from <foo>.<ext> to <md5>.<ext>
        basename = 'sf_' + f.md5 + f.ext
        targets = [os.path.join(d, basename)
                   for d in (self.localpath, self.outputpath)]
        filetools.copy_file(f.path, *targets)
        for target in targets:
            filetools.make_writable(target)

    def paths(self):
        for x in list(self.things.values()):
            yield x.path

    def next_item(self):
        '''
        Returns a seedfile object selected per the scorable_set object.
        Verifies that the seedfile exists, and removes any nonexistent
        seedfiles from the set
        '''
        if not len(self.things):
            raise SeedfileSetError

        while len(self.things):
            logger.debug('Thing count: %d', len(self.things))
            # continue until we find one that exists, or else the set is empty
            sf = MultiArmedBandit.next(self)
            if sf.exists():
                # it's still there, proceed
                return sf
            else:
                # it doesn't exist, remove it from the set
                logger.warning(
                    'Seedfile no longer exists, removing from set: %s', sf.path)
                self.del_item(sf.md5)
