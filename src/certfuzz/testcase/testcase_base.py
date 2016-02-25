'''
Created on Apr 12, 2013

@organization: cert.org
'''
import logging
import shutil
import tempfile

from certfuzz.fuzztools import hamming
from certfuzz.fuzztools.filetools import check_zip_file
from pprint import pformat
import os
from certfuzz.testcase.errors import CrashError


logger = logging.getLogger(__name__)


class TestCaseBase(object):
    _tmp_sfx = ''
    _tmp_pfx = 'BFF_testcase_'

    def __init__(self, seedfile, fuzzedfile, workdir_base=None):
        self.seedfile = seedfile
        self.fuzzedfile = fuzzedfile
        self.workdir_base = workdir_base

        # Exploitability is UNKNOWN unless proven otherwise
        self.exp = 'UNKNOWN'

        self.hd_bits = None
        self.hd_bytes = None
        self.signature = None
        self.working_dir = None
        self.is_zipfile = False

        # this will get overridden by calls to get_logger
        self.logger = logger

    def __enter__(self):
        self._setup_workdir()
        self.calculate_hamming_distances()
        return self

    def __exit__(self, etype, value, traceback):
        self._teardown_workdir()
        return

    def _setup_workdir(self):
        self.working_dir = tempfile.mkdtemp(suffix=self._tmp_sfx,
                                    prefix=self._tmp_pfx,
                                    dir=self.workdir_base)

    def __repr__(self):
        return pformat(self.__dict__)

    def _teardown_workdir(self):
        shutil.rmtree(self.working_dir)
        self.working_dir = None

    def calculate_hamming_distances(self):
        # If the fuzzed file is a valid zip, then we're fuzzing zip contents, not the container
        self.is_zipfile = check_zip_file(self.fuzzedfile.path)
        try:
            if self.is_zipfile:
                self.hd_bits = hamming.bitwise_zip_hamming_distance(self.seedfile.path, self.fuzzedfile.path)
                self.hd_bytes = hamming.bytewise_zip_hamming_distance(self.seedfile.path, self.fuzzedfile.path)
            else:
                self.hd_bits = hamming.bitwise_hamming_distance(self.seedfile.path, self.fuzzedfile.path)
                self.hd_bytes = hamming.bytewise_hamming_distance(self.seedfile.path, self.fuzzedfile.path)
        except KeyError:
            # one of the files wasn't defined
            logger.warning('Cannot find either sf_path or minimized file to calculate Hamming Distances')

        self.logger.info("bitwise_hd=%d", self.hd_bits)
        self.logger.info("bytewise_hd=%d", self.hd_bytes)


    def calculate_hamming_distances_a(self):
        with open(self.fuzzedfile.path, 'rb') as fd:
            fuzzed = fd.read()

        a_string = 'x' * len(fuzzed)

        self.hd_bits = hamming.bitwise_hd(a_string, fuzzed)
        self.logger.info("bitwise_hd=%d", self.hd_bits)

        self.hd_bytes = hamming.bytewise_hd(a_string, fuzzed)
        self.logger.info("bytewise_hd=%d", self.hd_bytes)

    def get_logger(self):
        '''
        sets self.logger to a logger specific to this crash
        '''
        self.logger = logging.getLogger(self.signature)
        if len(self.logger.handlers) == 0:
            if not os.path.exists(self.result_dir):
                logger.error('Result path not found: %s', self.result_dir)
                raise CrashError('Result path not found: {}'.format(self.result_dir))
            logger.debug('result_dir=%s sig=%s', self.result_dir, self.signature)
            logfile = '%s.log' % self.signature
            logger.debug('logfile=%s', logfile)
            logpath = os.path.join(self.result_dir, logfile)
            logger.debug('logpath=%s', logpath)
            hdlr = logging.FileHandler(logpath)
            self.logger.addHandler(hdlr)

        return self.logger

