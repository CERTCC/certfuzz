'''
Created on Oct 11, 2012

@organization: cert.org
'''
import logging
import os
import tempfile

from certfuzz.testcase.errors import CrashError
from certfuzz.testcase.testcase_base import TestCaseBase
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools import filetools


logger = logging.getLogger(__name__)


class Testcase(TestCaseBase):
    tmpdir_pfx = 'crash-'
    _debugger_cls = None

    def __init__(self, seedfile, fuzzedfile, dbg_timeout=30):
        logger.debug('Inititalize Testcase')
        TestCaseBase.__init__(self, seedfile, fuzzedfile)

        self.debugger_timeout = dbg_timeout

        self.debugger_template = None
        # All crashes are heisenbugs until proven otherwise
        self.is_heisenbug = True

        self.workdir_base = tempfile.gettempdir()

        # set some defaults
        # Not a crash until we're sure
        self.is_crash = False
        self.debugger_file = None
        self.is_unique = False
        self.should_proceed_with_analysis = False
        self.is_corrupt_stack = False
        self.copy_fuzzedfile = True
        self.pc = None
        self.logger = None
        self.result_dir = None
        self.debugger_missed_stack_corruption = False
        self.total_stack_corruption = False
        self.pc_in_function = False

    def _create_workdir_base(self):
        # make sure the workdir_base exists
        if not os.path.exists(self.workdir_base):
            filetools.make_directories([self.workdir_base])

    def __enter__(self):
        self._create_workdir_base()
        self.update_crash_details()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _get_output_dir(self, *args):
        raise NotImplementedError

    def _rename_dbg_file(self):
        raise NotImplementedError

    def _rename_fuzzed_file(self):
        raise NotImplementedError

    def _set_attr_from_dbg(self, attrname):
        raise NotImplementedError

    def _verify_crash_base_dir(self):
        raise NotImplementedError

    def calculate_hamming_distances(self):
        TestCaseBase.calculate_hamming_distances(self)
        self.logger.info("bitwise_hd=%d", self.hd_bits)
        self.logger.info("bytewise_hd=%d", self.hd_bytes)

    def calculate_hamming_distances_a(self):
        TestCaseBase.calculate_hamming_distances_a(self)
        self.logger.info("bitwise_hd=%d", self.hd_bits)
        self.logger.info("bytewise_hd=%d", self.hd_bytes)

    def clean_tmpdir(self):
        logger.debug('Cleaning up %s', self.tempdir)
        if os.path.exists(self.tempdir):
            filetools.delete_files_or_dirs([self.tempdir])
        else:
            logger.debug('No tempdir at %s', self.tempdir)

        if os.path.exists(self.tempdir):
            logger.debug('Unable to remove tempdir %s', self.tempdir)

    def confirm_crash(self):
        raise NotImplementedError

    def copy_files_to_temp(self):
        if self.fuzzedfile and self.copy_fuzzedfile:
            filetools.copy_file(self.fuzzedfile.path, self.tempdir)

        if self.seedfile:
            filetools.copy_file(self.seedfile.path, self.tempdir)

        new_fuzzedfile = os.path.join(self.tempdir, self.fuzzedfile.basename)
        self.fuzzedfile = BasicFile(new_fuzzedfile)

    def copy_files(self, outdir):
        crash_files = os.listdir(self.tempdir)
        for file in crash_files:
            filepath = os.path.join(self.tempdir, file)
            if os.path.isfile(filepath):
                filetools.copy_file(filepath, outdir)

    def debug(self, tries_remaining=None):
        raise NotImplementedError

    def debug_once(self):
        raise NotImplementedError

    def delete_files(self):
        if os.path.isdir(self.fuzzedfile.dirname):
            logger.debug('Deleting files from %s', self.fuzzedfile.dirname)
            filetools.delete_files_or_dirs([self.fuzzedfile.dirname])

    def get_debug_output(self, f):
        raise NotImplementedError

    def get_logger(self):
        raise NotImplementedError

    def get_result_dir(self):
        raise NotImplementedError

    def get_signature(self):
        raise NotImplementedError

    def set_debugger_template(self, option='bt_only'):
        raise NotImplementedError

    def update_crash_details(self):
        self.tempdir = tempfile.mkdtemp(prefix=self.tmpdir_pfx, dir=self.workdir_base)
        self.copy_files_to_temp()
#        raise NotImplementedError
