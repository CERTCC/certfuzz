'''
Created on Oct 11, 2012

@organization: cert.org
'''
import logging
import os
import tempfile

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools import filetools, hamming
from certfuzz.fuzztools.filetools import check_zip_file, mkdir_p
from certfuzz.fuzztools.command_line_templating import get_command_args_list
from pprint import pformat


logger = logging.getLogger(__name__)


class TestCaseBase(object):
    '''
    A BFF test case represents everything we know about a fuzzer finding.
    '''
    _tmp_sfx = ''
    _tmp_pfx = 'BFF_testcase_'
    _debugger_cls = None

    def __init__(self,
                 cfg,
                 seedfile,
                 fuzzedfile,
                 program,
                 cmd_template,
                 workdir_base,
                 cmdlist,
                 keep_faddr=False,
                 dbg_timeout=30):

        logger.debug('Inititalize TestCaseBase')

        self.cfg = cfg
        self.cmd_template = cmd_template
        self.cmdlist = cmdlist
        self.copy_fuzzedfile = True
        self.dbg_file = None
        self.dbg_files = {}
        self.debugger_missed_stack_corruption = False
        self.debugger_template = None
        self.debugger_timeout = dbg_timeout
        # Exploitability is UNKNOWN unless proven otherwise
        self.exp = 'UNKNOWN'
        self.hd_bits = None
        self.hd_bytes = None
        self.faddr = None
        self.fuzzedfile = fuzzedfile
        self.is_corrupt_stack = False
        # Not a crash until we're sure
        self.is_crash = False
        # All crashes are heisenbugs until proven otherwise
        self.is_heisenbug = True
        self.is_unique = False
        self.is_zipfile = False
        self.keep_uniq_faddr = keep_faddr
        self.pc = None
        self.pc_in_function = False
        self.program = program
        self.target_dir = None
        self.seedfile = seedfile
        self.should_proceed_with_analysis = False
        self.signature = None
        self.total_stack_corruption = False
        self.workdir_base = workdir_base
        self.working_dir = None

    def __enter__(self):
        mkdir_p(self.workdir_base)
        self.update_crash_details()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def __repr__(self):
        return pformat(self.__dict__)

    def _get_output_dir(self, *args):
        raise NotImplementedError

    def _rename_dbg_files(self):
        raise NotImplementedError

    def _rename_fuzzed_file(self):
        raise NotImplementedError

    def _set_attr_from_dbg(self, attrname):
        raise NotImplementedError

    def _verify_crash_base_dir(self):
        raise NotImplementedError

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

        # TODO: This seems hacky. Should be better way to have
        # minimizer_log.txt and core files survive update_crash_details
        minlog = os.path.join(self.fuzzedfile.dirname, 'minimizer_log.txt')
        if os.path.exists(minlog):
            filetools.copy_file(minlog, self.tempdir)

        corefile = os.path.join(self.workdir_base, 'core')
        if os.path.exists(corefile):
            filetools.copy_file(corefile, self.tempdir)

        calltracefile = os.path.join(
            self.fuzzedfile.dirname, '%s.calltrace' % self.fuzzedfile.basename)
        if os.path.exists(calltracefile):
            filetools.copy_file(calltracefile, self.tempdir)

        new_fuzzedfile = os.path.join(self.tempdir, self.fuzzedfile.basename)
        self.fuzzedfile = BasicFile(new_fuzzedfile)

    def copy_files(self, outdir):
        crash_files = os.listdir(self.tempdir)
        for f in crash_files:
            filepath = os.path.join(self.tempdir, f)
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

    def get_signature(self):
        raise NotImplementedError

    def set_debugger_template(self, *args):
        pass

    def update_crash_details(self):
        # We might be updating crash details because we have a new fuzzedfile
        # (with a different path)
        self.cmdlist = get_command_args_list(
            self.cmd_template, infile=self.fuzzedfile.path)[1]
        self.cmdargs = self.cmdlist[1:]
        self.tempdir = tempfile.mkdtemp(
            prefix=self._tmp_pfx, suffix=self._tmp_sfx, dir=self.workdir_base)
        self.copy_files_to_temp()

#        raise NotImplementedError
    def calculate_hamming_distances(self):
        # If the fuzzed file is a valid zip, then we're fuzzing zip contents,
        # not the container
        self.is_zipfile = check_zip_file(self.fuzzedfile.path)
        try:
            if self.is_zipfile:
                self.hd_bits = hamming.bitwise_zip_hamming_distance(
                    self.seedfile.path, self.fuzzedfile.path)
                self.hd_bytes = hamming.bytewise_zip_hamming_distance(
                    self.seedfile.path, self.fuzzedfile.path)
            else:
                self.hd_bits = hamming.bitwise_hamming_distance(
                    self.seedfile.path, self.fuzzedfile.path)
                self.hd_bytes = hamming.bytewise_hamming_distance(
                    self.seedfile.path, self.fuzzedfile.path)
        except KeyError:
            # one of the files wasn't defined
            logger.warning(
                'Cannot find either sf_path or minimized file to calculate Hamming Distances')

        logger.info("crasher=%s bitwise_hd=%d", self.signature, self.hd_bits)
        logger.info("crasher=%s bytewise_hd=%d", self.signature, self.hd_bytes)

    def calculate_hamming_distances_a(self):
        with open(self.fuzzedfile.path, 'rb') as fd:
            fuzzed = fd.read()

        a_string = 'x' * len(fuzzed)

        self.hd_bits = hamming.bitwise_hd(a_string, fuzzed)
        logger.info("crasher=%s bitwise_hd=%d", self.signature, self.hd_bits)

        self.hd_bytes = hamming.bytewise_hd(a_string, fuzzed)
        logger.info(
            "crasher=%s bytewise_hd=%d", self.signature, self.hd_bytes)
