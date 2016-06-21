'''
Created on Feb 9, 2012

@organization: cert.org
'''
import hashlib
import logging
import os

from certfuzz.testcase.testcase_base import TestCaseBase
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools.filetools import best_effort_move
from certfuzz.helpers.misc import random_str
from certfuzz.debuggers.msec import MsecDebugger
from certfuzz.fuzztools.command_line_templating import get_command_args_list


logger = logging.getLogger(__name__)


def logerror(func, path, excinfo):
    logger.warning('%s failed to remove %s: %s', func, path, excinfo)

short_exp = {
    'UNKNOWN': 'UNK',
    'PROBABLY_NOT_EXPLOITABLE': 'PNE',
    'PROBABLY_EXPLOITABLE': 'PEX',
    'EXPLOITABLE': 'EXP',
    'HEISENBUG': 'HSB',
}

exp_rank = {
    'EXPLOITABLE': 1,
    'PROBABLY_EXPLOITABLE': 2,
    'UNKNOWN': 3,
    'PROBABLY_NOT_EXPLOITABLE': 4,
    'HEISENBUG': 5,
}


class WindowsTestcase(TestCaseBase):
    _debugger_cls = MsecDebugger

    # TODO: do we still need fuzzer as an arg?
    def __init__(self, cmd_template, seedfile, fuzzedfile, cmdlist, fuzzer,
                 dbg_opts, workingdir_base, keep_faddr, program,
                 heisenbug_retries=4, copy_fuzzedfile=True):

        dbg_timeout = dbg_opts['runtimeout']

        TestCaseBase.__init__(self, seedfile, fuzzedfile, dbg_timeout)

        self.dbg_opts = dbg_opts
        self.copy_fuzzedfile = copy_fuzzedfile

        self.cmdargs = cmdlist
        self.workdir_base = workingdir_base

        self.keep_uniq_faddr = keep_faddr
        self.program = program
        self.dbg_result = {}
        self.crash_hash = None
        self.result_dir = None
        self.faddr = None
        self.dbg_file = ''
        self.cmd_template = cmd_template
        try:
            self.max_handled_exceptions = self.dbg_opts[
                'max_handled_exceptions']
        except KeyError:
            self.max_handled_exceptions = 6
        try:
            self.watchcpu = self.dbg_opts['watchcpu']
        except KeyError:
            self.watchcpu = False
        self.exception_depth = 0
        self.reached_secondchance = False
        self.parsed_outputs = []

        self.max_depth = heisenbug_retries

    def _get_file_basename(self):
        '''
        If self.copy_fuzzedfile is set, indicating that the fuzzer modifies the
        seedfile, then return the fuzzedfile basename. Otherwise return the
        seedfile basename.
        '''
        if self.copy_fuzzedfile:
            return self.fuzzedfile.basename
        return self.seedfile.basename

    def update_crash_details(self):
        '''
        Resets various properties of the crash object and regenerates crash data
        as needed. Used in both object runtime context and for refresh after
        a crash object is copied.
        '''
        TestCaseBase.update_crash_details(self)
        # Reset properties that need to be regenerated
        self.exception_depth = 0
        self.parsed_outputs = []
        self.exp = None
        fname = self._get_file_basename()
        outfile_base = os.path.join(self.tempdir, fname)
        # Regenerate target commandline with new crasher file

        cmdlist = get_command_args_list(self.cmd_template,
                                        outfile_base)[1]
        self.cmdargs = cmdlist[1:]
        self.debug()
        self._rename_fuzzed_file()
        self._rename_dbg_file()

    def debug_once(self):
        outfile_base = os.path.join(self.tempdir, self.fuzzedfile.basename)

        with self._debugger_cls(program=self.program, cmd_args=self.cmdargs, outfile_base=outfile_base, timeout=self.debugger_timeout, exception_depth=self.exception_depth, workingdir=self.tempdir, watchcpu=self.watchcpu) as debugger:
            self.parsed_outputs.append(debugger.go())

        self.reached_secondchance = self.parsed_outputs[
            self.exception_depth].secondchance

        if self.reached_secondchance and self.exception_depth > 0:
            # No need to process second-chance exception
            # Note that some exceptions, such as Illegal Instructions have no first-chance:
            # In those cases, proceed...
            return

        # Store highest exploitability of every exception in the chain
        current_exception_exp = self.parsed_outputs[self.exception_depth].exp
        if current_exception_exp:
            if not self.exp:
                self.exp = current_exception_exp
            elif exp_rank[current_exception_exp] < exp_rank[self.exp]:
                self.exp = current_exception_exp

        current_exception_hash = self.parsed_outputs[
            self.exception_depth].crash_hash
        current_exception_faddr = self.parsed_outputs[
            self.exception_depth].faddr
        if current_exception_hash:
            # We have a hash for the current exception
            if self.exception_depth == 0:
                # First exception - start exception hash chain from scratch
                self.crash_hash = current_exception_hash
            elif self.crash_hash:
                # Append to the exception hash chain
                self.crash_hash = self.crash_hash + \
                    '_' + current_exception_hash

            if self.keep_uniq_faddr and current_exception_faddr:
                self.crash_hash += '.' + current_exception_faddr

        # The first exception is the one that is representative for the crasher
        if self.exception_depth == 0:
            self.dbg_file = debugger.outfile
            # add debugger results to our own attributes
            self.is_crash = self.parsed_outputs[0].is_crash
            self.dbg_type = self.parsed_outputs[0]._key
            # self.exp = self.parsed_outputs[0].exp
            self.faddr = self.parsed_outputs[0].faddr
            # self.crash_hash = self.parsed_outputs[0].crash_hash

    def get_signature(self):
        self.signature = self.crash_hash
        return self.crash_hash

    def debug(self, tries_remaining=None):
        if tries_remaining is None:
            tries_remaining = self.max_depth

        logger.debug("tries left: %d", tries_remaining)
        self.debug_once()

        if self.is_crash:
            self.is_heisenbug = False

            logger.debug("checking for handled exceptions...")
            while self.exception_depth < self.max_handled_exceptions:
                self.exception_depth += 1
                self.debug_once()
                if self.reached_secondchance or not self.parsed_outputs[self.exception_depth].is_crash:
                    logger.debug("no more handled exceptions")
                    break
            # get the signature now that we've got all of the exceptions
            self.get_signature()
        else:
            # if we are still a heisenbug after debugging
            # we might need to try again
            # or give up if we've tried enough already
            if tries_remaining:
                # keep diving
                logger.debug(
                    "possible heisenbug (%d tries left)", tries_remaining)
                self.debug(tries_remaining - 1)
            else:
                # we're at the bottom
                self._set_heisenbug_properties()
                logger.debug("heisenbug found")

    def _set_heisenbug_properties(self):
        self.exp = 'HEISENBUG'
        try:
            fuzzed_content = self.fuzzedfile.read()
        except Exception, e:
            # for whatever reason we couldn't get the real content,
            # and since we're just generating a string here
            # any string will do
            logger.warning(
                'Unable to get md5 of %s, using random string for heisenbug signature: %s', self.fuzzedfile.path, e)
            fuzzed_content = random_str(64)
        self.is_heisenbug = True
        self.signature = hashlib.md5(fuzzed_content).hexdigest()

    def _get_output_dir(self, target_base):
        logger.debug('target_base: %s', target_base)
        logger.debug('signature: %s', self.signature)

        self.target_dir = os.path.join(target_base, 'crashers', self.signature)
        if len(self.target_dir) > 130:
            # Don't make a path too deep.  Windows won't support it
            self.target_dir = self.target_dir[:130] + '__'
        logger.debug('target_dir: %s', self.target_dir)
        return self.target_dir

    def _rename_fuzzed_file(self):
        if not self.faddr:
            return

        logger.debug('Attempting to rename %s', self.fuzzedfile.path)
        new_basename = '%s-%s%s' % (self.fuzzedfile.root,
                                    self.faddr, self.fuzzedfile.ext)
        new_fuzzed_file = os.path.join(self.fuzzedfile.dirname, new_basename)
        logger.debug(
            'renaming %s -> %s', self.fuzzedfile.path, new_fuzzed_file)

        # best_effort move returns a tuple of booleans indicating (copied, deleted)
        # we only care about copied
        copied = best_effort_move(self.fuzzedfile.path, new_fuzzed_file)[0]

        if copied:
            # replace fuzzed file
            self.fuzzedfile = BasicFile(new_fuzzed_file)

    def _rename_dbg_file(self):
        if not self.faddr:
            return

        (path, basename) = os.path.split(self.dbg_file)
        (basename, dbgext) = os.path.splitext(basename)
        (root, ext) = os.path.splitext(basename)
        for exception_num in range(0, self.exception_depth + 1):
            if exception_num > 0:
                new_basename = root + ext + '.e%s' % exception_num + dbgext
                self.dbg_file = os.path.join(path, new_basename)

            if not self.parsed_outputs[exception_num].is_crash:
                return

            faddr_str = '%s' % self.parsed_outputs[exception_num].faddr
            exp_str = short_exp[self.parsed_outputs[exception_num].exp]

            parts = [root]
            if faddr_str:
                parts.append(faddr_str)
            if exp_str:
                parts.append(exp_str)
            new_basename = '-'.join(parts) + ext + \
                '.e%s' % exception_num + dbgext

            new_dbg_file = os.path.join(path, new_basename)

            # best_effort move returns a tuple of booleans indicating (copied, deleted)
            # we only care about copied
            copied = best_effort_move(self.dbg_file, new_dbg_file)[0]
            if copied:
                self.dbg_file = new_dbg_file
