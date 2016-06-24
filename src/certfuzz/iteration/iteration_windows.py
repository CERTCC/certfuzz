'''
Created on Mar 2, 2012

@author: adh
'''
import glob
import logging
import os

from certfuzz.testcase.testcase_windows import WindowsTestcase
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.file_handlers.tmp_reaper import TmpReaper
from certfuzz.fuzztools.filetools import delete_files_or_dirs
from certfuzz.iteration.iteration_base import IterationBase
from certfuzz.tc_pipeline.tc_pipeline_windows import WindowsTestCasePipeline
from certfuzz.fuzztools.command_line_templating import get_command_args_list


# from certfuzz.iteration.iteration_base import IterationBase2
logger = logging.getLogger(__name__)


class WindowsIteration(IterationBase):
    tcpipeline_cls = WindowsTestCasePipeline

    def __init__(self,
                 seedfile=None,
                 seednum=None,
                 workdirbase=None,
                 outdir=None,
                 sf_set=None,
                 uniq_func=None,
                 config=None,
                 fuzzer_cls=None,
                 runner_cls=None,
                 debug=False,
                 ):
        IterationBase.__init__(self,
                               seedfile=seedfile,
                               seednum=seednum,
                               workdirbase=workdirbase,
                               outdir=outdir,
                               sf_set=sf_set,
                               uniq_func=uniq_func,
                               config=config,
                               fuzzer_cls=fuzzer_cls,
                               runner_cls=runner_cls,
                               )

        self.debug = debug
        # TODO: do we use keep_uniq_faddr at all?
        self.keep_uniq_faddr = config['runoptions'].get(
            'keep_unique_faddr', False)

        if self.runner_cls.is_nullrunner:
            # null runner_cls case
            self.retries = 0
        else:
            # runner_cls is not null
            self.retries = 4

        self.pipeline_options.update({'keep_duplicates': self.cfg['runoptions'].get('keep_duplicates', False),
                                      'keep_heisenbugs': self.cfg['campaign'].get('keep_heisenbugs', False),
                                      'cmd_template': self.cfg['target']['cmdline_template'],
                                      'null_runner': self.runner_cls.is_nullrunner,
                                      })

        # Windows testcase object needs a timeout, and we only pass debugger
        # options
        self.cfg['debugger']['runtimeout'] = self.cfg['runner']['runtimeout']

    def __exit__(self, etype, value, traceback):
        try:
            handled = IterationBase.__exit__(self, etype, value, traceback)
        except WindowsError as e:
            logger.warning('Caught WindowsError in iteration exit: %s', e)
            handled = True

        if etype and not handled:
            logger.warning(
                'WindowsIteration terminating abnormally due to %s: %s',
                etype.__name__,
                value
            )
            if self.debug:
                # don't clean up if we're in debug mode and have an unhandled
                # exception
                logger.debug('Skipping cleanup since we are in debug mode.')
                return handled

        self._tidy()
        return handled

    def _tidy(self):
        # wrap up this iteration
        paths = []
        # sweep up any iteration temp dirs left behind previously
        pattern = os.path.join(self.workdirbase, self._tmpdir_pfx + '*')
        paths.extend(glob.glob(pattern))
        delete_files_or_dirs(paths)
        # wipe them out, all of them
        TmpReaper().clean_tmp()

    def _construct_testcase(self):
        with WindowsTestcase(seedfile=self.seedfile,
                             fuzzedfile=BasicFile(
                                 self.fuzzer.output_file_path),
                             program=self.cfg['target']['program'],
                             cmd_template=self.cmd_template,
                             debugger_timeout=self.cfg[
                                 'runner']['runtimeout'],
                             cmdlist=get_command_args_list(
                                 self.cmd_template, self.fuzzer.output_file_path)[1],
                             dbg_opts=self.cfg['debugger'],
                             workdir_base=self.working_dir,
                             keep_faddr=self.cfg['runoptions'].get(
                                 'keep_unique_faddr', False),
                             heisenbug_retries=self.retries,
                             copy_fuzzedfile=self.fuzzer.fuzzed_changes_input) as testcase:

            # put it on the list for the analysis pipeline
            self.testcases.append(testcase)
