'''
Created on Jan 10, 2014

@author: adh
'''
import logging
import os
import platform
import sys
import time
from threading import Timer


from certfuzz.campaign.campaign_base import CampaignBase
from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.fuzzers.errors import FuzzerExhaustedError
from certfuzz.iteration.iteration_windows import WindowsIteration
from certfuzz.runners.killableprocess import Popen
from certfuzz.fuzztools.command_line_templating import get_command_args_list


logger = logging.getLogger(__name__)


class WindowsCampaign(CampaignBase):
    '''
    Extends CampaignBase to add windows-specific features like ButtonClicker
    '''

    def __init__(self, config_file, result_dir=None, debug=False):
        CampaignBase.__init__(self, config_file, result_dir, debug)
        self.use_buttonclicker = self.config['campaign'].get('use_buttonclicker', False)
        self.runner_module_name = 'certfuzz.runners.winrun'
        self.debugger_module_name = 'certfuzz.debuggers.gdb'

    def __getstate__(self):
        state = self.__dict__.copy()

        state['testcases_seen'] = list(state['testcases_seen'])
        if state['seedfile_set']:
            state['seedfile_set'] = state['seedfile_set'].__getstate__()

        # for attributes that are modules,
        # we can safely delete them as they will be
        # reconstituted when we __enter__ a context
        for key in ['fuzzer_module', 'fuzzer_cls',
                    'runner_module', 'runner_cls',
                    'debugger_module'
                    ]:
            if key in state:
                del state[key]
        return state

    def __setstate__(self, state):
        # turn the list into a set
        state['testcases_seen'] = set(state['testcases_seen'])

        # reconstitute the seedfile set
        with SeedfileSet(state['campaign_id'], state['seed_dir_in'], state['seed_dir_local'],
                         state['sf_set_out']) as sfset:
            new_sfset = sfset

        new_sfset.__setstate__(state['seedfile_set'])
        state['seedfile_set'] = new_sfset

        # update yourself
        self.__dict__.update(state)

    def _pre_enter(self):
        # check to see if the platform supports winrun
        # set runner module to none otherwise

        if sys.platform != 'win32':
            return

        if not self.runner_module_name == 'certfuzz.runners.winrun':
            return

        # if we got here, we're on win32, and trying to use winrun
        winver = sys.getwindowsversion().major
        machine = platform.machine()
        hook_incompatible = winver > 5 or machine == 'AMD64'

        if not hook_incompatible:
            return

        logger.debug('winrun is not compatible with Windows %s %s. Overriding.', winver, machine)
        self.runner_module_name = 'certfuzz.runners.nullrun'

    def _post_enter(self):
        self._start_buttonclicker()
        self._cache_app()

    def _pre_exit(self):
        self._stop_buttonclicker()

    def _cache_app(self):
        logger.debug('Caching application %s and determining if we need to watch the CPU...', self.program)
        sf = self.seedfile_set.next_item()
        targetdir = os.path.dirname(self.program)
        cmdargs = get_command_args_list(self.config['target']['cmdline_template'], infile=sf.path)[1]
        logger.info('Invoking %s' % cmdargs)

        # Use overriden Popen that uses a job object to make sure that
        # child processes are killed
        p = Popen(cmdargs, cwd=targetdir)
        runtimeout = self.config['runner']['runtimeout']
        logger.debug('...Timer: %f', runtimeout)
        t = Timer(runtimeout, self.kill, args=[p])
        logger.debug('...timer start')
        t.start()
        p.wait()
        logger.debug('...timer stop')
        t.cancel()
        if not self.gui_app:
            logger.debug('This seems to be a CLI application.')
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = runner_watchcpu
        except KeyError:
            self.config['runner']['watchcpu'] = 'auto'
            self.config['debugger']['watchcpu'] = 'auto'
            runner_watchcpu = 'auto'
            debugger_watchcpu = 'auto'
        if runner_watchcpu == 'auto':
            logger.debug('Disabling runner CPU monitoring for dynamic timeout')
            self.config['runner']['watchcpu'] = False
        if debugger_watchcpu == 'auto':
            logger.debug('Disabling debugger CPU monitoring for dynamic timeout')
            self.config['debugger']['watchcpu'] = False

        logger.info('Please ensure that the target program has just executed successfully')
        time.sleep(10)

    def kill(self, p):
        # The app didn't complete within the timeout.  Assume it's a GUI app
        logger.debug('This seems to be a GUI application.')
        self.gui_app = True
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = runner_watchcpu
        except KeyError:
            self.config['runner']['watchcpu'] = 'auto'
            self.config['debugger']['watchcpu'] = 'auto'
            runner_watchcpu = 'auto'
            debugger_watchcpu = 'auto'
        if runner_watchcpu == 'auto':
            logger.debug('Enabling runner CPU monitoring for dynamic timeout')
            self.config['runner']['watchcpu'] = True
            logger.debug('kill runner watchcpu: %s', self.config['runner']['watchcpu'])
        if debugger_watchcpu == 'auto':
            logger.debug('Enabling debugger CPU monitoring for dynamic timeout')
            self.config['debugger']['watchcpu'] = True
            logger.debug('kill debugger watchcpu: %s', self.config['debugger']['watchcpu'])
        logger.debug('kill %s', p)
        p.kill()

    def _start_buttonclicker(self):
        if self.use_buttonclicker:
            rootpath = os.path.dirname(sys.argv[0])
            buttonclicker = os.path.join(rootpath, 'buttonclicker', 'buttonclicker.exe')
            os.startfile(buttonclicker)  # @UndefinedVariable

    def _stop_buttonclicker(self):
        if self.use_buttonclicker:
            os.system('taskkill /im buttonclicker.exe')

    def _do_iteration(self, seedfile, range_obj, seednum):
        # use a with...as to ensure we always hit
        # the __enter__ and __exit__ methods of the
        # newly created WindowsIteration()
        with WindowsIteration(seedfile=seedfile,
                              seednum=seednum,
                              workdirbase=self.working_dir,
                              outdir=self.outdir,
                              sf_set=self.seedfile_set,
                              uniq_func=self._testcase_is_unique,
                              config=self.config,
                              fuzzer_cls=self.fuzzer_cls,
                              runner_cls=self.runner_cls,
                              cmd_template=self.cmd_template,
                              debug=self.debug,
                              ) as iteration:
            try:
                iteration()
            except FuzzerExhaustedError:
                # Some fuzzers run out of things to do. They should
                # raise a FuzzerExhaustedError when that happens.
                logger.info('Done with %s, removing from set', seedfile.basename)
                self.seedfile_set.remove_file(seedfile)

        if not seednum % self.status_interval:
            logger.info('Iteration: %d testcases found: %d', self.current_seed,
                        len(self.testcases_seen))
            # FIXME
            # self.seedfile_set.update_csv()
            logger.info('Seedfile Set Status:')
            logger.info('FIXME')
            # for k, score, successes, tries, p in self.seedfile_set.status():
            #    logger.info('%s %0.6f %d %d %0.6f', k, score, successes,
            #                tries, p)
