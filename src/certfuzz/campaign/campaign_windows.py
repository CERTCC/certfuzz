'''
Created on Jan 10, 2014

@author: adh
'''
import logging
import sys
import os
from threading import Timer
import platform
import gc

from certfuzz.campaign.campaign_base import CampaignBase
from certfuzz.campaign.config.config_windows import Config
from certfuzz.runners.killableprocess import Popen
from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.iteration.iteration_windows import Iteration
from certfuzz.fuzzers.errors import FuzzerExhaustedError

logger = logging.getLogger(__name__)

packages = {'fuzzers': 'certfuzz.fuzzers',
            'runners': 'certfuzz.runners',
            'debuggers': 'certfuzz.debuggers',
            }


class WindowsCampaign(CampaignBase):
    '''
    Extends CampaignBase to add windows-specific features like ButtonClicker
    '''
    def __init__(self, config_file, result_dir=None, debug=False):
        CampaignBase.__init__(self, config_file, result_dir, debug)

        self.gui_app = False

        #read configs
        logger.info('Reading config from %s', self.config_file)
        cfgobj = Config(self.config_file)
        self.config = cfgobj.config
        if self.config is None:
            raise WindowsCampaignError('Config load failed, exiting')
        self.configdate = cfgobj.configdate

        # pull stuff out of configs
        self.campaign_id = self.config['campaign']['id']

        self.use_buttonclicker = self.config['campaign'].get('use_buttonclicker')
        if not self.use_buttonclicker:
            self.use_buttonclicker = False

        self.current_seed = self.config['runoptions'].get('first_iteration')
        self.seed_interval = self.config['runoptions'].get('seed_interval')

        if self.outdir_base is None:
            # it wasn't spec'ed on the command line so use the config
            self.outdir_base = os.path.abspath(self.config['directories']['results_dir'])

        self.work_dir_base = os.path.abspath(self.config['directories']['working_dir'])

        self.seed_dir_in = self.config['directories']['seedfile_dir']

        self.keep_duplicates = self.config['runoptions']['keep_all_duplicates']
        self.keep_heisenbugs = self.config['campaign']['keep_heisenbugs']
        self.should_keep_u_faddr = self.config['runoptions']['keep_unique_faddr']

        self.program = self.config['target']['program']
        self.cmd_template = self.config['target']['cmdline_template']

        self.fuzzer_module_name = '%s.%s' % (packages['fuzzers'], self.config['fuzzer']['fuzzer'])
        if self.config['runner']['runner']:
            self.runner_module_name = '%s.%s' % (packages['runners'], self.config['runner']['runner'])
        self.debugger_module_name = '%s.%s' % (packages['debuggers'], self.config['debugger']['debugger'])

        # must occur after work_dir_base, outdir_base, and campaign_id are set
        self._common_init()

    def __getstate__(self):
        state = self.__dict__.copy()

        state['crashes_seen'] = list(state['crashes_seen'])
        if state['seedfile_set']:
            state['seedfile_set'] = state['seedfile_set'].__getstate__()

        # for attributes that are modules,
        # we can safely delete them as they will be
        # reconstituted when we __enter__ a context
        for key in ['fuzzer_module', 'fuzzer',
                    'runner_module', 'runner',
                    'debugger_module', 'dbg_class'
                    ]:
            if key in state:
                del state[key]
        return state

    def __setstate__(self, state):
        # turn the list into a set
        state['crashes_seen'] = set(state['crashes_seen'])

        # reconstitute the seedfile set
        with SeedfileSet(state['campaign_id'], state['seed_dir_in'], state['seed_dir_local'],
                         state['sf_set_out']) as sfset:
            new_sfset = sfset

        new_sfset.__setstate__(state['seedfile_set'])
        state['seedfile_set'] = new_sfset

        # update yourself
        self.__dict__.update(state)

    def _pre_enter(self):
        if sys.platform == 'win32':
            winver = sys.getwindowsversion().major
            machine = platform.machine()
            hook_incompat = winver > 5 or machine == 'AMD64'
            if hook_incompat and self.runner_module_name == 'certfuzz.runners.winrun':
                logger.debug('winrun is not compatible with Windows %s %s. Overriding.', winver, machine)
                self.runner_module_name = None

    def _post_enter(self):
        self._start_buttonclicker()
        self._cache_app()

    def _pre_exit(self):
        self._stop_buttonclicker()

    def _cache_app(self):
        logger.debug('Caching application %s and determining if we need to watch the CPU...', self.program)
        targetdir = os.path.dirname(self.program)
        # Use overriden Popen that uses a job object to make sure that
        # child processes are killed
        p = Popen(self.program, cwd=targetdir)
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
            debugger_watchcpu = str(self.config['debugger']['watchcpu']).lower()
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

    def kill(self, p):
        # The app didn't complete within the timeout.  Assume it's a GUI app
        logger.debug('This seems to be a GUI application.')
        self.gui_app = True
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = str(self.config['debugger']['watchcpu']).lower()
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

    def _do_interval(self):
        # choose seedfile
        sf = self.seedfile_set.next_item()

        logger.info('Selected seedfile: %s', sf.basename)
        rng_seed = int(sf.md5, 16)

        if self.current_seed % self.status_interval == 0:
            # cache our current state
            self._save_state()

        interval_limit = self.current_seed + self.seed_interval

        # start an iteration interval
        # note that range does not include interval_limit
        logger.debug('Starting interval %d-%d', self.current_seed, interval_limit)
        for seednum in xrange(self.current_seed, interval_limit):
            self._do_iteration(sf, rng_seed, seednum)

        del sf
        # manually collect garbage
        gc.collect()

        self.current_seed = interval_limit
        self.first_chunk = False

    def _do_iteration(self, sf, rng_seed, seednum):
        # use a with...as to ensure we always hit
        # the __enter__ and __exit__ methods of the
        # newly created Iteration()
        with Iteration(sf, rng_seed, seednum, self.config, self.fuzzer,
                     self.runner, self.debugger_module, self.dbg_class,
                     self.keep_heisenbugs, self.keep_duplicates,
                     self.cmd_template, self._crash_is_unique,
                     self.working_dir, self.outdir, self.debug) as iteration:
            try:
                iteration.go()
            except FuzzerExhaustedError:
                # Some fuzzers run out of things to do. They should
                # raise a FuzzerExhaustedError when that happens.
                logger.info('Done with %s, removing from set', sf.basename)
                # FIXME
                # self.seedfile_set.del_item(sf.md5)
        if not seednum % self.status_interval:
            logger.info('Iteration: %d Crashes found: %d', self.current_seed,
                        len(self.crashes_seen))
            # FIXME
            # self.seedfile_set.update_csv()
            logger.info('Seedfile Set Status:')
            logger.info('FIXME')
            # for k, score, successes, tries, p in self.seedfile_set.status():
            #    logger.info('%s %0.6f %d %d %0.6f', k, score, successes,
            #                tries, p)

    def _set_fuzzer(self):
        CampaignBase._set_fuzzer(self)

    def _set_runner(self):
        CampaignBase._set_runner(self)

    def _set_debugger(self):
        CampaignBase._set_debugger(self)
