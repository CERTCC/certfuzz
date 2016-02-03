'''
Created on Feb 9, 2012

@organization: cert.org
'''

import abc
import logging
import os
import re
import shutil
import tempfile
import traceback
import cPickle as pickle

from certfuzz.campaign.errors import CampaignError
from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.fuzztools import filetools
from certfuzz.runners.errors import RunnerArchitectureError, \
    RunnerPlatformVersionError
from certfuzz.version import __version__
from certfuzz.file_handlers.tmp_reaper import TmpReaper
import gc
from certfuzz.config.simple_loader import load_and_fix_config
from certfuzz.helpers.misc import import_module_by_name


logger = logging.getLogger(__name__)


class CampaignBase(object):
    '''
    Provides a fuzzing campaign object.
    '''
    __metaclass__ = abc.ABCMeta

    def __init__(self, config_file, result_dir=None, debug=False):
        '''
        Typically one would invoke a campaign as follows:

        with CampaignBase(params) as campaign:
            campaign.go()

        This will ensure that the runtime context is established properly, and
        that any cleanup activities can be completed if exceptions occur.

        @param config_file: path to a config file
        @param result_dir: path to a result directory
        (will be created if necessary)
        @param campaign_cache: path to a cached json object to rebuild an
        existing campaign
        @param debug: boolean indicating whether we are in debug mode
        '''
        logger.debug('initialize %s', self.__class__.__name__)
        # Read the cfg file
        self.config_file = config_file
        self.config = None
        self.cached_state_file = None
        self.debug = debug
        self._version = __version__

        self.crashes_seen = set()

        self.runner_module_name = None
        self.runner_module = None
        self.runner_cls = None

        self.seedfile_set = None
        self.working_dir = None
        self.seed_dir_local = None

        # flag to indicate whether this is a fresh script start up or not
        self.first_chunk = True

        # TODO: consider making this configurable
        self.status_interval = 100
        self.gui_app = False

        self.seed_interval = None
        self.current_seed = None

        self.outdir_base = None
        self.outdir = None
        self.sf_set_out = None
        if result_dir:
            self.outdir_base = os.path.abspath(result_dir)

        self._read_config_file()

        self.campaign_id = self.config['campaign']['id']
       
        self.current_seed = self.config['runoptions']['first_iteration']
        self.seed_interval = self.config['runoptions']['seed_interval']

        self.seed_dir_in = self.config['directories']['seedfile_dir']
        if self.outdir_base is None:
            # it wasn't spec'ed on the command line so use the config
            self.outdir_base = self.config['directories']['results_dir']

        self.work_dir_base = self.config['directories']['working_dir']
        self.program = self.config['target']['program']
        self.cmd_template = self.config['target']['cmdline_template']
        
        _campaign_id_no_space=re.sub('\s', '_', self.campaign_id)
        _campaign_id_with_underscores = re.sub('\W', '_', self.campaign_id)
        
        self.outdir = os.path.join(self.outdir_base, _campaign_id_no_space)
        logger.debug('outdir=%s', self.outdir)

        self.sf_set_out = os.path.join(self.outdir, 'seedfiles')
        if not self.cached_state_file:
            cachefile = 'campaign_%s.pkl' % _campaign_id_with_underscores
            self.cached_state_file = os.path.join(self.work_dir_base, cachefile)
        if not self.seed_interval:
            self.seed_interval = 1
        if not self.current_seed:
            self.current_seed = 0

        self.fuzzer_module_name = 'certfuzz.fuzzers.{}'.format(self.config['fuzzer']['fuzzer'])
        if self.config['runner']['runner']:
            self.runner_module_name = 'certfuzz.runners.{}'.format(self.config['runner']['runner'])
        self.debugger_module_name = 'certfuzz.debuggers.{}'.format(self.config['debugger']['debugger'])

    def _read_config_file(self):
        logger.info('Reading config from %s', self.config_file)
        self.config = load_and_fix_config(self.config_file)
        logger.info('Using target program: %s',self.config['target']['program'])

    @abc.abstractmethod
    def _pre_enter(self):
        '''
        Callback for class-specific tasks that happen before
        CampaignBase.__enter__() does its work.  If self is modified it must
        return self, otherwise no return value is needed.

        @return: None or self
        '''

    @abc.abstractmethod
    def _post_enter(self):
        '''
        Callback for class-specific tasks that happen after
        CampaignBase.__enter__() does its work. If self is modified it must
        return self, otherwise no return value is needed.

        @return: None or self
        '''

    def __enter__(self):
        '''
        Creates a runtime context for the campaign.
        '''
        _result = self._pre_enter()
        if _result is not None:
            self = _result

        self._read_state()
        self._check_prog()
        self._setup_workdir()
        self._set_fuzzer()
        self._set_runner()
        self._check_runner()
        self._setup_output()
        self._create_seedfile_set()

        _result = self._post_enter()
        if _result is not None:
            self = _result

        return self

    def _handle_common_errors(self, etype, value, mytraceback):
        '''
        Handles errors common to this class and all its subclasses
        :param etype:
        :param value:
        '''
        handled = False
        if etype is KeyboardInterrupt:
            logger.warning('Keyboard interrupt - exiting')
            handled = True
        elif etype is RunnerArchitectureError:
            logger.error('Unsupported architecture: %s', value)
            logger.error('Set "verify_architecture=false" in the runner         section of your config to override this check')
            handled = True
        elif etype is RunnerPlatformVersionError:
            logger.error('Unsupported platform: %s', value)
            handled = True
        return handled

    def _handle_errors(self, etype, value, mytraceback):
        '''
        Callback to handle class-specific errors. If used, it should be
        overridden by subclasses. Will be called after _handle_common_errors

        :param etype:
        :param value:
        :param mytraceback:
        '''

    def _log_unhandled_exception(self, etype, value, mytraceback):
        logger.debug('Unhandled exception:')
        logger.debug('  type: %s', etype)
        logger.debug('  value: %s', value)
        for l in traceback.format_exception(etype, value, mytraceback):
            logger.debug(l.rstrip())

    @abc.abstractmethod
    def _pre_exit(self):
        '''
        Implements methods to be completed prior to handling errors in the
        __exit__ method. No return value.
        '''

    def __exit__(self, etype, value, mytraceback):
        '''
        Handles known exceptions gracefully, attempts to clean up temp files
        before exiting.
        '''
        self._pre_exit()

        # handle common errors
        handled = self._handle_common_errors(etype, value, mytraceback)

        if etype and not handled:
            # call the class-specific error handler
            handled = self._handle_errors(etype, value, mytraceback)

        cleanup = True
        if etype and not handled:
            # if you got here, nothing has handled the error
            # so log it and keep going
            self._log_unhandled_exception(etype, value, mytraceback)

        if self.debug and etype:
            # short out if in debug mode and an error occurred
            logger.debug('Skipping cleanup since we are in debug mode.')
            return handled

        # debug not set, so we should clean up
        self._cleanup_workdir()

        return handled

    def _check_prog(self):
        if not os.path.exists(self.program):
            msg = 'Cannot find program "%s" (resolves to "%s")' % (self.program, os.path.abspath(self.program))
            raise CampaignError(msg)

    def _set_fuzzer(self):
        self.fuzzer_module = import_module_by_name(self.fuzzer_module_name)
        self.fuzzer_cls = self.fuzzer_module._fuzzer_class

    def _set_runner(self):
        if self.runner_module_name:
            self.runner_module = import_module_by_name(self.runner_module_name)
            self.runner_cls = self.runner_module._runner_class

    def _check_runner(self):
        # try to run the runner module's check_runner method
        try:
            self.runner_module.check_runner()
        except AttributeError:
            # not a big deal if it's not there, just note it and keep going.
            logger.warn('Runner module %s has no check_runner method. Skipping runner check.')

    @property
    def _version_file(self):
        return os.path.join(self.outdir, 'version.txt')

    def _write_version(self):
        version_string = 'Results produced by %s v%s' % (__name__, __version__)
        filetools.write_file(version_string, self._version_file)

    def _setup_output(self):
        # construct run output directory
        filetools.make_directories(self.outdir)
        # copy config to run output dir
        filetools.copy_file(self.config_file, self.outdir)
        self._write_version()

    def _setup_workdir(self):
        # make_directories silently skips existing dirs, so it's okay to call
        # it even if work_dir_base already exists
        filetools.make_directories(self.work_dir_base)
        # now we're sure work_dir_base exists, so it's safe to create temp dirs
        self.working_dir = tempfile.mkdtemp(prefix='campaign_', dir=self.work_dir_base)
        self.seed_dir_local = os.path.join(self.working_dir, 'seedfiles')

    def _cleanup_workdir(self):
        try:
            shutil.rmtree(self.working_dir)
        except:
            pass

        if os.path.exists(self.working_dir):
            logger.warning("Unable to remove campaign working dir: %s", self.working_dir)
        else:
            logger.debug('Removed campaign working dir: %s', self.working_dir)

    def _create_seedfile_set(self):
        if self.seedfile_set is not None:
            return

        logger.info('Building seedfile set')
        with SeedfileSet(campaign_id=self.campaign_id,
                         originpath=self.seed_dir_in,
                         localpath=self.seed_dir_local,
                         outputpath=self.sf_set_out) as sfset:
            self.seedfile_set = sfset

    @abc.abstractmethod
    def __getstate__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def __setstate__(self):
        raise NotImplementedError

    def _read_state(self, cache_file=None):
        if not cache_file:
            cache_file = self.cached_state_file

        if not os.path.exists(cache_file):
            logger.info('No cached campaign found, using new campaign')
            return

        try:
            with open(cache_file, 'rb') as fp:
                campaign = pickle.load(fp)
        except Exception, e:
            logger.warning('Unable to read %s, will use new campaign instead: %s', cache_file, e)
            return

        if campaign:
            try:
                if self.config['config_timestamp'] != campaign.__dict__['config_timestamp']:
                    logger.warning('Config file modified. Discarding cached campaign')
                else:
                    self.__dict__.update(campaign.__dict__)
                    logger.info('Reloaded campaign from %s', cache_file)
            except KeyError:
                logger.warning('No config date detected. Discarding cached campaign')
        else:
            logger.warning('Unable to reload campaign from %s, will use new campaign instead', cache_file)

    def _save_state(self, cachefile=None):
        if not cachefile:
            cachefile = self.cached_state_file
        # FIXME
        # dump_obj_to_file(cachefile, self)

    def _crash_is_unique(self, crash_id, exploitability='UNKNOWN'):
        '''
        If crash_id represents a new crash, add the crash_id to crashes_seen
        and return True. Otherwise return False.

        @param crash_id: the crash_id to look up
        @param exploitability: not used at this time
        '''
        if not crash_id in self.crashes_seen:
            self.crashes_seen.add(crash_id)
            logger.debug("%s did not exist in cache, crash is unique", crash_id)
            return True
        logger.debug('%s was found, not unique', crash_id)
        return False

    def _keep_going(self):
        '''
        Returns True if a campaign should proceed. False otherwise.
        '''
        return True

    def _do_interval(self):
        '''
        Implements a loop over a set of iterations
        '''
        # wipe the tmp dir clean to try to avoid filling the VM disk
        TmpReaper().clean_tmp()

        # choose seedfile
        sf = self.seedfile_set.next_item()
        logger.info('Selected seedfile: %s', sf.basename)

# TODO: restore this
#         if self.current_seed % self.status_interval == 0:
#             # cache our current state
#             self._save_state()

        r = sf.rangefinder.next_item()

#         rng_seed = int(sf.md5, 16)

        interval_limit = self.current_seed + self.seed_interval

        # start an iteration interval
        # note that range does not include interval_limit
        logger.debug('Starting interval %d-%d', self.current_seed, interval_limit)
        for seednum in xrange(self.current_seed, interval_limit):
            self._do_iteration(sf, r, seednum)

        del sf
        # manually collect garbage
        gc.collect()

        self.current_seed = interval_limit
        self.first_chunk = False

    @abc.abstractmethod
    def _do_iteration(self):
        '''
        Implements a single iteration of the fuzzing process.
        '''

    def go(self):
        '''
        Starts campaign
        '''
        while self._keep_going():
            self._do_interval()
