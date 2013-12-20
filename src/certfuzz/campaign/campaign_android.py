'''
Created on Feb 7, 2013

@organization: cert.org
'''
import logging
import random
from . import __version__
from .campaign import Campaign
from .iteration_android import do_iteration
from .config.android_config import AndroidConfig
from ..db.couchdb.db import TestCaseDb, put_file
from ..db.couchdb.datatypes.campaign_doc import AndroidCampaignDoc
from ..file_handlers.directory import Directory
from ..android.api.intent import Intent
from ..android.worker import worker
from .errors import AndroidCampaignError
from socket import error as socket_error
import errno

logger = logging.getLogger(__name__)


# TODO this should inherit from campaignbase?
class AndroidCampaign(Campaign):
    def __init__(self, config_file='config/android_config.yaml',
                 intent_yaml=None,
                 repeat_count=None):
        logger.debug('initialize %s', self.__class__.__name__)
        self.config_file = config_file
        self._version = __version__

        cfgobj = AndroidConfig(self.config_file)
        self.config = cfgobj.config
        logger.debug('Config: %s', self.config)

        self.campaign_id = self.config['campaign']['id']
        self.fuzzopts = self.config['fuzzer']
        self.runopts = self.config['runner']
        self.apk_dir = self.config['directories']['apk_dir']
        self.emu_opts = self.config['emulator']
        self.task_timeout = 3600  # an hour should be plenty long enough

        self.intent = Intent()
        if intent_yaml is None:
            self.intent.__dict__.update(self.config['target']['intent'])
        else:
            self.intent.__dict__.update(intent_yaml)

        self.dbcfg = self.config['db']

        # if the config doesn't specify otherwise...
        self.current_seed = 0

        try:
            self.current_seed = self.config['runoptions']['first_iteration']
        except KeyError:
            pass

        self.seed_interval = 10

        if repeat_count != None:
            self.stop_seed = repeat_count
        else:
            try:
                self.stop_seed = self.config['runoptions']['last_iteration']
            except KeyError:
                self.stop_seed = None

        self.results = []
        self.result_db = None
        self.seedfiles = None
        self.emu_handles = set()
        self.handle_selector = 0

    def _connect_db(self):
        host = self.dbcfg['host']
        port = self.dbcfg['port']
        username = self.dbcfg['username']
        password = self.dbcfg['password']
        db = self.dbcfg['dbname']
        self.result_db = TestCaseDb(host, port, username, password, db)

    def _clear_db(self):
        self.result_db = None

    def _store_seedfiles(self, sf_dir):
        logger.info('loading seedfiles into database')
        self.seedfiles = Directory(sf_dir).files

        if not len(self.seedfiles):
            raise AndroidCampaignError('No seedfiles found')

        for basicfile in self.seedfiles:
            put_file(basicfile, self.result_db.db)

    def _store_campaign_details(self):
        # get or create the doc
        try:
            doc = AndroidCampaignDoc.load(self.result_db.db,
                                          self.config['campaign']['id'])
        except KeyError:
            doc = None

        if doc is None:
            doc = AndroidCampaignDoc()
            try:
                doc.id = self.config['campaign']['id']
            except KeyError:
                logger.debug('Campaign id not set in config, will autogenerate')

        # add data to the doc
        doc.target = self.config['target']
        doc.config = self.config['runoptions']
        doc.fuzzopts = self.config['fuzzer']
        doc.runopts = self.config['runner']

        # store it
        doc.store(self.result_db.db)

        # remember the id of this doc
        self.campaign_id = doc.id

    def _store_campaign(self):
        '''
        Stores information about the campaign to the db
        '''
        self._store_campaign_details()

        sf_dir = self.config['directories']['seedfile_dir']
        self._store_seedfiles(sf_dir)

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        '''
        Kill workers...
        :param etype:
        :param value:
        :param traceback:
        '''
        handled = False

        self._clear_db()

        if etype == KeyboardInterrupt:
            logger.warning('Campaign cancelled by ctrl-c')
            handled = True
        elif etype == AndroidCampaignError:
            logger.warning('Campaign exiting due to: %s', value)
            handled = True
        elif etype == socket_error:
            # we can handle socket error only if it's a connection refused
            if etype.errno == errno.ECONNREFUSED:
                logger.warning('Failed to connect to db: (%s) %s', etype, value)
                handled = True

        logger.info('Campaign Complete')
        return handled

    def __getstate__(self):
        pass

    def __setstate__(self):
        pass

    def _write_version(self):
        Campaign._write_version(self)

    def _keep_going(self):
        return (not self.stop_seed
                or (self.current_seed < self.stop_seed))

    def _pick_seedfile(self):
        sf = random.choice(self.seedfiles)
        return sf.sha1

    def _do_interval(self):
        interval_limit = self.current_seed + self.seed_interval

        # don't overshoot stop_seed
        if self.stop_seed:
            interval_limit = min(interval_limit, self.stop_seed)

        interval = xrange(self.current_seed, interval_limit)

        iter_args = {'campaign_id': 'campaign_id',
                'db_config': self.config['db'],
                'fuzzopts': self.fuzzopts,
                 'runopts': self.runopts,
                 'intent': self.intent,
                 'sf': self._pick_seedfile(),
                 'sf_dir': self.config['directories']['seedfile_dir'],
                 'num': None,
                 }

        # asynchronously call each iteration for this interval
        # iterations are thus passed out to the worker pool
        for iteration_num  in interval:
            iter_args['num'] = iteration_num
            logger.debug('queueing iteration %d', iteration_num)

            do_iteration(iter_args)
        logger.debug('interval complete')

        # move the current_seed pointer to the next interval
        self.current_seed = interval_limit

    def go(self):
        '''
        1. Connect to database
        2. Put campaign info into db
        3. Spawn workers
        4. Do stuff
        '''
        logger.info('Starting Campaign')
        self._connect_db()
        self._store_campaign()
        logger.info('Using db %s@%s for campaign %s',
                    self.result_db.db_name,
                    self.result_db.connection_string,
                    self.campaign_id)

        worker.start_emulator(self.emu_opts, self.apk_dir)

        Campaign.go(self)
