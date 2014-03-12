'''
Created on Mar 20, 2013

@organization: cert.org
'''
from certfuzz.campaign.config.config_base import Config as ConfigBase
#from ...android.controller.defaults import CONFIG as DEFAULT_CONFIG
import logging

logger = logging.getLogger(__name__)


class AndroidConfig(ConfigBase):

    def __init__(self, config_file):

        super(AndroidConfig, self).__init__(config_file)

        self._set_derived_options()
        self.validations = []
        self._add_validations()
        self.validate()

    def _set_derived_options(self):
        ConfigBase._set_derived_options(self)

    def _add_validations(self):
        self.validations.append(self._validate_intent)
        self.validations.append(self._validate_directories)
        self.validations.append(self._validate_db_config)

    def _validate_intent(self):
        # TODO validating the specified intent action, categories, and mime_type
        # against the list of valid entries from the android spec could be
        # a good future capability
        return

    def _validate_directories(self):
        # Make sure apk_dir exists if it is specified, otherwise it
        # should be None
        try:
            self.config['directories']['apk_dir']
        except KeyError:
            logger.warning('No APK installation directory specified. ' +
                           'Make sure any needed APKs are already installed.')
            self.config['directories']['apk_dir'] = None

    def _validate_db_config(self):

        # Validate username and password.  If not found, set to None
        for x in ['username', 'password']:
            try:
                x = self.config['db'][x]
            except KeyError:
                logger.warning('No %s specified in config' % x)
                self.config['db'][x] = None

        # Validate host
        try:
            self.config['db']['host']
        except KeyError:
            logger.warning('No host specified in config.  Defaulting to localhost.')
            self.config['db']['host'] = 'localhost'

        # Validate port
        try:
            db_port = self.config['db']['port']
        except KeyError:
            logger.warning('No db port specified in config')
            db_port = None
        if db_port == None or db_port < 0 or db_port > 65535:
            logger.warning('Invalid db port specified in config.  Defaulting to 5984.')
            self.config['db']['port'] = 5984

        # Validate dbname
        try:
            self.config['db']['dbname']
        except KeyError:
            logger.warning('No dbname specified in config.  Defaulting to bff.')
            self.config['db']['dbname'] = 'bff'
